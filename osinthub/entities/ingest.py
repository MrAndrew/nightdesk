"""Text ingest hook: `ingest_text(ref_type, ref_id, text, url, source_tier)`.

Called by the news package for each article (and usable for any text). Runs extract(),
stores mentions for everything found and reported claims (with the verified quote, the
publisher and its tier as evidence). Blocking and LLM-bound: call it from a worker thread.
Docs: okf/data/entities.md#text-ingest
"""
from __future__ import annotations

import datetime as dt
import logging
from urllib.parse import urlsplit

from .extract import extract
from .link import Batch, country_entity
from .normalize import entity_id, key
from .refdata import catalog

log = logging.getLogger("osinthub.entities.ingest")

IOC_TYPES = {"ip": "ip", "domain": "domain", "url": "url", "md5": "hash", "sha1": "hash", "sha256": "hash", "cve": "cve"}


def _publisher(url: str | None, source: str | None) -> str:
    if source:
        return source
    try:
        h = (urlsplit(url or "").hostname or "").lower()
        return h[4:] if h.startswith("www.") else (h or "unknown")
    except ValueError:
        return "unknown"


def _country_id(name: str) -> str | None:
    import re
    if re.fullmatch(r"[A-Za-z]{2}", name.strip()):
        c = country_entity(name)
        return c["id"] if c else None
    try:
        from .. import geo
        for n, iso in geo.country_name_index():
            if n == name.lower().strip() or n == name.lower().strip().removeprefix("the "):
                return entity_id("country", iso)
    except Exception:
        pass
    # adjectives the model often gives ("Iranian", "Chinese")
    adj = {"chinese": "CN", "russian": "RU", "iranian": "IR", "north korean": "KP", "korean": "KR", "ukrainian": "UA",
           "american": "US", "israeli": "IL", "vietnamese": "VN", "pakistani": "PK", "indian": "IN", "turkish": "TR",
           "belarusian": "BY", "taiwanese": "TW", "japanese": "JP", "south korean": "KR", "mongolian": "MN"}
    iso = adj.get(name.lower().strip())
    return entity_id("country", iso) if iso else None


def ingest_text(ref_type: str, ref_id: str, text: str, url: str | None = None, source_tier: str = "C",
                source: str | None = None, ts: dt.datetime | None = None, use_llm: bool = True,
                story_id: str | None = None) -> dict:
    """Extract entities and claims from a text and store them. Returns the extract() result
    plus counts. `source` is the publisher name (defaults to the URL's host); syndicated
    copies are recognised in scoring by identical quotes or a shared `story_id`."""
    if ref_type == "article" and (source is None or story_id is None or ts is None):
        try:
            from .. import db
            r = db.query("SELECT source, story_id, coalesce(published, fetched_at) AS ts FROM articles WHERE id = ?", [ref_id])
            if r:
                source = source or r[0]["source"]
                story_id = story_id or r[0]["story_id"]
                ts = ts or r[0]["ts"]
        except Exception:
            pass
    ts = ts or dt.datetime.now(dt.UTC)
    tier = (source_tier or "C").upper()[:1]
    pub = _publisher(url, source)
    res = extract(text or "", url, use_llm=use_llm)
    cat = catalog()
    b = Batch()
    from .extract import LAST_STATS
    method = "llm" if LAST_STATS.get("llm") else "alias"

    def ev(quote=None):
        e = {"source": pub, "tier": tier, "url": url, "ref_type": ref_type, "ref_id": ref_id, "ts": ts.isoformat(),
             "method": "llm"}
        if quote:
            e["quote"] = quote
        if story_id:
            e["story_id"] = story_id
        return e

    def claim(subj, pred, obj, quote=None):
        b.claims.append({"subj": subj, "predicate": pred, "obj": obj, "origin": "reported", "sources": [pub],
                         "first_seen": ts, "last_seen": ts, "evidence": [ev(quote)]})

    known: dict[str, str] = {}   # key(name) -> entity id, for claims

    for kind, vals in (res.get("iocs") or {}).items():
        t = IOC_TYPES.get(kind)
        for v in vals:
            eid = b.ent(t, v, name=v, attrs={"hash_type": kind} if t == "hash" else {}, ts=ts)
            b.mention(eid, ref_type, ref_id, "mentioned", "regex", 0.9, ts)
            known[key(v)] = eid

    def named(type_list, names, role, conf):
        out = []
        for n in names or []:
            eid = cat.resolve(n, types=type_list, fuzzy=False)
            if eid:
                e = cat.entities[eid]
                b.ent(e["type"], e["name"], name=e["name"], ts=ts)
            else:
                eid = b.ent(type_list[0], n, name=n, ts=ts)
            b.mention(eid, ref_type, ref_id, role, method, conf, ts)
            known[key(n)] = eid
            out.append(eid)
        return out

    actors = named(("actor",), res.get("actors"), "actor", 0.75)
    malware = named(("malware", "tool"), res.get("malware"), "malware", 0.75)
    campaigns = named(("campaign",), res.get("campaigns"), "campaign", 0.7)
    for s in res.get("sectors") or []:
        eid = b.ent("sector", s.lower(), name=s.lower(), ts=ts)
        b.mention(eid, ref_type, ref_id, "target", "llm", 0.6, ts)
        known[key(s)] = eid
    for c in res.get("countries") or []:
        cid = _country_id(c)
        if cid:
            ce = country_entity(cid.split(":", 1)[1])
            b.entities.append({**ce, "first_seen": ts, "last_seen": ts})
            b.mention(cid, ref_type, ref_id, "mentioned", "llm", 0.6, ts)
            known[key(c)] = cid
    for o in res.get("orgs") or []:              # named by the model as an actor, but nothing malicious attributed
        eid = b.ent("org", o, name=o, ts=ts)
        b.mention(eid, ref_type, ref_id, "mentioned", "llm", 0.3, ts)
        known[key(o)] = eid
    for v in res.get("victims") or []:
        eid = b.ent("org", v, name=v, ts=ts)
        b.mention(eid, ref_type, ref_id, "victim", "llm", 0.6, ts)
        known[key(v)] = eid
    for tid in res.get("suggested_techniques") or []:
        teid = entity_id("technique", tid)
        b.ent("technique", tid, name=(cat.entities.get(teid) or {}).get("name", tid), ts=ts)
        b.mention(teid, ref_type, ref_id, "technique-suggested", "llm", 0.3, ts)
        quote = (res.get("technique_quotes") or {}).get(tid)
        actor = (actors or malware or campaigns or [None])[0]
        if actor and quote:
            e = ev(quote)
            e["suggested"] = True
            b.claims.append({"subj": actor, "predicate": "uses", "obj": teid, "origin": "reported", "sources": [pub],
                             "first_seen": ts, "last_seen": ts, "evidence": [e]})
    for tid in res.get("techniques") or []:
        teid = entity_id("technique", tid)
        b.ent("technique", tid, name=(cat.entities.get(teid) or {}).get("name", tid), ts=ts)
        b.mention(teid, ref_type, ref_id, "technique", "llm", 0.7, ts)
        quote = (res.get("technique_quotes") or {}).get(tid)
        actor = (actors or malware or campaigns or [None])[0]
        if actor and quote:
            claim(actor, "uses", teid, quote)

    def ent_for(name: str) -> str | None:
        k = key(name)
        if k in known:
            return known[k]
        eid = cat.resolve(name, types=("actor", "malware", "tool", "campaign"), fuzzy=True)
        if eid:
            e = cat.entities[eid]
            b.ent(e["type"], e["name"], name=e["name"], ts=ts)
            return eid
        cid = _country_id(name)
        if cid:
            return cid
        return None

    stored = 0
    for c in res.get("claims") or []:
        s, o = ent_for(c["subject"]), ent_for(c["object"])
        if not s or not o or s == o:
            if s and not o and c["predicate"] in ("targets",):
                o = b.ent("org", c["object"], name=c["object"], ts=ts)
            else:
                continue
        claim(s, c["predicate"], o, c["quote"])
        stored += 1
    n = b.flush()
    res["stored"] = {"entities": n[0], "mentions": n[1], "claims": n[2], "llm_claims": stored}
    return res
