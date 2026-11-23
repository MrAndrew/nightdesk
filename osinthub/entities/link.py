"""Deterministic linking of events (and texts) to entities, mentions and observed claims.

Runs as a background task: every event not yet linked (or whose content changed) is turned
into entities and mentions; the seed history is backfilled on the first pass.
Docs: okf/data/entities.md#linking
"""
from __future__ import annotations

import gzip
import ipaddress
import json
import logging
import re
from pathlib import Path

from .. import config, db
from . import store
from .iocs import extract_iocs
from .normalize import entity_id
from .refdata import catalog
from .scoring import tier_of

log = logging.getLogger("osinthub.entities.link")

PREFIX_SOURCES = {"spamhaus_drop", "ris_live"}       # their `ip` column is a synthetic first host
TEXT_CATEGORIES = {"news", "social", "custom"}
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_PFX = re.compile(r"\b([0-9a-f:.]+/\d{1,3})\b", re.I)
_ORIGIN = re.compile(r"AS(\d+)\s*→\s*AS(\d+)")
_SKIP_TAGS = {"low", "medium", "high", "critical", "offline", "online", "bgp", "moas", "arin", "ripencc", "apnic",
              "lacnic", "afrinic", "unknown", "none", "other"}


def _country_names() -> dict[str, str]:
    try:
        from .. import geo
        return {k: v.get("name") or k for k, v in geo.countries().items()}
    except Exception:
        return {}


_CN: dict[str, str] | None = None


def country_entity(cc: str) -> dict | None:
    global _CN
    if not cc or not re.fullmatch(r"[A-Za-z]{2}", cc):
        return None
    if _CN is None:
        _CN = _country_names()
    cc = cc.upper()
    return {"id": entity_id("country", cc), "type": "country", "name": _CN.get(cc, cc), "attrs": {"iso2": cc}}


class Batch:
    def __init__(self):
        self.entities: list[dict] = []
        self.mentions: list[dict] = []
        self.claims: list[dict] = []

    def ent(self, type_, value, name=None, attrs=None, ts=None, aliases=None) -> str:
        eid = entity_id(type_, value)
        self.entities.append({"id": eid, "type": type_, "name": name or value, "attrs": attrs or {},
                              "first_seen": ts, "last_seen": ts, "aliases": aliases or []})
        return eid

    def mention(self, eid, ref_type, ref_id, role, method, conf, ts):
        self.mentions.append({"entity_id": eid, "ref_type": ref_type, "ref_id": ref_id, "role": role,
                              "method": method, "confidence": conf, "ts": ts})

    def claim(self, subj, pred, obj, origin, source, ts, ev=None):
        e = {"source": source, "tier": tier_of(source), "ts": ts.isoformat() if hasattr(ts, "isoformat") else ts}
        if ev:
            e.update(ev)
        self.claims.append({"subj": subj, "predicate": pred, "obj": obj, "origin": origin, "sources": [source],
                            "first_seen": ts, "last_seen": ts, "evidence": [e]})

    def flush(self):
        n = (store.upsert_entities(self.entities), store.add_mentions(self.mentions), store.upsert_claims(self.claims))
        self.entities, self.mentions, self.claims = [], [], []
        return n


# ---------------------------------------------------------------- KEV raw records
_KEV: dict[str, dict] | None = None
_KEV_FILES: set[str] = set()


def kev_records() -> dict[str, dict]:
    """Latest KEV record per CVE, replayed from the lake's record files (new files only)."""
    global _KEV
    if _KEV is None:
        _KEV = {}
    root = Path(config.RAW_DIR) / "cisa_kev"
    for f in sorted(root.glob("*/*/*/*.records.ndjson.gz")):
        if str(f) in _KEV_FILES:
            continue
        _KEV_FILES.add(str(f))
        try:
            with gzip.open(f, "rt") as fh:
                for line in fh:
                    r = json.loads(line)
                    if r.get("op") == "put" and isinstance(r.get("data"), dict):
                        _KEV[r["key"].upper()] = r["data"]
        except Exception as e:
            log.warning("could not read %s: %s", f, e)
    return _KEV


_FEODO: dict[str, dict] | None = None


def feodo_records() -> dict[str, dict]:
    global _FEODO
    _FEODO = _FEODO or {}
    for f in sorted((Path(config.RAW_DIR) / "feodo_c2").glob("*/*/*/*.records.ndjson.gz")):
        try:
            with gzip.open(f, "rt") as fh:
                for line in fh:
                    r = json.loads(line)
                    if r.get("op") == "put" and isinstance(r.get("data"), dict):
                        _FEODO[r["data"].get("ip_address")] = r["data"]
        except Exception:
            continue
    return _FEODO


ABUSECH = ("threatfox", "urlhaus", "sslbl")
_AB: dict[str, dict[str, dict]] = {}
_AB_FILES: set[str] = set()


def abusech_records(source: str) -> dict[str, dict]:
    """Latest abuse.ch record per event id (source:sha1(key)), replayed from the lake's record files (new files only)."""
    from ..sources.base import make_id
    out = _AB.setdefault(source, {})
    for f in sorted((Path(config.RAW_DIR) / source).glob("*/*/*/*.records.ndjson.gz")):
        if str(f) in _AB_FILES:
            continue
        _AB_FILES.add(str(f))
        try:
            with gzip.open(f, "rt") as fh:
                for line in fh:
                    r = json.loads(line)
                    if r.get("op") == "put" and isinstance(r.get("data"), dict):
                        out[make_id(source, r["key"])] = r["data"]
        except Exception as e:
            log.warning("could not read %s: %s", f, e)
    return out


def _family(b: Batch, names: list[str | None], malpedia: str | None, ts, create: bool) -> str | None:
    """Entity id of a malware family: by Malpedia id, then each name through the alias catalogue (MISP,
    Malpedia, ATT&CK). An unknown name becomes a new malware entity only when `create`, marked as coming
    from abuse.ch so it is never embedded (abuse.ch terms)."""
    cat = catalog()
    eid = cat.malpedia.get((malpedia or "").strip().lower()) if malpedia else None
    if eid:
        b.ent(eid.split(":", 1)[0], cat.entities[eid]["name"], name=cat.entities[eid]["name"], ts=ts)
        return eid
    for n in names:
        if n and (hit := _resolve_name(n, ("malware", "tool"))):
            b.ent(hit[0].split(":", 1)[0], hit[1], name=hit[1], ts=ts)
            return hit[0]
    first = next((n for n in names if n), None)
    if create and first:
        return b.ent("malware", first, name=first, attrs={"ai_excluded": "abuse.ch terms of use"}, ts=ts)
    return None


def _url_name(u: str) -> str:
    """A URL entity name: scheme and host lower-cased (they are case-insensitive), path and query as given."""
    from urllib.parse import urlsplit, urlunsplit
    u = (u or "").strip()
    try:
        p = urlsplit(u)
        return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path, p.query, ""))
    except ValueError:
        return u


def link_abusech(b: Batch, ev: dict, rec: dict, ip_id: str | None) -> None:
    """ThreatFox, URLhaus and SSLBL events: the IOC entity (ip, domain, URL, hash), its malware family and an
    observed claim between them. okf/data/entities.md#linking"""
    from ..sources import abusech as ab
    src, ts, ref = ev["source"], ev["ts"], ev["id"]
    ev_note = {"ref_type": "event", "ref_id": ref, "url": ev.get("url")}
    iocs: list[str] = [ip_id] if ip_id else []

    def ioc(type_, value, attrs=None):
        eid = b.ent(type_, value, name=value, attrs=attrs or {}, ts=ts)
        b.mention(eid, "event", ref, "indicator", "field", 1.0, ts)
        iocs.append(eid)
        return eid

    if src == "threatfox":
        i = ab.tf_ioc(rec)
        if not i:
            return
        if i.get("host_kind") == "domain" and i["type"] == "domain":
            ioc("domain", i["host"])
        elif i["type"] == "url":
            ioc("url", _url_name(i["value"]))
            if i["host_kind"] == "domain":
                ioc("domain", i["host"])
        elif i.get("hash"):
            ioc("hash", i["hash"], {"hash_type": i["type"].replace("_hash", "")})
        aliases = [a.strip() for a in str(rec.get("malware_alias") or "").split(",") if a.strip()]
        fam = _family(b, [ab.tf_family(rec), *aliases], rec.get("malware"), ts, create=True)
        tt = (rec.get("threat_type") or "").lower()
        pred = "indicates" if i.get("hash") else "delivers" if tt == "payload_delivery" else "hosts-malware"
        extra = {"threat_type": tt, "confidence": rec.get("confidence_level"), "port": i.get("port")}
    elif src == "urlhaus":
        nu = ab.norm_url(rec.get("url"))
        if not nu:
            return
        ioc("url", _url_name(str(rec.get("url"))))
        if nu[0] == "domain":
            ioc("domain", nu[1])
        tags = ab._tags(rec.get("tags"))
        fam = _family(b, [t for t in tags if t.lower() not in ab.UH_GENERIC], None, ts, create=False)
        pred, extra = "delivers", {"status": rec.get("url_status")}
    else:
        return
    if not fam:
        return
    # no family mention per IOC: thousands of feed rows a day must not outrank what reports say (mention counts
    # drive the entity directory and trends); the observed claims below link the indicators to the family
    for eid in dict.fromkeys(iocs):
        b.claim(eid, pred, fam, "observed", src, ts, {**ev_note, **{k: v for k, v in extra.items() if v not in (None, "")}})


def link_sslbl_family(b: Batch, ev: dict) -> None:
    """SSLBL certificates are indicators, not activity: no entity, mention or claim per certificate. A family's
    summary event ("Vidar: 731 C2 TLS certificates on SSL Blacklist") gives one fact on a family the catalogue
    already knows, attrs sslbl_certificates / sslbl_last_listed, and one mention. Unknown names make nothing."""
    name = next(iter(ev.get("tags") or []), None)
    hit = _resolve_name(name, ("malware", "tool")) if name else None
    if not hit:
        return
    ts = ev["ts"]
    attrs = {"sslbl_certificates": int(ev.get("value") or 0),
             "sslbl_last_listed": ts.isoformat()[:10] if hasattr(ts, "isoformat") else str(ts)[:10]}
    eid = b.ent(hit[0].split(":", 1)[0], hit[1], name=hit[1], attrs=attrs, ts=ts)
    b.mention(eid, "event", ev["id"], "malware", "field", 1.0, ts)


# ---------------------------------------------------------------- per event
def _resolve_name(name: str, types) -> tuple[str, str] | None:
    cat = catalog()
    eid = cat.resolve(name, types=types, fuzzy=False)
    if eid:
        return eid, cat.entities[eid]["name"]
    return None


def link_event(b: Batch, ev: dict, kev: dict, feodo: dict) -> None:
    eid_ref = ev["id"]
    ts = ev["ts"]
    src = ev["source"]
    if src == "epss":   # a score refresh is not a sighting or a mention (EPSS makes no events any more)
        return
    kind = ev["kind"]
    ip = ev.get("ip")
    asn = ev.get("asn")
    cc = ev.get("country")
    tags = ev.get("tags") or []
    title = ev.get("title") or ""
    is_threat = ev.get("category") == "threat"

    ip_id = None
    if ip and src not in PREFIX_SOURCES:
        attrs = {"asn": asn, "country": cc}
        if src == "tor_exits":
            attrs["tor"] = True
        ip_id = b.ent("ip", ip, attrs=attrs, ts=ts)
        b.mention(ip_id, "event", eid_ref, "indicator" if is_threat else "subject", "field", 1.0, ts)
    asn_id = None
    if asn:
        org = next((t[4:] for t in tags if t.startswith("org:")), None)
        asn_id = b.ent("asn", asn, name=asn.upper(), attrs={"org": org} if org else {}, ts=ts)
        b.mention(asn_id, "event", eid_ref, "asn", "field", 1.0, ts)
    if cc:
        c = country_entity(cc)
        if c:
            b.entities.append({**c, "first_seen": ts, "last_seen": ts})
            b.mention(c["id"], "event", eid_ref, "country", "field", 1.0, ts)

    # prefixes: Spamhaus DROP and BGP
    if src in PREFIX_SOURCES:
        for p in _PFX.findall(title):
            try:
                net = ipaddress.ip_network(p, strict=False)
            except ValueError:
                continue
            pid = b.ent("prefix", str(net), attrs={"version": net.version, "size": net.num_addresses,
                                                   **({"drop": True} if src == "spamhaus_drop" else {})}, ts=ts)
            b.mention(pid, "event", eid_ref, "indicator" if is_threat else "subject", "field", 1.0, ts)
            m = _ORIGIN.search(title)
            if m and kind == "bgp_origin_change":
                for i, a in enumerate(m.groups()):
                    aid = b.ent("asn", f"AS{a}", name=f"AS{a}", ts=ts)
                    b.claim(pid, "announced-by", aid, "observed", src, ts,
                            {"ref_type": "event", "ref_id": eid_ref, "note": "previous origin" if i == 0 else "new origin"})
            elif asn_id and src == "spamhaus_drop":
                b.mention(asn_id, "event", eid_ref, "asn", "geoip", 0.6, ts)

    # CVEs from vulnerability events (and KEV vendor / product)
    if kind in ("kev", "cve") or ev.get("category") == "vuln":
        for c in dict.fromkeys(x.upper() for x in _CVE.findall(title)):
            attrs = {}
            if kind == "cve" and ev.get("value") is not None:
                attrs["cvss"] = ev.get("value")
            rec = kev.get(c) if kind == "kev" else None
            if rec:
                attrs.update({"kev": True, "kev_added": rec.get("dateAdded"), "kev_name": rec.get("vulnerabilityName"),
                              "ransomware_use": rec.get("knownRansomwareCampaignUse"), "cwes": rec.get("cwes")})
            cid = b.ent("cve", c, name=c, attrs=attrs, ts=ts)
            b.mention(cid, "event", eid_ref, "subject", "field", 1.0, ts)
            if rec and rec.get("vendorProject"):
                vendor = rec["vendorProject"].strip()
                vid = b.ent("vendor", vendor, name=vendor, ts=ts)
                prod = (rec.get("product") or "").strip()
                if prod:
                    pid = b.ent("product", f"{vendor} {prod}", name=f"{vendor} {prod}", attrs={"vendor": vendor, "product": prod}, ts=ts)
                    b.mention(pid, "event", eid_ref, "affected", "field", 1.0, ts)
                    b.claim(cid, "affects", pid, "observed", src, ts, {"ref_type": "event", "ref_id": eid_ref,
                                                                       "quote": rec.get("vulnerabilityName")})
                    b.claim(pid, "made-by", vid, "observed", src, ts, {"ref_type": "event", "ref_id": eid_ref})
                b.mention(vid, "event", eid_ref, "vendor", "field", 1.0, ts)

    # CISA CSAF advisories: CVEs, vendors and products from the advisory's structured rows
    if src == "cisa_advisories" and kind == "advisory":
        link_advisory(b, ev)

    # malware from Feodo
    if src == "feodo_c2" and ip_id:
        rec = feodo.get(ip) or {}
        fam = rec.get("malware") or (title.split(" C2 ")[0] if " C2 " in title else (tags[0] if tags else None))
        if fam:
            hit = _resolve_name(fam, ("malware", "tool"))
            if hit:
                mid = b.ent(hit[0].split(":", 1)[0], hit[1], name=hit[1], ts=ts)
            else:   # known only from abuse.ch: never embedded (ai_ok = False, abuse.ch ToS s7.3), as _family()
                mid = b.ent("malware", fam, name=fam, attrs={"ai_excluded": "abuse.ch terms of use"}, ts=ts)
            b.mention(mid, "event", eid_ref, "malware", "field", 1.0, ts)
            b.claim(ip_id, "hosts-malware", mid, "observed", src, ts,
                    {"ref_type": "event", "ref_id": eid_ref, "port": rec.get("port"), "status": rec.get("status")})

    # abuse.ch: IOC entities, malware family (Malpedia id or alias), observed claim
    if src == "sslbl":
        link_sslbl_family(b, ev)
        return
    if src in ABUSECH:
        rec = abusech_records(src).get(eid_ref)
        if rec:
            link_abusech(b, ev, rec, ip_id)
        return   # their tags are reporter free text: the record gives the family

    # tags: owners, known malware / actors, countries
    for t in tags:
        if not t or t.lower() in _SKIP_TAGS:
            continue
        if t.startswith("org:"):
            oid = b.ent("org", t[4:], name=t[4:], ts=ts)
            b.mention(oid, "event", eid_ref, "owner", "tag", 0.9, ts)
            continue
        if re.fullmatch(r"[A-Z]{2}", t):
            c = country_entity(t)
            if c and c["id"] != (f"country:{cc.lower()}" if cc else None):
                b.entities.append({**c, "first_seen": ts, "last_seen": ts})
                b.mention(c["id"], "event", eid_ref, "mentioned", "tag", 0.8, ts)
            continue
        if src == "feodo_c2" or kind in ("kev", "advisory"):
            continue
        hit = _resolve_name(t, ("malware", "actor", "tool"))
        if hit:
            typ = hit[0].split(":", 1)[0]
            b.ent(typ, hit[1], name=hit[1], ts=ts)
            b.mention(hit[0], "event", eid_ref, "mentioned", "tag", 0.8, ts)

    # IOCs and known names in free text (not CSAF advisories: their CVEs and products are linked from structured data)
    if ev.get("category") in TEXT_CATEGORIES and src != "cisa_advisories":
        text = f"{title}\n{ev.get('summary') or ''}"
        link_text_iocs(b, "event", eid_ref, text, ev.get("url"), ts, method="regex", spot=True)


def link_advisory(b: Batch, ev: dict) -> None:
    """A CSAF advisory event: each CVE it covers (mention), the vendors and products it names, and observed
    `cve affects product` and `product made-by vendor` claims, as KEV gives them. Rows come from the
    `advisory_cves` table the source keeps (sources/vulns.py)."""
    from ..sources.vulns import ADVISORY_ID
    m = ADVISORY_ID.match(ev.get("title") or "")
    if not m:
        return
    eid_ref, ts, src = ev["id"], ev["ts"], ev["source"]
    try:
        rows = db.query("SELECT cve, cvss, vendors, products, title FROM advisory_cves WHERE advisory = ?", [m.group(1).upper()])
    except Exception:
        return
    for r in rows:
        attrs = {"cvss": r["cvss"]} if r["cvss"] is not None else {}
        cid = b.ent("cve", r["cve"], name=r["cve"], attrs=attrs, ts=ts)
        b.mention(cid, "event", eid_ref, "subject", "field", 1.0, ts)
        vendors = [v for v in (r["vendors"] or []) if v]
        for v in vendors:
            vid = b.ent("vendor", v, name=v, ts=ts)
            b.mention(vid, "event", eid_ref, "vendor", "field", 1.0, ts)
        for full in r["products"] or []:
            vendor = next((v for v in vendors if full == v or full.startswith(v + " ")
                           or full.split()[0].lower() == v.split()[0].lower()), None)
            prod = full[len(vendor) + 1:] if vendor and full.startswith(vendor + " ") else full
            pid = b.ent("product", full, name=full, attrs={"vendor": vendor, "product": prod} if vendor else {"product": prod}, ts=ts)
            b.mention(pid, "event", eid_ref, "affected", "field", 1.0, ts)
            b.claim(cid, "affects", pid, "observed", src, ts, {"ref_type": "event", "ref_id": eid_ref, "quote": r["title"]})
            if vendor:
                b.claim(pid, "made-by", entity_id("vendor", vendor), "observed", src, ts, {"ref_type": "event", "ref_id": eid_ref})


def link_text_iocs(b: Batch, ref_type, ref_id, text, url, ts, method="regex", spot=False, conf=0.9):
    io = extract_iocs(text, url)
    for kind, vals in io.items():
        for v in vals:
            t = "hash" if kind in ("md5", "sha1", "sha256") else kind
            eid = b.ent(t, v, name=v, attrs={"hash_type": kind} if t == "hash" else {}, ts=ts)
            b.mention(eid, ref_type, ref_id, "mentioned", method, conf, ts)
    if spot:
        from .extract import spot_names
        cat = catalog()
        a, m = spot_names(text)
        for name in a + m:
            eid = cat.resolve(name, types=("actor", "malware", "tool"), fuzzy=False)
            if eid:
                b.ent(eid.split(":", 1)[0], cat.entities[eid]["name"], name=cat.entities[eid]["name"], ts=ts)
                b.mention(eid, ref_type, ref_id, "mentioned", "alias", 0.8, ts)
    return io


# ---------------------------------------------------------------- passes
def pending_events(limit: int) -> list[dict]:
    return db.query(f"""
        SELECT e.id, e.source, e.kind, e.category, e.ts, e.title, e.summary, e.ip, e.asn, e.country, e.tags, e.url, e.value,
               coalesce(e.content_hash, CAST(epoch_ms(e.ts) AS VARCHAR)) AS h
        FROM events e LEFT JOIN entity_linked l ON l.ref_type = 'event' AND l.ref_id = e.id
        WHERE l.ref_id IS NULL OR l.hash IS DISTINCT FROM coalesce(e.content_hash, CAST(epoch_ms(e.ts) AS VARCHAR))
        ORDER BY e.ts LIMIT {int(limit)}""")


def link_pending(limit: int = 5000) -> int:
    evs = pending_events(limit)
    if not evs:
        return 0
    kev = kev_records() if any(e["kind"] == "kev" for e in evs) else {}
    feodo = feodo_records() if any(e["source"] == "feodo_c2" for e in evs) else {}
    b = Batch()
    for ev in evs:
        try:
            link_event(b, ev, kev, feodo)
        except Exception as e:
            log.warning("linking %s failed: %s", ev.get("id"), e)
    b.flush()
    store.mark_linked("event", [(e["id"], e["h"]) for e in evs])
    return len(evs)


def link_ip_prefixes() -> int:
    """Observed `ip in-prefix prefix` claims for every IP inside a known prefix (new pairs only)."""
    cur = db.cursor()
    prefixes = {}
    for pid, in cur.execute("SELECT id FROM entities WHERE type = 'prefix'").fetchall():
        try:
            prefixes[ipaddress.ip_network(pid.split(":", 1)[1], strict=False)] = pid
        except ValueError:
            continue
    if not prefixes:
        return 0
    by_len: dict[tuple[int, int], set] = {}
    for net in prefixes:
        by_len.setdefault((net.version, net.prefixlen), set()).add(net)
    have = {(s, o) for s, o in cur.execute("SELECT subj, obj FROM claims WHERE predicate = 'in-prefix'").fetchall()}
    srcs = {}
    for pid, src, ts in cur.execute("""SELECT m.entity_id, any_value(e.source), max(m.ts) FROM mentions m JOIN events e
                                        ON m.ref_type = 'event' AND m.ref_id = e.id
                                        WHERE split_part(m.entity_id, ':', 1) = 'prefix' GROUP BY 1""").fetchall():
        srcs[pid] = (src, ts)
    b = Batch()
    n = 0
    for iid, last in cur.execute("SELECT id, last_seen FROM entities WHERE type = 'ip'").fetchall():
        try:
            ip = ipaddress.ip_address(iid.split(":", 1)[1])
        except ValueError:
            continue
        for (ver, plen), nets in by_len.items():
            if ver != ip.version:
                continue
            net = ipaddress.ip_network(f"{ip}/{plen}", strict=False)
            if net in nets:
                pid = prefixes[net]
                if (iid, pid) in have:
                    continue
                src, ts = srcs.get(pid, ("ris_live", last))
                b.claim(iid, "in-prefix", pid, "observed", src, last or ts, {"note": "address inside prefix"})
                n += 1
    b.flush()
    return n


def link_reference() -> dict:
    """Load the reference catalogue (ATT&CK, MISP) as entities and reported claims."""
    cat = catalog()
    rows = []
    for e in cat.entities.values():
        rows.append({"id": e["id"], "type": e["type"], "name": e["name"], "aliases": e["aliases"], "attrs": e["attrs"]})
    store.upsert_entities(rows)
    store.rename_entities({e["id"]: e["name"] for e in cat.entities.values()})
    claims = []
    countries = []
    for subj, pred, obj, src, url in cat.relations:
        if obj.startswith("country:"):
            c = country_entity(obj.split(":", 1)[1])
            if c:
                countries.append(c)
        when = cat.entities.get(subj, {}).get("attrs", {})
        claims.append({"subj": subj, "predicate": pred, "obj": obj, "origin": "reported", "sources": [src],
                       "first_seen": when.get("first_seen"), "last_seen": when.get("last_seen"),
                       "evidence": [{"source": src, "tier": tier_of(src), "url": url, "ref_type": "reference",
                                     "note": f"{src} lists this relation"}]})
    store.upsert_entities(countries)
    store.upsert_claims(claims)
    return {"entities": len(rows), "claims": len(claims)}


def cleanup_placeholders() -> int:
    """Remove placeholder entities ("unknown threat actor") that earlier extraction created,
    with their mentions and claims. Reference entities are never touched."""
    from .normalize import is_placeholder
    cat = catalog()
    rows = db.query("SELECT id, name FROM entities WHERE type IN ('actor','malware','tool','campaign')")
    ids = sorted({r["id"] for r in rows if r["id"] not in cat.entities and is_placeholder(r["name"] or "")})
    if not ids:
        return 0
    with store._tx() as cur:
        cur.execute("DELETE FROM claims WHERE subj IN (SELECT unnest(?)) OR obj IN (SELECT unnest(?))", [ids, ids])
        cur.execute("DELETE FROM mentions WHERE entity_id IN (SELECT unnest(?))", [ids])
        cur.execute("DELETE FROM entity_dirty WHERE id IN (SELECT unnest(?))", [ids])
        cur.execute("DELETE FROM entities WHERE id IN (SELECT unnest(?))", [ids])
    log.info("removed %d placeholder entities", len(ids))
    return len(ids)
