"""News API under /api/news. Reference: okf/architecture/api.md#news"""
from __future__ import annotations

import datetime as dt
import json
import re

from fastapi import APIRouter, Body, HTTPException, Query

from .. import apiutil, db
from . import fetcher, pipeline, stories
from . import search as nsearch
from .common import ensure_schema, log, offline, vectors
from .sources import SKIPPED

router = APIRouter(prefix="/api/news", tags=["news"])


def _marker() -> str | None:
    """The app's one last-seen marker (osinthub/watch/marker.py; it reads the old news-only value too)."""
    from ..watch import marker
    return marker.get()["last_seen"]


_csv = apiutil.csv_list


def _j(rows):
    for r in rows:
        for k, v in list(r.items()):
            if isinstance(v, dt.datetime):
                r[k] = v.isoformat()
            elif k in ("tier_counts", "top_entities") and isinstance(v, str):
                try:
                    r[k] = json.loads(v)
                except ValueError:
                    pass
    return rows


like = apiutil.like


def _has_table(name: str) -> bool:
    return db.has_table(name)


def _ts(v):
    try:
        return nsearch._ts(v)
    except ValueError:
        raise HTTPException(400, f"bad time: {v}")


# Stored ids (watchlists, top_entities) are read through these: the ids that mean this entity now under the
# user's merges and retypes (okf/data/entities.md#overrides), or just the id when the entities layer is off.
_same = apiutil.entity_equivalents
_resolve = apiutil.entity_resolve


def _story_where(since=None, until=None, sources=None, tiers=None, entity=None, q=None, min_articles=1):
    cl, p = ["s.article_count >= ?"], [min_articles]
    if since:
        cl.append("s.last_seen >= ?"); p.append(since)
    if until:
        cl.append("s.first_seen <= ?"); p.append(until)
    if sources:
        cl.append(f"s.id IN (SELECT story_id FROM articles WHERE lower(source) IN ({','.join('?' * len(sources))}) "
                  f"OR source_id IN ({','.join('?' * len(sources))}))")
        p += [s.lower() for s in sources] + sources
    if tiers:
        cl.append(f"s.id IN (SELECT story_id FROM articles WHERE tier IN ({','.join('?' * len(tiers))}))")
        p += [t.upper() for t in tiers]
    if entity:
        same = _same(entity)
        tops = " OR ".join(["CAST(s.top_entities AS VARCHAR) ILIKE ? ESCAPE '\\'"] * len(same))
        if _has_table("mentions"):
            cl.append(f"""(s.id IN (SELECT a.story_id FROM articles a JOIN mentions m ON m.ref_id = a.id
                                   WHERE m.ref_type = 'article' AND lower(m.entity_id) IN ({','.join('lower(?)' for _ in same)}))
                          OR {tops})""")
            p += same + [like(f'"{e}"') for e in same]
        else:
            cl.append(f"({tops})"); p += [like(f'"{e}"') for e in same]
    if q:   # contains-text: % and _ in q are literal characters
        cl.append("s.id IN (SELECT story_id FROM articles WHERE title ILIKE ? ESCAPE '\\' OR dek ILIKE ? ESCAPE '\\')"); p += [like(q), like(q)]
    return " WHERE " + " AND ".join(cl), p


# ------------------------------------------------------------------ stories
@router.get("/stories")
def list_stories(limit: int = Query(30, ge=0, le=500), offset: int = Query(0, ge=0, le=2**63 - 1), since: str | None = None, until: str | None = None,
                 sources: str | None = None, tiers: str | None = None, entity: str | None = None, q: str | None = None,
                 min_articles: int = 1, new_since: str | None = None, order: str = "last_seen"):
    """Stories, newest activity first. `new_since` (ISO time, '24h', or 'marker') flags stories and
    articles that appeared after it."""
    ensure_schema()
    ns = _marker() if new_since == "marker" else new_since
    ns_t = _ts(ns) if ns else None
    w, p = _story_where(_ts(since), _ts(until), _csv(sources), _csv(tiers), entity, q, min_articles)
    orders = {"last_seen": "s.last_seen DESC", "first_seen": "s.first_seen DESC",
              "size": "s.source_count DESC, s.article_count DESC, s.last_seen DESC"}
    if order not in orders:   # a typo is reported, not silently replaced by the default
        raise HTTPException(400, f"order must be one of {', '.join(orders)}")
    order_sql = orders[order] + ", s.id"  # unique tiebreaker: offset pages are disjoint and cover every row
    total = db.query(f"SELECT count(*) n FROM stories s{w}", p)[0]["n"]
    rows = db.query(f"""SELECT s.*, a.url AS lead_url, a.source AS lead_source FROM stories s
                        LEFT JOIN articles a ON a.id = s.lead_article{w} ORDER BY {order_sql} LIMIT ? OFFSET ?""", p + [limit, offset])
    if ns_t and rows:
        ids = [r["id"] for r in rows]
        new = {r["story_id"]: r["n"] for r in db.query(
            f"""SELECT story_id, count(*) n FROM articles WHERE story_id IN ({','.join('?' * len(ids))})
                AND coalesce(published, queued_at) > ? GROUP BY 1""", ids + [ns_t])}
        for r in rows:
            r["new_articles"] = new.get(r["id"], 0)
            r["is_new"] = r["first_seen"] is not None and r["first_seen"] > ns_t
    return {"total": total, "limit": limit, "offset": offset, "new_since": ns, "stories": _j(rows)}


def _article_entities(ids: list[str]) -> dict[str, list[dict]]:
    if not ids or not _has_table("mentions"):
        return {}
    has_ent = _has_table("entities")
    rows = db.query(f"""SELECT m.ref_id, m.entity_id, {'e.name, e.type, e.aliases' if has_ent else 'NULL AS name, NULL AS type, NULL AS aliases'},
                               max(m.confidence) AS confidence, string_agg(DISTINCT m.method, ',') AS method
                        FROM mentions m {'LEFT JOIN entities e ON e.id = m.entity_id' if has_ent else ''}
                        WHERE m.ref_type = 'article' AND m.ref_id IN ({','.join('?' * len(ids))})
                        GROUP BY ALL""", ids)
    out: dict[str, list[dict]] = {}
    for r in rows:
        out.setdefault(r["ref_id"], []).append({"id": r["entity_id"], "name": r["name"] or r["entity_id"].split(":", 1)[-1],
                                                "type": r["type"] or r["entity_id"].split(":")[0],
                                                "confidence": r["confidence"], "method": r["method"],
                                                "aliases": list(r["aliases"] or [])})
    return out


def _fang_pattern(value: str) -> str:
    """Regex for a value as written in reports, including defanged forms: example[.]com, 1.2.3[.]4,
    hxxps://, example(.)com, example[dot]com, [:]//."""
    import re as _re
    out = []
    for ch in value:
        if ch == ".":
            out.append(r"(?:\.|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\s\[?dot\]?\s)")
        elif ch == ":":
            out.append(r"(?:\:|\[:\])")
        else:
            out.append(_re.escape(ch))
    pat = "".join(out)
    return _re.sub(r"^http", "h(?:tt|xx|XX)p", pat) if value.lower().startswith("http") else pat


def mention_offsets(text: str, ent: dict) -> list[list[int]]:
    """[start, end) character offsets of an entity's name, aliases or value in the article text, for
    highlighting. Case-insensitive, whole words; CVE ids and IOCs match as written."""
    import re as _re
    if not text:
        return []
    value = ent["id"].split(":", 1)[-1]
    names = {n for n in [ent.get("name"), value, *(ent.get("aliases") or [])] if n and len(n) >= 3}
    spans = []
    for n in sorted(names, key=len, reverse=True):
        for m in _re.finditer(r"(?<![\w.-])" + _fang_pattern(n) + r"(?![\w-])", text, _re.I):
            if not any(a < m.end() and m.start() < b for a, b in spans):
                spans.append((m.start(), m.end()))
    return [list(x) for x in sorted(spans)[:200]]


_CVE_ID = __import__("re").compile(r"CVE-\d{4}-\d{4,7}", __import__("re").I)


def cve_enrichment(cves: list[str]) -> list[dict]:
    """CVE facts from data already in the lake, joined on the normalised id (upper case):

    * CVSS, severity, published and description from NVD events (`nvd_recent` keeps a 72-hour window
      of new CVEs). A CVE outside that window takes its CVSS from a CISA CSAF advisory when one covers it
      (`cvss_status: "from CISA advisory"`); otherwise `cvss_status` says "not in NVD data";
    * KEV status, date added, ransomware use and the vulnerability name from CISA KEV events;
    * EPSS from the `epss` table (FIRST's latest daily file, every scored CVE): `epss` (probability 0-1),
      `epss_percentile` (0-1), `epss_date`, `epss_since` (when the probability last changed) and `epss_prev`
      (the probability before that). `epss_status` is "ok", "not scored" (EPSS is loaded but has no score
      for this id) or "not loaded" (no EPSS file loaded yet);
    * `advisories`: CISA CSAF advisories covering the CVE (id, title, kind, url, cvss, updated), newest first.
    """
    from ..sources.vulns import epss_lookup
    ids = sorted({m.group(0).upper() for c in cves if c for m in [_CVE_ID.search(str(c))] if m})
    if not ids:
        return []
    out = {c: {"id": c, "cvss": None, "severity": None, "published": None, "cvss_status": "not in NVD data",
               "kev": False, "kev_added": None, "kev_name": None, "ransomware": False,
               "epss": None, "epss_percentile": None, "epss_date": None, "epss_since": None, "epss_prev": None,
               "epss_status": "not loaded", "advisories": [],
               "summary": None, "url": f"https://nvd.nist.gov/vuln/detail/{c}"} for c in ids}
    ph = ",".join("?" * len(ids))
    rows = db.query(f"""SELECT kind, title, summary, value, severity, tags, ts FROM events
                        WHERE kind IN ('cve', 'kev')
                          AND upper(regexp_extract(title, 'CVE-[0-9]{{4}}-[0-9]{{4,7}}', 0, 'i')) IN ({ph})
                        ORDER BY ts""", ids)
    for r in rows:
        m = _CVE_ID.search(r["title"] or "")
        o = out.get(m.group(0).upper()) if m else None
        if o is None:
            continue
        if r["kind"] == "kev":
            o["kev"], o["kev_added"] = True, r["ts"]
            o["ransomware"] = "ransomware" in (r["tags"] or [])
            o["kev_name"] = (r["summary"] or "").split(". ")[0] or None
            o["summary"] = o["summary"] or r["summary"]
        else:
            score = r["value"] if r["value"] is not None else (r["severity"] * 10 if r["severity"] is not None else None)
            o["cvss"], o["published"], o["cvss_status"] = score, r["ts"], ("ok" if score is not None else "no score yet")
            o["severity"] = (r["tags"] or [None])[0]
            o["summary"] = r["summary"] or o["summary"]
    loaded = bool(db.query("SELECT 1 FROM epss LIMIT 1"))
    scores = epss_lookup(ids) if loaded else {}
    for c, o in out.items():
        s = scores.get(c)
        if s:
            o.update(epss=s["epss"], epss_percentile=s["percentile"], epss_date=s["score_date"], epss_since=s["since"],
                     epss_prev=s["prev_epss"], epss_status="ok")
        elif loaded:
            o["epss_status"] = "not scored"
    for a in db.query(f"""SELECT cve, advisory, title, kind, url, cvss, severity, updated FROM advisory_cves
                          WHERE cve IN ({ph}) ORDER BY updated DESC, advisory""", ids):
        o = out[a["cve"]]
        o["advisories"].append({"id": a["advisory"], "title": a["title"], "kind": a["kind"], "url": a["url"],
                                "cvss": a["cvss"], "updated": a["updated"]})
        if o["cvss"] is None and a["cvss"] is not None:
            o["cvss"], o["cvss_status"], o["severity"] = a["cvss"], "from CISA advisory", a["severity"]
    for o in out.values():
        o["advisories"] = _j(o["advisories"])
    return _j(list(out.values()))


def epss_bulk(ids: list[str]) -> dict:
    """{cve: {epss, percentile, since, prev_epss}} for up to 10,000 ids, plus the loaded file's date and model;
    for list panels that badge thousands of rows at once."""
    from ..sources.vulns import epss_lookup
    want = sorted({m.group(0).upper() for c in ids[:10000] if c for m in [_CVE_ID.search(str(c))] if m})
    meta = db.query("SELECT max(score_date) AS score_date, any_value(model_version) AS model_version FROM epss")[0]
    scores = epss_lookup(want)
    return {"score_date": meta["score_date"].isoformat() if meta["score_date"] else None, "model_version": meta["model_version"],
            "scores": {c: {"epss": s["epss"], "percentile": s["percentile"], "prev_epss": s["prev_epss"],
                           "since": s["since"].isoformat() if s["since"] else None} for c, s in scores.items()}}


_FIELD_WORDS = set("""container host process user file event source destination agent cloud network service dns http url
registry observer threat rule kibana winlog powershell log logs data args parent client server os device message
error event_data system security config settings window document object module self this""".split())
_IOC_CONTEXT = __import__("re").compile(r"(indicator|ioc|c2|c&c|command[- ]and[- ]control|beacon|callback|exfiltrat|"
                                        r"malicious|phishing|payload|download(ed)? from|hosted on|sinkhole|staging|dropper|"
                                        r"domain|hash|sha-?256|md5|ip address)", __import__("re").I)
_TLD = __import__("re").compile(r"\.[a-z]{2,24}$")


def _popular(domain: str) -> bool:
    d = domain.lower().strip(".")
    try:
        from ..netlog import allowlist
        return bool(allowlist.benign_domain(d))
    except Exception:
        pass
    global _TRANCO
    if "_TRANCO" not in globals():
        from .. import config
        f = config.REF_DIR / "tranco-top20k.csv"
        _TRANCO = {l.split(",", 1)[1].strip() for l in f.read_text().splitlines() if "," in l} if f.exists() else set()
    parts = d.split(".")
    return any(".".join(parts[i:]) in _TRANCO for i in range(len(parts) - 1))


try:   # the entities extractor's rules, so both layers judge dotted numbers the same way
    from ..entities.iocs import _IOC_SECTION, _IP_CTX, _VERSION_AFTER, _VERSION_CTX
except Exception:  # entities package unavailable: local copies of the same rules
    import re as _r
    _VERSION_CTX = _r.compile(r"(?:\bv|\bver\.?|\bversions?|\brelease|\bbuild|\bupdate|\bpatch|\bfirmware|\bkb|\bsdk|\bfixed in|"
                              r"\bprior to|\bbefore|\bthrough|\bup to|\bupgrade to|\bos|\bios|\bandroid|"
                              r"\bchrome|\bfirefox|\bwindows|\bkernel|\bpython|\bjava|\bnode|\bphp|\bopenssl|\bapache|\bnginx|\b\w+/)\s*$", _r.I)
    _VERSION_AFTER = _r.compile(r"^\s*(?:and|or) (?:later|earlier|above|below|newer|older|prior)\b|^\s*(?:release|build|version)\b", _r.I)
    _IP_CTX = _r.compile(r"\b(?:c2|c&c|command and control|ip|ips|address(?:es)?|connect\w*|server|hosts?|beacon\w*|callback|"
                         r"resolv\w*|dns|infrastructure|contacted|communicat\w*)\b", _r.I)
    _IOC_SECTION = _r.compile(r"\b(?:indicators? of compromise|iocs?)\b", _r.I)

_LEGIT = __import__("re").compile(r"\b(legitimate|legit|benign|trusted|official|well-known|popular|reputable|"
                                  r"abus(e|es|ed|ing) (the )?(legitimate|trusted)|open[- ]source (tool|project|repository)|"
                                  r"public (repository|code hosting|service))\b", __import__("re").I)


def _occurrences(value: str, texts: list[str]):
    """(text, start, end) for every place the value is written, defanged or not."""
    import re as _re
    pat = _re.compile(r"(?<![\w.-])" + _fang_pattern(value) + r"(?![\w-])", _re.I)
    for t in texts:
        for m in pat.finditer(t or ""):
            yield t, m.start(), m.end()


def _sentence(t: str, a: int, b: int) -> str:
    s0 = max(t.rfind(". ", 0, a) + 1, a - 160, 0)
    e = t.find(". ", b)
    return t[s0: min(e if e >= 0 else len(t), b + 160)]


def _version_like(t: str, a: int, b: int, value: str) -> bool:
    pre, post = t[max(0, a - 24):a], t[b:b + 24]
    if _VERSION_CTX.search(pre) or _VERSION_AFTER.match(post):
        return True
    small = all(o.isdigit() and int(o) <= 31 for o in value.split("."))
    return small and not _IOC_SECTION.search(t) and not _IP_CTX.search(t[max(0, a - 80):b + 80])


def ioc_noise(etype: str, value: str, texts: list[str]) -> str | None:
    """Why a mention is not a usable indicator, or None:
    * field names that look like domains (container.id, host.name);
    * CVE ids that only occur as the prefix of a longer id (truncated);
    * popular, benign domains and URLs (Tranco top 20k, the netlog allowlist) unless the reports
      defang them or name them in an IOC context (table row, list of indicators, C2, payload host)."""
    import re as _re
    v = (value or "").strip()
    occ = list(_occurrences(v, texts))
    if not occ and etype != "cve":
        return "no_evidence: not found in the stored article text"
    if etype == "ip":
        if occ and all(_version_like(t, a, b, v) for t, a, b in occ):
            return "version number, not an address"
        return None
    if etype == "cve":
        # Whole id only: not the start of a longer id, nor a pattern such as CVE-2026-10961[89].
        if not any(_re.search(_re.escape(v) + r"(?![\d\[\*\?\]x])", t, _re.I) for t in texts):
            return "truncated CVE id"
        return None
    if etype in ("domain", "url"):
        host = v.lower()
        if etype == "url":
            host = _re.sub(r"^[a-z]+://", "", host).split("/")[0].split(":")[0]
        first = host.split(".")[0]
        if etype == "domain" and (first in _FIELD_WORDS or not _TLD.search(host) or "_" in host):
            return "field name, not a domain"
        pat = _fang_pattern(v)
        defanged = any(_re.search(_re.escape(v).replace("\\.", r"(\[\.\]|\(\.\)|\[dot\])"), t, _re.I) for t in texts) or \
            any(_re.search(r"h(xx|XX)p", t) and _re.search(pat, t, _re.I) for t in texts)
        if defanged:
            return None
        # Described as a legitimate service or tool, or a legitimate one being abused (code on GitHub):
        # not an indicator.
        if occ and all(_LEGIT.search(_sentence(t, a, b)) for t, a, b in occ):
            return "described as a legitimate service"
        if _popular(host):
            in_ctx = False
            for t in texts:
                for line in t.split("\n"):
                    for m in _re.finditer(pat, line, _re.I):
                        # The sentence around the mention, at most 80 characters either side.
                        a = max(line.rfind(". ", 0, m.start()) + 1, m.start() - 80, 0)
                        b = line.find(". ", m.end())
                        near = line[a: min(b if b >= 0 else len(line), m.end() + 80)]
                        if (line.lstrip().startswith(("|", "-", "•", "*")) and len(line) < 200) or _IOC_CONTEXT.search(near):
                            in_ctx = True
                            break
                    if in_ctx:
                        break
                if in_ctx:
                    break
            if not in_ctx:
                return "popular benign domain, not named as an indicator"
    return None


def _story_iocs(arts: list[dict]) -> list[dict]:
    """Indicators named by the story's articles: type, value, first and last seen in this story and
    globally, the outlets naming them, and their relationships (claims) to other entities."""
    ids = [a["id"] for a in arts]
    if not ids or not (_has_table("mentions") and _has_table("entities")):
        return []
    pub = {a["id"]: a["published"] for a in arts}
    src = {a["id"]: a["source"] for a in arts}
    # Headline and dek too: entities are extracted from them, and some reports name a CVE only in the title.
    texts = {r["id"]: r["text"] or "" for r in db.query(f"SELECT id, concat_ws(chr(10), title, dek, text) AS text FROM articles WHERE id IN ({','.join('?' * len(ids))})", ids)}
    rows = db.query(f"""SELECT m.entity_id, m.ref_id, e.type, e.name, e.first_seen, e.last_seen FROM mentions m
                        JOIN entities e ON e.id = m.entity_id
                        WHERE m.ref_type = 'article' AND m.ref_id IN ({','.join('?' * len(ids))})
                          AND e.type IN ('ip', 'domain', 'url', 'sha256', 'sha1', 'md5', 'hash', 'cve', 'email')""", ids)
    by: dict[str, dict] = {}
    for r in rows:
        if ioc_noise(r["type"], r["name"] or r["entity_id"].split(":", 1)[-1], [texts.get(r["ref_id"], "")]):
            continue
        o = by.setdefault(r["entity_id"], {"id": r["entity_id"], "type": r["type"], "value": r["name"] or r["entity_id"].split(":", 1)[-1],
                                           "first_seen": None, "last_seen": None, "global_first_seen": r["first_seen"],
                                           "global_last_seen": r["last_seen"], "sources": set(), "articles": 0, "relationships": []})
        t = pub.get(r["ref_id"])
        if t:
            o["first_seen"] = min(filter(None, [o["first_seen"], t]))
            o["last_seen"] = max(filter(None, [o["last_seen"], t]))
        o["sources"].add(src.get(r["ref_id"]))
        o["articles"] += 1
    if by and _has_table("claims"):
        keys = list(by)
        for c in db.query(f"""SELECT c.subj, c.predicate, c.obj, c.origin, c.confidence, s.name AS sn, o.name AS obn
                              FROM claims c LEFT JOIN entities s ON s.id = c.subj LEFT JOIN entities o ON o.id = c.obj
                              WHERE c.subj IN ({','.join('?' * len(keys))}) OR c.obj IN ({','.join('?' * len(keys))})
                              ORDER BY c.confidence DESC LIMIT 1000""", keys + keys):
            for k, other, oname, direction in ((c["subj"], c["obj"], c["obn"], "out"), (c["obj"], c["subj"], c["sn"], "in")):
                if k in by and len(by[k]["relationships"]) < 10:
                    by[k]["relationships"].append({"predicate": c["predicate"], "direction": direction, "entity": other,
                                                   "name": oname or other.split(":", 1)[-1], "origin": c["origin"],
                                                   "confidence": c["confidence"]})
    # corroboration: threat lists (Feodo, ThreatFox, URLhaus, SSLBL, ...) that hold the same indicator
    listed: dict = {}
    if by and _has_table("indicator_intervals"):
        try:
            from ..netlog import intervals
            listed = intervals.listed([(o["type"], o["value"]) for o in by.values()])
        except Exception as e:  # noqa: BLE001  (the IoC table still renders without it)
            log.warning("story IoC list lookup failed: %s", e)
    out = []
    for o in by.values():
        o["sources"] = sorted(x for x in o["sources"] if x)
        o["listed_by"] = listed.get((o["type"], o["value"]), [])
        out.append(o)
    out.sort(key=lambda o: (o["type"], -o["articles"], o["value"]))
    return _j(out)


def _timeline(arts: list[dict]) -> list[dict]:
    """The story as it unfolded: first report, follow-ups (new outlet or same outlet again) and copies."""
    seen: set[str] = set()
    out = []
    for i, a in enumerate(arts):
        kind = "copy" if a["dup_of"] else ("first_report" if i == 0 else ("follow_up" if a["source"] in seen else "corroboration"))
        seen.add(a["source"])
        out.append({"ts": a["published"] or a["fetched_at"], "article_id": a["id"], "source": a["source"], "tier": a["tier"],
                    "role": a["role"], "title": a["title"], "kind": kind})
    return _j(out)


@router.get("/stories/{sid:path}")
def story_detail(sid: str):
    ensure_schema()
    s = db.query("SELECT * FROM stories WHERE id = ?", [sid])
    if not s:
        raise HTTPException(404, "unknown story")
    arts = db.query("""SELECT id, url, source, source_id, tier, tier_reason, role, title, dek, author, published, fetched_at, status, reason,
                              dup_of, lang, chunks, updated_at FROM articles WHERE story_id = ?
                       ORDER BY coalesce(published, fetched_at, queued_at)""", [sid])
    ents = _article_entities([a["id"] for a in arts])
    merged: dict[str, dict] = {}
    for a in arts:
        a["entities"] = ents.get(a["id"], [])
        for e in a["entities"]:
            m = merged.setdefault(e["id"], {**e, "articles": 0})
            m["articles"] += 1
    story = _j(s)[0]
    story["entities"] = sorted(merged.values(), key=lambda e: (-e["articles"], e["id"])) or story.get("top_entities") or []
    story["timeline"] = _timeline(arts)
    story["iocs"] = _story_iocs(arts)
    cves = {i["value"] for i in story["iocs"] if i["type"] == "cve"}
    if not cves:   # no entities layer: CVE ids named in the story's top entities
        cves = {e["name"] for e in (story.get("top_entities") or []) if isinstance(e, dict) and e.get("type") == "cve"}
    story["cves"] = cve_enrichment(sorted(cves))
    story["articles"] = _j(arts)
    story["syndicated"] = sum(1 for a in arts if a["dup_of"])
    return story


# ------------------------------------------------------------------ articles
@router.get("/articles")
def list_articles(limit: int = Query(50, ge=0, le=1000), offset: int = Query(0, ge=0, le=2**63 - 1), status: str | None = None, sources: str | None = None,
                  story: str | None = None, since: str | None = None):
    ensure_schema()
    cl, p = [], []
    if status:
        st = _csv(status); cl.append(f"status IN ({','.join('?' * len(st))})"); p += st
    if sources:
        ss = _csv(sources); cl.append(f"(source IN ({','.join('?' * len(ss))}) OR source_id IN ({','.join('?' * len(ss))}))"); p += ss + ss
    if story:
        cl.append("story_id = ?"); p.append(story)
    if since:
        cl.append("coalesce(published, queued_at) >= ?"); p.append(_ts(since))
    w = (" WHERE " + " AND ".join(cl)) if cl else ""
    rows = db.query(f"""SELECT id, url, source, source_id, tier, title, dek, published, fetched_at, status, reason, story_id, dup_of, lang,
                               author, sponsored, updated_at
                        FROM articles{w} ORDER BY coalesce(published, queued_at) DESC, id LIMIT ? OFFSET ?""", p + [limit, offset])
    return _j(rows)


def similar_articles(aid: str, k: int = 8) -> dict:
    """Nearest articles outside this article's own story, by embedding (osinthub.vectors), else by keyword search."""
    me = db.query("SELECT story_id FROM articles WHERE id = ?", [aid])
    own = me[0]["story_id"] if me else None
    v = db.query("SELECT vec FROM article_vecs WHERE article_id = ?", [aid])
    vec = vectors()
    if v and vec is not None:
        try:
            hits = vec.search(pipeline.COLLECTION, list(v[0]["vec"]), k * 6)
            best: dict[str, float] = {}
            for h in hits or []:
                p = h.get("payload") or {}
                o = p.get("article_id")
                if o and o != aid:
                    best[o] = max(best.get(o, -1), float(h.get("score") or 0))
            ids = sorted(best, key=lambda x: -best[x])[:k * 4]
            if ids:
                rows = {r["id"]: r for r in db.query(f"""SELECT id, title, url, source, tier, published, story_id FROM articles
                                                        WHERE id IN ({','.join('?' * len(ids))})""", ids)}
                res = [{**rows[i], "score": round(best[i], 4)} for i in ids if i in rows and (own is None or rows[i]["story_id"] != own)]
                return {"method": "vector", "excludes_story": own, "results": _j(res[:k])}
        except Exception:
            pass
    t = db.query("SELECT title, dek FROM articles WHERE id = ?", [aid])
    if not t:
        return {"method": "none", "results": []}
    res = [r for r in nsearch.search(f"{t[0]['title']} {t[0]['dek'] or ''}"[:400], k=k * 4, mode="keyword")["results"]
           if r["id"] != aid and (own is None or r.get("story_id") != own)][:k]
    return {"method": "keyword", "excludes_story": own, "results": res}


@router.get("/articles/{aid}")
def article_detail(aid: str, similar: int = Query(8, ge=0, le=100)):
    ensure_schema()
    rows = db.query("SELECT * EXCLUDE (minhash) FROM articles WHERE id = ?", [aid])
    if not rows:
        raise HTTPException(404, "unknown article")
    a = _j(rows)[0]
    a["entities"] = _article_entities([aid]).get(aid, [])
    for e in a["entities"]:
        e["offsets"] = mention_offsets(a.get("text") or "", e)
    a["cves"] = cve_enrichment([e["id"].split(":", 1)[-1] for e in a["entities"]
                                if e["type"] == "cve" and not ioc_noise("cve", e["name"], ["\n".join(filter(None, [a.get("title"), a.get("dek"), a.get("text")]))])])
    a["similar"] = similar_articles(aid, similar) if similar else None
    if a.get("dup_of"):
        o = db.query("SELECT id, title, url, source FROM articles WHERE id = ?", [a["dup_of"]])
        a["original"] = _j(o)[0] if o else None
    a["copies"] = _j(db.query("SELECT id, title, url, source FROM articles WHERE dup_of = ?", [aid]))
    return a


# ------------------------------------------------------------------ search
@router.get("/search")
def search(q: str, k: int = Query(10, ge=1, le=100), since: str | None = None, until: str | None = None,
           sources: str | None = None, tiers: str | None = None, mode: str = "hybrid", collapse: str | None = None):
    """`collapse=story` returns one result per story (its best article) with `story_hits`, the number of
    matching articles in that story."""
    _ts(since), _ts(until)  # a bad time is a 400 "bad time", as on the other news endpoints
    try:
        return nsearch.search(q, k=k, since=since, until=until, sources=_csv(sources), tiers=_csv(tiers), mode=mode,
                              collapse=collapse)
    except ValueError as e:
        raise HTTPException(400, str(e))


# ------------------------------------------------------------------ sources / queue
@router.get("/sources")
def sources_status():
    """Feeds, fetch queue and blocked counts per outlet."""
    ensure_schema()
    from .. import scheduler
    from ..sources import SOURCES
    states = {r["id"]: r for r in db.query("SELECT * FROM source_state")}
    feeds = []
    for sid, s in SOURCES.items():
        if s.category != "news":
            continue
        st = states.get(sid, {})
        feeds.append({"id": sid, "name": s.name, "provider": s.provider, "interval": s.interval,
                      "trust_tier": getattr(s, "trust_tier", None), "role": getattr(s, "role", None),
                      "default_enabled": s.default_enabled, "enabled": scheduler.is_enabled(s),   # as /api/sources: the default when never set
                      **{k: st.get(k) for k in ("status", "message", "last_ok", "items_total")}})
    outlets = db.query("""SELECT source, any_value(tier) tier, count(*) total,
                                 count(*) FILTER (status = 'ok') ok, count(*) FILTER (status = 'queued') queued,
                                 count(*) FILTER (status = 'blocked') blocked, count(*) FILTER (status = 'failed') failed,
                                 count(*) FILTER (status = 'skipped') skipped, count(*) FILTER (sponsored IS NOT NULL) sponsored,
                                 round(count(*) FILTER (status = 'ok') / nullif(count(*) FILTER (status <> 'queued'), 0), 3) success_rate,
                                 max(fetched_at) last_fetch
                          FROM articles GROUP BY 1 ORDER BY 1""")
    reasons = db.query("""SELECT source, status, reason, count(*) n FROM articles WHERE status IN ('blocked', 'failed', 'skipped')
                          GROUP BY ALL ORDER BY n DESC LIMIT 50""")
    q = db.query("""SELECT count(*) FILTER (status = 'queued' AND (next_attempt IS NULL OR next_attempt <= now())) due,
                           count(*) FILTER (status = 'queued' AND next_attempt > now()) waiting_retry,
                           count(*) FILTER (status = 'ok' AND chunks > 0 AND embedded_at IS NULL) embed_pending,
                           count(*) FILTER (status = 'ok' AND embedded_at IS NOT NULL) embedded,
                           count(*) FILTER (story_id IS NULL AND status <> 'skipped') unclustered
                    FROM articles""")[0]
    return _j([{"offline": offline(), "queue": q, "fetcher": dict(fetcher.stats), "pipeline": dict(pipeline.state),
                "stories": {**stories.state, "total": db.query("SELECT count(*) n FROM stories")[0]["n"]},
                "feeds": _j(feeds), "outlets": _j(outlets), "reasons": reasons,
                "skipped_feeds": [{"name": k, "reason": v} for k, v in SKIPPED.items()]}])[0]


@router.get("/cves")
def cves(ids: str):
    """CVE enrichment from data already in the lake: CVSS (NVD, else a CISA advisory), KEV status and date,
    EPSS (FIRST) and the CISA advisories covering each CVE."""
    return cve_enrichment(_csv(ids)[:200])


EPSS_GET_MAX = 500   # ids per GET: ~7 KB of query string, well under the server's request-line limit


@router.get("/epss")
def epss_scores_get(ids: str = ""):
    """Latest EPSS for many CVEs at once (`?ids=CVE-…,CVE-…`, at most 500 per call): list panels badge every row.
    A read, so it is a GET (v1.2): the Ops panels call it in chunks on every load."""
    want = _csv(ids)
    if len(want) > EPSS_GET_MAX:
        raise HTTPException(400, f"at most {EPSS_GET_MAX} CVE ids per request")
    return epss_bulk(want)


@router.post("/epss")
def epss_scores(body: dict = Body(...)):
    """Deprecated (v1.2): the same lookup as GET /api/news/epss, body {"ids": [...]}, at most 10,000. Kept for one
    release for outside scripts; the app itself no longer calls it. Remove in v1.3."""
    ids = body.get("ids")
    if not isinstance(ids, list) or len(ids) > 10000:
        raise HTTPException(400, "ids must be a list of at most 10000 CVE ids")
    return epss_bulk([str(x) for x in ids])


@router.post("/fetch/run")
async def run_fetch():
    if offline():
        return {"offline": True, "fetched": 0}
    return await fetcher.fetch_pass()


@router.post("/reextract")
async def reextract():
    """Re-run main-text extraction on stored HTML (works offline)."""
    import asyncio
    return {"updated": await asyncio.to_thread(fetcher.reextract)}


@router.post("/recluster")
def recluster():
    return {"clustered": stories.recluster_all()}


# ------------------------------------------------------------------ watchlist + marker
def _watch() -> dict:
    """The followed list (osinthub/stack.py): entities, keywords and the vendors/products of My stack."""
    from .. import stack
    return stack.get()


@router.get("/watchlist")
def get_watchlist():
    """Same list as GET /api/stack: {entities, keywords, stack, names, equivalents, count}."""
    from .. import stack
    return stack.public()


@router.put("/watchlist")
def put_watchlist(body: dict = Body(...)):
    """Replace entities and keywords (v1.0 shape). `stack` is replaced only when sent, so the old News rail never
    drops the vendors and products followed elsewhere."""
    from .. import stack
    w = stack.get()
    w["entities"] = body.get("entities") or []
    w["keywords"] = body.get("keywords") or []
    if "stack" in body:
        w["stack"] = body.get("stack") or []
    stack.save(w)
    return stack.public()


@router.get("/watchlist/digest")
def watchlist_digest(since: str | None = None, limit: int = Query(50, ge=0, le=500)):
    """New stories (or stories with new articles) since `since` that match a followed entity, keyword, vendor or
    product. `since` defaults to the marker, then to 24 hours ago."""
    ensure_schema()
    from .. import stack
    w = _watch()
    since_v = since or _marker() or "24h"
    t = _ts(since_v)
    hits: dict[str, set[str]] = {}
    # a followed id is read through the user's merges: following either name of a merged pair keeps working,
    # and `matched` names the id as it was followed (so the UI's followed chips still match)
    same = {e: _same(e) for e in w["entities"]}
    back: dict[str, set[str]] = {}
    for e, ids in same.items():
        for i in ids:
            back.setdefault(i.lower(), set()).add(e)
    if w["entities"] and _has_table("mentions"):
        for r in db.query(f"""SELECT DISTINCT a.story_id, m.entity_id FROM articles a JOIN mentions m
                              ON m.ref_type = 'article' AND m.ref_id = a.id
                              WHERE lower(m.entity_id) IN ({','.join('?' * len(back))})
                                AND coalesce(a.published, a.queued_at) > ? AND a.story_id IS NOT NULL""",
                          list(back) + [t]):
            hits.setdefault(r["story_id"], set()).update(back.get(r["entity_id"].lower(), {r["entity_id"]}))
    for e in w["entities"]:   # entities named in story top_entities (CVE ids work before the entities layer exists)
        for i in same[e]:
            for r in db.query("""SELECT id FROM stories WHERE last_seen > ? AND CAST(top_entities AS VARCHAR) ILIKE ? ESCAPE '\\'""", [t, like(f'"{i}"')]):
                hits.setdefault(r["id"], set()).add(e)
    for kw in w["keywords"]:
        for r in db.query("""SELECT DISTINCT story_id FROM articles WHERE story_id IS NOT NULL AND coalesce(published, queued_at) > ?
                             AND (title ILIKE ? ESCAPE '\\' OR dek ILIKE ? ESCAPE '\\' OR text ILIKE ? ESCAPE '\\')""", [t, like(kw), like(kw), like(kw)]):
            hits.setdefault(r["story_id"], set()).add(f"keyword:{kw}")
    T = stack.Terms(w)
    if w["stack"] or T.vendor_entities:   # vendors and products named in the articles (whole words, guarded)
        for sid, lbs in stack.story_hits(T, t).items():
            hits.setdefault(sid, set()).update(lbs)
    if not hits:
        return {"since": since_v, "watchlist": w, "stories": []}
    ids = list(hits)
    rows = db.query(f"""SELECT s.*, (SELECT count(*) FROM articles a WHERE a.story_id = s.id AND coalesce(a.published, a.queued_at) > ?) new_articles
                        FROM stories s WHERE s.id IN ({','.join('?' * len(ids))}) ORDER BY s.last_seen DESC, s.id LIMIT ?""", [t] + ids + [limit])
    for r in rows:
        r["matched"] = sorted(hits[r["id"]])
        r["matched_names"] = {m: T.name(m) for m in r["matched"]}
        r["is_new"] = r["first_seen"] > t
    return {"since": since_v, "watchlist": w, "stories": _j(rows)}


@router.get("/marker")
def get_marker():
    """The app-wide marker (same as GET /api/marker): `last_seen` as before, plus `previous` and `set_at`."""
    from ..watch import marker
    return marker.public()


@router.put("/marker")
def put_marker(body: dict = Body(default={})):
    """"Mark all as read" is "Caught up": the app-wide marker moves (same as PUT /api/marker)."""
    from ..watch.api import put_marker_body
    return put_marker_body(body)


# ------------------------------------------------------------------ intel (claims + indicators) for the News UI
IOC_TYPES = ("ip", "domain", "url", "hash", "cve", "technique")
QUOTE_MAX = 400
TECH_ID = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")
TECH_KINDS = ("named", "likely", "possible")


def _sentence_with(text: str, i: int, j: int) -> str:
    """The sentence of `text` around the span i..j (bounded by . ! ? or a line break). A sentence over QUOTE_MAX
    characters is cut to a window around the span, with an ellipsis on each cut side, so the span (the printed ATT&CK
    id) is always in what is shown. Same rule as web/js/core/ttp.js sentenceAt."""
    a = max(text.rfind(c, 0, i) for c in (". ", "! ", "? ", "\n"))
    a = 0 if a < 0 else a + 1
    ends = [k for k in (text.find(c, j) for c in (". ", "! ", "? ", "\n")) if k >= 0]
    b = min(ends) + 1 if ends else len(text)
    while a < i and text[a].isspace():
        a += 1
    while b > j and text[b - 1].isspace():
        b -= 1
    if b - a <= QUOTE_MAX:
        return text[a:b]
    w = QUOTE_MAX - 2
    start = max(a, min(i - (w - (j - i)) // 2, b - w))
    end = min(b, start + w)
    return ("…" if start > a else "") + text[start:end].strip() + ("…" if end < b else "")


def _techniques(ids: list[str], like: list[str]) -> list[dict]:
    """The ATT&CK techniques read from these articles, each with one plain label (okf/data/entities.md#technique-labels):
    `named` when an article prints the id itself, `likely` for the extractor's confirmed tier (a mention with role
    `technique`), `possible` for the suggested tier only (`technique-suggested`). Each carries the sentence it was read
    from when one is stored: the printed id's sentence, else the quote ingest keeps on the technique's `uses` claim
    (so a technique found without a named actor or malware has none). Read-only; no extraction logic here."""
    ph = ",".join("?" * len(ids))
    out: dict[str, dict] = {}
    for r in db.query(f"""SELECT m.entity_id, e.name, bool_or(m.role <> 'technique-suggested') AS confirmed
                          FROM mentions m LEFT JOIN entities e ON e.id = m.entity_id
                          WHERE m.ref_type = 'article' AND m.ref_id IN ({ph}) AND m.entity_id LIKE 'technique:%'
                          GROUP BY ALL""", ids):
        tid = r["entity_id"].split(":", 1)[1].upper()
        out[tid] = {"id": tid, "entity": r["entity_id"], "name": r["name"], "kind": "likely" if r["confirmed"] else "possible",
                    "quote": None, "ref_id": None, "source": None}
    for a in db.query(f"SELECT id, source, concat_ws(chr(10), title, dek, text) AS text FROM articles WHERE id IN ({ph}) ORDER BY id", ids):
        text = a["text"] or ""
        for m in TECH_ID.finditer(text):
            t = out.setdefault(m.group(0), {"id": m.group(0), "entity": f"technique:{m.group(0)}", "name": None, "kind": "named",
                                            "quote": None, "ref_id": None, "source": None})
            if t["kind"] != "named" or not t["quote"]:
                t.update(kind="named", quote=_sentence_with(text, m.start(), m.end()), ref_id=a["id"], source=a["source"])
    if out and like:
        idset = set(ids)
        for r in db.query(f"""SELECT c.obj, CAST(c.evidence AS VARCHAR) AS evidence FROM claims c
                              WHERE c.origin = 'reported' AND c.obj LIKE 'technique:%'
                                AND ({' OR '.join(['CAST(c.evidence AS VARCHAR) LIKE ?'] * len(like))})
                              ORDER BY c.obj, c.confidence DESC""", like):
            t = out.get(r["obj"].split(":", 1)[1].upper())
            if not t or t["kind"] == "named":
                continue
            try:
                ev = json.loads(r["evidence"] or "[]")
            except ValueError:
                continue
            for e in ev:
                if not isinstance(e, dict) or e.get("ref_id") not in idset or not e.get("quote"):
                    continue
                if not t["quote"] or (t.get("_sug") and not e.get("suggested")):
                    q = str(e["quote"])
                    t.update(quote=q if len(q) <= QUOTE_MAX else q[:QUOTE_MAX - 1].rstrip() + "…", ref_id=e["ref_id"],
                             source=e.get("source"), _sug=bool(e.get("suggested")))
    names = [t["entity"] for t in out.values() if not t["name"]]
    if names:
        known = {r["id"]: r["name"] for r in db.query(f"SELECT id, name FROM entities WHERE id IN ({','.join('?' * len(names))})", names)}
        for t in out.values():
            t["name"] = t["name"] or known.get(t["entity"])
    for t in out.values():
        t.pop("_sug", None)
    return sorted(out.values(), key=lambda t: (TECH_KINDS.index(t["kind"]), t["id"]))


@router.get("/intel")
def intel(story: str | None = None, article: str | None = None):
    """Claims whose evidence cites this story or article, and the indicators its articles mention with their
    global first/last seen, mention count and the outlets in this story naming them, and `techniques`: the
    ATT&CK techniques read from the text, each labelled named / likely / possible with the sentence it came from. Empty without the entities layer."""
    ensure_schema()
    if not story and not article:
        raise HTTPException(400, "story or article required")
    # an unknown id is a 404, as on the story and article detail endpoints (not an empty result that looks real)
    if story:
        if not db.query("SELECT 1 FROM stories WHERE id = ?", [story]):
            raise HTTPException(404, "unknown story")
        ids = [r["id"] for r in db.query("SELECT id FROM articles WHERE story_id = ?", [story])]
    else:
        if not db.query("SELECT 1 FROM articles WHERE id = ?", [article]):
            raise HTTPException(404, "unknown article")
        ids = [article]
    out = {"story": story, "article": article, "claims": [], "indicators": [], "techniques": [], "available": _has_table("claims") and _has_table("mentions")}
    if not ids or not out["available"]:
        return out
    ph = ",".join("?" * len(ids))
    like = [f'%"ref_id": "{i}"%' for i in ids]
    rows = db.query(f"""SELECT c.id, c.subj, c.predicate, c.obj, c.origin, c.confidence, c.sources, c.first_seen, c.last_seen,
                               CAST(c.evidence AS VARCHAR) AS evidence, s.name AS subj_name, s.type AS subj_type,
                               o.name AS obj_name, o.type AS obj_type
                        FROM claims c LEFT JOIN entities s ON s.id = c.subj LEFT JOIN entities o ON o.id = c.obj
                        WHERE c.origin = 'reported' AND ({' OR '.join(['CAST(c.evidence AS VARCHAR) LIKE ?'] * len(like))})
                          -- a user row is a verdict, not a claim; a triple the analyst rejected is left out
                          AND NOT EXISTS (SELECT 1 FROM claims u WHERE u.origin = 'user' AND u.subj = c.subj
                                          AND u.predicate = c.predicate AND u.obj = c.obj
                                          AND json_extract_string(u.evidence, '$[-1].verdict') = 'reject')
                        ORDER BY c.confidence DESC, c.last_seen DESC LIMIT 300""", like)
    idset = set(ids)
    for r in rows:
        try:
            ev = json.loads(r["evidence"] or "[]")
        except ValueError:
            ev = []
        # a link MITRE's catalogue also states keeps that standing in the UI (core/ttp.js ttpLinkKind), though only
        # this story's own evidence items are returned
        r["catalogue"] = any(isinstance(e, dict) and e.get("ref_type") == "reference" for e in ev)
        r["evidence"] = [e for e in ev if e.get("ref_id") in idset]
    out["claims"] = _j(rows)
    out["techniques"] = _techniques(ids, like)
    out["indicators"] = _j(db.query(f"""
        WITH m AS (SELECT entity_id, ref_id, max(confidence) conf, string_agg(DISTINCT method, ',') method FROM mentions
                   WHERE ref_type = 'article' AND ref_id IN ({ph}) GROUP BY ALL)
        SELECT e.id, e.type, e.name, e.first_seen, e.last_seen, max(m.conf) AS confidence, string_agg(DISTINCT m.method, ',') AS method,
               count(DISTINCT m.ref_id) AS articles, list(DISTINCT a.source) AS outlets,
               (SELECT count(*) FROM mentions g WHERE g.entity_id = e.id) AS mentions,
               (SELECT count(*) FROM claims c WHERE c.subj = e.id OR c.obj = e.id) AS relationships
        FROM m JOIN entities e ON e.id = m.entity_id JOIN articles a ON a.id = m.ref_id
        WHERE e.type IN ({','.join('?' * len(IOC_TYPES))})
        GROUP BY ALL ORDER BY e.type, articles DESC, e.name LIMIT 500""", ids + list(IOC_TYPES)))
    # Same noise filter as the story IoC table: field names, truncated CVEs, benign popular domains.
    texts = [r["text"] or "" for r in db.query(f"SELECT concat_ws(chr(10), title, dek, text) AS text FROM articles WHERE id IN ({ph})", ids)]
    out["indicators"] = [i for i in out["indicators"] if not ioc_noise(i["type"], i["name"] or i["id"].split(":", 1)[-1], texts)]
    return out


@router.get("/entity-brief/{eid:path}")
def entity_brief(eid: str, llm: bool = True):
    """'Why this matters now' and 'what to do' for an entity, with citations; see news/brief.py."""
    from . import brief
    ensure_schema()
    eid = _resolve(eid)          # a merged id briefs the entity it joined
    known = any(_has_table(t) and db.query(sql, [eid] * sql.count("?")) for t, sql in (
        ("entities", "SELECT 1 FROM entities WHERE id = ?"),
        ("mentions", "SELECT 1 FROM mentions WHERE entity_id = ? LIMIT 1"),
        ("claims", "SELECT 1 FROM claims WHERE subj = ? OR obj = ? LIMIT 1")))
    if not known:   # as /api/entities/{id}: no brief for an entity the lake has never seen
        raise HTTPException(404, "unknown entity")
    b = brief.brief(eid, llm=llm)
    try:
        from ..ai import client
        down = client.is_down()
    except Exception:
        down = True
    fresh = bool(b["llm"]) and not b["llm_stale"]
    # Wording is wanted (asked for, there is evidence to word, none fresh) but the AI helper cannot write it.
    b["llm_unavailable"] = bool(llm and b.get("evidence") and not fresh and not b["llm_pending"] and down)
    b["llm_status"] = ("off" if not llm else "fresh" if fresh else "pending" if b["llm_pending"]
                       else "unavailable" if b["llm_unavailable"] else "stale" if b["llm_stale"] else "none")
    return _j([b])[0]
