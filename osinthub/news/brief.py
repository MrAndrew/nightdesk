"""Entity brief for the shared entity panel: "why this matters now" and "what to do".

Deterministic parts come from the lake (claims, mentions, article text, CISA KEV and NVD events) and the
ATT&CK bundle in <lake>/ref/ (technique -> mitigation). An optional local-LLM rewrite of the same facts,
with citations, is generated in the background and cached per entity in `settings`
(`news.entity_brief.<id>`), keyed by a hash of the entity's claims so it refreshes when they change.
Reference: okf/architecture/web-client.md#entity-panel
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import re
import threading
from functools import lru_cache

from .. import config, db

log = logging.getLogger("osinthub.news.brief")
IOC_TYPES = ("ip", "domain", "url", "hash", "sha256", "sha1", "md5")
TTP_RE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")
CACHE_KEY = "news.entity_brief."
_running: set[str] = set()
_lock = threading.Lock()


def _has(t: str) -> bool:
    return db.has_table(t)


# ------------------------------------------------------------------ reference data
@lru_cache(maxsize=1)
def _attack() -> dict:
    """{technique id: {name, mitigations: [(M-id, name)]}} and alias sources, from the ATT&CK bundle."""
    out = {"tech": {}, "aliases": {}, "objs": {}}
    p = config.REF_DIR / "enterprise-attack.json"
    if not p.exists():
        return out
    try:
        objs = json.loads(p.read_text())["objects"]
    except Exception as e:  # noqa: BLE001
        log.warning("ATT&CK bundle unreadable: %s", e)
        return out
    ext = lambda o: next((r.get("external_id") for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)  # noqa: E731
    live = [o for o in objs if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_id = {o["id"]: o for o in live}
    for o in live:
        if o["type"] == "attack-pattern" and ext(o):
            out["tech"][ext(o)] = {"name": o.get("name"), "mitigations": []}
        if o["type"] in ("intrusion-set", "malware", "tool", "campaign") and ext(o):
            rec = {"id": ext(o), "created": o.get("created"), "modified": o.get("modified"), "description": o.get("description"), "name": o.get("name")}
            out["objs"][ext(o)] = rec
            out["objs"].setdefault("name:" + (o.get("name") or "").lower(), rec)
        if o["type"] in ("intrusion-set", "malware", "tool"):
            for a in o.get("aliases", []) + o.get("x_mitre_aliases", []):
                out["aliases"].setdefault(a.lower(), set()).add("MITRE ATT&CK")
    for o in live:
        if o["type"] == "relationship" and o.get("relationship_type") == "mitigates":
            s, t = by_id.get(o["source_ref"]), by_id.get(o["target_ref"])
            if s and t and s["type"] == "course-of-action" and ext(s) and ext(t) in out["tech"]:
                out["tech"][ext(t)]["mitigations"].append((ext(s), s.get("name")))
    return out


@lru_cache(maxsize=1)
def _misp_aliases() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for fn, label in (("misp-threat-actor.json", "MISP threat-actor"), ("misp-malpedia.json", "MISP Malpedia"), ("misp-tool.json", "MISP tool")):
        p = config.REF_DIR / fn
        if not p.exists():
            continue
        try:
            for v in json.loads(p.read_text()).get("values", []):
                for a in [v.get("value", "")] + (v.get("meta") or {}).get("synonyms", []):
                    if a:
                        out.setdefault(a.lower(), set()).add(label)
        except Exception as e:  # noqa: BLE001
            log.warning("MISP galaxy %s unreadable: %s", fn, e)
    return out


VENDOR_NAMING = [
    (r"(?i)\b(typhoon|blizzard|sleet|sandstorm|tempest|storm-\d+|dust|hail|tsunami|cyclone|flood|rain)\b", "Microsoft naming"),
    (r"(?i)\b(panda|bear|kitten|chollima|spider|jackal|buffalo|tiger|leopard)\b", "CrowdStrike naming"),
    (r"(?i)^(apt\d+|unc\d+|fin\d+|temp\.\w+)$", "Mandiant naming"),
    (r"(?i)^ta\d{3,4}$", "Proofpoint naming"),
    (r"(?i)^(cl-|cl-sta-|cl-cri-|cl-unk-)", "Unit 42 naming"),
    (r"(?i)^uac-\d+$", "CERT-UA naming"),
    (r"(?i)^(g\d{4}|s\d{4})$", "MITRE id"),
]


def alias_sources(name: str, aliases: list[str]) -> list[dict]:
    att, misp = _attack()["aliases"], _misp_aliases()
    rows = []
    for a in [name] + [x for x in aliases if x.lower() != (name or "").lower()]:
        src = sorted(att.get(a.lower(), set()) | misp.get(a.lower(), set()))
        vend = next((lab for rx, lab in VENDOR_NAMING if re.search(rx, a)), None)
        rows.append({"alias": a, "sources": src, "naming": vend, "primary": a == name})
    return rows


# ------------------------------------------------------------------ facts
def _refs(eid: str) -> list[str]:
    return [r["ref_id"] for r in db.query("SELECT DISTINCT ref_id FROM mentions WHERE entity_id = ? AND ref_type = 'article'", [eid])]


def ai_excluded_sources() -> frozenset[str]:
    """Sources whose terms forbid using their data with AI models (Source.ai_ok = False: every abuse.ch source,
    ThreatFox, URLhaus, SSLBL and Feodo Tracker). Their claims, evidence and mentions never reach the brief, so never
    the LLM prompt."""
    try:
        from ..sources import SOURCES
        return frozenset(sid for sid, s in SOURCES.items() if not getattr(s, "ai_ok", True))
    except Exception:
        return frozenset({"threatfox", "urlhaus", "sslbl", "feodo_c2"})


def _not_excluded_sql() -> str:
    ex = sorted(ai_excluded_sources())
    if not ex:
        return "TRUE"
    return "NOT (ref_type = 'event' AND split_part(ref_id, ':', 1) IN (" + ", ".join(f"'{s}'" for s in ex) + "))"


def _claims(eid: str) -> list[dict]:
    if not _has("claims"):
        return []
    rows = db.query("""SELECT c.id, c.subj, c.predicate, c.obj, c.origin, c.confidence, c.sources, c.first_seen, c.last_seen,
                              CAST(c.evidence AS VARCHAR) AS evidence, s.name sn, s.type st, o.name obn, o.type ot
                       FROM claims c LEFT JOIN entities s ON s.id = c.subj LEFT JOIN entities o ON o.id = c.obj
                       WHERE (c.subj = ? OR c.obj = ?) AND c.origin IN ('reported', 'user', 'observed')
                         AND c.predicate NOT IN ('announced-by', 'in-prefix')
                       ORDER BY c.confidence DESC, c.last_seen DESC LIMIT 200""", [eid, eid])
    ex = ai_excluded_sources()
    out = []
    for r in rows:
        try:
            r["evidence"] = json.loads(r["evidence"] or "[]")
        except ValueError:
            r["evidence"] = []
        if ex:   # drop evidence from AI-excluded feeds, and claims that only they support
            had = any(s in ex for s in (r["sources"] or []))
            r["evidence"] = [e for e in r["evidence"] if e.get("source") not in ex]
            r["sources"] = [s for s in (r["sources"] or []) if s not in ex]
            if not r["sources"] and r["origin"] == "observed":
                continue
            if had:
                # a claim merged with an abuse.ch one (Feodo + ThreatFox): its stored confidence and dates include
                # the abuse.ch part, so neither is used; the dates come from the remaining evidence only
                ts = sorted(str(e.get("ts")) for e in r["evidence"] if e.get("ts"))
                r["confidence"] = None
                r["first_seen"], r["last_seen"] = (ts[0], ts[-1]) if ts else (None, None)
        out.append(r)
    return out


def _tech_link(c: dict) -> str | None:
    """For a link to an ATT&CK technique: 'catalogue' (any reference evidence, or observed / the analyst's), 'possible'
    (every article item is the suggested tier), else 'article'. None when neither end is a technique."""
    if "technique" not in (c.get("st"), c.get("ot")) and not any(str(x).startswith("technique:") for x in (c["subj"], c["obj"])):
        return None
    ev = [e for e in c.get("evidence") or [] if isinstance(e, dict) and not e.get("verdict")]
    if c.get("origin") in ("observed", "user") or any(e.get("ref_type") == "reference" for e in ev):
        return "catalogue"
    return "possible" if ev and all(e.get("suggested") for e in ev) else "article"


def trend(eid: str, days: int = 365) -> dict:
    keep = _not_excluded_sql()
    rows = db.query(f"""SELECT date_trunc('week', ts) AS t, count(*) AS n, count(*) FILTER (ref_type = 'article') AS articles
                       FROM mentions WHERE entity_id = ? AND ts > now() - (? * INTERVAL 1 DAY) AND {keep}
                       GROUP BY 1 ORDER BY 1""", [eid, days])
    first = db.query(f"SELECT min(ts) AS f, count(*) AS n FROM mentions WHERE entity_id = ? AND {keep}", [eid])[0]
    pts = [{"t": r["t"].isoformat() if hasattr(r["t"], "isoformat") else r["t"], "n": r["n"], "articles": r["articles"]} for r in rows]
    now = dt.datetime.now(dt.UTC)
    last30 = db.query(f"SELECT count(*) n FROM mentions WHERE entity_id = ? AND ts > ? AND {keep}", [eid, now - dt.timedelta(days=30)])[0]["n"]
    prev30 = db.query(f"SELECT count(*) n FROM mentions WHERE entity_id = ? AND ts > ? AND ts <= ? AND {keep}",
                      [eid, now - dt.timedelta(days=60), now - dt.timedelta(days=30)])[0]["n"]
    f = first["f"]
    return {"bucket": "week", "days": days, "points": pts, "total": first["n"], "since": f.isoformat() if hasattr(f, "isoformat") else f,
            "last30": last30, "prev30": prev30, "sparse": sum(1 for p in pts if p["n"]) < 3}


def _cves(ids: list[str]) -> list[dict]:
    from .api import cve_enrichment
    rows = cve_enrichment([i.split(":", 1)[-1] for i in ids])
    # Known exploited first, then likely to be exploited (EPSS), then by CVSS.
    rows.sort(key=lambda c: (not c["kev"], -(c["epss"] or 0), -(c["cvss"] or 0), c["id"]))
    return rows


def facts(eid: str) -> dict:
    ent = db.query("SELECT id, type, name, aliases, attrs, first_seen, last_seen FROM entities WHERE id = ?", [eid]) if _has("entities") else []
    e = ent[0] if ent else {"id": eid, "type": eid.split(":")[0], "name": eid.split(":", 1)[-1], "aliases": [], "attrs": None}
    etype, name = e["type"], e["name"]
    # A technique link read from article text only says how sure it is (okf/data/entities.md#technique-labels): a
    # possible one (suggested tier only) is left out of the brief, as from exports; a likely one on a technique's page
    # is worded as found automatically. A link MITRE's catalogue states is a plain fact.
    claims = [c for c in _claims(eid) if _tech_link(c) != "possible"]
    refs = _refs(eid)
    ev_list: list[dict] = []

    def cite(evs) -> list[int]:
        out = []
        for x in (evs or [])[:2]:
            k = x.get("url") or x.get("ref_id")
            i = next((j for j, y in enumerate(ev_list) if (y.get("url") or y.get("ref_id")) == k), None)
            if i is None:
                ev_list.append({k2: x.get(k2) for k2 in ("source", "tier", "url", "ref_type", "ref_id", "ts", "quote")})
                i = len(ev_list) - 1
            out.append(i + 1)
        return out

    def other(c):
        return (c["obj"], c["obn"] or c["obj"].split(":", 1)[-1], c["ot"] or c["obj"].split(":")[0]) if c["subj"] == eid else \
               (c["subj"], c["sn"] or c["subj"].split(":", 1)[-1], c["st"] or c["subj"].split(":")[0])

    # co-mentions in the same articles
    co = []
    if refs:
        co = db.query(f"""SELECT m.entity_id id, e.type, e.name, count(DISTINCT m.ref_id) n FROM mentions m JOIN entities e ON e.id = m.entity_id
                          WHERE m.ref_type = 'article' AND m.ref_id IN ({','.join('?' * len(refs))}) AND m.entity_id <> ?
                            AND coalesce(m.role, '') <> 'technique-suggested'
                          GROUP BY ALL ORDER BY n DESC LIMIT 400""", refs + [eid])
    arts = db.query(f"""SELECT id, title, source, tier, url, published, text FROM articles WHERE id IN ({','.join('?' * len(refs))})
                        ORDER BY published DESC NULLS LAST""", refs) if refs else []
    tr = trend(eid)

    # ---- why this matters now
    why = []
    if arts:
        a = arts[0]
        why.append({"text": f"Most recent report: “{a['title']}” ({a['source']}, {str(a['published'])[:10]}).",
                    "cites": cite([{"source": a["source"], "tier": a["tier"], "url": a["url"], "ref_type": "article", "ref_id": a["id"], "ts": str(a["published"])}])})
    if tr["last30"] or tr["prev30"]:
        trendw = "rising" if tr["last30"] > tr["prev30"] * 1.5 + 1 else "falling" if tr["prev30"] > tr["last30"] * 1.5 + 1 else "steady"
        outlets = sorted({a["source"] for a in arts})
        why.append({"text": f"{tr['last30']} mentions in the last 30 days (previous 30: {tr['prev30']}), {trendw}; covered by {len(outlets)} news outlet{'s' if len(outlets) != 1 else ''} in all"
                            + (f" ({', '.join(outlets[:4])}{'…' if len(outlets) > 4 else ''})." if outlets else "."), "cites": []})
    cve_row = (_cves([eid]) or [None])[0] if etype == "cve" else None
    if cve_row and cve_row["epss_status"] == "ok":
        from ..sources.vulns import epss_pct
        d = str(cve_row["epss_date"] or "")[:10]
        moved = (f", {'up' if cve_row['epss'] > cve_row['epss_prev'] else 'down'} from {epss_pct(cve_row['epss_prev'])} on "
                 f"{str(cve_row['epss_since'])[:10]}" if cve_row["epss_prev"] is not None else "")
        pctl = round((cve_row["epss_percentile"] or 0) * 100, 1)
        txt = (f"EPSS gives a {epss_pct(cve_row['epss'])} probability of exploitation activity in the next 30 days "
               f"(higher than {pctl}% of scored CVEs{moved}).")
        why.append({"text": txt, "cites": cite([{"source": "epss", "tier": "B", "url": "https://www.first.org/epss", "ts": d,
                                                 "quote": f"EPSS {cve_row['epss']} (percentile {cve_row['epss_percentile']}) on {d}"}])})
    for adv in (cve_row or {}).get("advisories", [])[:2]:
        why.append({"text": f"CISA {adv['kind'] or 'advisory'} {adv['id']}: “{adv['title']}” ({str(adv['updated'])[:10]}).",
                    "cites": cite([{"source": "cisa_advisories", "tier": "A", "url": adv["url"], "ts": str(adv["updated"]),
                                    "quote": f"{adv['id']}: {adv['title']}"}])})
    by_pred: dict[str, list] = {}
    for c in claims:
        if c["origin"] == "observed" and c["predicate"] in ("made-by",):
            continue
        by_pred.setdefault((c["predicate"], c["subj"] == eid), []).append(c)
    phr = {("targets", True): "Targets", ("exploits", True): "Exploits", ("uses", True): "Uses", ("attributed-to", True): "Attributed to",
           ("uses", False): "Used by", ("exploits", False): "Exploited by", ("targets", False): "Targeted by", ("affects", True): "Affects",
           ("drops", True): "Drops", ("communicates-with", True): "Talks to", ("variant-of", True): "Variant of", ("part-of", True): "Part of"}
    for key in [("exploits", True), ("exploits", False), ("targets", True), ("attributed-to", True), ("uses", True), ("uses", False), ("affects", True), ("drops", True)]:
        cs = [c for c in by_pred.get(key, []) if other(c)[2] not in ("technique",)][:5]
        if not cs:
            continue
        # on a technique's page each link is worded by its own evidence: catalogue links as facts, links read from
        # article text in a sentence of their own that says so (never one sentence mixing the two)
        parts = [(cs, "")] if etype != "technique" else [
            (g, q) for g, q in (([c for c in cs if _tech_link(c) != "article"], ""),
                                ([c for c in cs if _tech_link(c) == "article"], " (read automatically from articles; it can be wrong)")) if g]
        for grp, qual in parts:
            names = list(dict.fromkeys(other(c)[1] for c in grp))
            why.append({"text": f"{phr[key]} {', '.join(names)}{qual}.", "cites": sorted({n for c in grp for n in cite(c["evidence"])})[:4],
                        "entities": [{"id": other(c)[0], "name": other(c)[1], "type": other(c)[2]} for c in grp]})

    # ---- what to do
    todo: dict = {"mitigations": [], "block": [], "patch": [], "techniques": []}
    if etype in ("actor", "malware", "tool", "campaign"):
        ttps: dict[str, int] = {}
        for c in claims:
            o = other(c)
            if o[2] == "technique":
                t = o[0].split(":", 1)[-1].upper()
                ttps[t] = ttps.get(t, 0) + 2
        for x in co:
            if x["type"] == "technique":
                t = x["id"].split(":", 1)[-1].upper()
                ttps[t] = ttps.get(t, 0) + x["n"]
        for a in arts:
            for t in set(TTP_RE.findall(a["text"] or "")):
                ttps[t] = ttps.get(t, 0) + 1
        att = _attack()["tech"]
        mit: dict[str, dict] = {}
        for t, w in ttps.items():
            ms = (att.get(t) or {}).get("mitigations") or (att.get(t.split(".")[0]) or {}).get("mitigations") or []
            for mid, mname in ms:
                if mid == "M1056":  # Pre-compromise: nothing a defender can do
                    continue
                m = mit.setdefault(mid, {"id": mid, "name": mname, "techniques": [], "weight": 0})
                m["techniques"].append(t); m["weight"] += w
        todo["techniques"] = [{"id": t, "name": (att.get(t) or {}).get("name")} for t, _ in sorted(ttps.items(), key=lambda x: -x[1])][:20]
        todo["mitigations"] = sorted(mit.values(), key=lambda m: (-len(m["techniques"]), -m["weight"]))[:6]
        for m in todo["mitigations"]:
            m["techniques"] = sorted(set(m["techniques"]))
        blk = {}
        for c in claims:
            o = other(c)
            if o[2] in IOC_TYPES:
                blk[o[0]] = {"id": o[0], "type": o[2], "value": o[1], "how": c["predicate"], "n": len(c["sources"] or []) or 1, "cites": cite(c["evidence"])}
        for x in co:
            if x["type"] in IOC_TYPES and x["id"] not in blk and len(blk) < 25:
                blk[x["id"]] = {"id": x["id"], "type": x["type"], "value": x["name"], "how": "named in the same report", "n": x["n"], "cites": []}
        todo["block"] = list(blk.values())[:25]
        cve_ids = {other(c)[0] for c in claims if other(c)[2] == "cve"} | {x["id"] for x in co if x["type"] == "cve"}
        todo["patch"] = _cves(sorted(cve_ids))[:10]
    if etype == "cve":
        cv = [cve_row] if cve_row else []
        todo["cve"] = cv[0] if cv else None
        prods = [{"id": other(c)[0], "name": other(c)[1], "type": other(c)[2], "cites": cite(c["evidence"])}
                 for c in claims if c["predicate"] in ("affects",) and c["subj"] == eid]
        prods += [{"id": x["id"], "name": x["name"], "type": x["type"], "cites": []} for x in co if x["type"] in ("product", "vendor") and x["id"] not in {p["id"] for p in prods}][:8]
        todo["products"] = prods[:12]
        exploiters = [{"id": other(c)[0], "name": other(c)[1], "type": other(c)[2], "cites": cite(c["evidence"])} for c in claims if c["predicate"] == "exploits" and c["obj"] == eid]
        status = "Known exploited (CISA KEV)" if cv and cv[0]["kev"] else ("Exploitation reported" if exploiters else "No exploitation reported")
        todo["exploitation"] = {"status": status, "by": exploiters[:8], "ransomware": bool(cv and cv[0]["ransomware"])}

    attrs = e.get("attrs")
    if isinstance(attrs, str):
        try:
            attrs = json.loads(attrs)
        except ValueError:
            attrs = {}
    objs = _attack()["objs"]
    ref = objs.get((attrs or {}).get("attack_id") or "") or objs.get("name:" + (name or "").lower())
    earliest = min((c["first_seen"] for c in claims if c["first_seen"] and c["origin"] == "reported"), default=None)
    dates = {"data_first_seen": e.get("first_seen"), "earliest_claim": earliest,
             "attack_id": ref["id"] if ref else None, "attack_created": ref["created"] if ref else None,
             "description": re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", re.sub(r"\(Citation:[^)]*\)", "", ref["description"])).strip() if ref and ref.get("description") else None}
    return {"id": eid, "type": etype, "name": name, "why": why, "ref": dates, "todo": todo, "evidence": ev_list, "trend": tr,
            "aliases": alias_sources(name, list(e.get("aliases") or [])), "attrs": attrs or {},
            "claims_hash": hashlib.sha1("|".join(sorted(f"{c['id']}:{c['last_seen']}" for c in claims)).encode()).hexdigest()[:16]}


# ------------------------------------------------------------------ LLM rewrite (background, cached)
SCHEMA = {"type": "object", "properties": {
    "why_now": {"type": "array", "maxItems": 4, "items": {"type": "object", "properties": {"text": {"type": "string"}, "cites": {"type": "array", "items": {"type": "integer"}}}, "required": ["text", "cites"]}},
    "actions": {"type": "array", "maxItems": 5, "items": {"type": "object", "properties": {"text": {"type": "string"}, "cites": {"type": "array", "items": {"type": "integer"}}}, "required": ["text", "cites"]}}},
    "required": ["why_now", "actions"]}


def _generate(eid: str, f: dict) -> None:
    from ..ai import client
    try:
        ev = "\n".join(f"[{i + 1}] {e.get('source')} ({str(e.get('ts'))[:10]}): {e.get('quote') or ''}" for i, e in enumerate(f["evidence"]))
        facts_txt = "\n".join(f"- {w['text']} {''.join(f'[{n}]' for n in w.get('cites', []))}" for w in f["why"])
        todo = f["todo"]
        acts = []
        if todo.get("mitigations"):
            acts.append("Mitigations: " + "; ".join(f"{m['id']} {m['name']} (covers {', '.join(m['techniques'][:4])})" for m in todo["mitigations"]))
        if todo.get("patch"):
            def _cve_txt(c):
                epss = f" EPSS {round(c['epss'] * 100, 1)}%" if c.get("epss") is not None else ""
                return f"{c['id']}{' KEV' if c['kev'] else ''}{epss}"
            acts.append("CVEs: " + "; ".join(_cve_txt(c) for c in todo["patch"]))
        if todo.get("block"):
            acts.append(f"{len(todo['block'])} indicators to block")
        msg = [{"role": "system", "content": "You write terse threat-intel briefs for a defender. Use only the facts given. Cite with the bracket numbers given; never invent a number. No speculation."},
               {"role": "user", "content": f"Entity: {f['name']} ({f['type']})\nFacts:\n{facts_txt}\n{chr(10).join(acts)}\nEvidence:\n{ev}\n\n"
                                           "Write why_now (2-4 sentences: why this matters to a defender now) and actions (3-5 concrete steps). Each item has text and cites."}]
        out = client.chat(msg, json_schema=SCHEMA, max_tokens=700, timeout=600)
        if out:
            j = json.loads(out)
            n = len(f["evidence"])
            for k in ("why_now", "actions"):
                for it in j.get(k, []):
                    it["cites"] = [c for c in it.get("cites", []) if isinstance(c, int) and 1 <= c <= n]
            db.set_setting(CACHE_KEY + eid, {"hash": f["claims_hash"], "at": dt.datetime.now(dt.UTC).isoformat(), **j})
    except Exception as e:  # noqa: BLE001
        log.warning("entity brief LLM failed for %s: %s", eid, e)
    finally:
        with _lock:
            _running.discard(eid)


def brief(eid: str, llm: bool = True) -> dict:
    f = facts(eid)
    cached = db.get_setting(CACHE_KEY + eid)
    fresh = cached if cached and cached.get("hash") == f["claims_hash"] else None
    pending = False
    attrs = f.get("attrs") if isinstance(f.get("attrs"), dict) else {}
    if attrs.get("ai_excluded"):   # an entity known only from an AI-excluded feed: no LLM wording at all
        llm = False
    if llm and not fresh and f["evidence"]:
        from ..ai import client
        if not client.is_down():
            with _lock:
                if eid not in _running:
                    _running.add(eid)
                    threading.Thread(target=_generate, args=(eid, f), daemon=True).start()
                pending = True
    f["llm"] = fresh or (cached if cached else None)
    f["llm_stale"] = bool(cached and not fresh)
    f["llm_pending"] = pending
    return f
