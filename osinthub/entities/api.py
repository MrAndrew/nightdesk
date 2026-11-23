"""HTTP API under /api/entities. Reference: okf/data/entities.md#api"""
from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import json
import logging
import math
import re
from collections import defaultdict

from fastapi import APIRouter, HTTPException, Query

from .. import apiutil, db
from . import overrides, scoring, store
from .normalize import TYPES, entity_id
from .scoring import band

router = APIRouter(prefix="/api/entities", tags=["entities"])
log = logging.getLogger("osinthub.entities.api")

STATUS: dict = {}


def _j(v):
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return v
    return v


def _clean(rows):
    for r in rows:
        for k, v in list(r.items()):
            if isinstance(v, dt.datetime):
                r[k] = v.isoformat()
            elif k in ("attrs", "evidence"):
                r[k] = _j(v)
    return rows


def _iso(v):
    return v.isoformat() if isinstance(v, dt.datetime) else v


_csv = apiutil.csv_list


# ---------------------------------------------------------------- verdicts and hypotheses
# A verdict (an origin "user" claim on the same subj/predicate/obj) annotates the claims of its triple; it is
# never a claim of its own in any count. Its latest verdict is the last evidence item (feedback keeps it so).
# A rejected triple drops out of Related, the graph and every count; a confirmed one counts once.
REJECTED_SQL = ("SELECT subj, predicate, obj FROM claims WHERE origin = 'user' "
                "AND json_extract_string(evidence, '$[-1].verdict') = 'reject'")
# The links that count: one per triple, never a rejected one, never a hypothesis (an inferred link).
COUNTED_SQL = (f"(SELECT DISTINCT c.subj, c.predicate, c.obj FROM claims c ANTI JOIN ({REJECTED_SQL}) r "
               "USING (subj, predicate, obj) WHERE c.origin <> 'inferred')")
# Reference sets whose relations are listings, not judgements: nothing for the analyst to confirm or reject.
REFERENCE_SOURCES = {"MITRE ATT&CK", "MISP galaxy"}
# Which claim stands for a triple when several origins hold it (graph edges, the rejected list).
ORIGIN_RANK = {"observed": 0, "reported": 1, "local": 2, "user": 3, "inferred": 4}


def verdicts_for(ids: list[str]) -> dict[tuple, dict]:
    """(subj, predicate, obj) -> latest verdict {verdict, note, ts, id} for triples touching any of ids."""
    out: dict[tuple, dict] = {}
    if not ids:
        return out
    for r in db.query("""SELECT id, subj, predicate, obj, evidence FROM claims WHERE origin = 'user'
                         AND (subj IN (SELECT unnest(?)) OR obj IN (SELECT unnest(?)))""", [ids, ids]):
        ev = _j(r["evidence"]) or []
        vs = [e for e in ev if isinstance(e, dict) and e.get("verdict")]
        if vs:
            v = vs[-1]
            out[(r["subj"], r["predicate"], r["obj"])] = {"verdict": v["verdict"], "note": v.get("note") or "",
                                                          "reason": v.get("reason") or "", "ts": v.get("ts"), "id": r["id"]}
    return out


def is_authoritative(c: dict, evidence: list) -> bool:
    """A feed fact (observed: KEV, NVD, threat lists) or a pure reference listing (ATT&CK, MISP galaxy)."""
    if c.get("origin") == "observed":
        return True
    if c.get("origin") != "reported":
        return False
    items = [x for x in evidence or [] if isinstance(x, dict) and not x.get("verdict")]
    if items:
        return all(x.get("ref_type") == "reference" for x in items)
    return bool(c.get("sources")) and set(c["sources"]) <= REFERENCE_SOURCES


_SHARED = re.compile(r"^(?:shared|co-mentioned) \S+ (.+?) \(held by")


def hypothesis_why(ev0: dict) -> str:
    """One line for an inferred link: what the two ends share, and that no source said it."""
    names = []
    for r in (ev0 or {}).get("reasons") or []:
        m = _SHARED.match(str(r.get("text") or ""))
        if m and m.group(1) not in names:
            names.append(m.group(1))
    if names:
        return f"Computed by the hub, not said by any source: both share {', '.join(names[:3])}"
    return "Computed by the hub from shared tools and infrastructure; no source has said it"


# ---------------------------------------------------------------- list
@router.get("")
def list_entities(type: str | None = None, q: str | None = None, limit: int = Query(100, ge=0, le=2000), offset: int = Query(0, ge=0, le=2**63 - 1),
                  sort: str = "mentions", since_hours: float | None = None):
    types = _csv(type)
    cl, p = [], []
    if types:
        cl.append(f"e.type IN ({','.join('?' * len(types))})"); p += types
    if q:
        # contains-text on name and id (% and _ are literal), whole alias case-insensitively
        cl.append("(e.name ILIKE ? ESCAPE '\\' OR e.id ILIKE ? ESCAPE '\\' OR list_contains(list_transform(e.aliases, lambda x: lower(x)), lower(?)))")
        lq = apiutil.like(q)
        p += [lq, lq, q]
    if since_hours is not None and (not math.isfinite(since_hours) or since_hours < 0):
        raise HTTPException(400, "since_hours must be a finite number >= 0")
    win, wp = "", []   # the time window alone: the per-type counts follow it (the Intel rail shows the window's counts)
    if since_hours is not None and since_hours <= 24 * 365 * 200:   # longer windows are all history; 0 is empty
        win, wp = "e.last_seen > now() - to_microseconds(?)", [int(round(since_hours * 3_600_000_000))]
        cl.append(win); p += wp
    w = (" WHERE " + " AND ".join(cl)) if cl else ""
    orders = {"mentions": "mentions DESC, e.last_seen DESC NULLS LAST", "last_seen": "e.last_seen DESC NULLS LAST",
              "name": "e.name", "claims": "claims DESC"}
    if sort not in orders:   # a typo is reported, not silently replaced by the default
        raise HTTPException(400, f"sort must be one of {', '.join(orders)}")
    order = orders[sort] + ", e.id"  # unique tiebreaker: offset pages are disjoint and cover every row
    rows = db.query(f"""
        WITH m AS (SELECT entity_id, count(*) AS n, count(DISTINCT ref_type) AS kinds FROM mentions GROUP BY 1),
             t AS {COUNTED_SQL},
             c AS (SELECT x, count(*) AS n FROM (SELECT subj AS x FROM t UNION ALL SELECT obj FROM t) GROUP BY 1)
        SELECT e.id, e.type, e.name, e.aliases[1:6] AS aliases, len(e.aliases) AS alias_count, e.first_seen, e.last_seen,
               coalesce(m.n, 0) AS mentions, coalesce(c.n, 0) AS claims,
               json_extract_string(e.attrs, '$.description') AS description
        FROM entities e LEFT JOIN m ON m.entity_id = e.id LEFT JOIN c ON c.x = e.id{w}
        ORDER BY {order} LIMIT ? OFFSET ?""", p + [limit, offset])
    for r in rows:
        if r.get("description"):
            r["description"] = r["description"][:240]
    counts = {r["type"]: r["n"] for r in db.query(
        f"SELECT type, count(*) AS n FROM entities e{' WHERE ' + win if win else ''} GROUP BY 1 ORDER BY 2 DESC", wp)}
    total = db.query(f"SELECT count(*) AS n FROM entities e{w}", p)[0]["n"]
    return {"counts": counts, "total": total, "items": _clean(rows)}


@router.get("/status")
def status():
    from . import refdata
    n = db.query("""SELECT (SELECT count(*) FROM entities) AS entities, (SELECT count(*) FROM mentions) AS mentions,
                           (SELECT count(*) FROM claims) AS claims,
                           (SELECT count(*) FROM entity_linked WHERE ref_type = 'event') AS events_linked,
                           (SELECT count(*) FROM events) AS events""")[0]
    by_origin = {r["origin"]: r["n"] for r in db.query("SELECT origin, count(*) AS n FROM claims GROUP BY 1")}
    files = {k: refdata.path(k).exists() for k in refdata.FILES}
    return {**n, "claims_by_origin": by_origin, "reference_files": files, "task": STATUS}


# ---------------------------------------------------------------- lookup
_HASH = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.I)


def guess_ids(value: str) -> list[str]:
    """Candidate entity ids for a typed value, resolved through the user's merges and retypes."""
    return list(dict.fromkeys(overrides.resolve(x) for x in _guess_ids(value)))


def _guess_ids(value: str) -> list[str]:
    v = value.strip()
    if not v:
        return []
    if ":" in v and v.split(":", 1)[0] in TYPES:
        return [v]
    out = []
    try:
        ipaddress.ip_address(v)
        return [entity_id("ip", v)]
    except ValueError:
        pass
    if "/" in v:
        try:
            return [entity_id("prefix", str(ipaddress.ip_network(v, strict=False)))]
        except ValueError:
            pass
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", v, re.I):
        return [entity_id("cve", v)]
    if re.fullmatch(r"AS\d+", v, re.I):
        return [entity_id("asn", v)]
    if _HASH.match(v):
        return [entity_id("hash", v)]
    if re.fullmatch(r"T\d{4}(\.\d{3})?", v, re.I):
        return [entity_id("technique", v)]
    if re.match(r"^(https?|ftp)://", v, re.I):
        return [entity_id("url", v)]
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", v, re.I):
        out.append(entity_id("domain", v))
    from .refdata import catalog
    eid = catalog().resolve(v, types=("actor", "malware", "tool", "campaign"))
    if eid:
        out.append(eid)
    for t in ("actor", "malware", "tool", "campaign", "vendor", "product", "org", "country", "sector"):
        out.append(entity_id(t, v))
    return list(dict.fromkeys(out))


@router.get("/lookup")
def lookup(values: str = Query(..., description="comma-separated IPs, domains, hashes, CVEs, names")):
    vals = _csv(values)[:500]
    cand = {v: guess_ids(v) for v in vals}
    ids = list({i for c in cand.values() for i in c})
    found = {}
    if ids:
        for r in db.query(f"""SELECT e.id, e.type, e.name, e.first_seen, e.last_seen,
                                    (SELECT count(*) FROM mentions m WHERE m.entity_id = e.id) AS mentions,
                                    (SELECT count(*) FROM {COUNTED_SQL} c WHERE c.subj = e.id OR c.obj = e.id) AS claims
                             FROM entities e WHERE e.id IN (SELECT unnest(?))""", [ids]):
            found[r["id"]] = _clean([r])[0]
        # aliases (case-insensitive) for names
        names = [v for v in vals if not any(i in found for i in cand[v])]
        if names:
            for r in db.query("""SELECT id, type, name, first_seen, last_seen, a FROM
                                   (SELECT id, type, name, first_seen, last_seen, lower(unnest(aliases)) AS a FROM entities)
                                 WHERE a IN (SELECT lower(unnest(?)))""", [names]):
                for v in names:
                    if v.lower() == r["a"]:
                        cand[v].insert(0, r["id"])
                        found.setdefault(r["id"], _clean([{k: r[k] for k in ("id", "type", "name", "first_seen", "last_seen")}])[0])
    out = []
    for v in vals:
        hit = next((found[i] for i in cand[v] if i in found), None)
        out.append({"value": v, "found": hit is not None, "entity": hit})
    return {"results": out}


# ---------------------------------------------------------------- graph
@router.get("/graph")
def graph(id: str, depth: int = Query(1, ge=1, le=2), limit: int = Query(150, ge=0, le=1000), min_confidence: float = Query(0.0, ge=0, le=1, allow_inf_nan=False),
          collapse_over: int = Query(15, ge=0, le=100_000)):
    id = overrides.resolve(id)          # an old link to a merged entity opens the one it joined
    if not db.query("SELECT 1 FROM entities WHERE id = ?", [id]):
        raise HTTPException(404, "unknown entity")
    nodes = {id}
    edges = []
    frontier = {id}
    seen_triples = set()
    verdicts: dict[tuple, dict] = {}
    for d in range(depth):
        if not frontier:
            break
        # Rejected triples are gone; sourced links come before hypotheses, so these never crowd them out of the cap.
        rows = db.query(f"""SELECT c.id, c.subj, c.predicate, c.obj, c.origin, c.confidence, c.sources, c.first_seen, c.last_seen
                           FROM claims c ANTI JOIN ({REJECTED_SQL}) r USING (subj, predicate, obj)
                           WHERE (c.subj IN (SELECT unnest(?)) OR c.obj IN (SELECT unnest(?))) AND (c.confidence IS NULL OR c.confidence >= ?)
                           ORDER BY (c.origin = 'inferred'), c.confidence DESC NULLS LAST, c.id LIMIT ?""",
                        [list(frontier), list(frontier), min_confidence, limit * 4])
        verdicts.update(verdicts_for(list(frontier)))
        # one edge per triple: the best-sourced claim stands for it (a verdict is never a second edge)
        best: dict[tuple, dict] = {}
        for r in rows:
            k = (r["subj"], r["predicate"], r["obj"])
            if k in seen_triples:
                continue
            if k not in best or ORIGIN_RANK.get(r["origin"], 9) < ORIGIN_RANK.get(best[k]["origin"], 9):
                best[k] = r
        nxt = set()
        for k, r in best.items():
            seen_triples.add(k)
            v = verdicts.get(k)
            r["verdict"] = v["verdict"] if v else None
            r["hypothesis"] = r["origin"] == "inferred" and r["verdict"] != "confirm"
            edges.append(r)
            for x in (r["subj"], r["obj"]):
                if x not in nodes:
                    nxt.add(x)
        # co-mentions add context at the first hop when claims are sparse. They carry no confidence, and a link
        # without one passes any confidence floor, as in the client's slider (web/js/views/entities/graph.js).
        # "Sparse" counts every claim, so raising the floor never adds co-mentions the unfiltered graph lacks.
        if d == 0 and db.query("SELECT count(*) AS n FROM claims WHERE subj = ? OR obj = ?", [id, id])[0]["n"] < 10:
            # a pair the analyst rejected is not redrawn as a same-article hypothesis
            gone = {o for (sj, _, ob), v in verdicts.items() if v["verdict"] == "reject" for o in (sj, ob) if o != id and id in (sj, ob)}
            for r in db.query("""SELECT b.entity_id AS other, count(*) AS n FROM mentions a JOIN mentions b
                                   ON a.ref_type = b.ref_type AND a.ref_id = b.ref_id AND b.entity_id <> a.entity_id
                                 WHERE a.entity_id = ? GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 200""", [id]):   # id breaks ties: same graph every time
                if (id, "mentioned-with", r["other"]) in seen_triples or r["other"] in gone:
                    continue
                edges.append({"id": f"mentioned-with:{id}|{r['other']}", "subj": id, "predicate": "mentioned-with", "obj": r["other"],
                              "origin": "co-mention", "hypothesis": True, "confidence": None, "sources": [], "count": r["n"]})
                nxt.add(r["other"])
        nodes |= nxt
        frontier = nxt
        if len(nodes) > limit:
            break
    info = {r["id"]: r for r in db.query("SELECT id, type, name, attrs FROM entities WHERE id IN (SELECT unnest(?))", [list(nodes)])}
    # collapse large IP sets by ASN: per (other end, predicate) with many IP neighbours
    groups: dict[tuple, list] = defaultdict(list)
    for i, e in enumerate(edges):
        for a, b in ((e["subj"], e["obj"]), (e["obj"], e["subj"])):
            if a.startswith("ip:") and not b.startswith("ip:"):
                groups[(b, e["predicate"])].append((i, a))
    drop_edges, drop_nodes, extra_nodes, extra_edges = set(), set(), {}, []
    for (other, pred), items in groups.items():
        if len(items) <= collapse_over:
            continue
        by_asn = defaultdict(list)
        for i, ipn in items:
            a = _j((info.get(ipn) or {}).get("attrs")) or {}
            by_asn[a.get("asn") or "unknown"].append((i, ipn))
        for asn, its in by_asn.items():
            gid = f"group:{asn}:{other}:{pred}"
            extra_nodes[gid] = {"id": gid, "type": "ip-group", "name": f"{len(its)} IPs in {asn}", "count": len(its),
                                "asn": asn, "members": [x for _, x in its[:50]]}
            e0 = edges[its[0][0]]
            extra_edges.append({"id": f"edge:{gid}", "source": gid if e0["subj"].startswith("ip:") else other,
                                "target": other if e0["subj"].startswith("ip:") else gid, "predicate": pred,
                                # best member confidence; null when no member has one (co-mentions), so the group
                                # passes a confidence floor exactly as its members would
                                "origin": e0["origin"], "hypothesis": bool(e0.get("hypothesis")), "confidence": max((edges[i]["confidence"] for i, _ in its
                                                                           if edges[i]["confidence"] is not None), default=None),
                                "count": len(its)})
            for i, ipn in its:
                drop_edges.add(i)
                drop_nodes.add(ipn)
    # cap the node list: the root always, then nodes in the order their edges were found (hop by hop, best
    # confidence first). Edges are trimmed to the kept nodes below, so every edge's two ends are in `nodes`.
    rank = {id: 0}
    for e in edges:
        for x in (e["subj"], e["obj"]):
            rank.setdefault(x, len(rank))
    ranked = []
    for n in nodes:
        if n in drop_nodes and n != id:
            continue
        r = info.get(n) or {"id": n, "type": n.split(":", 1)[0], "name": n.split(":", 1)[1] if ":" in n else n}
        ranked.append((rank.get(n, len(rank)), n, {"id": n, "type": r["type"], "name": r["name"], "root": n == id}))
    # an ASN bubble stands where its first member IP was found, and counts against the cap like any node
    for gid, g in extra_nodes.items():
        ranked.append((min(rank.get(x, len(rank)) for x in g["members"]), gid, g))
    out_nodes = [x for _, _, x in sorted(ranked, key=lambda t: (t[0], t[1]))][:max(limit, 1)]
    out_edges = [{"id": e["id"], "source": e["subj"], "target": e["obj"], "predicate": e["predicate"], "origin": e["origin"],
                  "hypothesis": bool(e.get("hypothesis")), **({"verdict": e["verdict"]} if e.get("verdict") else {}),
                  "confidence": e["confidence"],
                  "band": "hypothesis" if e.get("hypothesis") and e["confidence"] is not None
                  else band(e["confidence"]) if e["confidence"] is not None else None,
                  "sources": e.get("sources") or [], **({"count": e["count"]} if e.get("count") else {}),
                  **({"first_seen": _iso(e.get("first_seen")), "last_seen": _iso(e.get("last_seen"))} if e.get("first_seen") or e.get("last_seen") else {})}
                 for i, e in enumerate(edges) if i not in drop_edges]
    out_edges += extra_edges
    spec = scoring.specificity([n["id"] for n in out_nodes if not n["id"].startswith("group:")])
    for e in out_edges:
        # the weight of the less specific end: a link through a commodity tool or a CDN address is weak evidence
        vals = [spec[x] for x in (e["source"], e["target"]) if x in spec and x.split(":", 1)[0] not in ("actor", "campaign")]
        e["specificity"] = min(vals) if vals else None
    keep = {n["id"] for n in out_nodes}
    out_edges = [e for e in out_edges if e["source"] in keep and e["target"] in keep]
    # an ASN bubble whose other end was capped away has nothing left to hang on
    linked = {x for e in out_edges for x in (e["source"], e["target"])}
    out_nodes = [n for n in out_nodes if n["type"] != "ip-group" or n["id"] in linked]
    return {"root": id, "nodes": out_nodes, "edges": out_edges}


# ---------------------------------------------------------------- metro-map timeline
@router.get("/timeline")
def timeline(ids: str | None = None, type: str = "campaign", limit: int = Query(12, ge=0, le=50),
             station_types: str = "malware,tool,domain,ip,url,hash,cve,technique"):
    lanes_ids = list(dict.fromkeys(overrides.resolve(i) for i in _csv(ids)))
    if not lanes_ids:
        lanes_ids = [r["id"] for r in db.query("""
            SELECT e.id FROM entities e JOIN (SELECT x, count(*) n FROM (SELECT subj x FROM claims WHERE origin <> 'inferred'
                 UNION ALL SELECT entity_id FROM mentions WHERE ref_type <> 'reference') GROUP BY 1) c ON c.x = e.id
            WHERE e.type IN (SELECT unnest(?)) ORDER BY c.n DESC LIMIT ?""", [_csv(type), limit])]
    st = _csv(station_types)
    lanes = []
    station_lanes: dict[str, list] = defaultdict(list)
    for lid in lanes_ids:
        info = db.query("SELECT id, type, name, first_seen, last_seen FROM entities WHERE id = ?", [lid])
        if not info:
            continue
        stations = db.query("""
            SELECT x AS id, min(ts) AS ts, any_value(how) AS how FROM (
              SELECT obj AS x, coalesce(first_seen, last_seen) AS ts, 'claim' AS how FROM claims
                WHERE subj = ? AND origin IN ('observed','reported','user')
              UNION ALL SELECT subj, coalesce(first_seen, last_seen), 'claim' FROM claims
                WHERE obj = ? AND origin IN ('observed','reported','user')
              UNION ALL SELECT b.entity_id, b.ts, 'mention' FROM mentions a JOIN mentions b
                ON a.ref_type = b.ref_type AND a.ref_id = b.ref_id AND b.entity_id <> a.entity_id
                WHERE a.entity_id = ? AND a.ref_type <> 'event')
            WHERE split_part(x, ':', 1) IN (SELECT unnest(?)) GROUP BY 1 ORDER BY ts NULLS LAST LIMIT 200""", [lid, lid, lid, st])
        names = {r["id"]: r["name"] for r in db.query("SELECT id, name FROM entities WHERE id IN (SELECT unnest(?))",
                                                      [[s["id"] for s in stations]])}
        for s in stations:
            s["name"] = names.get(s["id"], s["id"].split(":", 1)[1])
            s["type"] = s["id"].split(":", 1)[0]
            station_lanes[s["id"]].append(lid)
        ts = [s["ts"] for s in stations if s["ts"]]
        lane = _clean(info)[0]
        lane["start"] = min(ts).isoformat() if ts else lane.get("first_seen")
        lane["end"] = max(ts).isoformat() if ts else lane.get("last_seen")
        lane["stations"] = _clean(stations)
        lanes.append(lane)
    shared = [{"id": s, "lanes": ls, "type": s.split(":", 1)[0]} for s, ls in station_lanes.items() if len(set(ls)) > 1]
    names = {r["id"]: r["name"] for r in db.query("SELECT id, name FROM entities WHERE id IN (SELECT unnest(?))", [[s["id"] for s in shared]])} if shared else {}
    for s in shared:
        s["name"] = names.get(s["id"], s["id"])
        s["lanes"] = sorted(set(s["lanes"]))
    spec = scoring.specificity(list(station_lanes))
    for s_ in shared:
        s_["specificity"] = spec.get(s_["id"])
    for lane in lanes:
        sh = {s["id"] for s in shared}
        lane["stations"] = [dict(s, shared=s["id"] in sh, specificity=spec.get(s["id"])) for s in lane["stations"]]
    shared.sort(key=lambda s: -len(s["lanes"]))
    return {"lanes": lanes, "shared": shared}


# ---------------------------------------------------------------- UI helpers (Entities tab)
@router.get("/activity")
def activity(ids: str = "", weeks: int = Query(26, ge=4, le=104)):
    """Per-entity weekly mention counts (oldest first, ending this week) and claim confidence, for directory rows.
    No ids (an empty page) is an empty result, not an error."""
    asked = _csv(ids)[:300]
    if not asked:
        return {"weeks": weeks, "items": {}}
    idl = list(dict.fromkeys(overrides.resolve(i) for i in asked))   # merged ids answer for the entity they joined
    out = {i: {"spark": [0] * weeks, "confidence": None, "origins": {}} for i in idl}
    for r in db.query(f"""SELECT entity_id, (date_diff('week', date_trunc('week', ts), date_trunc('week', now())))::INT AS w, count(*) AS n
                          FROM mentions WHERE entity_id IN (SELECT unnest(?)) AND ts > now() - INTERVAL ({weeks * 7}) DAY
                          GROUP BY ALL""", [idl]):
        if 0 <= r["w"] < weeks:
            out[r["entity_id"]]["spark"][weeks - 1 - r["w"]] = r["n"]
    # verdicts are not claims, and rejected links don't count
    for r in db.query(f"""WITH k AS (SELECT c.* FROM claims c ANTI JOIN ({REJECTED_SQL}) r USING (subj, predicate, obj) WHERE c.origin <> 'user')
                           SELECT x, origin, count(*) AS n, max(confidence) AS c FROM
                           (SELECT subj AS x, origin, confidence FROM k WHERE subj IN (SELECT unnest(?))
                            UNION ALL SELECT obj, origin, confidence FROM k WHERE obj IN (SELECT unnest(?))) GROUP BY ALL""", [idl, idl]):
        o = out[r["x"]]
        o["origins"][r["origin"]] = r["n"]
        if r["c"] is not None and r["origin"] != "inferred":
            o["confidence"] = max(o["confidence"] or 0, r["c"])
    for o in out.values():
        o["band"] = band(o["confidence"]) if o["confidence"] is not None else None
    return {"weeks": weeks, "items": {**out, **{i: out[overrides.resolve(i)] for i in asked if i not in out}}}


@router.get("/techniques")
def techniques():
    """ATT&CK techniques with their tactics, for the matrix strip."""
    rows = db.query("""SELECT id, json_extract_string(attrs, '$.attack_id') AS attack_id, json_extract_string(attrs, '$.title') AS title,
                              json_extract(attrs, '$.tactics') AS tactics FROM entities WHERE type = 'technique'""")
    return {"items": [{"id": r["id"], "attack_id": r["attack_id"], "title": r["title"], "tactics": _j(r["tactics"]) or []} for r in rows]}


# ---------------------------------------------------------------- feedback
# "Disagree…" is a reject with a reason (okf/data/entities.md#disagree); each still hides the link like any reject.
DISAGREE_REASONS = ("wrong-link", "wrong-type", "outdated", "other")


@router.post("/claims/{cid}/feedback")
def feedback(cid: str, body: dict):
    """Record a verdict on a claim's triple ('confirm' or 'reject'), or withdraw it ('clear', the Undo).
    The verdict is kept as an origin "user" row on the same triple whose evidence is the verdict history,
    latest last; it annotates the triple's claims and is never counted as a claim itself."""
    verdict = (body or {}).get("verdict")
    if verdict not in ("confirm", "reject", "clear"):
        raise HTTPException(400, "verdict must be 'confirm', 'reject' or 'clear'")
    reason = str((body or {}).get("reason") or "")
    if reason and (verdict != "reject" or reason not in DISAGREE_REASONS):
        raise HTTPException(400, f"reason goes with a reject and must be one of {', '.join(DISAGREE_REASONS)}")
    rows = db.query("SELECT * FROM claims WHERE id = ?", [cid])
    if not rows:
        raise HTTPException(404, "unknown claim")
    c = rows[0]
    triple = [c["subj"], c["predicate"], c["obj"]]
    now = dt.datetime.now(dt.UTC)
    note = str((body or {}).get("note") or "")[:1000]
    if verdict == "clear":
        store.execute("DELETE FROM claims WHERE origin = 'user' AND subj = ? AND predicate = ? AND obj = ?", triple)
    else:
        prior = db.query("SELECT evidence FROM claims WHERE origin = 'user' AND subj = ? AND predicate = ? AND obj = ?", triple)
        hist = [e for r in prior for e in (_j(r["evidence"]) or []) if isinstance(e, dict) and e.get("verdict")]
        hist.append({"verdict": verdict, "note": note, **({"reason": reason} if reason else {}),
                     "ts": now.isoformat(), "claim": cid, "source": "user", "ref_id": now.isoformat()})
        hist = sorted(hist, key=lambda e: str(e.get("ts") or ""))[-store.EVIDENCE_CAP:]   # latest last, newest kept
        store.upsert_claims([{"subj": c["subj"], "predicate": c["predicate"], "obj": c["obj"], "origin": "user",
                              "sources": ["user"], "first_seen": now, "last_seen": now, "evidence": hist}],
                            replace_evidence=True)
    store.execute("UPDATE claims SET confidence = NULL WHERE subj = ? AND predicate = ? AND obj = ? AND origin <> 'inferred'",
                  [c["subj"], c["predicate"], c["obj"]])
    store.mark_dirty([c["subj"], c["obj"]])
    scoring.drain_dirty()
    out = _clean(db.query("SELECT * FROM claims WHERE subj = ? AND predicate = ? AND obj = ? ORDER BY origin",
                          [c["subj"], c["predicate"], c["obj"]]))
    for r in out:
        r["band"] = band(r["confidence"])
    return {"verdict": verdict, "claims": out}


# ---------------------------------------------------------------- identity: merge, retype, duplicates
def _ov(fn, *a):
    try:
        out = fn(*a)
    except overrides.OverrideError as ex:
        raise HTTPException(ex.status, str(ex)) from ex
    scoring.drain_dirty()          # rescore the moved claims and re-infer, so counts and the graph follow at once
    return out


@router.get("/duplicates")
def duplicates(id: str | None = None, limit: int = Query(50, ge=0, le=500)):
    """Likely duplicate entities to review (same name under two types, or one lists the other's name)."""
    items = overrides.suggestions_for(overrides.resolve(id)) if id else overrides.suggestions()
    return {"total": len(items), "items": items[:limit]}


@router.post("/merge")
async def merge(body: dict):
    """"Same as…": {src, dst, note}: src joins dst (aliases, mentions, claims). Undo: POST /overrides/{id}/undo."""
    b = body or {}
    return await asyncio.to_thread(_ov, overrides.merge, str(b.get("src") or ""), str(b.get("dst") or ""), str(b.get("note") or ""))


@router.post("/retype")
async def retype(body: dict):
    """"Wrong type…": {id, type, note}: the entity becomes that type (joins a same-name entity of it when one exists)."""
    b = body or {}
    return await asyncio.to_thread(_ov, overrides.retype, str(b.get("id") or ""), str(b.get("type") or ""), str(b.get("note") or ""))


@router.post("/not-same")
async def not_same(body: dict):
    """"Not the same": {a, b}: the pair is no longer suggested as a duplicate."""
    b = body or {}
    try:
        return await asyncio.to_thread(overrides.not_same, str(b.get("a") or ""), str(b.get("b") or ""), str(b.get("note") or ""))
    except overrides.OverrideError as ex:
        raise HTTPException(ex.status, str(ex)) from ex


@router.get("/overrides")
def list_overrides(limit: int = Query(200, ge=0, le=1000)):
    return {"items": overrides.listing(limit)}


@router.get("/overrides/{oid}/undo-preview")
def undo_preview(oid: str):
    """What Undo would do with changes made since the merge: `moved_back` (how many go back to the merged entity)
    and `stays` (plain sentences for those that can't be split and stay on the kept one)."""
    try:
        return overrides.undo_preview(oid)
    except overrides.OverrideError as ex:
        raise HTTPException(ex.status, str(ex)) from ex


@router.post("/overrides/{oid}/undo")
async def undo_override(oid: str):
    return await asyncio.to_thread(_ov, overrides.undo, oid)


@router.get("/review")
def review(limit: int = Query(50, ge=0, le=500)):
    """The review queue: likely duplicates, claims you disagreed with, and contested attributions you have not
    settled yet; plus the identity changes you made (merges, retypes, "not the same"), each with Undo."""
    dups = overrides.suggestions()
    # claims you disagreed with: one per triple, latest verdict a reject
    dis = []
    for r in db.query("""SELECT id, subj, predicate, obj, evidence, last_seen FROM claims WHERE origin = 'user'
                         AND json_extract_string(evidence, '$[-1].verdict') = 'reject' ORDER BY last_seen DESC LIMIT ?""", [limit]):
        ev = (_j(r["evidence"]) or [{}])[-1]
        dis.append({"id": r["id"], "subj": r["subj"], "predicate": r["predicate"], "obj": r["obj"],
                    "reason": ev.get("reason") or "", "note": ev.get("note") or "", "ts": ev.get("ts")})
    # contested: a subject with two or more sourced attributions of one type, none of them confirmed by you,
    # where at least one is a judgement (not only reference listings)
    rows = db.query(f"""
        WITH a AS (SELECT c.id, c.subj, c.obj, c.origin, c.confidence, c.sources, c.evidence, split_part(c.obj, ':', 1) AS ot
                   FROM claims c ANTI JOIN ({REJECTED_SQL}) r USING (subj, predicate, obj)
                   WHERE c.predicate = 'attributed-to' AND c.origin IN ('observed', 'reported', 'local')),
             g AS (SELECT subj, ot FROM a GROUP BY 1, 2 HAVING count(DISTINCT obj) > 1)
        SELECT a.* FROM a JOIN g USING (subj, ot) ORDER BY a.subj, a.ot, a.confidence DESC NULLS LAST""")
    conf = {(r["subj"], r["obj"]) for r in db.query("""SELECT subj, obj FROM claims WHERE origin = 'user' AND predicate = 'attributed-to'
                                                       AND json_extract_string(evidence, '$[-1].verdict') = 'confirm'""")}
    groups: dict[tuple, list] = defaultdict(list)
    for r in rows:
        groups[(r["subj"], r["ot"])].append(r)
    contested = []
    for (subj, ot), cs in groups.items():
        if any((subj, c["obj"]) in conf for c in cs):
            continue
        best: dict[str, dict] = {}
        for c in cs:
            ev = _j(c["evidence"]) or []
            c["authoritative"] = is_authoritative(c, ev)
            q = next((x.get("quote") for x in ev if isinstance(x, dict) and x.get("quote")), None)
            if c["obj"] not in best or (c["confidence"] or 0) > (best[c["obj"]]["confidence"] or 0):
                best[c["obj"]] = {"id": c["id"], "obj": c["obj"], "confidence": c["confidence"], "band": band(c["confidence"]),
                                  "sources": list(c["sources"] or []), "authoritative": c["authoritative"], "quote": q}
        if all(c["authoritative"] for c in cs):
            continue
        contested.append({"subj": subj, "type": ot, "candidates": list(best.values())})
    contested.sort(key=lambda g: -max((c["confidence"] or 0) for c in g["candidates"]))
    ids = {x for d in dis for x in (d["subj"], d["obj"])} | {g["subj"] for g in contested} | {c["obj"] for g in contested for c in g["candidates"]}
    names = {r["id"]: r for r in db.query("SELECT id, name, type FROM entities WHERE id IN (SELECT unnest(?))", [list(ids)])} if ids else {}
    nm = lambda i: (names.get(i) or {}).get("name") or i.split(":", 1)[-1]   # noqa: E731
    for d in dis:
        d["subj_name"], d["obj_name"] = nm(d["subj"]), nm(d["obj"])
    for g in contested:
        g["subj_name"] = nm(g["subj"])
        for c in g["candidates"]:
            c["name"] = nm(c["obj"])
    return {"counts": {"duplicates": len(dups), "disagreed": len(dis), "contested": len(contested)},
            "duplicates": dups[:limit], "disagreed": dis, "contested": contested[:limit], "changes": overrides.listing(limit)}


# ---------------------------------------------------------------- detail
@router.get("/{eid:path}")
def detail(eid: str, evidence: int = Query(5, ge=0, le=25), bucket: str = "day"):
    if bucket not in ("hour", "day", "week", "month"):
        raise HTTPException(400)
    rows = db.query("SELECT * FROM entities WHERE id = ?", [eid])
    redirected = None
    if not rows and overrides.resolve(eid) != eid:
        # merged or retyped by the user: the page lives under the kept id now (old links keep working)
        redirected = eid
        rows = db.query("SELECT * FROM entities WHERE id = ?", [overrides.resolve(eid)])
        if rows:
            eid = rows[0]["id"]
    if not rows:
        alt = guess_ids(eid)
        rows = db.query("SELECT * FROM entities WHERE id IN (SELECT unnest(?)) LIMIT 1", [alt]) if alt else []
        if not rows:
            raise HTTPException(404, "unknown entity")
        eid = rows[0]["id"]
    e = _clean(rows)[0]
    if redirected:
        e["redirected_from"] = next(({"id": o["src"], "name": o["src_name"], "action": o["action"], "override": o["id"]}
                                     for o in overrides.listing(1000) if o["src"] == redirected),
                                    {"id": redirected, "name": redirected.split(":", 1)[-1]})
    # identity: what the user merged here (with Undo) and likely duplicates still to review
    e["merged_here"] = overrides.merged_into(eid) if e.get("type") in overrides.NAMED_TYPES else []
    e["possible_duplicates"] = overrides.suggestions_for(eid) if e.get("type") in overrides.SUGGEST_TYPES else []
    e["mentions"] = db.query("SELECT count(*) AS n, count(DISTINCT ref_id) AS refs FROM mentions WHERE entity_id = ?", [eid])[0]
    # per-source histogram: events by source, articles by outlet, others by ref type
    hist = db.query(f"""
        SELECT date_trunc('{bucket}', m.ts) AS t, coalesce(ev.source, {_article_source_sql()} m.ref_type) AS source, count(*) AS n
        FROM mentions m LEFT JOIN events ev ON m.ref_type = 'event' AND ev.id = m.ref_id
        {_article_join_sql()}
        WHERE m.entity_id = ? AND m.ts IS NOT NULL GROUP BY ALL ORDER BY t""", [eid])
    e["timeline"] = _clean(hist)
    e["sources"] = sorted({h["source"] for h in hist})
    claims = _clean(db.query("""SELECT c.*, CASE WHEN c.subj = ? THEN 'out' ELSE 'in' END AS direction,
                                       o.name AS other_name, o.type AS other_type
                                FROM claims c LEFT JOIN entities o ON o.id = (CASE WHEN c.subj = ? THEN c.obj ELSE c.subj END)
                                WHERE c.subj = ? OR c.obj = ? ORDER BY c.confidence DESC NULLS LAST LIMIT 1000""", [eid] * 4))
    # Claims by origin. "inferred" holds the hypotheses (links the hub computed); "user" only links an analyst
    # confirmed whose original claim is gone. A verdict on a claim is folded into that claim's row (verdict,
    # verdict_note, verdict_ts); a rejected triple leaves every list and count and is listed once in "rejected".
    grouped: dict[str, list] = {o: [] for o in ("observed", "reported", "user", "inferred", "local")}
    rejected: dict[tuple, dict] = {}
    attributions = defaultdict(set)
    observed = {(r["subj"], r["predicate"], r["obj"]) for r in claims if r["origin"] == "observed"}
    judged = {(r["subj"], r["predicate"], r["obj"]) for r in claims if r["origin"] != "user"}
    sourced = {(r["subj"], r["predicate"], r["obj"]) for r in claims if r["origin"] in ("observed", "reported", "local")}
    verdicts = verdicts_for([eid])
    for c in claims:
        k = (c["subj"], c["predicate"], c["obj"])
        if c["origin"] == "user" and k in judged:
            continue                              # the verdict is shown on the claim it judges, not as a second link
        v = verdicts.get(k)
        c["verdict"] = v["verdict"] if v else None
        if v:
            c["verdict_note"], c["verdict_ts"], c["verdict_reason"] = v["note"], v["ts"], v.get("reason") or ""
        c["other"] = c["obj"] if c["direction"] == "out" else c["subj"]
        c["hypothesis"] = c["origin"] == "inferred" and c["verdict"] != "confirm"
        c["band"] = "hypothesis" if c["hypothesis"] else band(c["confidence"])
        ev_all = c.get("evidence") if isinstance(c.get("evidence"), list) else []
        c["authoritative"] = is_authoritative(c, ev_all)
        # MITRE's catalogue (or a MISP galaxy) states this link, even if articles report it too: the UI keeps such a
        # link "confirmed" and never gives it an article label (web/js/core/ttp.js ttpLinkKind)
        c["catalogue"] = any(isinstance(x, dict) and x.get("ref_type") == "reference" for x in ev_all)
        # how many articles report it, over all of its evidence (the returned evidence is cut to `evidence` items)
        c["article_count"] = len({x.get("ref_id") for x in ev_all if isinstance(x, dict) and x.get("ref_type") == "article"})
        if c["origin"] in ("observed", "reported", "local"):
            _, _, c["why"] = scoring.assess(ev_all, c.get("sources") or [],
                                            c["origin"] != "observed" and k in observed)
        elif c["origin"] == "inferred":
            c["why"] = hypothesis_why(ev_all[0] if ev_all else {})
        else:
            c["why"] = "only you have confirmed this link; the claim you judged is no longer held"
        ev = c.get("evidence") or []
        c["evidence_count"] = len(ev) if isinstance(ev, list) else 1
        c["suggested"] = scoring.is_suggested(ev) if isinstance(ev, list) else False
        c["evidence"] = ev[:evidence] if isinstance(ev, list) else ev
        if c["verdict"] == "reject":
            if k not in rejected or ORIGIN_RANK.get(c["origin"], 9) < ORIGIN_RANK.get(rejected[k]["origin"], 9):
                rejected[k] = c
            continue
        if c["predicate"] == "attributed-to" and c["direction"] == "out" and c["origin"] not in ("user", "inferred"):
            attributions[c["other"].split(":", 1)[0]].add(c["other"])
        # a hypothesis the analyst confirmed is the analyst's link: it counts under "user", not as a hypothesis,
        # and only once: when a source also states the triple, that claim's row (also marked confirmed) stands for it
        if c["origin"] == "inferred" and c["verdict"] == "confirm" and k in sourced:
            continue
        grouped.setdefault("user" if c["origin"] == "inferred" and c["verdict"] == "confirm" else c["origin"], []).append(c)
    for o in grouped.values():
        for c in o:
            if c["predicate"] == "attributed-to" and c["direction"] == "out" and c["origin"] not in ("user", "inferred"):
                c["conflict"] = len(attributions[c["other"].split(":", 1)[0]]) > 1
    e["claims"] = grouped
    e["claim_counts"] = {k: len(v) for k, v in grouped.items()}
    e["rejected"] = list(rejected.values())
    e["conflicting_attribution"] = any(len(v) > 1 for v in attributions.values())
    # Related: entities a counted claim links to (one per triple, no verdict rows, no rejected links).
    e["related"] = db.query(f"""
        WITH t AS (SELECT DISTINCT c.subj, c.predicate, c.obj FROM claims c ANTI JOIN ({REJECTED_SQL}) r USING (subj, predicate, obj)
                   WHERE (c.subj = ? OR c.obj = ?) AND c.origin <> 'inferred'),
             cl AS (SELECT CASE WHEN subj = ? THEN obj ELSE subj END AS id, count(*) AS n FROM t GROUP BY 1)
        SELECT cl.id, 'claim' AS how, cl.n, e.type, e.name FROM cl LEFT JOIN entities e ON e.id = cl.id
        WHERE cl.id <> ? ORDER BY cl.n DESC, cl.id LIMIT 60""", [eid] * 4)
    # Hypotheses: entities named in the same texts, and links the hub inferred. Shown only on request.
    have = {r["id"] for r in e["related"]}
    hyp = db.query(f"""
        WITH co AS (SELECT b.entity_id AS id, count(*) AS n FROM mentions a JOIN mentions b
                      ON a.ref_type = b.ref_type AND a.ref_id = b.ref_id AND b.entity_id <> a.entity_id
                    WHERE a.entity_id = ? AND a.ref_type <> 'event' GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 40),
             inf AS (SELECT CASE WHEN c.subj = ? THEN c.obj ELSE c.subj END AS id, count(*) AS n
                     FROM claims c ANTI JOIN ({REJECTED_SQL}) r USING (subj, predicate, obj)
                     WHERE (c.subj = ? OR c.obj = ?) AND c.origin = 'inferred' GROUP BY 1)
        SELECT r.id, CASE WHEN bool_or(r.how = 'inferred') THEN 'inferred' ELSE 'mentioned-with' END AS how, sum(r.n) AS n,
               any_value(e.type) AS type, any_value(e.name) AS name
        FROM (SELECT id, n, 'mentioned-with' AS how FROM co UNION ALL SELECT id, n, 'inferred' FROM inf) r
        LEFT JOIN entities e ON e.id = r.id GROUP BY r.id ORDER BY n DESC, r.id LIMIT 60""", [eid] * 4)
    gone = {c["other"] for c in e["rejected"]}          # a pair the analyst rejected never comes back as a hypothesis
    e["related_hypotheses"] = [r for r in hyp if r["id"] not in have and r["id"] not in gone]
    e["refs"] = _clean(db.query("""
        SELECT m.ref_type, m.ref_id, m.role, m.method, m.confidence, m.ts, ev.title AS title, ev.source AS source, ev.url AS url
        FROM mentions m LEFT JOIN events ev ON m.ref_type = 'event' AND ev.id = m.ref_id
        WHERE m.entity_id = ? ORDER BY m.ts DESC NULLS LAST LIMIT 30""", [eid]))
    _article_titles(e["refs"])
    if e.get("type") == "cve":
        _cve_live_attrs(e)
        _kev_facts(e)
    if e.get("type") in ("ip", "prefix"):
        e["owner"] = _owner(e)
    # threat lists holding this indicator now or before (Feodo, ThreatFox, URLhaus, SSLBL, DROP ...)
    e["listed_by"] = []
    if e.get("type") in ("ip", "domain", "url", "hash"):
        try:
            from ..netlog import intervals
            val = e.get("name") or eid.split(":", 1)[-1]
            e["listed_by"] = _clean(intervals.listed([(e["type"], val)]).get((e["type"], val), []))
        except Exception as ex:  # noqa: BLE001  (no netlog tables yet: the page works without it)
            log.debug("listed_by lookup failed for %s: %s", eid, ex)
    return e


def _cve_live_attrs(e: dict) -> None:
    """Live CVE facts on a CVE entity, read at request time so they are never stale: the latest EPSS
    (attrs.epss, epss_percentile, epss_date, epss_since, epss_prev) and the CISA advisories covering it
    (attrs.advisories, plus attrs.cvss from an advisory when NVD gave none)."""
    try:
        from ..news.api import cve_enrichment
        c = (cve_enrichment([e.get("name") or e["id"].split(":", 1)[-1]]) or [None])[0]
    except Exception:
        return
    if not c:
        return
    a = e.get("attrs") if isinstance(e.get("attrs"), dict) else {}
    if c["epss_status"] == "ok":
        a.update(epss=c["epss"], epss_percentile=c["epss_percentile"], epss_date=c["epss_date"],
                 epss_since=c["epss_since"], epss_prev=c["epss_prev"])
    a["epss_status"] = c["epss_status"]
    if c["advisories"]:
        a["advisories"] = c["advisories"]
    if a.get("cvss") is None and c["cvss"] is not None:
        a["cvss"] = c["cvss"]
        a["cvss_source"] = "NVD" if c["cvss_status"] == "ok" else c["cvss_status"]
    e["attrs"] = a


# ---------------------------------------------------------------- assessment fields (drawer and entity page)
def _owner(e: dict) -> dict | None:
    """Who runs an address: ASN, AS organisation and country, from the entity's attributes, else the offline DB-IP
    lite databases (no network)."""
    a = e.get("attrs") if isinstance(e.get("attrs"), dict) else {}
    ip = (e.get("name") or e["id"].split(":", 1)[-1]).split("/")[0]
    asn, org, cc = a.get("asn"), a.get("as_name"), a.get("country") or a.get("cc")
    try:
        from .. import geo
        if not org or not asn:
            r = geo.asn_for_ip(ip)
            if r:
                asn, org = asn or r[0], org or r[1]
        if not cc:
            cc = (geo.locate_ip(ip) or {}).get("country")
    except Exception:  # noqa: BLE001  (no geo databases: owner stays partial)
        pass
    if not (asn or org or cc):
        return None
    return {"asn": asn, "name": org or None, "country": cc}


_KEV_FILES: dict = {}


def _kev_record(cve: str) -> dict | None:
    """The CISA KEV catalogue record for a CVE (due date, required action, notes), read from the raw record file
    that listed it (indicator_intervals.start_path, resolved under this lake's raw/ folder). None when the record
    file is not on disk."""
    try:
        rows = db.query("""SELECT start_path FROM indicator_intervals WHERE source = 'cisa_kev' AND kind = 'cve'
                           AND value = ? ORDER BY "start" DESC LIMIT 1""", [cve.upper()])
    except Exception:  # noqa: BLE001  (no netlog tables)
        return None
    if not rows or not rows[0]["start_path"]:
        return None
    import gzip
    from pathlib import Path
    from .. import config
    sp = str(rows[0]["start_path"])
    if "/raw/" not in sp:
        return None
    path = Path(config.RAW_DIR) / sp.split("/raw/", 1)[1]   # always inside this lake, wherever it was recorded
    if not path.is_file():
        return None
    key = (str(path), path.stat().st_mtime)
    recs = _KEV_FILES.get(key)
    if recs is None:
        recs = {}
        try:
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                for line in fh:
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    if r.get("op") == "put" and isinstance(r.get("data"), dict):
                        recs[str(r.get("key") or "").upper()] = r["data"]
        except OSError:
            return None
        if len(_KEV_FILES) > 8:
            _KEV_FILES.clear()
        _KEV_FILES[key] = recs
    return recs.get(cve.upper())


_URL_RE = re.compile(r"https?://[^\s;,]+")


def _kev_facts(e: dict) -> None:
    """KEV due date, required action, vendor/product and advisory links on a CVE entity (attrs.kev_due,
    kev_action, kev_vendor, kev_product, kev_links), when the catalogue record is in the lake."""
    a = e.get("attrs") if isinstance(e.get("attrs"), dict) else {}
    cve = (e.get("name") or e["id"].split(":", 1)[-1]).upper()
    if not a.get("kev_vendor"):
        ev = db.query("""SELECT tags FROM events WHERE source = 'cisa_kev' AND kind = 'kev'
                         AND upper(split_part(title, ' ', 1)) = ? ORDER BY ts DESC LIMIT 1""", [cve])
        tags = [t for t in ((ev[0]["tags"] if ev else None) or []) if t != "ransomware"]
        if tags:
            a["kev_vendor"] = tags[0]
            if len(tags) > 1:
                a["kev_product"] = tags[1]
    rec = _kev_record(cve)
    if rec:
        a["kev_due"] = rec.get("dueDate") or None
        a["kev_action"] = rec.get("requiredAction") or None
        a.setdefault("kev_added", rec.get("dateAdded"))
        a["kev_vendor"] = rec.get("vendorProject") or a.get("kev_vendor")
        a["kev_product"] = rec.get("product") or a.get("kev_product")
        links = [u.rstrip(").") for u in _URL_RE.findall(str(rec.get("notes") or ""))]
        a["kev_links"] = list(dict.fromkeys(links))[:8]
    e["attrs"] = a


def _has_articles() -> bool:
    try:
        return db.has_table("articles")
    except Exception:
        return False


def _article_source_sql() -> str:
    return "ar.source," if _has_articles() else ""


def _article_join_sql() -> str:
    return "LEFT JOIN articles ar ON m.ref_type = 'article' AND ar.id = m.ref_id" if _has_articles() else ""


def _article_titles(refs):
    ids = [r["ref_id"] for r in refs if r["ref_type"] == "article"]
    if not ids or not _has_articles():
        return
    info = {r["id"]: r for r in db.query("SELECT id, title, source, url FROM articles WHERE id IN (SELECT unnest(?))", [ids])}
    for r in refs:
        a = info.get(r["ref_id"]) if r["ref_type"] == "article" else None
        if a:
            r.update(title=a["title"], source=a["source"], url=a["url"])
