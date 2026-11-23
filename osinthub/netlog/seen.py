""""Seen on your network": one batched lookup of indicator values against the imported logs and the alerts.

    GET  /api/netlog/seen?v=203.0.113.7,198.51.100.0/24,evil.example,CVE-2024-3400
    POST /api/netlog/seen   {"values": [...]}            (same answer; for long lists)

Each value (an IP, a CIDR, a domain, a file or certificate hash, or a CVE; entity ids such as "ip:..." and defanged
text such as "evil[.]example" are accepted) is classified, normalised and looked up:

* IP: rows where it is either end of a connection or a DNS answer. CIDR: the same for every logged address inside
  it (an integer range join over netlog_ipnum). Domain: DNS queries, TLS server names and HTTP hosts equal to it
  or under it. Hash: files.log / x509 / ssl / EVE hashes (the matcher's HASH_EXPR). CVE: Zeek notice, weird and
  software rows and IDS alerts that name it.
* Devices: the home end of each row, resolved to the device that held that address then (netlog_ipdev, as of
  the row's time), named the way the Devices page names it.
* Alerts and the open incident: alerts whose indicator is the value, or whose observed value is (an address inside
  a listed range, a sub-domain). With the incidents module (alerts lane) the incident and its state come from
  there (open = new or acknowledged and not info; dismissed, "expected" and info-only history are not open);
  without it each alert is its own incident. A value with an alert is always "seen", even if its log rows are gone.
* Demo data (files with origin "demo"): ignored unless the demo is loaded; then rows and alerts that come only
  from demo files are reported with demo=true, and real data always wins when both exist.

Answer: {"items": [{value, kind, seen, first, last, rows, devices: [{id, name}], n_devices, log_types, alerts,
incident: {id, severity, state, title, open: n} | null, demo, demo_also}], "logs": {rows, first, last},
"demo_loaded", "ms"}. Values it cannot classify come back with kind "unknown" and seen false. With context=true
each item also has listed_by (threat lists, as on an entity) and owner ({asn, name, country} for an address), for
values that have no entity page.

Docs: okf/architecture/web-client.md#seen-on-your-network
"""
from __future__ import annotations

import re
import time

from fastapi import APIRouter, Body, HTTPException, Query

from .. import db
from . import ipnum, util

router = APIRouter(tags=["netlog"])   # mounted under /api/netlog by ext.py
MAX_VALUES = 500
DEMO_FILES = "(SELECT id FROM netlog_files WHERE origin = 'demo' OR name LIKE 'night-desk-demo%')"
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
_HASH = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")


# ------------------------------------------------------------------ classify
def classify(raw: str) -> tuple[str, str]:
    """(kind, normalised value): ip | cidr | domain | hash | cve | unknown."""
    v = str(raw or "").strip().strip("'\"<>").replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    if ":" in v and v.split(":", 1)[0] in ("ip", "prefix", "domain", "hash", "cve"):
        v = v.split(":", 1)[1]
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$", v) or re.match(r"^\[([0-9a-fA-F:.]+)\]:\d{1,5}$", v)
    if m:                                          # "203.0.113.7:443", "[2001:db8::1]:443": the address
        v = m.group(1)
    if re.match(r"^https?://", v, re.I):           # a URL stands for its host
        v = re.sub(r"^https?://", "", v, flags=re.I).split("/", 1)[0].split("@")[-1]
        if v.startswith("[") and "]" in v:
            v = v[1:v.index("]")]
        elif v.count(":") == 1:
            v = v.split(":", 1)[0]
    if _CVE.match(v):
        return "cve", v.upper()
    if "/" in v:
        r = ipnum.net_range(v)
        if r:
            lo, hi, norm = r
            return ("ip", ipnum.canonical(norm.split("/")[0])) if lo == hi else ("cidr", norm)
        return "unknown", v
    if ipnum.is_ip(v):
        return "ip", ipnum.canonical(v)
    h = v.lower().replace(":", "")
    if _HASH.match(h):
        return "hash", h
    d = v.lower().rstrip(".")
    if _DOMAIN.match(d):
        return "domain", d
    return "unknown", v


# ------------------------------------------------------------------ the scans
# Each scan is a SQL fragment giving hit rows (qv, rk, ts, file_id, log_type, home, obs): home is the address on
# the user's side of the row, obs the looked-up address itself (IP scans only: a home address is its own device).
# The fragments run together in one summarising query, so no row leaves DuckDB.
def _ip_scan(q: list[tuple[str, int, int]]) -> tuple[str | None, list, dict[str, set]]:
    """IPs and CIDRs: the logged addresses each covers (integer range join), then rows where one is either end of a
    connection or a DNS answer."""
    ipm = db.query("""WITH q AS (SELECT kv[1] AS qv, kv[2]::UHUGEINT AS lo, kv[3]::UHUGEINT AS hi
                                 FROM (SELECT unnest(?::VARCHAR[][]) AS kv))
                      SELECT q.qv, i.ip FROM q JOIN netlog_ipnum i ON i.n BETWEEN q.lo AND q.hi""",
                   [[[v, str(lo), str(hi)] for v, lo, hi in q]])
    cover: dict[str, set] = {}
    for r in ipm:
        cover.setdefault(r["qv"], set()).add(r["ip"])
    # a single address is also matched as written: netlog_ipnum leaves out special addresses (multicast, broadcast)
    for v, lo, hi in q:
        if lo == hi:
            cover.setdefault(v, set()).add(v)
    if not cover:
        return None, [], cover
    pairs = sorted([qv, ip] for qv, ips in cover.items() for ip in ips)
    m = "(SELECT kv[1] AS qv, kv[2] AS ip FROM (SELECT unnest(?::VARCHAR[][]) AS kv))"
    sql = f"""
        SELECT m.qv, n.rk, n.ts, n.file_id, n.log_type, n.orig_h AS home, m.ip AS obs FROM netlog n JOIN {m} m ON n.resp_h = m.ip
        WHERE n.ts IS NOT NULL
        UNION ALL
        SELECT m.qv, n.rk, n.ts, n.file_id, n.log_type, n.resp_h, m.ip FROM netlog n JOIN {m} m ON n.orig_h = m.ip
        WHERE n.ts IS NOT NULL AND n.resp_h IS DISTINCT FROM n.orig_h
        UNION ALL
        SELECT m.qv, x.rk, x.ts, x.file_id, x.log_type, x.orig_h, m.ip
        FROM (SELECT rk, ts, file_id, log_type, orig_h, unnest(answers) AS a FROM netlog
              WHERE answers IS NOT NULL AND ts IS NOT NULL AND list_has_any(answers, ?::VARCHAR[])) x
        JOIN {m} m ON x.a = m.ip"""
    return sql, [pairs, pairs, sorted({p[1] for p in pairs}), pairs], cover


def _domain_scan(q: list[str]) -> tuple[str | None, list, dict[str, set]]:
    """Domains: DNS queries, TLS SNI and HTTP Host equal to the domain or under it."""
    names = db.query("""WITH q AS (SELECT unnest(?::VARCHAR[]) AS qv),
                        nm AS (SELECT DISTINCT unnest(list_filter([query, server_name, host], lambda x: x IS NOT NULL)) AS name
                               FROM netlog WHERE query IS NOT NULL OR server_name IS NOT NULL OR host IS NOT NULL)
                        SELECT q.qv, nm.name FROM q JOIN nm
                          ON lower(nm.name) = q.qv OR ends_with(lower(nm.name), '.' || q.qv)""", [q])
    cover: dict[str, set] = {}
    for r in names:
        cover.setdefault(r["qv"], set()).add(r["name"])
    if not names:
        return None, [], cover
    sql = """
        SELECT m.qv, x.rk, x.ts, x.file_id, x.log_type, x.orig_h, NULL
        FROM (SELECT rk, ts, file_id, log_type, orig_h,
                     unnest(list_distinct(list_filter([query, server_name, host], lambda x: x IS NOT NULL))) AS nm
              FROM netlog WHERE (query IS NOT NULL OR server_name IS NOT NULL OR host IS NOT NULL) AND ts IS NOT NULL) x
        JOIN (SELECT kv[1] AS qv, kv[2] AS name FROM (SELECT unnest(?::VARCHAR[][]) AS kv)) m ON m.name = x.nm"""
    return sql, [[[r["qv"], r["name"]] for r in names]], cover


def _hash_scan(q: list[str]) -> tuple[str, list]:
    """File and certificate hashes, read the way the matcher reads them (either end may be home)."""
    from .matcher import HASH_EXPR, HASH_LOGS
    expr = HASH_EXPR.replace("{{", "{").replace("}}", "}")
    x = f"""(SELECT rk, ts, file_id, log_type, orig_h, resp_h, unnest({expr}) AS hh
              FROM (SELECT *, raw AS hraw FROM netlog WHERE log_type IN {HASH_LOGS} AND ts IS NOT NULL))"""
    sql = f"""
        SELECT x.hh, x.rk, x.ts, x.file_id, x.log_type, unnest([x.orig_h, x.resp_h]), NULL
        FROM {x} x WHERE x.hh IN (SELECT unnest(?::VARCHAR[]))"""
    return sql, [q]


def _cve_scan(q: list[str]) -> tuple[str, list]:
    """CVEs named in Zeek notice / weird / software rows and IDS alerts. The host the row is about is its
    originator (a notice's src, a software row's host, an EVE alert's src_ip)."""
    sql = """
        SELECT x.cve, x.rk, x.ts, x.file_id, x.log_type, x.orig_h, NULL
        FROM (SELECT rk, ts, file_id, log_type, orig_h,
                     unnest(list_distinct(regexp_extract_all(upper(raw), 'CVE-\\d{4}-\\d{4,7}'))) AS cve
              FROM netlog WHERE log_type IN ('notice', 'weird', 'software', 'eve_alert') AND ts IS NOT NULL
                AND raw ILIKE '%cve-%') x
        WHERE x.cve IN (SELECT unnest(?::VARCHAR[]))"""
    return sql, [q]


def _summarise(frags: list[tuple[str, list]]) -> dict[tuple[str, bool], dict]:
    """Per (query value, demo): rows, first, last, log types and the devices on the home end (the device that held
    that address at the row's time)."""
    if not frags:
        return {}
    union = "\n        UNION ALL\n".join(f"SELECT * FROM ({s})" for s, _ in frags)
    params = [p for _, ps in frags for p in ps]
    res = db.cursor().execute(f"""
        WITH h AS (SELECT * FROM ({union}) AS t(qv, rk, ts, file_id, log_type, home, obs)),
        d AS (SELECT h.*, h.file_id IN {DEMO_FILES} AS demo FROM h),
        -- a looked-up address that is itself a home device names that device, not the far end (the gateway)
        v0 AS (SELECT d.*, p.device AS self_dev FROM d ASOF LEFT JOIN netlog_ipdev p ON p.ip = d.obs AND d.ts >= p.from_ts),
        v1 AS (SELECT v0.*, p.device AS home_dev FROM v0 ASOF LEFT JOIN netlog_ipdev p ON p.ip = v0.home AND v0.ts >= p.from_ts),
        v AS (SELECT *, coalesce(self_dev, home_dev) AS device FROM v1)
        SELECT qv, demo, count(DISTINCT rk) AS rows, min(ts) AS first, max(ts) AS last,
               list(DISTINCT log_type) AS log_types, list(DISTINCT device) FILTER (WHERE device IS NOT NULL) AS devices
        FROM v GROUP BY qv, demo""", params).fetchall()
    return {(r[0], bool(r[1])): {"rows": int(r[2]), "first": r[3], "last": r[4], "log_types": sorted(r[5] or []),
                                 "devices": list(r[6] or [])} for r in res}


# ------------------------------------------------------------------ alerts and incidents
def _cols(table: str) -> set[str]:
    return {r["column_name"] for r in db.query(
        "SELECT column_name FROM information_schema.columns WHERE table_name = ?", [table])}


def _alerts(keys: dict[str, set[str]]) -> dict[str, list[dict]]:
    """Alerts per query value: indicator or observed value in that value's key set."""
    allk = sorted({k for ks in keys.values() for k in ks})
    if not allk:
        return {}
    try:   # add the incident and demo columns first (incidents.py, once per database)
        from . import incidents
        incidents.ensure()
    except Exception:  # noqa: BLE001
        pass
    cols = _cols("alerts")
    if not cols:
        return {}
    has_inc, has_demo = "incident" in cols, "demo" in cols
    rows = db.query(f"""
        SELECT id, {'coalesce(incident, id)' if has_inc else 'id'} AS inc, severity, status, indicator, title, ts, last_ts,
               device, {'coalesce(demo, false)' if has_demo else 'NULL'} AS demo,
               json_extract_string(evidence, '$.indicator.observed[0]') AS observed
        FROM alerts
        WHERE indicator IN (SELECT unnest(?::VARCHAR[]))
           OR json_extract_string(evidence, '$.indicator.observed[0]') IN (SELECT unnest(?::VARCHAR[]))""", [allk, allk])
    if not rows:
        return {}
    if not has_demo:   # before the alerts lane: an alert is demo when every matched row came from a demo file
        dm = {r["alert_id"]: bool(r["demo"]) for r in db.query(f"""
            SELECT m.alert_id, bool_and(n.file_id IN {DEMO_FILES}) AS demo
            FROM netlog_matches m JOIN netlog n ON n.rk = m.rk
            WHERE m.alert_id IN (SELECT unnest(?::VARCHAR[])) GROUP BY 1""", [[r["id"] for r in rows]])}
        for r in rows:
            r["demo"] = dm.get(r["id"], False)
    _incidents(rows, has_inc)
    out: dict[str, list[dict]] = {}
    for qv, ks in keys.items():
        out[qv] = [r for r in rows if r["indicator"] in ks or (r["observed"] or "").lower() in ks or r["observed"] in ks]
    return out


def _incidents(rows: list[dict], has_inc: bool) -> None:
    """Attach each alert's incident: {id, severity, state, title, last_ts}."""
    inc: dict[str, dict] = {}
    if has_inc:
        try:
            from . import incidents
            incidents.ensure()
            ids = sorted({r["id"] for r in rows})
            for i in db.query(incidents.incidents_sql(f"WHERE id IN ({','.join('?' * len(ids))})"), ids):
                for aid in i["alerts"] or []:
                    inc[aid] = {"id": i["id"], "severity": i["severity"], "state": i["state"], "title": i["title"],
                                "last_ts": i["last_ts"]}
        except Exception:   # noqa: BLE001  (an older or newer incidents module: fall back to the alert itself)
            inc = {}
    for r in rows:
        r["incident"] = inc.get(r["id"]) or {"id": r["inc"], "severity": r["severity"], "state": r["status"] or "new",
                                             "title": r["title"], "last_ts": r["last_ts"]}


SEV = {"high": 3, "medium": 2, "low": 1, "info": 0}


# ------------------------------------------------------------------ the lookup
def demo_loaded() -> bool:
    try:
        from .demo import state
        s = state() or {}
        return s.get("status") == "loaded" or bool(s.get("loaded"))
    except Exception:  # noqa: BLE001
        return False


def logs_summary(demo: bool) -> dict:
    w = "" if demo else f"WHERE file_id NOT IN {DEMO_FILES}"
    r = db.query(f"SELECT count(*) AS rows, min(ts) AS first, max(ts) AS last FROM netlog {w}")[0]
    return util.jsonable({"rows": int(r["rows"] or 0), "first": r["first"], "last": r["last"]})


def lookup(values: list[str], context: bool = False) -> dict:
    t0 = time.perf_counter()
    if len(values) > MAX_VALUES:
        raise ValueError(f"at most {MAX_VALUES} values per lookup")
    want: dict[str, tuple[str, str]] = {}          # input value -> (kind, normalised)
    for v in values:
        if str(v or "").strip() and v not in want:
            want[v] = classify(v)
    by_kind: dict[str, list[str]] = {}
    for k, nv in want.values():
        if nv not in by_kind.setdefault(k, []):
            by_kind[k].append(nv)
    show_demo = demo_loaded()
    frags: list[tuple[str, list]] = []
    keys: dict[str, set[str]] = {nv: {nv} for k, nv in want.values() if k != "unknown"}
    ipq = []
    for k in ("ip", "cidr"):
        for v in by_kind.get(k, []):
            r = ipnum.net_range(v)
            if r:
                ipq.append((v, r[0], r[1]))
    if ipq:
        sql, ps, cover = _ip_scan(ipq)
        if sql:
            frags.append((sql, ps))
        for qv, ips in cover.items():
            keys[qv] |= ips
    if by_kind.get("domain"):
        sql, ps, cover = _domain_scan(by_kind["domain"])
        if sql:
            frags.append((sql, ps))
        for qv, ns in cover.items():
            keys[qv] |= {n.lower() for n in ns} | ns
    if by_kind.get("hash"):
        frags.append(_hash_scan(by_kind["hash"]))
    if by_kind.get("cve"):
        frags.append(_cve_scan(by_kind["cve"]))
    stats = _summarise(frags)
    alerts = _alerts(keys)
    dev_ids = sorted({d for s in stats.values() for d in s["devices"]}
                     | {a["device"] for al in alerts.values() for a in al if a.get("device")})
    names = {}
    if dev_ids:
        try:
            from .devices import display_names
            names = display_names(dev_ids)
        except Exception:  # noqa: BLE001
            names = {}

    def dev(d: str) -> dict:
        n = names.get(d) or {}
        return {"id": d, "name": n.get("name") or d.split(":", 1)[-1]}

    items = []
    for raw, (kind, nv) in want.items():
        it = {"value": raw, "normalized": nv, "kind": kind, "seen": False, "first": None, "last": None, "rows": 0,
              "devices": [], "n_devices": 0, "log_types": [], "alerts": 0, "incident": None, "demo": False,
              "demo_also": False}
        if kind != "unknown":
            real, dem = stats.get((nv, False)), stats.get((nv, True)) if show_demo else None
            al = alerts.get(nv, [])
            al_real = [a for a in al if not a["demo"]]
            al_dem = [a for a in al if a["demo"]] if show_demo else []
            if real or al_real:
                base, bal, it["demo_also"] = real, al_real, bool(dem or al_dem)
            elif dem or al_dem:
                base, bal, it["demo"] = dem, al_dem, True
            else:
                base, bal = None, []
            if base or bal:
                devs = list(dict.fromkeys([*(base["devices"] if base else []), *[a["device"] for a in bal if a.get("device")]]))
                firsts = [x for x in [base and base["first"], *[a["ts"] for a in bal]] if x]
                lasts = [x for x in [base and base["last"], *[a["last_ts"] or a["ts"] for a in bal]] if x]
                # open: untriaged or acknowledged, not dismissed or expected; info (history) is a record, not open
                opened = [a["incident"] for a in bal
                          if a["incident"]["state"] in ("new", "ack") and a["incident"]["severity"] != "info"]
                uniq = list({i["id"]: i for i in opened}.values())
                uniq.sort(key=lambda i: (-SEV.get(i["severity"], 0), -(i["last_ts"].timestamp() if i.get("last_ts") else 0)))
                top = dict(uniq[0], open=len(uniq)) if uniq else None
                if top:
                    top.pop("last_ts", None)
                it.update(seen=True, rows=base["rows"] if base else 0, first=min(firsts) if firsts else None,
                          last=max(lasts) if lasts else None, log_types=base["log_types"] if base else [],
                          devices=[dev(d) for d in devs[:6]], n_devices=len(devs),
                          alerts=len({a["incident"]["id"] for a in bal}), incident=top)
        items.append(it)
    if context:
        _context(items)
    return util.jsonable({"items": items, "logs": logs_summary(show_demo), "demo_loaded": show_demo,
                          "ms": round((time.perf_counter() - t0) * 1000, 1)})


def _context(items: list[dict]) -> None:
    """context=1: the threat lists holding each value (intervals.listed, the same rows as an entity's listed_by)
    and, for an address, its owner from the offline ASN and city databases. For values with no entity page."""
    from . import intervals
    pairs = [(it["kind"], it["normalized"]) for it in items if it["kind"] in ("ip", "domain", "hash")]
    try:
        lists = intervals.listed(pairs)
    except Exception:  # noqa: BLE001
        lists = {}
    for it in items:
        it["listed_by"] = lists.get((it["kind"], it["normalized"]), [])
        it["owner"] = None
        if it["kind"] == "ip":
            try:
                from .. import geo
                a = geo.asn_for_ip(it["normalized"]) or (None, None)
                cc = (geo.locate_ip(it["normalized"]) or {}).get("country")
                if a[0] or cc:
                    it["owner"] = {"asn": a[0], "name": a[1] or None, "country": cc}
            except Exception:  # noqa: BLE001
                pass


def _vals(v: str | list | None) -> list[str]:
    if isinstance(v, list):
        return [str(x) for x in v if str(x).strip()]
    return [x.strip() for x in (v or "").split(",") if x.strip()]


@router.get("/seen")
def seen_get(v: str = Query("", description="comma-separated IPs, CIDRs, domains, hashes, CVEs (or entity ids)"),
             context: bool = False):
    """Whether each value appeared in your network logs: first/last time, devices, alerts and the open incident.
    context=true adds listed_by (threat lists) and owner (ASN, country) per value."""
    try:
        return lookup(_vals(v), context)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/seen")
def seen_post(body: dict = Body(...)):
    vals = body.get("values")
    if not isinstance(vals, list):
        raise HTTPException(400, "values must be a list")
    try:
        return lookup(_vals(vals), bool(body.get("context")))
    except ValueError as e:
        raise HTTPException(400, str(e))
