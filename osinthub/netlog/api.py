"""/api/netlog/... endpoints. Reference: okf/architecture/api.md and okf/data/netlog.md"""
from __future__ import annotations

import datetime as dt
import json
import logging
import math
from collections import defaultdict

import re
from dataclasses import dataclass

from fastapi import APIRouter, Body, Depends, File, HTTPException, Query, Response, UploadFile

from .. import apiutil, db
from . import ipnum, util
from . import query as Q

router = APIRouter(prefix="/api/netlog", tags=["netlog"])
log = logging.getLogger("osinthub.netlog")
STATUSES = {"new", "ack", "dismissed"}
SEVERITIES = ["high", "medium", "low", "info"]
PEER_GEO_CAP = 100_000  # peers geolocated one by one in the country/ASN breakdown; the rest sum to "other"
MAX_ROWS = 100_000  # hard ceiling so limit=0 ("all") cannot pull millions of rows into one response
MAX_OFFSET = 2**63 - 1
MAX_WINDOW_HOURS = 24 * 365 * 200  # a since_hours window longer than about 200 years is all history

# Validated counts (FastAPI: a negative or oversized value is a 422 naming the field), as on the core API.
def _limit(default: int, le: int = MAX_ROWS):
    return Query(default, ge=0, le=le)


def _offset():
    return Query(0, ge=0, le=MAX_OFFSET)


def _n(limit: int) -> int:
    """A row count for SQL LIMIT: limit=0 means all rows, capped at MAX_ROWS."""
    return int(limit) if limit else MAX_ROWS


def _page(limit: int, offset: int = 0) -> str:
    """LIMIT/OFFSET clause; offset applies whatever the limit (limit=0 is all rows from offset, capped)."""
    return f"LIMIT {_n(limit)} OFFSET {max(0, int(offset))}"


_csv = apiutil.csv_list


def _ts(v: str | None) -> dt.datetime | None:
    if not v:
        return None
    try:
        if v.replace(".", "", 1).isdigit():
            return dt.datetime.fromtimestamp(float(v), util.UTC)
        t = dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=util.UTC)
    except (ValueError, OverflowError, OSError):  # unparseable, or an epoch beyond year 9999
        raise HTTPException(400, f"bad time: {v}")


def _hours(v: float | None, name: str = "since_hours") -> float | None:
    """A validated window in hours: None stays None, NaN / inf / negative is a 400, beyond ~200 years is all history."""
    if v is None:
        return None
    if not math.isfinite(v) or v < 0:
        raise HTTPException(400, f"{name} must be a finite number >= 0")
    return None if v > MAX_WINDOW_HOURS else v


def _time_where(clauses: list, params: list, since, until, since_hours, col: str = "ts") -> None:
    h = _hours(since_hours)
    if h is not None:  # whole microseconds, so fractions count (0.5 is 30 minutes) and 0 is an empty window
        clauses.append(f"{col} >= now() - to_microseconds(?)"); params.append(int(round(h * 3_600_000_000)))
    if (t := _ts(since)) is not None:
        clauses.append(f"{col} >= ?"); params.append(t)
    if (t := _ts(until)) is not None:
        clauses.append(f"{col} < ?"); params.append(t)


def _out(rows):
    return util.jsonable(rows)


# ------------------------------------------------------------------ settings
@router.get("/settings")
def get_settings():
    from . import devices
    s = util.settings()
    eff, how = devices.effective_prefixes()
    return {**s, "suggested": devices.suggest(), "effective_prefixes": eff, "effective_from": how}


@router.put("/settings")
def put_settings(body: dict = Body(...)):
    from . import devices, matcher
    s = util.settings()
    if "home_prefixes" in body:
        prefs = body["home_prefixes"] or []
        if not isinstance(prefs, list):
            raise HTTPException(400, "home_prefixes must be a list of CIDRs")
        norm = []
        for p in prefs:
            r = ipnum.net_range(str(p))
            if not r:
                raise HTTPException(400, f"not a prefix: {p}")
            norm.append(r[2])
        s["home_prefixes"] = util.unique_prefixes(norm)
    if "p2p_cap" in body:
        if not isinstance(body["p2p_cap"], bool):
            raise HTTPException(400, "p2p_cap must be true or false")
        s["p2p_cap"] = body["p2p_cap"]
    if "suricata" in body:
        t = body["suricata"] or {}
        if not isinstance(t, dict) or not isinstance(t.get("suppress", []), list) or not isinstance(t.get("severity", {}), dict):
            raise HTTPException(400, "suricata must be {suppress: [signature_id], severity: {signature_id: severity}}")
        bad = [v for v in (t.get("severity") or {}).values() if v not in SEVERITIES]
        if bad:
            raise HTTPException(400, f"severity values must be one of {SEVERITIES}")
        s["suricata"] = {"suppress": [str(x) for x in t.get("suppress") or []],
                         "severity": {str(k): v for k, v in (t.get("severity") or {}).items()}}
    for k, (lo, hi) in util.NUMERIC.items():
        if k in body and body[k] is not None:
            v = util.number(body[k], lo, hi)
            if v is None:  # inf, NaN, true, text or out of range: nothing is saved
                raise HTTPException(400, f"{k} must be a finite number from {lo:.0f} to {hi:.0f}")
            s[k] = v
    with util.LOCK:
        # Devices and alerts are rebuilt from the saved settings; if that fails, the previous settings
        # (and the devices and alerts built from them) are put back, so a failed save changes nothing.
        old = util.settings()
        util.save_settings(s)
        res = {}
        try:
            if db.query("SELECT count(*) AS n FROM netlog")[0]["n"]:
                res["devices"] = devices.rebuild()
                res["rehunt"] = matcher.match("true", settings=True)
        except Exception:
            log.exception("netlog settings: applying failed; restoring the previous settings")
            util.save_settings(old)
            try:
                if "devices" in res:  # devices were rebuilt from the new settings: rebuild them from the old
                    devices.rebuild()
                    matcher.match("true", settings=True)
            except Exception:
                log.exception("netlog settings: rebuilding from the previous settings failed")
            raise HTTPException(500, "could not apply the settings; the previous settings were kept")
    return {**get_settings(), "applied": res}


# ------------------------------------------------------------------ import and files
@router.post("/import")
def import_logs(files: list[UploadFile] = File(...)):
    """Import one or more Zeek JSON logs. Returns when matching for them has finished."""
    from . import importer
    out = []
    for f in files:
        f.file.seek(0)
        out.append(importer.import_any(f.file, f.filename or "upload.log", origin="upload"))
    return {"files": out, "inserted": sum(r.get("inserted", 0) for r in out),
            "errors": [r for r in out if r.get("error")]}


@router.post("/inbox/scan")
def inbox_scan():
    """Read the inbox folder now. Files still being written are left for later, as the watcher does; a folder that
    fails its check is not scanned (`stopped` says why)."""
    from . import importer
    files = importer.scan_inbox()
    p = importer.last_pass
    return {"files": files, "still_writing": p.get("still_writing", 0), "not_logs": p.get("not_logs", 0),
            "stopped": p.get("stopped")}


def _inbox_view() -> dict:
    from . import importer
    from .ingest import in_docker, inbox_location
    try:
        out = importer.inbox_status()
    except Exception as e:   # never a 500: the page still offers "Change folder" and the default folder
        log.exception("netlog inbox status failed")
        out = {**util.inbox_settings(), "waiting": 0, "writing": 0, "imported": 0, "failed": [], "failed_count": 0,
               "not_logs": [], "not_logs_count": 0, "links": [], "links_count": 0, "earlier_failed": 0,
               "too_deep": [], "too_deep_count": 0, "imported_total": 0,
               "problem": f"Night Desk could not read this folder ({type(e).__name__}).", "docker": False}
    out["docker"] = in_docker()
    out["where"] = inbox_location()   # the folder as the user reaches it (in Docker: the host folder or a copy command)
    return out


@router.get("/inbox")
def get_inbox():
    """The watched folder: {path, default_path, from_env, delete_after_import, problem, waiting, writing, imported,
    imported_total, failed: [{path, error, moved}], failed_count, not_logs, not_logs_count, links, earlier_failed}.
    Names only, never contents. Reference: okf/data/netlog.md#inbox-folder"""
    return _inbox_view()


@router.get("/inbox/check")
def check_inbox(path: str = Query("", max_length=4096)):
    """Would this folder be accepted? {ok, path, error}: always 200, so the page can show the reason inline before
    saving (a refused PUT is a 400 with the same message)."""
    try:
        return {"ok": True, "path": util.check_inbox_dir(path), "error": None}
    except ValueError as e:
        return {"ok": False, "path": None, "error": str(e)}


@router.put("/inbox")
def put_inbox(body: dict = Body(...)):
    """Change the folder ({path}, or {reset: true} for the default) and/or {delete_after_import: bool}. The watcher
    reads both on its next pass. A folder set by OSINTHUB_INBOX cannot be changed here."""
    path = None
    if body.get("reset") is True or "path" in body:
        if util.inbox_settings()["from_env"]:
            raise HTTPException(409, "The folder is set by OSINTHUB_INBOX when Night Desk starts; change it there.")
        if body.get("reset") is True:
            path = str(util.default_inbox())
            util.default_inbox().mkdir(parents=True, exist_ok=True)
        else:
            try:
                path = util.check_inbox_dir(body["path"])
            except ValueError as e:
                raise HTTPException(400, str(e))
    delete = None
    if "delete_after_import" in body:
        if not isinstance(body["delete_after_import"], bool):
            raise HTTPException(400, "delete_after_import must be true or false")
        delete = body["delete_after_import"]
    util.save_inbox_settings(path=path, delete_after_import=delete)
    return _inbox_view()


@router.get("/files")
def list_files(limit: int = _limit(200)):
    rows = db.query("SELECT * FROM netlog_files ORDER BY imported_at DESC LIMIT ?", [_n(limit)])
    for r in rows:
        r["log_types"] = json.loads(r["log_types"] or "{}")
        r["warnings"] = json.loads(r.get("warnings") or "[]")
    return _out(rows)


# ------------------------------------------------------------------ devices
def _dev(r: dict, label: dict | None = None) -> dict:
    from . import devices
    for k in ("top_dests", "top_names", "evidence"):
        r[k] = json.loads(r.get(k) or ("{}" if k == "evidence" else "[]"))
    return devices.present(r, label)


@router.get("/devices")
def list_devices(sort: str = "bytes", limit: int = _limit(500), q: str | None = None):
    """Devices with what to call them (`name`: the user's label, else a readable name from the evidence, else
    'Unnamed device · hint · short id'), `type`, `owner`, `note`, and `fragment` for low-evidence addresses."""
    from . import devices
    devices.ensure_tables()
    orders = {"bytes": "bytes_out + bytes_in DESC", "last_seen": "last_seen DESC", "rows": "rows DESC",
              "alerts": "coalesce(a.max_rank, 0) DESC, alerts DESC, bytes_out + bytes_in DESC"}
    if sort not in orders:   # a typo is reported, not silently replaced by the default
        raise HTTPException(400, f"sort must be one of {', '.join(orders)}")
    order = orders[sort]
    where, params = "", []
    if q:
        where = """WHERE d.id ILIKE ? OR list_contains(d.ips, ?) OR array_to_string(d.hostnames, ' ') ILIKE ?
                   OR l.name ILIKE ? OR l.owner ILIKE ? OR l.note ILIKE ?"""
        params = [f"%{q}%", q, f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"]
    # per-device counts are incidents under the one count rule (incidents.needs_you): open = untriaged, not
    # expected, not demo; alerts_high_medium is the device's share of "needs you"
    from . import incidents
    incidents.ensure()
    rows = db.query(f"""
        SELECT d.*, coalesce(a.alerts, 0) AS alerts, coalesce(a.alerts_hm, 0) AS alerts_high_medium, a.max_rank
        FROM devices d LEFT JOIN netlog_device_labels l ON l.id = d.id LEFT JOIN (
            SELECT device, count(*) FILTER (WHERE severity IN ('high', 'medium', 'low')) AS alerts,
                   count(*) FILTER (WHERE severity IN ('high', 'medium')) AS alerts_hm,
                   max(CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)
                       FILTER (WHERE severity <> 'info') AS max_rank
            FROM ({incidents.incidents_sql(inc_where="WHERE state = 'new' AND NOT demo")}) GROUP BY device) a ON a.device = d.id
        {where} ORDER BY {order}, d.id LIMIT ?""", [*params, _n(limit)])
    lab = devices.labels([r["id"] for r in rows])
    for r in rows:
        r["max_severity"] = {3: "high", 2: "medium", 1: "low"}.get(r.pop("max_rank", None))
    return _out([_dev(r, lab.get(r["id"])) for r in rows])


@router.post("/devices/merge")
def device_merge(body: dict = Body(...)):
    """Merge device `src` into device `dst` (the same machine seen twice). Undo with /devices/unmerge."""
    from . import devices
    src, dst = str(body.get("src") or ""), str(body.get("dst") or "")
    try:
        return _out(devices.merge(src, dst))
    except LookupError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/devices/unmerge")
def device_unmerge(body: dict = Body(...)):
    from . import devices
    try:
        return _out(devices.unmerge(str(body.get("src") or "")))
    except LookupError as e:
        raise HTTPException(404, str(e))


@router.patch("/devices/{did:path}")
def device_label(did: str, body: dict = Body(...)):
    """Set the user's name, type, owner or note for a device (keys left out are kept; '' or null clears one)."""
    from . import devices
    if not isinstance(body, dict):
        raise HTTPException(400, "body must be an object")
    known = bool(db.query("SELECT 1 FROM devices WHERE id = ?", [did])) or did in devices.merges()
    if not known:
        raise HTTPException(404, "no such device")
    try:
        devices.set_label(did, body)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return device_detail(did)


@router.get("/devices/{did:path}")
def device_detail(did: str):
    from . import devices
    devices.ensure_tables()
    asked = did
    rows = db.query("SELECT * FROM devices WHERE id = ?", [did])
    if not rows:   # an id the user merged away: show the device it is part of now
        did = devices.merge_resolver()(did)
        rows = db.query("SELECT * FROM devices WHERE id = ?", [did]) if did != asked else []
    if not rows:
        raise HTTPException(404, "no such device")
    d = _dev(rows[0], devices.labels([did]).get(did))
    if did != asked:
        d["merged_into"], d["asked"] = did, asked
    d["ip_history"] = db.query("SELECT ip, from_ts, how, confidence FROM netlog_ipdev WHERE device = ? ORDER BY ip, from_ts", [did])
    d["alerts"] = _alerts_rows("WHERE device = ?", [did], 100, 0)
    # Hourly from the same per-IP aggregates (both directions, conn + eve_flow) the device totals are
    # built from, so the timeline sums to conns and bytes_out + bytes_in.
    from .devices import CONN_TYPES
    d["timeline"] = db.query(f"""
        WITH o AS (SELECT ip, hr, sum(rows) AS rows, sum(bo) AS bo, sum(bi) AS bi FROM netlog_agg_ip
                   WHERE log_type IN {CONN_TYPES} AND ip IN (SELECT ip FROM netlog_ipdev WHERE device = ?) GROUP BY ALL),
             r AS (SELECT o.* FROM o ASOF JOIN netlog_ipdev d ON d.ip = o.ip AND o.hr >= d.from_ts WHERE d.device = ?)
        SELECT hr AS t, sum(rows) AS conns, coalesce(sum(bo), 0) + coalesce(sum(bi), 0) AS bytes,
               coalesce(sum(bo), 0) AS bytes_out, coalesce(sum(bi), 0) AS bytes_in
        FROM r GROUP BY 1 ORDER BY 1""", [did, did])
    m = devices.merges(names=True)
    d["merged_from"] = sorted(k for k, v in m.items() if v["dst"] == did)
    d["merged_from_names"] = {k: m[k]["src_name"] or f"Unnamed device · {devices.short_id(k)}" for k in d["merged_from"]}
    d["events"] = _device_events(d)
    d["similar"] = devices.similar(did)
    return _out(d)


def _device_events(d: dict) -> list[dict]:
    """A plain per-device timeline, newest first: first and last activity, address changes, alerts."""
    ev = []
    if d.get("first_seen"):
        ev.append({"t": d["first_seen"], "kind": "first", "text": "First seen in your logs"})
    for h in d.get("ip_history") or []:
        if h.get("from_ts") and not str(util.jsonable(h["from_ts"])).startswith("1970"):
            ev.append({"t": h["from_ts"], "kind": "address", "text": f"Took the address {h['ip']}"})
    for a in d.get("alerts") or []:
        ev.append({"t": a["ts"], "kind": "alert", "severity": a["severity"], "alert": a["id"], "status": a["status"],
                   "text": a.get("title") or a.get("indicator"), "indicator": a.get("indicator"), "rule": a.get("rule")})
    if d.get("last_seen"):
        ev.append({"t": d["last_seen"], "kind": "last", "text": "Last seen in your logs"})
    return sorted(util.jsonable(ev), key=lambda e: str(e["t"]), reverse=True)


def _name_alerts(rows: list[dict]) -> None:
    """Every alert carries the device's current display name (the user's label first): `device_name`,
    evidence.device.name / type / owner, and the title reads with it instead of the raw id or a junk hostname."""
    from . import devices
    try:
        names = devices.display_names([r.get("device") for r in rows if r.get("device")])
    except Exception:   # naming is a nicety: never fail an alert listing over it
        log.exception("netlog: device names for alerts failed")
        return
    for r in rows:
        n = names.get(r.get("device"))
        if not n:
            continue
        r["device_name"] = n["name"]
        r["device_name_source"] = n["name_source"]
        r["device_hint"] = n.get("hint")
        dv = (r.get("evidence") or {}).get("device")
        if isinstance(dv, dict):
            dv.update(name=n["name"], name_source=n["name_source"], type=n["type"], owner=n["owner"], hint=n.get("hint"))
            old = f"{dv['hostnames'][0]} ({r['device']})" if dv.get("hostnames") else r["device"]
        else:
            old = r["device"]
        if isinstance(r.get("title"), str) and old in r["title"]:
            r["title"] = r["title"].replace(old, n["name"], 1)


# ------------------------------------------------------------------ log filters (shared by every log endpoint)
@dataclass
class LogFilter:
    """Include filters, their not_* exclusions, and the hunt `query` (grammar in query.py)."""
    device: str | None = None
    ip: str | None = None
    port: str | None = None
    log_type: str | None = None
    proto: str | None = None
    service: str | None = None
    uid: str | None = None
    since: str | None = None
    until: str | None = None
    since_hours: float | None = None
    q: str | None = None
    query: str | None = None
    not_ip: str | None = None
    not_port: str | None = None
    not_device: str | None = None
    not_log_type: str | None = None
    not_q: str | None = None


def _conn_where(f: LogFilter):
    c, p = [], []
    for field, v in (("device", f.device), ("ip", f.ip), ("port", f.port), ("log_type", f.log_type),
                     ("proto", f.proto), ("uid", f.uid)):
        if vals := _csv(str(v) if v else None):  # " " or "," is no filter, as on the alert filters
            c.append(Q.log_term(field, vals, p))
    if f.service:
        c.append("service ILIKE ?"); p.append(f"%{f.service}%")
    _time_where(c, p, f.since, f.until, f.since_hours)
    if f.q:
        c.append(Q.text_clause(f.q, p))
    c += Q.log_where(f.query, p)
    c += Q.log_where(Q.excludes(f.not_ip, f.not_port, f.not_device, f.not_log_type, f.not_q), p)
    return (" WHERE " + " AND ".join(c)) if c else "", p


def _source(group_fields: list[str] | tuple = ()) -> str:
    """netlog, or netlog with a per-row device column when a group needs it."""
    return Q.DEVICE_VIEW if "device" in group_fields else "netlog"


@router.get("/connections")
def connections(f: LogFilter = Depends(), limit: int = _limit(200), offset: int = _offset(),
                order: str = "desc", raw: bool = False, response: Response = None):
    where, params = _conn_where(f)
    total = db.query(f"SELECT count(*) AS n FROM netlog{where}", params)[0]["n"]
    cols = "* EXCLUDE (rk)" if raw else "* EXCLUDE (rk, raw)"
    rows = db.query(f"SELECT {cols} FROM netlog{where} ORDER BY {_order(order)} {_page(limit, offset)}", params)
    if raw:
        for r in rows:
            r["raw"] = json.loads(r["raw"]) if r.get("raw") else None
    if response is not None:
        response.headers["X-Total-Count"] = str(total)
    return {"total": total, "rows": _out(rows)}


def _order(order: str) -> str:
    """'asc' / 'desc' (by time), or a column: 'bytes', 'resp_bytes:asc', '-duration' (descending)."""
    o = (order or "desc").strip().lower()
    if o in ("asc", "desc"):  # rk (unique per row) breaks ties, so offset pages never skip or repeat a row
        return f"ts {o.upper()} NULLS LAST, rk"
    desc = True
    if o.startswith("-"):
        o = o[1:]
    elif o.startswith("+"):
        o, desc = o[1:], False
    if ":" in o:
        o, d = o.split(":", 1)
        if d not in ("asc", "desc"):
            raise HTTPException(400, "order direction must be asc or desc")
        desc = d == "desc"
    if o == "bytes":
        expr = "coalesce(orig_bytes, 0) + coalesce(resp_bytes, 0)"
    elif o in Q.LOG_COLS and o != "answers":
        expr = o
    else:
        raise HTTPException(400, f"cannot order by {order!r}: asc, desc, bytes or a column name")
    return f"{expr} {'DESC' if desc else 'ASC'} NULLS LAST, ts DESC, rk"


# ------------------------------------------------------------------ generic aggregation (hunt)
METRICS = {"count": "count(*)", "bytes": "sum(coalesce(orig_bytes, 0) + coalesce(resp_bytes, 0))",
           "bytes_out": "sum(coalesce(orig_bytes, 0))", "bytes_in": "sum(coalesce(resp_bytes, 0))",
           "duration": "sum(coalesce(duration, 0))"}


@router.get("/aggregate")
def aggregate(group: str = Query(..., description="one or two fields, comma-separated"), f: LogFilter = Depends(),
              metric: str = "count", order: str = "desc", limit: int = _limit(25), offset: int = _offset(),
              sublimit: int = _limit(10),
              distinct: str | None = None):
    """Group logs by one or two fields (columns, device, hour, day, raw.<field>) after filtering.

    order=asc lists the rarest values first; offset pages through first-level groups."""
    fields = _csv(group)
    if not 1 <= len(fields) <= 2:
        raise HTTPException(400, "group takes one or two fields")
    exprs = [Q.log_expr(x) for x in fields]
    if metric not in METRICS:
        raise HTTPException(400, f"metric must be one of {sorted(METRICS)}")
    if order not in ("asc", "desc"):
        raise HTTPException(400, "order must be asc or desc")
    where, params = _conn_where(f)
    d = order.upper()
    m_extra = "" if metric in ("count", "bytes") else f", {METRICS[metric]} AS {metric}"
    dist = ""
    if distinct and len(fields) == 1:
        dist = f", count(DISTINCT {Q.log_expr(distinct)}) AS distinct_{re.sub(r'[^a-z0-9_]', '_', distinct.lower())}"
    lim = f"LIMIT {_n(limit)}"
    off = f"OFFSET {int(offset)}" if offset else ""
    src = _source([*fields, *([distinct] if dist else [])])
    if len(fields) == 1:
        rows = db.query(f"""
            WITH base AS (SELECT {exprs[0]} AS key, count(*) AS count, {METRICS['bytes']} AS bytes,
                                 min(ts) AS first, max(ts) AS last{m_extra}{dist}
                          FROM {src}{where} GROUP BY 1)
            SELECT *, sum(count) OVER () AS _total, count(*) OVER () AS _groups FROM base
            ORDER BY {metric} {d} NULLS LAST, key {lim} {off}""", params)
    else:
        sub = int(sublimit) if sublimit else 10**9
        rows = db.query(f"""
            WITH base AS (SELECT {exprs[0]} AS g0, {exprs[1]} AS g1, count(*) AS count, {METRICS['bytes']} AS bytes,
                                 min(ts) AS first, max(ts) AS last{m_extra}
                          FROM {src}{where} GROUP BY 1, 2),
            l1 AS (SELECT g0 AS key, sum(count) AS count, sum(bytes) AS bytes, min(first) AS first, max(last) AS last
                          {'' if metric in ('count', 'bytes') else f', sum({metric}) AS {metric}'},
                          sum(sum(count)) OVER () AS _total, count(*) OVER () AS _groups
                   FROM base GROUP BY g0 ORDER BY {metric} {d} NULLS LAST, key {lim} {off}),
            l2 AS (SELECT * FROM base WHERE g0 IN (SELECT key FROM l1) OR (g0 IS NULL AND EXISTS (SELECT 1 FROM l1 WHERE key IS NULL))
                   QUALIFY row_number() OVER (PARTITION BY g0 ORDER BY {metric} {d} NULLS LAST, g1) <= {sub}),
            kids AS (SELECT g0, list({{'key': g1, 'count': count, 'bytes': bytes, 'first': first, 'last': last
                                       {'' if metric in ('count', 'bytes') else f", '{metric}': {metric}"}}}
                                     ORDER BY {metric} {d} NULLS LAST, g1) AS children FROM l2 GROUP BY g0)
            SELECT l1.*, coalesce(kids.children, []) AS children FROM l1 LEFT JOIN kids ON kids.g0 IS NOT DISTINCT FROM l1.key
            ORDER BY {metric} {d} NULLS LAST, key""", params)
    if rows:
        total, n_groups = rows[0]["_total"], rows[0]["_groups"]
    else:  # empty page (offset past the last group): the totals still describe the whole result
        total = db.query(f"SELECT count(*) AS n FROM netlog{where}", params)[0]["n"]
        n_groups = db.query(f"SELECT count(*) AS n FROM (SELECT {exprs[0]} FROM {src}{where} GROUP BY 1)", params)[0]["n"] if total else 0
    for r in rows:
        r.pop("_total", None), r.pop("_groups", None)
    return _out({"group": fields, "metric": metric, "order": order, "total": int(total or 0), "groups_total": n_groups,
                 "offset": offset, "groups": rows})


# ------------------------------------------------------------------ dashboard aggregations
@router.get("/stats/top")
def stats_top(field: str = "talkers", limit: int = _limit(15), f: LogFilter = Depends()):
    where, params = _conn_where(f)
    w = where or " WHERE true"
    log_type = f.log_type
    if field == "talkers":
        return _out(db.query(f"""
            WITH n AS (SELECT * FROM netlog{w} AND log_type IN ('conn', 'eve_flow'))
            SELECT coalesce(d.device, 'ip:' || n.orig_h) AS key, count(*) AS conns,
                   sum(coalesce(orig_bytes, 0)) AS bytes_out, sum(coalesce(resp_bytes, 0)) AS bytes_in,
                   sum(coalesce(orig_bytes, 0) + coalesce(resp_bytes, 0)) AS bytes
            FROM n ASOF LEFT JOIN netlog_ipdev d ON d.ip = n.orig_h AND n.ts >= d.from_ts
            GROUP BY 1 ORDER BY bytes DESC LIMIT ?""", [*params, _n(limit)]))
    simple = {
        "ports": "resp_p", "services": "coalesce(service, '(none)')", "log_types": "log_type",
        "protos": "proto", "dests": "resp_h", "names": "coalesce(query, server_name, host)",
        "conn_states": "conn_state",
    }
    if field in simple:
        expr = simple[field]
        extra = " AND log_type IN ('conn', 'eve_flow')" if field in ("ports", "services", "protos", "dests", "conn_states") and not log_type else ""
        if field == "names":
            extra = " AND coalesce(query, server_name, host) IS NOT NULL"
        return _out(db.query(f"""SELECT {expr} AS key, count(*) AS conns,
                   sum(coalesce(orig_bytes, 0) + coalesce(resp_bytes, 0)) AS bytes
                   FROM netlog{w}{extra} GROUP BY 1 ORDER BY conns DESC LIMIT ?""", [*params, _n(limit)]))
    if field in ("countries", "asns"):
        from .. import geo
        # Every external peer is counted. The top PEER_GEO_CAP by bytes are looked up one by one; on a
        # network with more peers than that, the rest are summed into one "other" row (ip NULL).
        peers = db.query(f"""
            WITH p AS (SELECT resp_h AS ip, count(*) AS conns, sum(coalesce(orig_bytes, 0) + coalesce(resp_bytes, 0)) AS bytes
                       FROM netlog{w} AND log_type IN ('conn', 'eve_flow') AND resp_h NOT IN (SELECT ip FROM netlog_ipdev)
                       GROUP BY 1),
                 r AS (SELECT *, row_number() OVER (ORDER BY bytes DESC, ip) AS rn FROM p)
            SELECT ip, conns, bytes, 1 AS ips FROM r WHERE rn <= {int(PEER_GEO_CAP)}
            UNION ALL
            SELECT NULL, sum(conns), sum(bytes), count(*) FROM r WHERE rn > {int(PEER_GEO_CAP)} HAVING count(*) > 0""", params)
        agg: dict = defaultdict(lambda: {"conns": 0, "bytes": 0, "ips": 0})
        names: dict = {}
        for p in peers:
            if p["ip"] is None:
                k = "other"
            elif field == "countries":
                loc = geo.locate_ip(p["ip"])
                k = (loc or {}).get("country") or "??"
            else:
                a = geo.asn_for_ip(p["ip"])
                k = a[0] if a else "unknown"
                if a:
                    names[k] = a[1]
            agg[k]["conns"] += int(p["conns"] or 0)
            agg[k]["bytes"] += int(p["bytes"] or 0)
            agg[k]["ips"] += int(p["ips"])
        out = [{"key": k, **v, **({"name": names[k]} if k in names else {})} for k, v in agg.items()]
        return sorted(out, key=lambda o: -o["bytes"])[:_n(limit)]
    # any other field: generic one-level group (same shape)
    expr = Q.log_expr(field)
    return _out(db.query(f"""SELECT {expr} AS key, count(*) AS conns, {METRICS['bytes']} AS bytes
                             FROM {_source([field])}{w} GROUP BY 1 ORDER BY conns DESC LIMIT ?""", [*params, _n(limit)]))


BUCKETS = {"minute": "1 MINUTE", "5m": "5 MINUTE", "15m": "15 MINUTE", "hour": "1 HOUR", "day": "1 DAY"}


def _split_rows(rows: list[dict], split_rows: list[dict], split_limit: int) -> None:
    """Attach `by` ({value: rows}) to timeline rows; values beyond the top split_limit go to "other"."""
    tot: dict = defaultdict(int)
    for r in split_rows:
        tot[r["v"]] += r["n"]
    keep = {k for k, _ in sorted(tot.items(), key=lambda kv: -kv[1])[:split_limit or None]}  # 0: every value
    by: dict = defaultdict(lambda: defaultdict(int))
    for r in split_rows:
        by[r["t"]][str(r["v"]) if r["v"] in keep else "other"] += r["n"]
    for r in rows:
        r["by"] = dict(by.get(r["t"], {}))


@router.get("/stats/timeline")
def stats_timeline(bucket: str = "hour", f: LogFilter = Depends(), split: str | None = None,
                   split_limit: int = _limit(8, 1000)):
    """Rows, conns and bytes per time bucket, with alert counts; `split` adds per-value counts in `by`."""
    iv = BUCKETS.get(bucket)
    if not iv:
        raise HTTPException(400, "bucket must be minute, 5m, 15m, hour or day")
    where, params = _conn_where(f)
    rows = db.query(f"""SELECT time_bucket(INTERVAL {iv}, ts) AS t, count(*) AS rows,
                               count(*) FILTER (WHERE log_type IN ('conn', 'eve_flow')) AS conns,
                               sum(coalesce(orig_bytes, 0) + coalesce(resp_bytes, 0)) AS bytes
                        FROM netlog{where or ' WHERE true'} AND ts IS NOT NULL GROUP BY 1 ORDER BY 1""", params)
    if split:
        sr = db.query(f"""SELECT time_bucket(INTERVAL {iv}, ts) AS t, {Q.log_expr(split)} AS v, count(*) AS n
                          FROM {_source([split])}{where or ' WHERE true'} AND ts IS NOT NULL GROUP BY ALL""", params)
        _split_rows(rows, sr, split_limit)
    ac, ap = [], []
    _time_where(ac, ap, f.since, f.until, f.since_hours)
    import dataclasses
    nw, np_ = _conn_where(dataclasses.replace(f, since=None, until=None, since_hours=None))
    if nw:
        # the overlay counts only alerts built from rows the filter selects
        ac.append(f"id IN (SELECT alert_id FROM netlog_matches WHERE rk IN (SELECT rk FROM netlog{nw}))")
        ap += np_
    al = db.query(f"""SELECT time_bucket(INTERVAL {iv}, ts) AS t, severity, count(*) AS n FROM alerts
                      {('WHERE ' + ' AND '.join(ac)) if ac else ''} GROUP BY ALL""", ap)
    by_t: dict = defaultdict(dict)
    for a in al:
        by_t[a["t"]][a["severity"]] = a["n"]
    for r in rows:
        r["alerts"] = by_t.pop(r["t"], {})
    rows += [{"t": t, "rows": 0, "conns": 0, "bytes": 0, "alerts": v, **({"by": {}} if split else {})} for t, v in by_t.items()]
    return _out(sorted(rows, key=lambda r: r["t"]))


FRESH_ORIGINS = {"upload": "Files you uploaded", "inbox": "Inbox folder", "api": "Imported by a script"}


@router.get("/freshness")
def freshness():
    """How current the logs are, per source (upload, inbox folder, each push sender): the newest record's own time
    (not when it was imported), and stale when nothing newer arrived for longer than the silence threshold (a push
    sender's own, else the stale_hours setting). Demo data is left out. Reference: okf/data/netlog.md#freshness"""
    from . import ingest
    now = util.now()
    default_s = float(util.settings().get("stale_hours") or 24) * 3600
    rows = db.query("""SELECT origin, count(*) AS files, max(ts_max) AS newest, max(imported_at) AS last_import
                       FROM netlog_files WHERE coalesce(status, 'ok') = 'ok' AND coalesce(origin, '') <> 'demo'
                       GROUP BY 1""")
    for r in rows:
        if r["newest"] is None:   # files from before ts_max was recorded: read it from the rows
            r["newest"] = db.query("""SELECT max(ts) AS t FROM netlog WHERE file_id IN
                                      (SELECT id FROM netlog_files WHERE origin IS NOT DISTINCT FROM ?)""", [r["origin"]])[0]["t"]
    try:
        senders = {s["name"]: s for s in ingest.senders()}
    except Exception:
        senders = {}
    out, seen = [], set()
    for r in sorted(rows, key=lambda r: str(r["origin"])):
        origin = r["origin"] or "api"
        th, th_from, label, kind = default_s, "setting", FRESH_ORIGINS.get(origin, origin), "import"
        if origin.startswith("push:"):
            label, kind = origin[5:], "sender"
            s = senders.get(label)
            seen.add(label)
            if s and s.get("health", {}).get("threshold_s"):
                th, th_from = float(s["health"]["threshold_s"]), "sender"
        newest = r["newest"]
        age = (now - newest).total_seconds() if newest else None
        out.append({"source": origin, "label": label, "kind": kind, "newest": newest, "last_import": r["last_import"],
                    "files": r["files"], "age_s": age, "threshold_s": th, "threshold_from": th_from,
                    "stale": bool(age is not None and age > th)})
    for name, s in senders.items():   # a sender that has not delivered logs yet
        if name not in seen and not s.get("paused"):
            out.append({"source": f"push:{name}", "label": name, "kind": "sender", "newest": None, "last_import": None,
                        "files": 0, "age_s": None, "threshold_s": None, "threshold_from": None, "stale": False,
                        "waiting": True})
    newest = max((o["newest"] for o in out if o["newest"]), default=None)
    demo = db.query("SELECT count(*) AS n, max(ts_max) AS newest FROM netlog_files WHERE origin = 'demo'")[0]
    return _out({"now": now, "newest": newest, "age_s": (now - newest).total_seconds() if newest else None,
                 "stale_hours": default_s / 3600, "stale": [o["source"] for o in out if o["stale"]],
                 "sources": out, "demo": {"loaded": bool(demo["n"]), "newest": demo["newest"]}})


# A record far older than the rest (a clock that was wrong once, a stray old file) would stretch an "all data" chart
# so that everything real sits in a sliver at its right edge. The chart starts where the data is dense instead:
# at the time by which DENSE_Q of the rows have been seen (widened back by DENSE_MIN_TRIM of the rest, so neighbours
# of that row stay in), when that trims at least DENSE_MIN_TRIM of the span. okf/data/netlog.md#chart-start
DENSE_Q = 0.001
DENSE_MIN_TRIM = 0.10


def _dense_start(n: dict) -> dict:
    """{dense_first, before_dense}: where an all-data chart should start, and how many rows lie before it."""
    first, last = n.get("first"), n.get("last")
    if not n.get("rows") or not first or not last or last <= first:
        return {"dense_first": first, "before_dense": 0}
    q = db.query("SELECT quantile_disc(ts, ?) AS q FROM netlog", [DENSE_Q])[0]["q"]
    if not q or (q - first) < (last - first) * DENSE_MIN_TRIM:
        return {"dense_first": first, "before_dense": 0}
    # the dense part starts a little before the quantile: rows just older than it belong to it, not to the stray tail
    start = db.query("SELECT min(ts) AS t FROM netlog WHERE ts >= ?", [q - (last - q) * DENSE_MIN_TRIM])[0]["t"] or q
    before = db.query("SELECT count(*) AS n FROM netlog WHERE ts < ?", [start])[0]["n"]
    return {"dense_first": start, "before_dense": int(before)}


@router.get("/summary")
def summary():
    n = db.query("""SELECT count(*) AS rows, count(*) FILTER (WHERE log_type = 'conn') AS conns,
                           min(ts) AS first, max(ts) AS last FROM netlog""")[0]
    n["files"] = db.query("SELECT count(*) AS n FROM netlog_files")[0]["n"]
    n["devices"] = db.query("SELECT count(*) AS n FROM devices")[0]["n"]
    # alerts: open incidents by severity under the one count rule (incidents.needs_you); needs_you = high + medium
    from . import incidents
    c = incidents.needs_you()
    n["alerts"] = {k: c[k] for k in SEVERITIES}
    n["needs_you"] = c["needs_you"]
    n["alerts_other"] = {k: c[k] for k in ("demo", "expected", "incidents", "open")}
    n.update(_dense_start(n))
    n["log_types"] = {r["log_type"]: r["n"] for r in db.query("SELECT log_type, count(*) AS n FROM netlog GROUP BY 1 ORDER BY 2 DESC")}
    return _out(n)


# ------------------------------------------------------------------ demo data
@router.get("/demo")
def demo_status():
    """Whether the demo is loaded, and each planted scenario checked against the alert it produced."""
    from . import demo
    out = demo.verify()
    alerts_ = [sc["alert"] for sc in out.get("scenarios") or [] if sc.get("alert")]
    if alerts_:   # alert titles read with the device's current name, as in the alert list
        full = {r["id"]: r for r in _alerts_rows("WHERE id IN (SELECT unnest(?::VARCHAR[]))", [[a["id"] for a in alerts_]], 0, 0)}
        for a in alerts_:
            if a["id"] in full:
                a["title"], a["device_name"] = full[a["id"]]["title"], full[a["id"]].get("device_name")
    return _out(out)


@router.post("/demo")
def demo_load():
    """Generate a demo day from the indicators listed now and import it (origin "demo")."""
    from . import demo
    try:
        return _out(demo.load())
    except ValueError as e:
        raise HTTPException(409, str(e))


@router.delete("/demo")
def demo_unload():
    """Remove all demo rows, matches, alerts and files, and the home prefixes the demo added."""
    from . import demo
    return _out(demo.unload())


@router.get("/demo/bundle")
def demo_bundle():
    """The demo logs as a tar.gz to import by hand (generated now; nothing is stored)."""
    from fastapi.responses import Response
    from . import demo
    files, plan = demo.build()
    return Response(demo.bundle(files, plan), media_type="application/gzip",
                    headers={"Content-Disposition": f'attachment; filename="{demo.BUNDLE}.tar.gz"'})


# ------------------------------------------------------------------ threat intervals
@router.get("/indicators")
def indicators(value: str | None = None, source: str | None = None, active: bool | None = None, limit: int = _limit(200)):
    if value is None and source is None and active is None:
        from . import intervals
        return _out(intervals.summary())
    c, p = [], []
    if value:
        n = ipnum.ip_int(value)
        if n is not None:
            c.append("(lo <= ?::UHUGEINT AND hi >= ?::UHUGEINT)"); p += [str(n), str(n)]
        else:
            c.append("value = ?"); p.append(value.lower() if not value.upper().startswith("CVE-") else value.upper())
    if source:
        c.append("source = ?"); p.append(source)
    if active is not None:
        c.append('"end" IS NULL' if active else '"end" IS NOT NULL')
    rows = db.query(f"""SELECT source, kind, value, "start", "end", key, category, meta FROM indicator_intervals
                        {('WHERE ' + ' AND '.join(c)) if c else ''} ORDER BY "start" DESC LIMIT ?""", [*p, _n(limit)])
    for r in rows:
        r["meta"] = json.loads(r["meta"] or "{}")
    return _out(rows)


@router.get("/status")
def status():
    """Threat-interval health: last refresh, recent errors, the reported-IOC loader, intervals per source."""
    from . import intervals
    return _out({**intervals.STATUS, "sources": intervals.summary(),
                 "files": db.query("SELECT source, count(*) AS files, max(ts) AS last FROM netlog_ti_files GROUP BY 1")})


@router.post("/indicators/refresh")
def indicators_refresh(full: bool = False, rehunt: bool = True):
    from . import intervals, matcher
    changed = intervals.refresh(full=full)
    return {"changed": changed, "rehunt": matcher.rehunt() if (changed and rehunt) else None}


@router.post("/rehunt")
def rehunt(days: float | None = None):
    from . import intervals, matcher
    if days is not None:
        lo, hi = util.NUMERIC["rehunt_days"]
        if util.number(days, lo, hi) is None:
            raise HTTPException(400, f"days must be a finite number from {lo:.0f} to {hi:.0f}")
    changed = intervals.refresh()
    return {"changed": changed, **matcher.rehunt(days)}


# ------------------------------------------------------------------ alerts
def _alerts_rows(where: str, params: list, limit: int, offset: int) -> list[dict]:
    from . import incidents
    incidents.ensure()
    lim = _page(limit, offset)
    rows = db.query(f"""SELECT * FROM alerts {where}
                        ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END,
                                 last_ts DESC, id {lim}""", params)
    for r in rows:
        r["evidence"] = json.loads(r["evidence"] or "{}")
    _name_alerts(rows)
    return _out(rows)


@dataclass
class AlertFilter:
    severity: str | None = None
    status: str | None = None
    device: str | None = None
    source: str | None = None
    rule: str | None = None
    indicator: str | None = None
    direction: str | None = None
    since: str | None = None
    until: str | None = None
    since_hours: float | None = None
    q: str | None = None
    query: str | None = None
    min_severity: str | None = None
    not_severity: str | None = None
    not_status: str | None = None
    not_device: str | None = None
    not_source: str | None = None
    not_rule: str | None = None
    not_indicator: str | None = None
    not_direction: str | None = None
    not_q: str | None = None
    ip: str | None = None
    not_ip: str | None = None


def _alert_where(f: AlertFilter) -> tuple[str, list]:
    c, p = [], []
    for col, v, neg in (("severity", f.severity, False), ("status", f.status, False), ("source", f.source, False),
                        ("rule", f.rule, False), ("direction", f.direction, False), ("device", f.device, False),
                        ("indicator", f.indicator, False), ("indicator", f.ip, False),
                        ("severity", f.not_severity, True), ("status", f.not_status, True),
                        ("source", f.not_source, True), ("rule", f.not_rule, True), ("direction", f.not_direction, True),
                        ("device", f.not_device, True), ("indicator", f.not_indicator, True), ("indicator", f.not_ip, True)):
        vals = _csv(v)
        if vals:
            cl = f"{col} IN ({','.join('?' * len(vals))})"
            c.append(f"NOT coalesce({cl}, false)" if neg else cl); p += vals
    min_sev = (f.min_severity or "").strip().lower()  # any case: High, HIGH and high are the same
    if min_sev and min_sev not in SEVERITIES:
        raise HTTPException(400, f"min_severity must be one of {', '.join(SEVERITIES)}")
    if min_sev:
        keep = SEVERITIES[: SEVERITIES.index(min_sev) + 1]
        c.append(f"severity IN ({','.join('?' * len(keep))})"); p += keep
    _time_where(c, p, f.since, f.until, f.since_hours)
    if f.q:
        c.append("(title ILIKE ? OR indicator ILIKE ? OR device ILIKE ? OR evidence ILIKE ?)"); p += [f"%{f.q}%"] * 4
    if f.not_q:
        c.append("NOT (title ILIKE ? OR indicator ILIKE ? OR coalesce(device, '') ILIKE ? OR evidence ILIKE ?)")
        p += [f"%{f.not_q}%"] * 4
    c += Q.alert_where(f.query, p)
    return ("WHERE " + " AND ".join(c)) if c else "", p


# ------------------------------------------------------------------ incidents, the count, expected-traffic rules
INC_LEVEL = ("severity", "status", "min_severity", "not_severity", "not_status")
STATES = {"new", "ack", "dismissed", "expected"}


def _inc_where(f: AlertFilter, demo: bool | None = None, needs_you: bool = False) -> tuple[str, list, str, list]:
    """Alert-level filters pick incidents; severity and status apply to the incident (its worst severity, its
    state: new | ack | dismissed | expected)."""
    import dataclasses
    mw, mp = _alert_where(dataclasses.replace(f, **{k: None for k in INC_LEVEL}))
    c, p = [], []
    for col, v, neg in (("severity", f.severity, False), ("state", f.status, False),
                        ("severity", f.not_severity, True), ("state", f.not_status, True)):
        vals = _csv(v)
        if col == "state" and any(x not in STATES for x in vals):
            raise HTTPException(400, f"status must be one of {sorted(STATES)}")
        if vals:
            cl = f"{col} IN ({','.join('?' * len(vals))})"
            c.append(f"NOT ({cl})" if neg else cl); p += vals
    min_sev = (f.min_severity or "").strip().lower()
    if min_sev and min_sev not in SEVERITIES:
        raise HTTPException(400, f"min_severity must be one of {', '.join(SEVERITIES)}")
    if min_sev:
        keep = SEVERITIES[: SEVERITIES.index(min_sev) + 1]
        c.append(f"severity IN ({','.join('?' * len(keep))})"); p += keep
    if demo is not None:
        c.append("demo" if demo else "NOT demo")
    if needs_you:
        c.append("state = 'new' AND NOT demo AND severity IN ('high', 'medium')")
    return mw, mp, ("WHERE " + " AND ".join(c)) if c else "", p


@router.get("/incidents")
def incidents_list(f: AlertFilter = Depends(), demo: bool | None = None, needs_you: bool = False,
                   limit: int = _limit(500), offset: int = _offset(), response: Response = None):
    """Incidents (alerts of one device + indicator + kind joined across days), most severe then most recent first.
    status takes new | ack | dismissed | expected (hidden by a rule); needs_you=true is the count rule's set."""
    from . import incidents
    incidents.ensure()
    mw, mp, iw, ip = _inc_where(f, demo, needs_you)
    if response is not None:
        response.headers["X-Total-Count"] = str(db.query(f"SELECT count(*) AS n FROM ({incidents.incidents_sql(mw, iw)})",
                                                         [*mp, *ip])[0]["n"])
    rows = db.query(incidents.incidents_sql(mw, iw, incidents.ORDER, _page(limit, offset)), [*mp, *ip])
    for r in rows:
        r["evidence"] = json.loads(r["evidence"] or "{}")
    if callable(namer := globals().get("_name_alerts")):   # the user's device labels, at read time (devices lane)
        namer(rows)
    return _out(rows)


@router.get("/incidents/summary")
def incidents_summary(f: AlertFilter = Depends()):
    """Incident counts by state and by severity (within the other filters), for the list's filter chips."""
    from . import incidents
    import dataclasses
    incidents.ensure()
    out = {}
    for name, skip in (("state", ("status", "not_status")), ("severity", ("severity", "min_severity", "not_severity"))):
        mw, mp, iw, ip = _inc_where(dataclasses.replace(f, **{k: None for k in skip}))
        out[name] = {r["k"]: r["n"] for r in db.query(
            f"SELECT {name} AS k, count(*) AS n FROM ({incidents.incidents_sql(mw, iw)}) GROUP BY 1", [*mp, *ip])}
    out["total"] = sum(out["state"].values())
    # untriaged demo incidents within the same filters (the range): the Network header's demo count beside its
    # in-range "new" count, so the two numbers on one line come from the same range
    mw, mp, iw, ip = _inc_where(dataclasses.replace(f, status=None, not_status=None))
    out["demo_new"] = int(db.query(f"SELECT count(*) AS n FROM ({incidents.incidents_sql(mw, iw)}) WHERE state = 'new' AND demo",
                                   [*mp, *ip])[0]["n"] or 0)
    return out


@router.get("/alerts/count")
def alerts_count(since: str | None = None, until: str | None = None, since_hours: float | None = None):
    """The one alert count: needs_you = untriaged, not expected, non-demo incidents of high + medium severity;
    low, info, demo and expected are counted separately; open = every untriaged incident (the list's "New").
    The badge, the Network header and the list all use it. Definitions: okf/data/netlog.md#the-needs-you-count
    With a time range (since/until/since_hours, as the other alert filters) the same counts cover only incidents
    with an alert in that range: the Network Overview card at 24H/7D agrees with the header above it."""
    from . import incidents
    if since or until or since_hours:
        mw, mp, iw, ip = _inc_where(AlertFilter(since=since, until=until, since_hours=since_hours))
        out = incidents.needs_you(mw, iw, [*mp, *ip])
    else:
        out = incidents.needs_you()
    # whether the demo is loaded at all (its alerts may all be triaged): the Help desk offers "Remove demo data"
    # instead of "Load demo data" then
    out["demo_loaded"] = bool(db.query("SELECT count(*) AS n FROM netlog_files WHERE origin = 'demo'")[0]["n"])
    return out


def _publish() -> None:
    util.publish_alerts({"triage": True})


@router.get("/rules")
def rules_list():
    """"This is expected" rules, each with how many alerts and incidents it hides."""
    from . import incidents
    return incidents.list_rules()


@router.post("/rules")
def rules_create(body: dict = Body(...)):
    """Create a rule: {from_alert, scope: device_indicator | indicator | device_kind, note?, expires_days?} or
    {device?, indicator?, kind?, note?, expires_at?}."""
    from . import incidents
    try:
        r = incidents.create_rule(body)
    except LookupError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    _publish()
    return r


@router.put("/rules/{rid}")
def rules_update(rid: str, body: dict = Body(...)):
    from . import incidents
    try:
        r = incidents.update_rule(rid, body)
    except LookupError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    _publish()
    return r


@router.delete("/rules/{rid}")
def rules_delete(rid: str):
    from . import incidents
    if not incidents.delete_rule(rid):
        raise HTTPException(404, "no such rule")
    _publish()
    return {"deleted": rid}


@router.get("/alerts")
def alerts(f: AlertFilter = Depends(), limit: int = _limit(200), offset: int = _offset(), response: Response = None):
    """Alerts, highest severity first. limit=0 returns all of them."""
    where, p = _alert_where(f)
    if response is not None:
        response.headers["X-Total-Count"] = str(db.query(f"SELECT count(*) AS n FROM alerts {where}", p)[0]["n"])
    return _alerts_rows(where, p, limit, offset)


_SEV_ORD = "CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"


@router.get("/alerts/aggregate")
def alerts_aggregate(group: str = "rule", f: AlertFilter = Depends(), limit: int = _limit(50), sublimit: int = _limit(10)):
    """Alerts grouped by one or two fields (rule, indicator, device, source, severity, status, direction, day,
    evidence.<path>), with counts by severity."""
    fields = _csv(group)
    if not 1 <= len(fields) <= 2:
        raise HTTPException(400, "group takes one or two fields")
    exprs = [Q.alert_expr(x) for x in fields]
    where, p = _alert_where(f)

    def summary(level_exprs, top: int):
        """One row per group of the given expressions, with the alert summary fields: the `top` first groups (0: all),
        or with two expressions the `top` first children of each parent. The cap is applied in SQL, so a large alert
        table never hands back every group (or every parent and child pair) to be cut in Python."""
        keys = [f"g{i}" for i in range(len(level_exprs))]
        order = f"max({_SEV_ORD}) DESC, count(*) DESC"
        qualify, limit_, params = "", "", list(p)
        if top and len(level_exprs) == 1:
            limit_, params = "LIMIT ?", [*params, top]
        elif top:
            qualify, params = f"QUALIFY row_number() OVER (PARTITION BY g0 ORDER BY {order}) <= ?", [*params, top]
        return db.query(f"""
        SELECT {', '.join(f'{e} AS {k}' for e, k in zip(level_exprs, keys))}, count(*) AS count, sum("count") AS rows,
               ['info', 'low', 'medium', 'high'][max({_SEV_ORD}) + 1] AS max_severity,
               count(*) FILTER (WHERE severity = 'high') AS high, count(*) FILTER (WHERE severity = 'medium') AS medium,
               count(*) FILTER (WHERE severity = 'low') AS low, count(*) FILTER (WHERE severity = 'info') AS info,
               count(*) FILTER (WHERE status = 'new') AS open, min(ts) AS first, max(last_ts) AS last,
               count(DISTINCT device) AS devices, count(DISTINCT indicator) AS indicators
        FROM alerts {where} GROUP BY {', '.join(keys)} {qualify} ORDER BY {order} {limit_}""", params)

    # Parents are summarised in SQL over their own alerts (distinct devices/indicators cannot be
    # summed from children), so a parent has the same fields as a one-level group plus children.
    groups = [{"key": r.pop("g0"), **r} for r in summary(exprs[:1], limit)]
    if len(fields) == 2:
        kids: dict = defaultdict(list)
        for r in summary(exprs, sublimit):   # every parent's first `sublimit` children (parents are few)
            kids[r.pop("g0")].append({"key": r.pop("g1"), **r})
        for g in groups:
            g["children"] = kids.get(g["key"], [])
    total = db.query(f"SELECT count(*) AS n FROM alerts {where}", p)[0]["n"]   # every alert sits in exactly one group
    return _out({"group": fields, "total": total, "groups": groups})


@router.get("/alerts/timeline")
def alerts_timeline(bucket: str = "hour", f: AlertFilter = Depends(), split: str = "severity",
                    split_limit: int = _limit(8, 1000)):
    iv = BUCKETS.get(bucket)
    if not iv:
        raise HTTPException(400, "bucket must be minute, 5m, 15m, hour or day")
    where, p = _alert_where(f)
    rows = db.query(f"SELECT time_bucket(INTERVAL {iv}, ts) AS t, count(*) AS alerts FROM alerts {where} GROUP BY 1 ORDER BY 1", p)
    sr = db.query(f"""SELECT time_bucket(INTERVAL {iv}, ts) AS t, {Q.alert_expr(split)} AS v, count(*) AS n
                      FROM alerts {where} GROUP BY ALL""", p)
    _split_rows(rows, sr, split_limit)
    return _out(rows)


@router.get("/alerts/{aid}/uids")
def alert_uids(aid: str, limit: int = _limit(0), offset: int = _offset()):
    """Every Zeek uid behind an alert (evidence.uids is capped)."""
    lim = _page(limit, offset)
    rows = db.query(f"""SELECT uid, count(*) AS matches, min(ts) AS first, max(ts) AS last FROM netlog_matches
                        WHERE alert_id = ? AND uid IS NOT NULL GROUP BY uid ORDER BY uid {lim}""", [aid])
    total = db.query("SELECT count(DISTINCT uid) AS n FROM netlog_matches WHERE alert_id = ?", [aid])[0]["n"]
    if not total and not db.query("SELECT 1 FROM alerts WHERE id = ?", [aid]):
        raise HTTPException(404, "no such alert")
    return _out({"id": aid, "total": total, "offset": offset, "uids": rows})


@router.get("/alerts/{aid}")
def alert_detail(aid: str, rows_limit: int = _limit(500), rows_offset: int = _offset()):
    rows = _alerts_rows("WHERE id = ?", [aid], 1, 0)
    if not rows:
        raise HTTPException(404, "no such alert")
    a = rows[0]
    if a.get("rule") == "sensor_silent":  # a device stopped checking in (ingest.py): no log rows or indicators
        from . import ingest
        s = next((x for x in ingest.senders() if x["id"] == (a["evidence"].get("sender") or {}).get("id")), None)
        return {**a, "rows": [], "rows_total": 0, "related": [], "intervals": [], "sender_now": s}
    uids = a["evidence"].get("uids") or []
    lim = _page(rows_limit, rows_offset)
    inc = _incident_of(aid)
    a["incident"] = inc
    mem = inc["alerts"] if inc else [aid]
    ph = ",".join("?" * len(mem))
    a["rows"] = _out(db.query(f"""SELECT * EXCLUDE (rk) FROM netlog WHERE rk IN (SELECT rk FROM netlog_matches WHERE alert_id IN ({ph}))
                                  ORDER BY ts, rk {lim}""", mem))
    a["rows_total"] = db.query(f"SELECT count(DISTINCT rk) AS n FROM netlog_matches WHERE alert_id IN ({ph})", mem)[0]["n"]
    for r in a["rows"]:
        r["raw"] = json.loads(r["raw"]) if r.get("raw") else None
    if uids:
        a["related"] = _out(db.query(f"""SELECT * EXCLUDE (rk, raw) FROM netlog WHERE uid IN ({','.join('?' * len(uids[:100]))})
                                         ORDER BY ts LIMIT 500""", uids[:100]))
    a["intervals"] = indicators(value=a["indicator"], source=a["source"], limit=50)
    a["still"] = _still_for(a, inc, mem)
    if a.get("source") == "reported" or any(x.get("source") == "reported" for x in a["evidence"].get("also_listed") or []):
        a["reports"] = _reports(a["indicator"], a["evidence"])
    return a


# ------------------------------------------------------------------ "Still happening?"
ONGOING_HOURS = 12   # last contact this close to the end of the logs reads as ongoing
STILL_FROM = {"upload": "from files you uploaded", "inbox": "from your inbox folder", "api": "imported by a script"}
STILL_LABELS = {"upload": "Logs from files you uploaded", "inbox": "Logs from your inbox folder", "api": "Logs imported by a script"}


def _dur(s: float) -> str:
    s = abs(float(s))
    if s < 3600:
        m = max(1, round(s / 60))
        return f"{m} min"
    if s < 48 * 3600:
        h = round(s / 3600)
        return f"{h} h"
    d = int(s // 86400)
    return f"{d} day{'' if d == 1 else 's'}"


LOG_KIND = {"conn": "connection", "dns": "DNS", "ssl": "TLS", "http": "HTTP", "dhcp": "DHCP", "notice": "notice",
            "weird": "weird", "software": "software", "x509": "certificate", "files": "file"}


def _kind_words(types: list[str]) -> str:
    """'DNS logs', 'connection and DNS logs', 'Suricata logs': the kinds of log that produced an incident."""
    ts = sorted(set(types))
    if all(t.startswith("eve_") for t in ts):
        return "Suricata logs"
    return " and ".join(LOG_KIND.get(t, t) for t in ts if not t.startswith("eve_"))[:60] + " logs"


def still_happening(last_contact, origins: list[str], device: bool = False, log_types: list[str] | None = None) -> dict:
    """Is it still happening? The incident's last contact against how far the logs of the sensor that saw it
    reach ("logs cover up to"): the newest row of the same log types from the same source when log_types is given
    (falling back to the source's newest file only when those are unknown), in words: ongoing, stopped, or unknown when those logs are stale or missing.
    origins: netlog_files.origin values (upload, inbox, push:<sender>, demo, ...)."""
    from . import ingest
    now = util.now()
    last = last_contact if isinstance(last_contact, dt.datetime) or last_contact is None else dt.datetime.fromisoformat(str(last_contact))
    if last is not None and last.tzinfo is None:
        last = last.replace(tzinfo=dt.UTC)
    origins = [o or "api" for o in origins] or ["api"]
    rows = db.query("""SELECT coalesce(origin, 'api') AS o, max(ts_max) AS newest FROM netlog_files
                       WHERE coalesce(status, 'ok') = 'ok' AND coalesce(origin, 'api') IN (SELECT unnest(?::VARCHAR[]))
                       GROUP BY 1""", [origins])
    for r in rows:
        if r["newest"] is None:
            r["newest"] = db.query("""SELECT max(ts) AS t FROM netlog WHERE file_id IN
                                      (SELECT id FROM netlog_files WHERE coalesce(origin, 'api') = ?)""", [r["o"]])[0]["t"]
    rows = [r for r in rows if r["newest"] is not None]
    sensor = None
    if rows and log_types:
        # the same sensor: the newest row of the same kinds of log, from the same source, not just any file there
        per = db.query("""SELECT coalesce(f.origin, 'api') AS o, max(n.ts) AS newest FROM netlog n JOIN netlog_files f ON f.id = n.file_id
                          WHERE coalesce(f.status, 'ok') = 'ok' AND coalesce(f.origin, 'api') IN (SELECT unnest(?::VARCHAR[]))
                            AND n.log_type IN (SELECT unnest(?::VARCHAR[])) GROUP BY 1""", [origins, list(log_types)])
        per = [r for r in per if r["newest"] is not None]
        if per:
            rows, sensor = per, _kind_words(log_types)
    default_s = float(util.settings().get("stale_hours") or 24) * 3600
    out: dict = {"last_contact": last, "origins": origins}
    if not rows:
        out.update(state="unknown", text="Can't tell: no logs from this source to compare with")
        return _out(out)
    top = max(rows, key=lambda r: r["newest"])
    newest = top["newest"] if top["newest"].tzinfo else top["newest"].replace(tzinfo=dt.UTC)
    th = default_s
    if str(top["o"]).startswith("push:"):
        try:
            snd = next((x for x in ingest.senders() if x["name"] == top["o"][5:]), None)
            th = float(((snd or {}).get("health") or {}).get("threshold_s") or th)
        except Exception:
            pass
    # the subject of "... cover up to <time>" in the detail line
    label = ("The demo logs" if top["o"] == "demo" else f"Logs from {top['o'][5:]}" if str(top["o"]).startswith("push:")
             else STILL_LABELS.get(top["o"], f"Logs from {top['o']}"))
    if sensor:   # "DNS logs from files you uploaded", "Suricata logs in the demo"
        where = ("in the demo" if top["o"] == "demo" else f"from {top['o'][5:]}" if str(top["o"]).startswith("push:")
                 else STILL_FROM.get(top["o"], f"from {top['o']}"))
        label = f"{sensor[0].upper()}{sensor[1:]} {where}"
    age = (now - newest).total_seconds()
    gap = max(0.0, (newest - last).total_seconds()) if last else None
    out.update(covered_to=newest, logs_age_s=age, gap_s=gap, source=top["o"], source_label=label, stale=age > th)
    on, off = ("likely still on your network", "likely gone (switched off or left)") if device else ("likely ongoing", "likely stopped")
    if gap is None:
        out.update(state="unknown", text="Can't tell: no contact time recorded")
    elif age > th:
        out.update(state="unknown", text=f"Can't tell: your logs are {_dur(age)} old"
                   + (f" (last contact {_dur(gap)} before they end)" if gap >= 60 else " (last contact right at their end)"))
    elif gap <= ONGOING_HOURS * 3600:
        out.update(state="ongoing", text=(f"Last contact {_dur(gap)} before your logs end — {on}" if gap >= 60
                                          else f"Last contact right at the end of your logs — {on}"))
    else:
        out.update(state="stopped", text=f"No contact for {_dur(gap)}; logs are current — {off}")
    return _out(out)


def _still_for(a: dict, inc: dict | None, mem: list[str]) -> dict | None:
    try:
        if a.get("rule") == "new_device":
            d = db.query("SELECT last_seen FROM devices WHERE id = ?", [(a.get("evidence") or {}).get("merged_into") or a.get("device")])
            last = d[0]["last_seen"] if d else a.get("last_ts")
            origins = [r["o"] for r in db.query("SELECT DISTINCT coalesce(origin, 'api') AS o FROM netlog_files WHERE coalesce(origin, '') <> 'demo'")]
            return still_happening(last, origins, device=True)
        ph = ",".join("?" * len(mem))
        src = db.query(f"""SELECT DISTINCT coalesce(f.origin, 'api') AS o, n.log_type AS t FROM netlog_matches m
                           JOIN netlog n ON n.rk = m.rk JOIN netlog_files f ON f.id = n.file_id
                           WHERE m.alert_id IN ({ph})""", mem)
        origins = sorted({r["o"] for r in src})
        types = sorted({r["t"] for r in src if r["t"]})
        if not origins:
            demo = (inc or {}).get("demo") or a.get("demo")
            origins = ["demo"] if demo else [r["o"] for r in db.query(
                "SELECT DISTINCT coalesce(origin, 'api') AS o FROM netlog_files WHERE coalesce(origin, '') <> 'demo'")]
        return still_happening((inc or {}).get("last_ts") or a.get("last_ts") or a.get("ts"), origins,
                               log_types=types if origins and types else None)
    except Exception:
        log.exception("netlog: still-happening line failed")
        return None


def _incident_of(aid: str) -> dict | None:
    """The incident an alert belongs to: its alerts, first and last contact, day span, state and the rule that
    hides it (if any)."""
    from . import incidents
    rows = db.query(incidents.incidents_sql("WHERE coalesce(incident, id) = (SELECT coalesce(incident, id) FROM alerts WHERE id = ?)"),
                    [aid])
    if not rows:
        return None
    r = rows[0]
    out = {k: r[k] for k in ("id", "lead", "ts", "last_ts", "severity", "count", "n_alerts", "alerts", "days", "status",
                             "state", "reopened", "suppressed", "demo", "kind", "sources")}
    if r["expected_rule"]:
        rr = db.query("SELECT * FROM netlog_rules WHERE id = ?", [r["expected_rule"]])
        out["rule"] = rr[0] if rr else None
    if r["reopened"]:
        t = db.query(f"""SELECT max(updated_at) AS t, any_value(status) AS s FROM alerts
                         WHERE id IN ({','.join('?' * len(r['alerts']))}) AND status <> 'new'""", r["alerts"])[0]
        out["triaged"] = {"status": t["s"], "at": t["t"]}
    return _out(out)


def _reports(value: str, ev: dict) -> list[dict]:
    """The stories and articles that named this indicator (reported IOCs): title, outlet, date, link and the
    sentence it appeared in, newest first."""
    from . import intervals
    tables = db.tables()
    if "mentions" not in tables:
        return []
    keys = [r["key"] for r in db.query("SELECT DISTINCT key FROM indicator_intervals WHERE source = 'reported' AND value = ?",
                                       [value]) if r["key"]]
    if not keys:
        return []
    out = []
    ph = ",".join("?" * len(keys))
    if "articles" in tables:
        story = "LEFT JOIN stories s ON s.id = a.story_id" if "stories" in tables else ""
        st_title = "s.title" if "stories" in tables else "NULL"
        for r in db.query(f"""SELECT DISTINCT a.id, a.title, a.source, a.published, a.url, a.story_id, {st_title} AS story_title,
                                     a.text, m.role
                              FROM mentions m JOIN articles a ON m.ref_type = 'article' AND a.id = m.ref_id {story}
                              WHERE m.entity_id IN ({ph}) ORDER BY a.published DESC NULLS LAST LIMIT 12""", keys):
            out.append({"type": "article", "id": r["id"], "title": r["title"], "source": r["source"],
                        "published": r["published"], "url": r["url"], "story_id": r["story_id"],
                        "story_title": r["story_title"], "role": r["role"], "quote": _quote(r.get("text"), value, intervals)})
    if "events" in tables:
        for r in db.query(f"""SELECT DISTINCT e.id, e.title, e.source, e.ts, e.url, e.summary FROM mentions m
                              JOIN events e ON m.ref_type = 'event' AND e.id = m.ref_id
                              WHERE m.entity_id IN ({ph}) ORDER BY e.ts DESC NULLS LAST LIMIT 6""", keys):
            out.append({"type": "event", "id": r["id"], "title": r["title"], "source": r["source"], "published": r["ts"],
                        "url": r["url"], "quote": _quote(r.get("summary"), value, intervals)})
    return _out(out)


_MD_LINK = re.compile(r"!?\[((?:\\.|[^\]\\])*)\]\([^)]*\)")   # link text may hold escaped brackets: [1.2.3\[.\]4](url)
_MD_JUNK = re.compile(r"(^|\s)[#>*|-]+\s+|[*_`|]+|\\(?=[\[\].()])")


def _plain(t: str) -> str:
    """Markdown and table syntax out, one line: [text](url) -> text, \\[.\\] -> [.], no list or heading marks."""
    t = _MD_LINK.sub(r"\1", t)
    t = _MD_JUNK.sub(lambda m: m.group(1) or "", t)
    return re.sub(r"\s+", " ", t).strip()


def _quote(text: str | None, value: str, intervals) -> str | None:
    """The sentence around the first mention of value, as plain text (no markdown), cut at word boundaries and
    shown defanged."""
    if not text:
        return None
    try:
        t = intervals._refang(text)
    except Exception:
        t = text
    t = _plain(t)
    i = t.lower().find(value.lower())
    if i < 0:
        return None
    lo = max(t.rfind(". ", 0, i) + 2, i - 200, 0)
    hi = t.find(". ", i)
    hi = len(t) if hi < 0 else hi + 1
    hi = min(hi, i + len(value) + 220)
    if lo > 0 and t[lo - 1] not in " .":   # do not start mid-word
        sp = t.find(" ", lo)
        lo = sp + 1 if 0 <= sp < i else lo
    if hi < len(t) and t[hi - 1] not in ".":   # do not end mid-word
        sp = t.rfind(" ", i + len(value), hi)
        hi = sp if sp > 0 else hi
    q = t[lo:hi].strip()
    if not q:
        return None
    q = ("… " if lo > 0 and t[lo - 2:lo] != ". " else "") + q + ("…" if hi < len(t) and not q.endswith(".") else "")
    return q.replace(value, value.replace(".", "[.]", 1))


def _set_status(ids: list[str], status: str) -> int:
    """Set the status of these alerts and of every other alert in their incidents (a beacon that ran past UTC
    midnight is triaged once). Returns how many of the given ids exist."""
    from . import incidents
    if status not in STATUSES:
        raise HTTPException(400, f"status must be one of {sorted(STATUSES)}")
    if not ids:
        return 0
    given = db.query(f"SELECT count(*) AS n FROM alerts WHERE id IN ({','.join('?' * len(ids))})", ids)[0]["n"]
    ids = incidents.members(ids) or ids
    n = db.query(f"SELECT count(*) AS n FROM alerts WHERE id IN ({','.join('?' * len(ids))})", ids)[0]["n"]
    db.execute(f"UPDATE alerts SET status = ?, updated_at = now() WHERE id IN ({','.join('?' * len(ids))})", [status, *ids])
    # with each alert's severity now: only a rise above it reopens the alert (okf/data/netlog.md#alert-status)
    found = db.query(f"SELECT id, severity FROM alerts WHERE id IN ({','.join('?' * len(ids))})", ids)
    for r in found:
        db.execute("INSERT OR REPLACE INTO netlog_alert_status (id, status, updated_at, severity) VALUES (?, ?, now(), ?)",
                   [r["id"], status, r["severity"]])
    if n:
        _publish()
    return given


@router.patch("/alerts/{aid}")
@router.post("/alerts/{aid}/status")
def alert_status(aid: str, body: dict = Body(...)):
    if not _set_status([aid], str(body.get("status"))):
        raise HTTPException(404, "no such alert")
    return {"id": aid, "status": body.get("status")}


@router.post("/alerts/status")
def alerts_status(body: dict = Body(...)):
    ids = [str(i) for i in body.get("ids") or []]
    return {"updated": _set_status(ids, str(body.get("status"))), "status": body.get("status")}


@router.post("/incidents/status")
def incidents_status(body: dict = Body(...)):
    """Set the status of whole incidents: {ids: [any alert id of each incident], status}."""
    ids = [str(i) for i in body.get("ids") or []]
    from . import incidents
    return {"updated": _set_status(ids, str(body.get("status"))), "alerts": len(incidents.members(ids)),
            "status": body.get("status")}
