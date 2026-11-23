"""The new-device rule: a device seen for the first time raises an info incident "New device joined: <name>".

Runs at the end of every device rebuild (devices._rebuild), on the devices as they are after your merges, so a
device is its stable identity (MAC when known, else its address) and a device you merged into another is that one.

* **Known devices** (netlog_known_devices) are every device Night Desk has seen, with how it learned it. A device
  is never new twice, so turning the rule off and on, a re-import or a rebuild never raises it again.
* **Learning period.** The first time devices are built (an empty lake's first import, or the first rebuild after
  upgrading), every device then present is taken as yours. Learning then lasts until BOTH your logs cover
  LEARN_LOG_DAYS (7) days AND LEARN_WALL_HOURS (24) hours have passed since that first build; every device that
  appears meanwhile (the other files of a big first import, a phone that is quiet for days) is taken as yours too.
* **Only newcomers, only now.** A device is announced only if its first log row is recent: within RECENT_HOURS (48)
  of now. A device first seen in older logs that are imported now is a historical arrival and is recorded quietly
  (`history`), as is one older than what Night Desk had already seen (LATE_HOURS of slack for late logs), which
  became visible because of a new home prefix (`recognized`). IPv6 privacy addresses that no MAC or name ties to a device (fragments) are
  never announced: they rotate daily. Demo devices are never announced either.
* **Off switch.** PUT /api/netlog/newdev {"enabled": false}: devices are still recorded as known, without incidents.
* The incident is info (it never counts in "needs you"), one per device, kind `newdev`, and goes through the
  incident machinery: acknowledge or dismiss it, or an expected-traffic rule for this device and this kind hides it.
  If you merge the device into one you already had, its incident is dismissed (it was not new after all); if the
  device disappears (its logs or the demo were removed), the incident goes with it.

Docs: okf/data/netlog.md#new-devices
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json

from fastapi import APIRouter, Body, HTTPException

from .. import db
from . import ipnum, util

router = APIRouter(prefix="/newdev", tags=["netlog"])  # mounted under /api/netlog by ext.py

STATE_KEY = "netlog_newdev"
LEARN_LOG_DAYS = 7      # learning lasts until the logs cover this many days ...
LEARN_WALL_HOURS = 24   # ... and this long has passed since the first build
RECENT_HOURS = 48       # only a device first seen this recently (wall clock) is announced
LATE_HOURS = 6
RULE = "new_device"
SOURCE = "devices"

SCHEMA = """
CREATE TABLE IF NOT EXISTS netlog_known_devices (
    id          VARCHAR PRIMARY KEY,   -- device id (mac:<mac> or ip:<ip>)
    noticed_at  TIMESTAMPTZ,           -- when Night Desk first had it
    first_seen  TIMESTAMPTZ,           -- its first log row then
    how         VARCHAR,               -- baseline | learning | history | recognized | fragment | demo | off | alerted
    alert_id    VARCHAR
);
"""


def _state(cur=None) -> dict:
    if cur is not None:
        r = cur.execute("SELECT value FROM settings WHERE key = ?", [STATE_KEY]).fetchall()
        return json.loads(r[0][0]) if r else {}
    return db.get_setting(STATE_KEY) or {}


def _save(cur, st: dict) -> None:
    cur.execute("INSERT OR REPLACE INTO settings VALUES (?, ?)", [STATE_KEY, json.dumps(util.jsonable(st), default=str)])


def enabled(st: dict | None = None) -> bool:
    st = _state() if st is None else st
    return st.get("enabled", True) is not False


def alert_id(did: str) -> str:
    return "nl-dev-" + hashlib.md5(did.encode()).hexdigest()[:16]


def _demo_ranges() -> list[tuple[int, int]]:
    from .demo import DEMO_PREFIXES
    return [r[:2] for p in DEMO_PREFIXES if (r := ipnum.net_range(p))]


def _is_demo(d: dict, ranges) -> bool:
    ips = d.get("ips") or []
    if not ips:
        return False
    for ip in ips:
        n = ipnum.ip_int(ip)
        if n is None or not any(lo <= n <= hi for lo, hi in ranges):
            return False
    return True


def _ts(v) -> dt.datetime | None:
    if v is None:
        return None
    if isinstance(v, dt.datetime):
        return v if v.tzinfo else v.replace(tzinfo=util.UTC)
    try:
        t = dt.datetime.fromisoformat(str(v))
        return t if t.tzinfo else t.replace(tzinfo=util.UTC)
    except ValueError:
        return None


def detect(cur, prev: list[dict] | None = None) -> dict:
    """Compare the rebuilt devices with the known ones and raise incidents for newcomers. prev: the devices before
    this rebuild (id, ips, first_seen, last_seen). Caller holds the write lock (devices._rebuild, in its transaction)."""
    from . import devices, incidents
    cur.execute(SCHEMA)
    incidents.ensure(cur)
    st = _state(cur)
    devs = util.rows_of(cur, """SELECT id, identity, mac, ips, hostnames, first_seen, last_seen, rows, conns, top_dests,
                                       top_names, confidence, evidence FROM devices""")
    known = {r[0]: r[1] for r in cur.execute("SELECT id, how FROM netlog_known_devices").fetchall()}
    resolve = devices.merge_resolver(cur)
    ranges = _demo_ranges()
    real = [d for d in devs if not _is_demo(d, ranges)]
    out = {"new": [], "quiet": 0}
    rows: list[tuple] = []
    now = util.now()
    if not st.get("baseline_at"):
        # learning: the devices of the lake as it was (an upgraded lake), else of this first import, are yours
        old = [d for d in (prev or []) if not _is_demo(d, ranges)]
        base = old or real
        if base:
            first = min((_ts(d["first_seen"]) for d in base if d.get("first_seen")), default=now)
            last = max((_ts(d["last_seen"]) for d in base if d.get("last_seen")), default=None)
            st.update(baseline_at=now, first_log=first, seen_until=last)
            for d in base:
                if d["id"] not in known:
                    rows.append((d["id"], now, d.get("first_seen"), "baseline", None))
                    known[d["id"]] = "baseline"
            out["baseline"] = len(rows)
    known_res = {resolve(k) for k in known}   # a device you merged another into is known when any of its parts is
    seen_until = _ts(st.get("seen_until"))
    firsts = [_ts(d["first_seen"]) for d in real if d.get("first_seen")]
    if st.get("baseline_at") and firsts and (not _ts(st.get("first_log")) or min(firsts) < _ts(st["first_log"])):
        st["first_log"] = min(firsts)   # older logs imported later extend what the logs cover
    lasts = [_ts(d["last_seen"]) for d in real if d.get("last_seen")]
    covered_to = max([x for x in [seen_until, *lasts] if x], default=None)
    learning = is_learning(st, now, covered_to)
    on = enabled(st)
    new_alerts = []
    for d in devs:
        if d["id"] in known or d["id"] in known_res:
            continue
        fs = _ts(d["first_seen"])
        nm = _ev(d).get("naming") or {}
        if _is_demo(d, ranges):
            how = "demo"
        elif not st.get("baseline_at"):
            continue   # nothing real yet: decided with the first real devices
        elif learning:
            how = "learning"
        elif not fs or fs < now - dt.timedelta(hours=RECENT_HOURS):
            how = "history"   # first seen in older logs imported now: it did not just join
        elif seen_until and fs and fs <= seen_until - dt.timedelta(hours=LATE_HOURS):
            how = "recognized"
        elif nm.get("fragment"):
            how = "fragment"
        elif not on:
            how = "off"
        else:
            how = "alerted"
        aid = alert_id(d["id"]) if how == "alerted" else None
        rows.append((d["id"], now, d["first_seen"], how, aid))
        if aid:
            new_alerts.append((d, aid))
        else:
            out["quiet"] += 1
    if new_alerts:
        _put_alerts(cur, new_alerts, resolve)
        out["new"] = [d["id"] for d, _ in new_alerts]
    if rows:
        cur.executemany("INSERT OR REPLACE INTO netlog_known_devices VALUES (?, ?, ?, ?, ?)", rows)
    last = max((_ts(d["last_seen"]) for d in real if d["last_seen"]), default=None)
    if st.get("baseline_at"):
        if last and (not seen_until or last > seen_until):
            st["seen_until"] = last
        _save(cur, st)
    out["tidied"] = _tidy(cur, {d["id"] for d in devs}, resolve)
    if out["new"] or out["tidied"]:
        incidents.regroup(cur)
        try:
            from .. import bus
            bus.publish("netlog_alerts", {"new_devices": len(out["new"])})
        except Exception:
            pass
    return out


def is_learning(st: dict, now: dt.datetime, covered_to: dt.datetime | None = None) -> bool:
    """Still learning: no baseline yet, or less than LEARN_WALL_HOURS since it, or logs covering under LEARN_LOG_DAYS."""
    base, first = _ts(st.get("baseline_at")), _ts(st.get("first_log"))
    to = covered_to or _ts(st.get("seen_until"))
    if not base:
        return True
    if now < base + dt.timedelta(hours=LEARN_WALL_HOURS):
        return True
    return not (first and to and to - first >= dt.timedelta(days=LEARN_LOG_DAYS))


def _ev(d: dict) -> dict:
    try:
        return json.loads(d.get("evidence") or "{}") if isinstance(d.get("evidence"), str) else (d.get("evidence") or {})
    except ValueError:
        return {}


def _put_alerts(cur, items: list[tuple[dict, str]], resolve) -> None:
    from . import devices
    labels = devices.labels([d["id"] for d, _ in items]) if items else {}
    recs = []
    for d, aid in items:
        ev0 = _ev(d)
        row = {**d, "evidence": ev0}
        p = devices.present(dict(row), labels.get(d["id"]))
        nm = p.get("naming") or {}
        # the hint is a maker (from the logs, or Apple from its services), else a type guess or an address kind
        not_maker = {None, "private address", "IPv6 address", *(t.lower() for t in devices.TYPES.values())}
        vendor = nm.get("hint") if nm.get("hint") not in not_maker else None
        try:
            dests = json.loads(d.get("top_dests") or "[]")[:5]
            names = json.loads(d.get("top_names") or "[]")[:5]
        except ValueError:
            dests, names = [], []
        private = False
        if d.get("mac"):
            try:
                private = bool(int(d["mac"].split(":")[0], 16) & 2)
            except ValueError:
                pass
        ev = {"kind": "new_device",
              "device": {"id": d["id"], "identity": d["identity"], "mac": d.get("mac"), "home_ips": d.get("ips") or [],
                         "hostnames": d.get("hostnames") or [], "confidence": d.get("confidence"), "name": p["name"],
                         "name_source": p["name_source"], "type": p.get("type"), "vendor": vendor,
                         "private_mac": private},
              "first_seen": d["first_seen"], "last_seen": d["last_seen"], "rows": d.get("rows"), "conns": d.get("conns"),
              "top_dests": dests, "top_names": names,
              "rule": {"id": RULE, "direction": "device", "severity": "info",
                       "description": "A device Night Desk had not seen before appeared in your logs."}}
        recs.append([aid, d["first_seen"], d["first_seen"], d["id"], d.get("mac") or (d.get("ips") or [d["id"]])[0],
                     f"New device joined: {p['name']}", int(d.get("rows") or 1),
                     json.dumps(util.jsonable(ev), default=str), aid])
    cur.executemany(f"""
        INSERT INTO alerts (id, ts, last_ts, severity, device, indicator, source, rule, direction, title, count, evidence,
                            status, created_at, updated_at, demo)
        VALUES (?, ?, ?, 'info', ?, ?, '{SOURCE}', '{RULE}', NULL, ?, ?, ?,
                coalesce((SELECT status FROM netlog_alert_status WHERE id = ?), 'new'), now(), now(), false)
        ON CONFLICT (id) DO NOTHING""", recs)


def _tidy(cur, current: set[str], resolve) -> int:
    """New-device incidents whose device is gone: merged into another device (dismissed, it was not new) or
    removed with its logs (deleted)."""
    n = 0
    for aid, did, ev, status in cur.execute(f"SELECT id, device, evidence, status FROM alerts WHERE rule = '{RULE}'").fetchall():
        if did in current:
            continue
        to = resolve(did)
        if to != did and to in current:
            e = json.loads(ev or "{}")
            if e.get("merged_into") == to:
                continue
            e["merged_into"] = to
            cur.execute("UPDATE alerts SET evidence = ?, status = CASE WHEN status = 'new' THEN 'dismissed' ELSE status END, "
                        "updated_at = now() WHERE id = ?", [json.dumps(e, default=str), aid])
            if status == "new":
                cur.execute("INSERT OR REPLACE INTO netlog_alert_status (id, status, updated_at, severity) "
                            "VALUES (?, 'dismissed', now(), 'info')", [aid])
        else:
            cur.execute("DELETE FROM alerts WHERE id = ?", [aid])
            cur.execute("DELETE FROM netlog_alert_status WHERE id = ?", [aid])
        n += 1
    return n


# ------------------------------------------------------------------ API
def status() -> dict:
    st = _state()
    try:
        counts = {r["how"]: r["n"] for r in db.query("SELECT how, count(*) AS n FROM netlog_known_devices GROUP BY 1")}
    except Exception:
        counts = {}
    now = util.now()
    base, first, to = _ts(st.get("baseline_at")), _ts(st.get("first_log")), _ts(st.get("seen_until"))
    days = round((to - first).total_seconds() / 86400, 1) if first and to else 0
    return util.jsonable({
        "enabled": enabled(st), "baseline_at": base, "learning": is_learning(st, now),
        "learn_until_wall": base + dt.timedelta(hours=LEARN_WALL_HOURS) if base else None,
        "logs_days": days, "learn_log_days": LEARN_LOG_DAYS, "learn_wall_hours": LEARN_WALL_HOURS,
        "recent_hours": RECENT_HOURS, "late_hours": LATE_HOURS, "first_log": first, "seen_until": to,
        "known": sum(counts.values()), "by_how": counts})


@router.get("")
def api_status():
    """The new-device rule: on or off, whether it is still learning, and how many devices it knows."""
    return status()


@router.put("")
def api_set(body: dict = Body(...)):
    if not isinstance(body, dict) or not isinstance(body.get("enabled"), bool):
        raise HTTPException(400, "enabled must be true or false")
    with db._write_lock:
        cur = db.cursor()
        st = _state(cur)
        st["enabled"] = body["enabled"]
        _save(cur, st)
    return status()
