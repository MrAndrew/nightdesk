"""Derived analytics: Cyber Pulse index, timelines, country rollups.

Cyber Pulse never scores missing data: a sub-index counts only while the feed behind it is current (see
INDEX_SOURCES), and with fewer than MIN_CURRENT current inputs there is no overall score at all, only a state
("warming", "stale" or "off"). Reference: okf/data/cyber-pulse.md
"""
from __future__ import annotations

import math

from . import db


def _scale(x: float, full: float) -> float:
    """Log-ish 0..100 scale where `full` maps to ~100."""
    if x <= 0:
        return 0.0
    return max(0.0, min(100.0, 100 * math.log1p(x) / math.log1p(full)))


def _count(where: str, hours_from: float, hours_to: float = 0, params: list | None = None) -> float:
    sql = (f"SELECT count(*) AS n FROM events WHERE {where} "
           f"AND ts > now() - INTERVAL ({hours_from}) HOUR AND ts <= now() - INTERVAL ({hours_to}) HOUR")
    return float(db.query(sql, params or [])[0]["n"])


def _sev_sum(where: str, hours_from: float, hours_to: float = 0) -> float:
    sql = (f"SELECT coalesce(sum(severity), 0) AS n FROM events WHERE {where} "
           f"AND ts > now() - INTERVAL ({hours_from}) HOUR AND ts <= now() - INTERVAL ({hours_to}) HOUR")
    return float(db.query(sql)[0]["n"])


def _metric_avg(name: str, minutes_from: float, minutes_to: float = 0) -> float | None:
    r = db.query(
        f"SELECT avg(value) AS v FROM metrics WHERE name = ? AND ts > now() - INTERVAL ({minutes_from}) MINUTE "
        f"AND ts <= now() - INTERVAL ({minutes_to}) MINUTE", [name])
    return r[0]["v"]


def _indices(offset_h: float) -> dict[str, float]:
    """Each sub-index 0..100 over its window ending offset_h hours ago. Routing's churn half is used only when
    both the recent and the baseline withdrawal rates were measured; there is no made-up neutral value."""
    o = offset_h
    exploitation = 0.6 * _scale(_count("kind = 'kev'", 24 * 7 + o, o), 20) + \
        0.4 * _scale(_count("kind = 'cve' AND severity >= 0.9", 24 + o, o), 60)
    ransomware = _scale(_count("kind = 'ransomware'", 24 + o, o), 60)
    outages = _scale(_sev_sum("kind = 'outage'", 24 + o, o), 40)
    routing_events = _count("kind IN ('bgp_origin_change', 'bgp_withdrawal_burst')", 1 + o, o)
    wd_now = _metric_avg("bgp.withdrawals_per_s", 15 + o * 60, o * 60)
    wd_base = _metric_avg("bgp.withdrawals_per_s", 24 * 60 + o * 60, o * 60)
    if wd_now is not None and wd_base:
        routing = 0.5 * max(0, min(100, 50 * wd_now / wd_base)) + 0.5 * _scale(routing_events, 300)
    else:
        routing = _scale(routing_events, 300)
    chatter = _scale(_count("kind = 'social'", 1 + o, o), 400)
    return {
        "exploitation": round(exploitation, 1),
        "ransomware": round(ransomware, 1),
        "connectivity": round(outages, 1),
        "routing": round(routing, 1),
        "chatter": round(chatter, 1),
    }


INDEX_META = {
    "exploitation": ("Exploitation", "New CISA KEV entries (7d) and critical CVEs (24h)"),
    "ransomware": ("Ransomware", "Victims posted to leak sites in the last 24h"),
    "connectivity": ("Connectivity", "Severity-weighted internet outages in the last 24h"),
    "routing": ("Routing", "Routing churn of the networks RIS Live follows (Routing watch) vs its 24h baseline; off unless RIS Live is on"),
    "chatter": ("Chatter", "Cyber posts on the Bluesky firehose in the last hour"),
}
WEIGHTS = {"exploitation": 0.25, "ransomware": 0.25, "connectivity": 0.2, "routing": 0.15, "chatter": 0.15}


# The feeds behind each sub-index. An input is current while one of its feeds delivered recently: a batch feed
# had a successful run within FRESH_RUNS of its interval (and at least FRESH_MIN_S), a stream sent data (events
# or rate metrics) within STREAM_FRESH_S.
INDEX_SOURCES = {
    "exploitation": ("cisa_kev", "nvd_recent"),
    "ransomware": ("ransomware_live",),
    "connectivity": ("ioda_outages",),
    "routing": ("ris_live",),
    "chatter": ("bluesky_cyber",),
}
STREAM_METRICS = {"ris_live": "bgp.%", "bluesky_cyber": "bluesky.%"}
FRESH_RUNS = 3
FRESH_MIN_S = 3 * 3600
STREAM_FRESH_S = 15 * 60
MIN_CURRENT = 3   # with fewer current inputs there is no overall score

INPUT_NOTE = {
    "current": "",
    "stale": "No recent data: its source has not delivered for a while",
    "waiting": "Waiting for its source's first data",
    "off": "Its source is turned off or needs a key (see Settings › Sources)",
}
_RANK = {"current": 0, "stale": 1, "waiting": 2, "off": 3}


def _age_s(t) -> float | None:
    if t is None:
        return None
    return float(db.query("SELECT epoch(now()) - epoch(?::TIMESTAMPTZ) AS s", [t])[0]["s"])


def _source_input(sid: str, st: dict) -> dict:
    """One feed: {state: current|stale|waiting|off, last: its latest data (stream) or successful run (batch)}."""
    from .sources import SOURCES
    src = SOURCES.get(sid)
    enabled = (src.default_enabled if src else False) if st.get("enabled") is None else bool(st["enabled"])
    if src is not None and src.unavailable():
        enabled = False
    if src is not None and src.mode == "stream":
        m = db.query("SELECT max(ts) AS t FROM metrics WHERE name LIKE ?", [STREAM_METRICS.get(sid, sid + ".%")])[0]["t"]
        e = db.query("SELECT max(ingested_at) AS t FROM events WHERE source = ?", [sid])[0]["t"]
        last = max([t for t in (m, e) if t is not None], default=None)
        fresh = STREAM_FRESH_S
    else:
        last = st.get("last_ok")
        fresh = max(FRESH_RUNS * (src.interval if src else 3600), FRESH_MIN_S)
    age = _age_s(last)
    if age is not None and age <= fresh:
        state = "current"
    elif not enabled:
        state = "off"
    elif last is not None:
        state = "stale"
    else:
        state = "waiting"
    return {"state": state, "last": last}


def inputs() -> dict[str, dict]:
    """Per sub-index: its best feed's state (current beats stale beats waiting beats off) and latest data time."""
    states = {r["id"]: r for r in db.query("SELECT * FROM source_state")}
    out = {}
    for k, sids in INDEX_SOURCES.items():
        ins = [_source_input(s, states.get(s, {})) for s in sids]
        best = min(ins, key=lambda x: _RANK[x["state"]])
        lasts = [x["last"] for x in ins if x["last"] is not None]
        out[k] = {"state": best["state"], "last": max(lasts) if lasts else None}
    return out


def _iso(t):
    return t.isoformat() if hasattr(t, "isoformat") else t


def pulse() -> dict:
    """The composite over the sub-indices whose inputs are current, re-weighted among them.

    state: 'ok' (every input current), 'partial' (at least MIN_CURRENT current; the rest stale, waiting or off),
    'warming' (too few current, nothing stale: a fresh install whose feeds have not delivered yet), 'stale' (too
    few current and some inputs that delivered before have stopped), 'off' (too few feeds turned on).
    score, level and change_24h are None unless state is 'ok' or 'partial'."""
    ins = inputs()
    now_i = _indices(0)
    prev_i = _indices(24)
    cur = [k for k in WEIGHTS if ins[k]["state"] == "current"]
    n, total = len(cur), len(WEIGHTS)
    counts = {s: sum(1 for k in WEIGHTS if ins[k]["state"] == s) for s in _RANK}
    score = change = level = None
    weights: dict[str, float] = {}
    if n >= MIN_CURRENT:
        tw = sum(WEIGHTS[k] for k in cur)
        weights = {k: WEIGHTS[k] / tw for k in cur}
        comp = sum(now_i[k] * w for k, w in weights.items())
        prev = sum(prev_i[k] * w for k, w in weights.items())
        score, change = round(comp, 1), round(comp - prev, 1)
        level = "LOW" if comp < 25 else "GUARDED" if comp < 45 else "ELEVATED" if comp < 65 else "HIGH" if comp < 80 else "SEVERE"
        state = "ok" if n == total else "partial"
    elif counts["stale"]:
        state = "stale"
    elif counts["waiting"]:
        state = "warming"
    else:
        state = "off"
    label = {
        "ok": None,
        "partial": f"{n} of {total} inputs current",
        "stale": f"Stale — {n} of {total} inputs current",
        "warming": f"Warming up — {n} of {total} inputs in",
        "off": f"Too few sources on — {n} of {total} inputs",
    }[state]
    return {
        "score": score,
        "change_24h": change,
        "level": level,
        "state": state,
        "label": label,
        "current": n,
        "total": total,
        "min_current": MIN_CURRENT,
        "indices": [
            {"id": k, "label": INDEX_META[k][0], "help": INDEX_META[k][1],
             "status": ins[k]["state"], "note": INPUT_NOTE[ins[k]["state"]], "last_data": _iso(ins[k]["last"]),
             "value": now_i[k] if k in cur else None,
             "change_24h": round(now_i[k] - prev_i[k], 1) if k in cur else None,
             "weight": round(weights.get(k, 0), 3), "active": ins[k]["state"] == "current"}
            for k in WEIGHTS
        ],
    }
