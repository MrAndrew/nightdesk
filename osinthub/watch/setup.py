"""Setup checklist: what is running and what is left to do, from real state. Watch shows it on a new lake; the Help
desk reuses GET /api/setup/status. Reference: okf/architecture/watch.md#setup-status
"""
from __future__ import annotations

from .. import config, db
from ..sources.base import key_steps

DISMISS_KEY = "watch.setup_dismissed"
# The setting names, for hover titles only: primary text says what to do in plain language.
OFFLINE_TECH = "Offline mode is the OSINTHUB_OFFLINE=1 setting in the command or file that starts Night Desk."
ABUSECH_TECH = ("The key is the ABUSECH_AUTH_KEY setting: in the Docker install, the .env file in its install folder "
                "(then run the install line again); otherwise the environment that starts Night Desk (then restart).")


def _tables() -> set[str]:
    return db.tables()


def _feeds() -> dict:
    from .. import scheduler
    from ..sources import SOURCES
    states = {r["id"]: r for r in db.query("SELECT id, status, last_ok FROM source_state")}
    on = [s for s in SOURCES.values() if scheduler.is_enabled(s) and not s.unavailable()]
    ok = [s for s in on if (states.get(s.id) or {}).get("last_ok")]
    first = db.query("SELECT min(ingested_at) AS t, count(*) AS n FROM events")[0]
    has_data = bool(first["n"])
    if has_data:
        detail = f"{len(ok)} of {len(on)} sources have fetched; {first['n']:,} items so far."
    elif config.OFFLINE:
        detail = "Offline mode is on, so nothing is fetched and no data has arrived yet."
    elif on:
        detail = f"{len(on)} sources are on. The first data usually arrives within a few minutes."
    else:
        detail = "Every source is turned off. Turn some on in Settings › Sources."
    action = {"label": "Open Sources", "href": "#settings/sources"}
    try:   # a new lake gets the one-time "Choose your sources" step in Settings › Sources
        from .. import feed_terms
        if feed_terms.state() == "pending":
            action = {"label": "Choose your sources", "href": "#settings/sources/choose"}
            detail += " First, choose which sources to use: each one's terms are listed."
    except Exception:
        pass
    # primary text names no setting; `tech` (shown on hover) names the variable
    return {"id": "feeds", "title": "Sources running", "done": has_data and bool(ok), "optional": False,
            "detail": detail, "first_data": first["t"], "enabled": len(on), "fetched": len(ok),
            "tech": OFFLINE_TECH if config.OFFLINE and not has_data else None, "action": action}


def _netlog(tables: set[str]) -> tuple[int, bool]:
    if "netlog_files" not in tables:
        return 0, False
    r = db.query("""SELECT count(*) FILTER (WHERE coalesce(origin, '') <> 'demo') AS real,
                           count(*) FILTER (WHERE origin = 'demo') AS demo FROM netlog_files""")[0]
    return int(r["real"] or 0), bool(r["demo"])


def _abusech() -> dict:
    from ..sources import SOURCES
    s = SOURCES.get("threatfox")
    missing = s.unavailable() if s else "not available in this build"
    return {"id": "abusech", "title": "Add the free abuse.ch key", "done": not missing, "optional": True,
            "detail": ("Key set: ThreatFox and URLhaus can run." if not missing else
                       "Unlocks ThreatFox and URLhaus: fresh malware servers and links to check your logs against, "
                       f"and two more demo scenarios. Get your free key at auth.abuse.ch, then {key_steps()}."),
            "tech": None if not missing else ABUSECH_TECH,
            "action": {"label": "How to add it", "href": "#sources"}}


def _watch() -> dict:
    """"Follow what you run": done once anything is followed (My stack, osinthub/stack.py). `quick` holds the
    "What do you run?" chips (common home-lab gear, with how many exploited bugs each matches); `suggest` the
    vendors most often in CISA KEV."""
    from .. import stack
    w = stack.get()
    n = len(w["entities"]) + len(w["keywords"]) + len(w["stack"])
    sugg = []
    try:   # the vendors most often in CISA KEV: one click follows them
        sugg = [r["v"] for r in db.query("""SELECT tags[1] AS v, count(*) AS n FROM events
                                            WHERE source = 'cisa_kev' AND len(tags) > 0 AND tags[1] <> 'ransomware'
                                            GROUP BY 1 ORDER BY n DESC, v LIMIT 10""")]
    except Exception:
        pass
    have = {k.lower() for k in w["keywords"]} | {stack.label(i).lower() for i in w["stack"]}
    try:
        quick = stack.quick(10)
    except Exception:
        quick = []
    return {"id": "watchlist", "title": "Follow what you run", "done": n > 0, "optional": False,
            "detail": (f"You follow {n} thing{'s' if n != 1 else ''}." if n else
                       "Tell Night Desk what you run, so its exploited bugs, news and alerts come first."),
            "suggest": [v for v in sugg if v.lower() not in have][:8], "quick": quick,
            "action": {"label": "Choose what you follow", "href": "#settings/follow"}}


def _ai() -> dict:
    try:
        from ..ai import client
        st = client.status()
        up = bool(st.get("ever_up")) and not st.get("down")
    except Exception:
        up = False
    return {"id": "ai", "title": "AI", "done": up, "optional": True,
            "detail": ("Running: search by meaning is on, on this Mac." if up else
                       "Optional: search by meaning on this Mac (Apple silicon, about 1.2 GB), and story summaries and "
                       "entity briefs from a chat model: built in, from Ollama or LM Studio, or from another server. "
                       "Everything works without it."),
            "action": {"label": "Set up AI", "href": "#settings/ai"}}


def status() -> dict:
    tables = _tables()
    real, demo = _netlog(tables)
    feeds = _feeds()
    items = [
        feeds,
        {"id": "demo", "title": "Try the demo network data", "done": demo or real > 0, "optional": False,
         "detail": ("Demo data is loaded: its alerts are marked DEMO." if demo else
                    "Not needed: your own logs are in." if real else
                    "See what Night Desk finds on a home network, with made-up devices. Remove it any time."),
         "action": ({"label": "See the demo alerts", "href": "#network/alerts"} if demo else
                    {"label": "Load demo data", "api": "/api/netlog/demo", "method": "POST"})},
        {"id": "logs", "title": "Connect your network logs", "done": real > 0, "optional": False,
         "detail": (f"{real} log file{'s' if real != 1 else ''} imported." if real else
                    "Import Zeek, Suricata, Pi-hole or AdGuard Home logs, or let a device upload them."),
         "action": {"label": "Open Import", "href": "#network/import"}},
        _abusech(),
        _watch(),
        _ai(),
    ]
    req = [i for i in items if not i["optional"]]
    no_data = not feeds["done"] and not feeds["first_data"]
    return {"items": db_safe(items), "done": sum(1 for i in req if i["done"]), "required": len(req),
            "complete": all(i["done"] for i in req), "first_run": (real == 0 and not demo) or no_data,
            "has_logs": real > 0, "demo": demo, "has_data": not no_data,
            "dismissed": bool(db.get_setting(DISMISS_KEY, False))}


def db_safe(v):
    from .briefing import _jsonable
    return _jsonable(v)


def dismiss(flag: bool) -> dict:
    db.set_setting(DISMISS_KEY, bool(flag))
    return {"dismissed": bool(flag)}
