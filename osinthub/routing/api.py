"""Routing watch API (Settings › Sources › Routing watch). okf/architecture/api.md#routing-watch

GET  /api/routing            watchlist, presets, the two settings, data used today, the four sources
GET  /api/routing/validate   ?value=  check one typed ASN or prefix (as the user types)
PUT  /api/routing/watchlist  {"watches": [{"value", "label"}]}   replaces the list (max 25)
PUT  /api/routing/settings   {"every", "limit_mb", "radar_token"}  radar_token: a string saves it, "" removes it
PUT  /api/routing/source     {"id", "enabled"}  turn a routing source on or off, also before any network is watched
GET  /api/routing/watches    one card per watch

PUTs go through the app's CSRF guard (osinthub/api.py _guard). The Radar token is write-only: answers say only
whether one is set and where it comes from. A change starts, stops or re-checks the routing sources (`sync`).
"""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, HTTPException, Query

from .. import config, scheduler
from ..sources.base import now
from . import detect, usage, watchlist

log = logging.getLogger("osinthub.routing")
router = APIRouter()

SOURCES_ORDER = ("rpki_roas", "cf_radar_bgp", "ripestat", "ris_live")
# On by itself once it can run, while the user has saved no choice: Radar, once the user saved their own token (a
# deliberate act tied to that source). The RPKI file has no stated terms (`ask` in osinthub/feed_terms.py), so it is
# never switched on by itself: with a network watched and no saved choice, the page asks once (ASK_FIRST, `ask` in
# GET /api/routing) and the answer is saved like a toggle.
AUTO_ON = ("cf_radar_bgp",)
ASK_FIRST = ("rpki_roas",)
KICK_DELAY_S = 45.0      # after a list or token change, wait this long for more edits before a network check
QUICK_KICK_S = 1.0       # the RPKI re-filter (local, from the cached file) and a raised limit: at once
_kicks: dict[str, asyncio.Task] = {}


def _src(sid: str):
    from ..sources import SOURCES
    return SOURCES[sid]


def why_not_checking() -> str | None:
    if config.OFFLINE:
        return "Offline mode is on, so nothing is checked."
    return usage.why_paused()


def sources_view() -> list[dict]:
    out = []
    for sid in SOURCES_ORDER:
        s = _src(sid)
        st = scheduler.state(sid)
        d = {"id": sid, "name": s.name, "provider": s.provider, "mode": s.mode, "license": s.license,
             "enabled": scheduler.is_enabled(s), "default_enabled": s.default_enabled,
             "status": st.get("status"), "message": st.get("message"), "last_ok": st.get("last_ok"),
             "unavailable": s.unavailable(), "interval": s.interval,
             "used_today": usage.used(sid), "requests_today": usage.requests(sid)}
        if sid == "cf_radar_bgp":
            d["token"] = watchlist.token_source()   # 'env', 'saved' or None: never the token itself
        for k in ("last_ok",):
            if hasattr(d[k], "isoformat"):
                d[k] = d[k].isoformat()
        out.append(d)
    return out


def needs_answer(wl: list | None = None) -> list[str]:
    """ASK_FIRST sources the page should ask about now: a network is watched and the user has saved no choice."""
    wl = watchlist.load() if wl is None else wl
    if not wl:
        return []
    return [sid for sid in ASK_FIRST if scheduler.state(sid).get("enabled") is None]


def overview() -> dict:
    wl = watchlist.load()
    ids = {w["id"] for w in wl}
    return {
        "ask": needs_answer(wl),
        "watchlist": wl,
        "max": watchlist.MAX_WATCHES,
        "presets": [{**p, "added": p["value"] in ids} for p in watchlist.PRESETS],
        "settings": watchlist.settings(),
        "every_choices": [{"value": k, "label": v, "advanced": k in watchlist.ADVANCED_EVERY} for k, v in watchlist.EVERY.items()],
        "usage": {**usage.snapshot(), "limit_bytes": usage.limit_bytes()},
        "paused": why_not_checking(),
        "offline": bool(config.OFFLINE),
        "sources": sources_view(),
    }


def card_sources() -> dict:
    why = why_not_checking()
    out = {}
    for s in sources_view():
        out[s["id"]] = {"on": bool(s["enabled"]) and not s["unavailable"], "interval": s["interval"] or 3600, "why": why}
    return out


@router.get("/api/routing")
def get_routing():
    return overview()


@router.get("/api/routing/validate")
def validate(value: str = Query("", max_length=200)):
    try:
        w = watchlist.parse(value)
    except watchlist.Invalid as e:
        return {"ok": False, "error": str(e)}
    dup = any(x["id"] == w["id"] for x in watchlist.load())
    return {"ok": True, **w, "label": watchlist.preset_label(w["id"]), "duplicate": dup}


@router.get("/api/routing/watches")
def get_watches():
    return {"cards": detect.cards(card_sources()), "paused": why_not_checking()}


@router.put("/api/routing/watchlist")
async def put_watchlist(body: dict):
    items = body.get("watches") if isinstance(body, dict) else None
    try:
        await asyncio.to_thread(watchlist.save, items)
    except watchlist.Invalid as e:
        raise HTTPException(400, str(e)) from None
    await sync(kick=True)
    return await asyncio.to_thread(overview)


@router.put("/api/routing/settings")
async def put_settings(body: dict):
    if not isinstance(body, dict):
        raise HTTPException(400, "send a JSON object")
    old = watchlist.settings()
    try:
        s = await asyncio.to_thread(watchlist.set_settings, body.get("every"), body.get("limit_mb"))
        if "radar_token" in body:
            await asyncio.to_thread(watchlist.set_token, body.get("radar_token"))
    except watchlist.Invalid as e:
        raise HTTPException(400, str(e)) from None
    # a raised limit lets paused sources go again now (they would otherwise look again within 10 minutes)
    await sync(restart=s["every"] != old["every"], kick="radar_token" in body or s["limit_mb"] > old["limit_mb"],
               quick=s["limit_mb"] > old["limit_mb"])
    return await asyncio.to_thread(overview)


@router.put("/api/routing/source")
async def put_source(body: dict):
    """Save the user's choice for one routing source. A source that only waits for a watched network keeps the
    choice (the first network starts it when on); one that needs a key cannot be turned on (409)."""
    sid = body.get("id") if isinstance(body, dict) else None
    enabled = body.get("enabled") if isinstance(body, dict) else None
    if sid not in SOURCES_ORDER or not isinstance(enabled, bool):
        raise HTTPException(400, "send {\"id\": a routing source, \"enabled\": true or false}")
    src = _src(sid)
    why = await asyncio.to_thread(src.unavailable)
    if why and why != watchlist.WAITING:
        if enabled:
            raise HTTPException(409, why)
        await scheduler._aset_state(sid, enabled=False)
    elif why:   # no network watched yet: save the choice only; sync() starts it with the first watch
        await scheduler._aset_state(sid, enabled=enabled)
    else:
        await scheduler.set_enabled(src, enabled)
    await sync(kick=enabled)
    return await asyncio.to_thread(overview)


async def sync(restart: bool = False, kick: bool = False, quick: bool = False) -> None:
    """Bring the routing sources in line with the watchlist, the token and the settings: stop those that cannot
    run (an empty watchlist stops everything, RIS Live included), start enabled ones that now can, re-subscribe
    RIS Live to the new list, restart the scheduled ones when Check every changed, and check soon after a change."""
    # Radar is on by default once it can run (a watchlist and the user's own token). Only an unset flag is set, so a
    # source the user turned off stays off. ASK_FIRST sources (the RPKI file) are never switched on here: an unset
    # flag stays unset and the page asks (needs_answer); the first-run box and the page's toggle save a choice too.
    if await asyncio.to_thread(watchlist.load):
        for sid in AUTO_ON:
            if (await asyncio.to_thread(scheduler.state, sid)).get("enabled") is None and not await asyncio.to_thread(_src(sid).unavailable):
                await scheduler._aset_state(sid, enabled=True)
    else:   # nothing watched: the cached RPKI file is not needed (it is downloaded again with the next watch)
        from ..sources import routing_rpki
        await asyncio.to_thread(routing_rpki.forget_cache)
    for sid in SOURCES_ORDER:
        src = _src(sid)
        t = scheduler._tasks.get(sid)
        running = bool(t and not t.done())
        why = await asyncio.to_thread(src.unavailable)
        if why:
            if running:
                await scheduler.stop_source(src)
            await scheduler._aset_state(sid, status="needs_key", message=why)
            continue
        st = await asyncio.to_thread(scheduler.state, sid)
        if not await asyncio.to_thread(scheduler.is_enabled, src):
            if st.get("status") == "needs_key":   # it can run now; it is simply off
                await scheduler._aset_state(sid, status="disabled", message="")
            continue
        if running and (src.mode == "stream" or restart):
            await scheduler.stop_source(src)
            running = False
        runs_now = False
        if not running:
            try:
                scheduler.start_source(src)
            except Exception as e:
                log.warning("routing source %s did not start: %s", sid, type(e).__name__)
                continue
            last = st.get("last_ok")   # a batch loop with nothing recent runs at once: no extra check needed
            runs_now = last is None or (now() - last).total_seconds() >= (src.interval or 0)
        if kick and src.mode == "batch" and not runs_now:
            _kick(src, QUICK_KICK_S if quick or sid == "rpki_roas" else KICK_DELAY_S)


def _kick(src, delay: float = KICK_DELAY_S) -> None:
    old = _kicks.pop(src.id, None)
    if old:
        old.cancel()

    async def go():
        await asyncio.sleep(delay)
        if config.OFFLINE or src.unavailable() or not scheduler.is_enabled(src):
            return
        await scheduler.run_batch(src)

    _kicks[src.id] = asyncio.create_task(go(), name=f"routing-kick:{src.id}")
