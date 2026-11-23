"""Data used today by each routing source, and the daily data limit (one limit for all of them).

Counted in bytes received over the wire (compressed size, plus a small allowance for headers), per local
calendar day, kept in memory and saved to the settings table (`routing.usage`) at most every few seconds.
When today's total reaches the limit every routing source pauses until midnight and says why.
"""
from __future__ import annotations

import datetime as dt
import logging
import threading
import time

from .. import db
from . import watchlist

log = logging.getLogger("osinthub.routing.usage")

KEY = "routing.usage"
HEADER_BYTES = 400          # rough size of the response headers, counted per request
SAVE_EVERY_S = 10

_lock = threading.Lock()
_u: dict | None = None
_saved_at = 0.0


def _today() -> str:
    return dt.date.today().isoformat()


def _cur() -> dict:
    global _u
    if _u is None:
        try:
            _u = db.get_setting(KEY, None) or {}
        except Exception:
            _u = {}
    if _u.get("day") != _today():
        _u = {"day": _today(), "bytes": {}, "requests": {}}
    _u.setdefault("bytes", {})
    _u.setdefault("requests", {})
    return _u


def _save(force: bool = False) -> None:
    global _saved_at
    if not force and time.monotonic() - _saved_at < SAVE_EVERY_S:
        return
    _saved_at = time.monotonic()
    snap = {"day": _u["day"], "bytes": dict(_u["bytes"]), "requests": dict(_u["requests"])}
    try:
        db.set_setting(KEY, snap)
    except Exception as e:
        # The 10 s throttle keeps this to one line per 10 s; a silent failure would quietly reset the daily counter.
        log.warning("could not save routing data usage: %s", e)


def add(sid: str, nbytes: int = 0, requests: int = 0, *, save: bool = True) -> None:
    with _lock:
        u = _cur()
        u["bytes"][sid] = int(u["bytes"].get(sid, 0)) + int(nbytes)
        if requests:
            u["requests"][sid] = int(u["requests"].get(sid, 0)) + int(requests)
        if save:
            _save()


def maybe_save() -> None:
    """Throttled save (every SAVE_EVERY_S), safe to run in a worker thread so the event loop never waits for the
    settings write. Pair it with `add(..., save=False)` on the event loop."""
    with _lock:
        if _u is not None:
            _save()


def flush() -> None:
    with _lock:
        if _u is not None:
            _save(force=True)


def used(sid: str | None = None) -> int:
    with _lock:
        u = _cur()
        return int(u["bytes"].get(sid, 0)) if sid else int(sum(u["bytes"].values()))


def requests(sid: str) -> int:
    with _lock:
        return int(_cur()["requests"].get(sid, 0))


def limit_bytes() -> int:
    return watchlist.settings()["limit_mb"] * 1_000_000


def remaining() -> int:
    return max(0, limit_bytes() - used())


def over() -> bool:
    return used() >= limit_bytes()


def why_paused() -> str | None:
    if not over():
        return None
    return (f"Paused for today: routing checks have used {used() / 1e6:.1f} MB, your daily data limit of "
            f"{watchlist.settings()['limit_mb']} MB. They start again after midnight, or raise the limit.")


def snapshot() -> dict:
    with _lock:
        u = _cur()
        return {"day": u["day"], "bytes": dict(u["bytes"]), "requests": dict(u["requests"]),
                "total": int(sum(u["bytes"].values()))}


def reset_for_tests() -> None:
    global _u
    with _lock:
        _u = {"day": _today(), "bytes": {}, "requests": {}}
