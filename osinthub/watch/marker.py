"""The one "last seen" marker for the whole app. Watch, News ("new since your last visit") and the KEV list read it.

It moves only when the user says so: "Caught up" on Watch, or "Mark all as read" in News (the same thing). The
previous value is kept (with a short history), so "Show since <previous> again" steps back. What Watch shows is
capped at CAP_DAYS even when the marker is older. Before this module the marker was the news-only setting
`news.last_seen` (a bare ISO string); it is still read when the new setting is missing, and kept in step on every
write, so an old value carries over. Reference: okf/architecture/watch.md#marker
"""
from __future__ import annotations

import datetime as dt

from .. import db

KEY = "app.last_seen"        # {"last_seen", "previous", "set_at", "history": [older values, newest first]}
OLD_KEY = "news.last_seen"   # the v1.0 news marker: a bare ISO string
CAP_DAYS = 7                 # Watch never reaches back further than this
FIRST_VISIT_HOURS = 24       # with no marker at all, Watch shows the last day
HISTORY = 10
REPRESS_MINUTES = 10         # a second "Caught up" this soon (double press, two tabs) keeps the older previous
FUTURE_SKEW = dt.timedelta(minutes=5)   # a marker later than now plus this is refused (clock skew allowed)


def now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def parse(v) -> dt.datetime | None:
    """An ISO time (a trailing Z is fine; a naive time is UTC), else None."""
    if isinstance(v, dt.datetime):
        t = v
    elif isinstance(v, str) and v.strip():
        try:
            t = dt.datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return t if t.tzinfo else t.replace(tzinfo=dt.UTC)


def _iso(t: dt.datetime | None) -> str | None:
    return t.astimezone(dt.UTC).isoformat() if t else None


def get() -> dict:
    """{last_seen, previous, set_at, history} (ISO strings or None)."""
    v = db.get_setting(KEY)
    if isinstance(v, dict) and parse(v.get("last_seen")):
        hist = [h for h in (v.get("history") or []) if parse(h)]
        return {"last_seen": v["last_seen"], "previous": v.get("previous") if parse(v.get("previous")) else None,
                "set_at": v.get("set_at"), "history": hist[:HISTORY]}
    old = db.get_setting(OLD_KEY)   # the v1.0 news marker
    if parse(old):
        return {"last_seen": _iso(parse(old)), "previous": None, "set_at": None, "history": []}
    return {"last_seen": None, "previous": None, "set_at": None, "history": []}


def _save(m: dict) -> dict:
    db.set_setting(KEY, m)
    if m["last_seen"]:
        db.set_setting(OLD_KEY, m["last_seen"])   # anything still reading the old setting stays in step
    return m


def caught_up(at=None) -> dict:
    """Move the marker to `at` (default now), keeping the old value as `previous`."""
    t = parse(at) if at is not None else now()
    if t is None:
        raise ValueError(f"bad time: {at!r}")
    if t > now() + FUTURE_SKEW:
        raise ValueError("the marker cannot be in the future")
    m = get()
    cur = parse(m["last_seen"])
    if cur is not None and abs((t - cur).total_seconds()) < REPRESS_MINUTES * 60:
        # pressed again within minutes: move the time, keep the previous visit to step back to
        return _save({**m, "last_seen": _iso(t), "set_at": _iso(now())})
    hist = ([m["last_seen"]] + m["history"])[:HISTORY] if m["last_seen"] else m["history"]
    return _save({"last_seen": _iso(t), "previous": m["last_seen"], "set_at": _iso(now()), "history": hist})


def step_back() -> dict:
    """Put the marker back to its previous value ("Show since <previous> again"). ValueError when there is none."""
    m = get()
    if not m["previous"]:
        raise ValueError("there is no earlier marker to go back to")
    hist = m["history"][1:] if m["history"] and m["history"][0] == m["previous"] else m["history"]
    return _save({"last_seen": m["previous"], "previous": hist[0] if hist else None, "set_at": _iso(now()),
                  "history": hist})


UNDO_KEYS = frozenset({"last_seen", "previous", "set_at", "history"})


def restore(prior: dict) -> dict:
    """Put the marker back exactly as it was before a move: the Undo of "Mark all as seen" (v1.2 mobile). `prior` must
    have exactly the shape of the `undo` a PUT returned: an object with the keys last_seen, previous and set_at (each an
    ISO 8601 time string or null) and history (a list of ISO time strings). A null last_seen means no marker at all (a
    first visit again). Anything else (a non-object, a missing or extra key, a non-string or unparseable time, a time in
    the future, a history that is not a list) is a ValueError, checked before anything is written."""
    if not isinstance(prior, dict) or set(prior) != UNDO_KEYS:
        raise ValueError("restore must be the undo object a marker move returned")

    def ok(v, key):
        if v is None:
            return None
        t = parse(v) if isinstance(v, str) else None
        if t is None or t > now() + FUTURE_SKEW:
            raise ValueError(f"bad time in {key}: {v!r}")
        return _iso(t)

    last, prev, set_at = ok(prior["last_seen"], "last_seen"), ok(prior["previous"], "previous"), ok(prior["set_at"], "set_at")
    if not isinstance(prior["history"], list):
        raise ValueError("history must be a list of times")
    hist = [ok(h, "history") for h in prior["history"]]
    if any(h is None for h in hist):
        raise ValueError("history must be a list of times")
    m = {"last_seen": last, "previous": prev if last else None, "set_at": set_at if last else None,
         "history": hist[:HISTORY] if last else []}
    db.set_setting(KEY, m)
    db.set_setting(OLD_KEY, last)   # the old news setting follows, so no marker means none there either
    return m


def window(m: dict | None = None, since: str | None = None, at: dt.datetime | None = None) -> dict:
    """The time Watch reads from: the marker (or `since`: an ISO time, or "previous"), never more than CAP_DAYS ago;
    with no marker at all, the last FIRST_VISIT_HOURS."""
    m = m or get()
    at = at or now()
    floor = at - dt.timedelta(days=CAP_DAYS)
    first = False
    if since == "previous":
        t = parse(m["previous"])
        if t is None:
            raise ValueError("there is no earlier marker")
    elif since:
        t = parse(since)
        if t is None:
            raise ValueError(f"bad time: {since!r}")
    else:
        t = parse(m["last_seen"])
        if t is None:
            first, t = True, at - dt.timedelta(hours=FIRST_VISIT_HOURS)
    capped = t < floor
    return {"since": _iso(max(t, floor)), "asked": _iso(t), "capped": capped, "first_visit": first,
            "cap_days": CAP_DAYS}


def public(m: dict | None = None) -> dict:
    m = m or get()
    return {"last_seen": m["last_seen"], "previous": m["previous"], "set_at": m["set_at"], **{"window": window(m)}}
