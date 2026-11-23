"""Watch API: GET /api/watch (the briefing), GET/PUT /api/marker (the one last-seen marker), GET /api/setup/status
and PUT /api/setup/dismiss. Reference: okf/architecture/watch.md#api"""
from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException

from . import briefing, marker, setup

router = APIRouter(tags=["watch"])


@router.get("/api/watch")
def get_watch(since: str | None = None):
    """The briefing since the marker (or `since`: "previous" or an ISO time, to look without moving the marker),
    never more than marker.CAP_DAYS back."""
    try:
        return briefing.build(since)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/api/marker")
def get_marker():
    return marker.public()


def put_marker_body(body: dict) -> dict:
    """{} or {"caught_up": true}: the marker moves to now. {"last_seen": ISO}: to that time. {"back": true}: to the
    previous value. The old value is kept as `previous` either way. {"restore": <undo>}: exactly as it was before a
    move (the `undo` every move returns), for an Undo button."""
    body = body if isinstance(body, dict) else {}
    before = marker.get()
    try:
        if "restore" in body:
            m = marker.restore(body.get("restore"))
        elif body.get("back"):
            m = marker.step_back()
        else:
            m = marker.caught_up(body.get("last_seen"))
    except ValueError as e:
        raise HTTPException(409 if body.get("back") else 400, str(e))
    try:
        from .. import bus
        bus.publish("marker", {"last_seen": m["last_seen"], "previous": m["previous"]})
    except Exception:
        pass
    return {**marker.public(m), "undo": before}


@router.put("/api/marker")
def put_marker(body: dict = Body(default={})):
    return put_marker_body(body)


@router.get("/api/setup/status")
def setup_status():
    return setup.status()


@router.put("/api/setup/dismiss")
def setup_dismiss(body: dict = Body(default={})):
    return setup.dismiss(bool(body.get("dismissed", True)))
