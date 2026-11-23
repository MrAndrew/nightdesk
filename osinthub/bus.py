"""Tiny in-process pub/sub used to push live updates to browsers over SSE."""
from __future__ import annotations

import asyncio
import json
from typing import Any

_subscribers: set[asyncio.Queue] = set()
_loop: asyncio.AbstractEventLoop | None = None


def bind_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _loop
    _loop = loop


def subscribe() -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=500)
    _subscribers.add(q)
    return q


def unsubscribe(q: asyncio.Queue) -> None:
    _subscribers.discard(q)


def _put(msg: str) -> None:
    for q in list(_subscribers):
        if q.full():
            try:
                q.get_nowait()
            except asyncio.QueueEmpty:
                pass
        q.put_nowait(msg)


def publish(topic: str, data: Any) -> None:
    """Thread-safe publish."""
    msg = json.dumps({"topic": topic, "data": data}, default=str)
    if _loop is None:
        return
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None
    if running is _loop:
        _put(msg)
    else:
        _loop.call_soon_threadsafe(_put, msg)
