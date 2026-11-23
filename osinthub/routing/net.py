"""The one HTTP GET the routing sources use: offline-safe, byte-counted, stopped at the daily data limit and at
the source's size cap (osinthub/sources/caps.py).

Request headers (the Radar token travels in `Authorization`) are never put in an error message or a log line;
errors name the host and the HTTP status only.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx

from .. import config
from ..sources import caps
from ..sources.base import Paused
from . import usage


class LimitReached(Paused):
    pass


class Offline(RuntimeError):
    pass


@dataclass
class Resp:
    status_code: int
    headers: httpx.Headers
    content: bytes
    url: str


async def get(client: httpx.AsyncClient, url: str, *, sid: str, params: dict | None = None,
              headers: dict | None = None, budget: bool = True) -> Resp:
    """GET url. Counts the bytes received against `sid`. With budget, refuses to start when today's limit is
    used up and stops reading (LimitReached) once the response would take the total over it."""
    if config.OFFLINE:
        raise Offline("offline mode: not fetching")
    if budget and usage.over():
        raise LimitReached(usage.why_paused())
    room = usage.remaining() if budget else None
    chunks: list[bytes] = []
    got = 0
    try:
        # redirects are followed by hand (a 3xx body is never read: caps.open_final)
        async with caps.open_final(client, "GET", url, params=params, headers=headers) as r:
            try:
                # decoded bytes count against the source's size cap (a gzip bomb stops at it: caps.py);
                # bytes on the wire count against the daily data limit
                async for chunk in caps.iter_decoded(r, caps.cap_for(sid), httpx.URL(url).host):
                    chunks.append(chunk)
                    if room is not None and r.num_bytes_downloaded > room:
                        got = r.num_bytes_downloaded
                        raise LimitReached(f"Stopped a download from {httpx.URL(url).host}: it would go over today's "
                                           f"data limit of {usage.limit_bytes() // 1_000_000} MB.")
            finally:
                got = got or r.num_bytes_downloaded
            return Resp(r.status_code, r.headers, b"".join(chunks), str(r.url))
    finally:
        usage.add(sid, got + usage.HEADER_BYTES, requests=1, save=False)   # count here, persist off the loop
        await asyncio.to_thread(usage.maybe_save)


def short_error(e: Exception, host: str) -> str:
    """A plain one-line reason with no request details (headers, query strings)."""
    if isinstance(e, caps.TooLarge):
        return str(e)
    if isinstance(e, httpx.TimeoutException):
        return f"{host} did not answer in time"
    if isinstance(e, httpx.ConnectError):
        return f"could not connect to {host}"
    if isinstance(e, httpx.HTTPError):
        return f"network error talking to {host} ({type(e).__name__})"
    return f"{type(e).__name__}"
