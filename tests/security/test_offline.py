"""OSINTHUB_OFFLINE=1 stops all fetching. Under a socket guard that refuses (and records) every connection or name
lookup that is not this machine: one run of every registered source, and every GET route without path parameters,
on a temporary lake. Anything that tried to reach the internet fails the test with what it tried.

    uv run --with pytest pytest tests/security/test_offline.py -q
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket

from _lake import make_lake
LAKE = make_lake("offline")   # offline=True: what is under test

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db, scheduler  # noqa: E402
import osinthub.api as A  # noqa: E402
from osinthub.sources import SOURCES  # noqa: E402
from osinthub.sources.base import StreamSink  # noqa: E402

db.connect()
TRIED: list[str] = []
# This machine's own names (looked up to list its addresses for the upload listener) are local, whatever they are.
LOCAL_NAMES = {"localhost", "testserver", "", None, socket.gethostname(), socket.gethostname().split(".")[0]}


def _local(host) -> bool:
    if host in LOCAL_NAMES:
        return True
    try:
        return ipaddress.ip_address(str(host).strip("[]").split("%")[0]).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def guard(monkeypatch):
    real_connect, real_connect_ex, real_gai = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo

    # A UDP connect() sends nothing (Night Desk uses one to learn which local address has the default route); a TCP
    # connect is a connection.
    def outbound(sock, address) -> bool:
        return sock.family in (socket.AF_INET, socket.AF_INET6) and sock.type == socket.SOCK_STREAM and not _local(address[0])

    def connect(self, address):
        if outbound(self, address):
            TRIED.append(f"connect {address}")
            raise ConnectionRefusedError(f"test guard: no connections off this machine ({address})")
        return real_connect(self, address)

    def connect_ex(self, address):
        if outbound(self, address):
            TRIED.append(f"connect_ex {address}")
            return 111
        return real_connect_ex(self, address)

    def getaddrinfo(host, *a, **k):
        if not _local(host.decode() if isinstance(host, bytes) else host):
            TRIED.append(f"lookup {host}")
            raise socket.gaierror(f"test guard: no name lookups ({host})")
        return real_gai(host, *a, **k)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    TRIED.clear()
    yield


def test_the_guard_catches_a_connection_and_a_lookup():
    with pytest.raises(OSError):
        socket.create_connection(("192.0.2.1", 443), timeout=0.2)
    with pytest.raises(OSError):
        socket.getaddrinfo("feeds.example", 443)
    assert any(t.startswith("connect") or "192.0.2.1" in t for t in TRIED) and "lookup feeds.example" in TRIED


def test_every_source_fetches_nothing_offline():
    assert config.OFFLINE

    async def flush(src, evs):
        return None

    async def run_all():
        out = {}
        for sid, src in SOURCES.items():
            if src.mode == "stream":
                try:
                    await asyncio.wait_for(src.stream(StreamSink(src, flush)), 0.1)   # returns at once offline
                    out[sid] = "returned"
                except TimeoutError:
                    out[sid] = "waiting"
            else:
                out[sid] = (await scheduler.run_batch(src)).get("error") or "ran"
        return out

    res = asyncio.run(run_all())
    assert len(res) >= 25, sorted(res)
    assert not TRIED, f"offline, these still reached out: {TRIED}"
    assert all(scheduler.state(s).get("status") in (None, "offline", "needs_key", "disabled") for s in SOURCES), \
        {s: scheduler.state(s).get("status") for s in SOURCES}


def _get_routes():
    def walk(routes, prefix=""):
        for r in routes:
            sub = getattr(r, "original_router", None)
            if sub is not None:
                yield from walk(sub.routes, prefix + (getattr(getattr(r, "include_context", None), "prefix", "") or ""))
            elif "GET" in (getattr(r, "methods", None) or ()):
                yield prefix + r.path
    return sorted(p for p in set(walk(A.app.routes)) if "{" not in p and p != "/api/stream")   # the live stream never ends


def test_every_get_route_reaches_out_to_nothing_offline():
    routes = _get_routes()
    assert len(routes) >= 80, len(routes)
    c = TestClient(A.app, base_url="http://localhost", raise_server_exceptions=False)
    codes = {p: c.get(p).status_code for p in routes}
    assert not TRIED, f"offline, these GETs still reached out: {TRIED}"
    assert not [p for p, s in codes.items() if s >= 500 and not re.search(r"/(ai|search/semantic)\b", p)], \
        {p: s for p, s in codes.items() if s >= 500}
