"""L3 (v1.2 housekeeping) backend-feature regressions.

3.1: own-list upload/replace run the re-hunt off the event loop (asyncio.to_thread), so the UI and SSE keep
answering while an upload is in flight. The old code ran the full re-hunt on the uvicorn loop and froze every
request until it finished.

    uv run --with pytest pytest tests/netlog/test_v12_hk_feat.py -q
"""
from __future__ import annotations

import asyncio
import threading
import time

from _lake import make_lake
LAKE = make_lake("netlog-v12-feat")

import httpx  # noqa: E402
from fastapi import FastAPI  # noqa: E402

from osinthub import db  # noqa: E402
from osinthub.netlog import api, newdev, ownlists  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
api.router.include_router(ownlists.router)
api.router.include_router(newdev.router)
_app = FastAPI()
_app.include_router(api.router)


def test_status_answers_while_an_upload_runs_off_the_loop(monkeypatch):
    """While /api/netlog/lists is busy (create() blocked in a worker thread), /api/netlog/status still
    answers promptly: the event loop is free because create() runs via asyncio.to_thread()."""
    ownlists.ensure()
    entered = threading.Event()
    release = threading.Event()
    real_create = ownlists.create

    def blocking_create(*a, **k):
        entered.set()
        assert release.wait(10), "release never set"
        return real_create(*a, **k)

    monkeypatch.setattr(ownlists, "create", blocking_create)

    async def run():
        transport = httpx.ASGITransport(app=_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            up = asyncio.create_task(
                c.post("/api/netlog/lists", data={"name": "Lab", "text": "198.51.100.7\n203.0.113.0/24"}))
            # wait until the worker thread is inside the (blocked) create()
            assert await asyncio.to_thread(entered.wait, 10), "upload never reached create()"
            # the loop must still serve /status quickly, before the upload is allowed to finish
            t0 = time.monotonic()
            r = await asyncio.wait_for(c.get("/api/netlog/status"), timeout=3)
            dt = time.monotonic() - t0
            assert r.status_code == 200, r.text
            assert dt < 2.0, f"/status took {dt:.2f}s while an upload was in flight (loop frozen?)"
            assert not up.done(), "the upload finished before we released it; timing is not meaningful"
            # let the upload complete cleanly
            release.set()
            ru = await asyncio.wait_for(up, timeout=15)
            assert ru.status_code == 200, ru.text
            assert ru.json()["name"] == "Lab"

    try:
        asyncio.run(run())
    finally:
        release.set()
