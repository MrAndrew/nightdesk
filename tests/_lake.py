"""Shared set-up for test modules: a temporary lake, the settings osinthub reads at import, and small builders.

osinthub reads OSINTHUB_LAKE, OSINTHUB_OFFLINE, AI_URL and friends once, when it is first imported, so a test module
calls make_lake() at its top, BEFORE it imports anything from osinthub:

    from _lake import make_lake
    LAKE = make_lake("notes")                    # a fresh lake, offline, AI helper and vectors off
    from osinthub import db  # noqa: E402

Each module runs in its own process (tests/conftest.py). The lake and every other temp folder the module makes live
under one folder that is deleted when the process ends, so a test run leaves nothing behind.
"""
from __future__ import annotations

import atexit
import io
import itertools
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = {"Origin": "http://testserver"}       # a same-origin write from the TestClient's own pages
DISCARD = "http://127.0.0.1:9"                  # nothing listens here: the AI helper, Qdrant, any fake upstream
_uid = itertools.count(1)


def make_lake(name: str, *, offline: bool = True, disable: str | None = None, **env: str) -> str:
    """A fresh lake for this module; returns its path. `disable` is OSINTHUB_DISABLE_EXT; `env` sets more variables."""
    root = Path(os.path.realpath(tempfile.mkdtemp(prefix=f"nd-test-{name}-")))
    atexit.register(shutil.rmtree, root, ignore_errors=True)
    (root / "tmp").mkdir()
    tempfile.tempdir = str(root / "tmp")        # later mkdtemp()s in this module land here too, outside the lake
    lake = root / "lake"
    lake.mkdir()
    (root / "config").mkdir()
    os.environ.update({"OSINTHUB_LAKE": str(lake), "OSINTHUB_OFFLINE": "1" if offline else "0",
                       "AI_URL": DISCARD, "OSINTHUB_NEWS_NO_VECTORS": "1",
                       "XDG_CONFIG_HOME": str(root / "config"),    # never the machine's own Night Desk settings
                       "HF_HUB_CACHE": str(root / "hf")})          # nor its downloaded AI models
    if disable is not None:
        os.environ["OSINTHUB_DISABLE_EXT"] = disable
    for k in ("OSINTHUB_SQL_CONSOLE", "OSINTHUB_DEBUG"):   # the SQL console is off unless a module turns it on
        os.environ.pop(k, None)
    os.environ.update(env)
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    return str(lake)


def client(*routers, base_url: str = "http://testserver"):
    """A TestClient on a bare app with just these routers (no lifespan, no middleware)."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    app = FastAPI()
    for r in routers:
        app.include_router(r)
    return TestClient(app, base_url=base_url)


def ndjson(rows: list[dict]) -> io.BytesIO:
    """Zeek JSON logs (one object per line) as an upload body."""
    return io.BytesIO("".join(json.dumps(r) + "\n" for r in rows).encode())


def conn(ts: float, src: str, dst: str, port: int = 443, *, uid: str | None = None, proto: str = "tcp",
         state: str = "SF", orig_bytes: int = 600, resp_bytes: int = 4000, **extra) -> dict:
    """One Zeek conn.log record."""
    return {"ts": ts, "uid": uid or f"C{next(_uid):09d}", "id.orig_h": src, "id.orig_p": 50000,
            "id.resp_h": dst, "id.resp_p": port, "proto": proto, "conn_state": state, "duration": 1.0,
            "orig_bytes": orig_bytes, "resp_bytes": resp_bytes, **extra}


def dns(ts: float, src: str, query: str, answers: list[str] | None = None, *, resolver: str = "192.0.2.53",
        uid: str | None = None) -> dict:
    """One Zeek dns.log record."""
    return {"ts": ts, "uid": uid or f"D{next(_uid):09d}", "id.orig_h": src, "id.orig_p": 53000,
            "id.resp_h": resolver, "id.resp_p": 53, "proto": "udp", "query": query, "qtype_name": "A",
            "answers": answers or [], "rcode_name": "NOERROR"}
