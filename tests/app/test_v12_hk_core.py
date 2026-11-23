"""L2 backend-core housekeeping regressions (v12-hk-core).

Covers the bug fixes: db.tx rolls back on error (the cursor is not left stuck in an aborted transaction),
"redact my network" fails closed, the geo bootstrap never keeps a truncated file, and the event-loop writes
(set_retention, sources-choice) run off the loop.

    uv run --with pytest pytest tests/app/test_v12_hk_core.py -q
"""
from __future__ import annotations

import asyncio
import sys

from _lake import make_lake
LAKE = make_lake("hk_core", disable="ai")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import bootstrap, config, db, feed_terms  # noqa: E402
from osinthub.api import app  # noqa: E402
from osinthub.notes import store  # noqa: E402

db.connect()
C = TestClient(app, base_url="http://localhost")
ORIGIN = {"Origin": "http://localhost"}


def _off_loop() -> bool:
    """True when called outside an event loop (i.e. in a worker thread, not on the loop)."""
    try:
        asyncio.get_running_loop()
        return False
    except RuntimeError:
        return True


# --------------------------------------------------------------------- db.tx rollback (R3)
def test_tx_rolls_back_and_leaves_the_cursor_usable():
    cur = db.cursor()
    cur.execute("CREATE OR REPLACE TABLE _txtest (x INTEGER PRIMARY KEY)")
    cur.execute("INSERT INTO _txtest VALUES (1)")
    import duckdb
    with pytest.raises(duckdb.ConstraintException):
        with db.tx(cur):
            cur.execute("INSERT INTO _txtest VALUES (2)")
            cur.execute("INSERT INTO _txtest VALUES (1)")   # primary-key clash: aborts the transaction
    # the partial write is gone...
    assert [r["x"] for r in db.query("SELECT x FROM _txtest ORDER BY x")] == [1]
    # ...and the thread-local cursor is not stuck in an aborted transaction (this would fail without ROLLBACK)
    cur.execute("INSERT INTO _txtest VALUES (3)")
    assert [r["x"] for r in db.query("SELECT x FROM _txtest ORDER BY x")] == [1, 3]
    cur.execute("DROP TABLE _txtest")


def test_tables_and_has_table():
    assert "events" in db.tables()
    assert db.has_table("events")
    assert not db.has_table("no_such_table_12345")


# --------------------------------------------------------------------- redaction fails closed (R6)
HOME = "my laptop reached 10.0.0.9 and talked to 203.0.113.7"


def test_redact_works_on_an_empty_lake():
    out = store.redact(HOME)
    assert "[home IP 1]" in out["text"]          # 10.0.0.9 is a private/home range
    assert "203.0.113.7" in out["text"]          # the threat address is kept


def test_redact_still_works_with_netlog_unavailable(monkeypatch):
    # Simulate the netlog package being disabled: importing its devices module raises ImportError.
    monkeypatch.setitem(sys.modules, "osinthub.netlog.devices", None)
    out = store.redact(HOME)
    assert "[home IP 1]" in out["text"]           # private ranges still redact


def test_redact_fails_closed_when_home_context_errors(monkeypatch):
    from osinthub.netlog import devices

    def boom():
        raise RuntimeError("column renamed")

    monkeypatch.setattr(devices, "effective_prefixes", boom)
    with pytest.raises(RuntimeError):
        store.redact(HOME)


def test_redact_endpoint_returns_500_when_home_context_errors(monkeypatch):
    from osinthub.netlog import devices

    monkeypatch.setattr(devices, "effective_prefixes", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    client = TestClient(app, base_url="http://localhost", raise_server_exceptions=False)
    r = client.post("/api/notes/redact", json={"text": HOME}, headers=ORIGIN)
    assert r.status_code == 500          # a leak is worse than an error: no unredacted text is returned


# --------------------------------------------------------------------- bootstrap truncation (R4)
def test_bootstrap_does_not_keep_a_truncated_mmdb(monkeypatch, tmp_path):
    import gzip

    target = tmp_path / "geo.mmdb"
    good = gzip.compress(b"x" * 5000)
    truncated = good[: len(good) // 2]   # half a gzip stream: decompression fails part-way

    class _Resp:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def raise_for_status(self):
            pass

        async def aiter_bytes(self, n=0):
            yield truncated

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def stream(self, method, url):
            return _Resp()

    monkeypatch.setattr(bootstrap, "REFERENCE", [(target, ["http://x/geo.mmdb.gz"], True)])
    monkeypatch.setattr(bootstrap.httpx, "AsyncClient", _Client)
    monkeypatch.setattr(config, "OFFLINE", False)

    asyncio.run(bootstrap.ensure_reference_data())

    assert not target.exists()                       # a half-written file is not left in place...
    assert not (tmp_path / "geo.mmdb.tmp").exists()  # ...and neither temp file survives
    assert not (tmp_path / "geo.mmdb.part").exists()


# --------------------------------------------------------------------- writes run off the event loop (R1)
def test_set_retention_write_runs_off_the_loop(monkeypatch):
    seen = {}
    orig = db.set_setting

    def spy(key, value):
        seen["off_loop"] = _off_loop()
        return orig(key, value)

    monkeypatch.setattr(db, "set_setting", spy)
    r = C.put("/api/settings/retention", json={"lake_days": None, "db_days": None}, headers=ORIGIN)
    assert r.status_code == 200
    assert seen["off_loop"] is True


def test_sources_choice_write_runs_off_the_loop(monkeypatch):
    seen = {}
    orig = feed_terms.mark_done

    def spy(how):
        seen["off_loop"] = _off_loop()
        return orig(how)

    monkeypatch.setattr(feed_terms, "mark_done", spy)
    r = C.post("/api/settings/sources-choice", json={"keep": True}, headers=ORIGIN)
    assert r.status_code == 200
    assert seen["off_loop"] is True
