"""L2 backend-core housekeeping regressions for the sources layer (v12-hk-core).

* StreamSink.metric records its metric off the event loop (the write no longer blocks the loop).
* sources/upload.ingest_file looks at only the first 4 KB for format detection (not the whole upload) and
  closes the DuckDB connection it opens.

    uv run --with pytest pytest tests/sources/test_v12_hk_sources.py -q
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from _lake import make_lake
LAKE = make_lake("hk_sources", disable="ai")

from osinthub import db  # noqa: E402
from osinthub.sources import upload  # noqa: E402
from osinthub.sources.base import StreamSink  # noqa: E402

db.connect()


def _off_loop() -> bool:
    try:
        asyncio.get_running_loop()
        return False
    except RuntimeError:
        return True


# --------------------------------------------------------------------- metric off the loop (R1)
def test_stream_metric_records_off_the_loop(monkeypatch):
    seen = {}
    orig = db.record_metric

    def spy(name, value):
        seen["off_loop"] = _off_loop()
        seen["args"] = (name, value)
        return orig(name, value)

    monkeypatch.setattr(db, "record_metric", spy)
    sink = StreamSink(source=object(), on_flush=None)

    async def run():
        await sink.metric("bgp.updates_per_s", 3.0)

    asyncio.run(run())
    assert seen["off_loop"] is True
    assert seen["args"] == ("bgp.updates_per_s", 3.0)


# --------------------------------------------------------------------- upload: 4 KB head + closed connection (R5)
def test_ingest_csv_does_not_read_the_whole_file(monkeypatch, tmp_path):
    p = tmp_path / "iocs.csv"
    p.write_text("ip,severity\n192.0.2.10,0.8\n198.51.100.5,0.4\n")

    # The old code did path.read_bytes()[:4096] (up to the 512 MB limit in RAM); the fix reads a 4 KB head
    # through an open file handle, so read_bytes must not be called for format detection.
    orig_read_bytes = Path.read_bytes

    def no_read_bytes(self, *a, **k):
        raise AssertionError("ingest_file read the whole file via read_bytes()")

    monkeypatch.setattr(Path, "read_bytes", no_read_bytes)
    evs = upload.ingest_file(p, "demo")
    monkeypatch.setattr(Path, "read_bytes", orig_read_bytes)
    assert {e.ip for e in evs} == {"192.0.2.10", "198.51.100.5"}


def test_ingest_closes_the_duckdb_connection(monkeypatch, tmp_path):
    p = tmp_path / "iocs.csv"
    p.write_text("ip,title\n203.0.113.9,bad host\n")

    created = []
    real_connect = upload.duckdb.connect

    class _TrackConn:
        def __init__(self, real):
            self._real = real
            self.exited = False

        def __enter__(self):
            return self._real.__enter__()

        def __exit__(self, *a):
            self.exited = True
            return self._real.__exit__(*a)

    def tracking(*a, **k):
        tc = _TrackConn(real_connect(*a, **k))
        created.append(tc)
        return tc

    monkeypatch.setattr(upload.duckdb, "connect", tracking)
    evs = upload.ingest_file(p, "demo")
    assert evs and evs[0].ip == "203.0.113.9"
    assert created and all(tc.exited for tc in created)   # the connection was closed by `with`


def test_ingest_plain_ip_list(tmp_path):
    p = tmp_path / "list.txt"
    p.write_text("# a comment\n192.0.2.1\n192.0.2.2\n")
    evs = upload.ingest_file(p, "block")
    assert [e.ip for e in evs] == ["192.0.2.1", "192.0.2.2"]
