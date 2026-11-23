"""v1.2 counts: the server numbers the UI shows side by side agree, and an "all data" chart starts where the data is.

    uv run --with pytest pytest tests/netlog/test_counts.py -q

Definitions (okf/data/netlog.md#the-needs-you-count):
- needs_you: untriaged, not expected, not demo, high + medium (badge, Network header, Watch);
- open: every untriaged incident, any severity, demo included (the Alerts tab count and the list's "New" chip);
- demo: untriaged demo incidents, any severity; demo_loaded: the demo files are in, whatever their alerts' state.
"""
from __future__ import annotations

import datetime as dt
import gzip
import io
import json

from _lake import make_lake
LAKE = make_lake("netlog-v12-counts")

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db  # noqa: E402
from osinthub.netlog import api, importer, incidents, intervals, util  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
UTC = dt.UTC
_app = FastAPI()
_app.include_router(api.router)
C = TestClient(_app)

NOW = dt.datetime.now(UTC).replace(minute=0, second=0, microsecond=0) - dt.timedelta(hours=2)
LISTED = NOW - dt.timedelta(days=400)
C2, SCAN = "198.51.100.7", "203.0.113.9"
TV, LAPTOP, NAS = "192.0.2.30", "192.0.2.21", "192.0.2.50"


def rec(source: str, when: dt.datetime, lines: list[dict]) -> None:
    p = config.RAW_DIR / source / when.strftime("%Y/%m/%d") / f"{when.strftime('%H%M%S')}.records.ndjson.gz"
    p.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(p, "wt") as fh:
        for line in lines:
            fh.write(json.dumps(line) + "\n")


def conn(t: dt.datetime, uid: str, src: str, dst: str, dport: int = 443, state: str = "SF") -> dict:
    return {"ts": t.timestamp(), "uid": uid, "id.orig_h": src, "id.orig_p": 50000, "id.resp_h": dst, "id.resp_p": dport,
            "proto": "tcp", "conn_state": state, "orig_bytes": 300, "resp_bytes": 700, "duration": 1.0, "history": "ShADadFf"}


def load(name: str, rows: list[dict]) -> dict:
    return importer.import_any(io.BytesIO("\n".join(json.dumps(r) for r in rows).encode()), name, origin="upload")


@pytest.fixture(scope="module")
def world():
    rec("feodo_c2", LISTED, [{"key": f"{C2}:443", "op": "put", "data": {"ip_address": C2, "port": 443, "malware": "QakBot"}}])
    rec("blocklist_de", LISTED, [{"key": SCAN, "op": "put", "data": SCAN}])
    intervals.refresh()
    s = util.settings()
    s["home_prefixes"] = util.unique_prefixes((s.get("home_prefixes") or []) + ["192.0.2.0/24"])
    util.save_settings(s)
    # three days of ordinary traffic, dense: a few thousand rows
    busy = [conn(NOW - dt.timedelta(minutes=m), f"Cn{m}", LAPTOP, "198.51.100.200") for m in range(0, 3 * 24 * 60, 2)]
    # the TV beacons to a C2 (high), a scanner knocks on the NAS (refused, low)
    beacon = [conn(NOW - dt.timedelta(minutes=m), f"Cb{m}", TV, C2) for m in (10, 40, 70)]
    scan = [conn(NOW - dt.timedelta(hours=5), "Cs1", SCAN, NAS, 22, "REJ")]
    # one stray record a year before everything else (a sensor whose clock was wrong once)
    stray = [conn(NOW - dt.timedelta(days=300), "Cold", NAS, "198.51.100.201")]
    load("v12-counts.log", busy + beacon + scan + stray)
    return True


def test_open_is_the_lists_new_count(world):
    c = C.get("/api/netlog/alerts/count").json()
    st = C.get("/api/netlog/incidents/summary").json()
    assert c["open"] == st["state"].get("new", 0)
    assert c["open"] == c["needs_you"] + c["low"] + c["info"] + c["demo"]
    assert c["needs_you"] >= 1 and c["demo"] == 0 and c["demo_loaded"] is False
    s = C.get("/api/netlog/summary").json()
    assert s["alerts_other"]["open"] == c["open"] and s["needs_you"] == c["needs_you"]


def test_demo_counts_apart_and_demo_loaded(world):
    before = C.get("/api/netlog/alerts/count").json()
    db.execute("UPDATE alerts SET demo = true WHERE indicator = ?", [C2])
    incidents.regroup(db.cursor())
    try:
        c = C.get("/api/netlog/alerts/count").json()
        assert c["needs_you"] == before["needs_you"] - 1 and c["demo"] == before["demo"] + 1
        assert c["open"] == before["open"]   # still untriaged: the list's "New" keeps counting it
        st = C.get("/api/netlog/incidents/summary").json()
        assert c["open"] == st["state"].get("new", 0)
    finally:
        db.execute("UPDATE alerts SET demo = false WHERE indicator = ?", [C2])
        incidents.regroup(db.cursor())
    db.execute("INSERT INTO netlog_files (id, name, origin) VALUES ('v12-demo-marker', 'demo.log', 'demo')")
    try:
        assert C.get("/api/netlog/alerts/count").json()["demo_loaded"] is True
    finally:
        db.execute("DELETE FROM netlog_files WHERE id = 'v12-demo-marker'")
    assert C.get("/api/netlog/alerts/count").json()["demo_loaded"] is False


def test_dense_start_skips_one_stray_old_record(world):
    s = C.get("/api/netlog/summary").json()
    first, last, dense = (dt.datetime.fromisoformat(s[k]) for k in ("first", "last", "dense_first"))
    assert first < NOW - dt.timedelta(days=200)          # the stray record is still the first one
    assert s["before_dense"] == 1                         # and the only row left out of the chart
    assert dense >= NOW - dt.timedelta(days=4)            # the chart starts where the traffic is
    assert (last - dense) / (last - first) > 0.005


def test_dense_start_keeps_evenly_spread_data(monkeypatch):
    # degenerate inputs: nothing to trim
    out = api._dense_start({"rows": 0, "first": None, "last": None})
    assert out == {"dense_first": None, "before_dense": 0}
    t = dt.datetime(2026, 1, 1, tzinfo=UTC)
    assert api._dense_start({"rows": 1, "first": t, "last": t}) == {"dense_first": t, "before_dense": 0}
    # evenly spread data: one row an hour for 60 days, no stray tail. _dense_start reads the netlog table, so point
    # its queries at a table holding only that data; the chart must start at the very first row and leave none out.
    db.execute("CREATE OR REPLACE TABLE v12_even AS SELECT TIMESTAMPTZ '2026-01-01 00:00:00+00' + i * INTERVAL 1 HOUR AS ts "
               "FROM range(60 * 24) r(i)")
    real = db.query
    monkeypatch.setattr(api.db, "query", lambda q, p=None: real(q.replace("FROM netlog", "FROM v12_even"), p or []))
    n = real("SELECT count(*) AS rows, min(ts) AS first, max(ts) AS last FROM v12_even")[0]
    out = api._dense_start(n)
    assert out["before_dense"] == 0
    assert out["dense_first"] == n["first"]
    db.execute("DROP TABLE v12_even")