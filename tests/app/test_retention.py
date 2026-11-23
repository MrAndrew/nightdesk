"""Retention (Settings › Data): off by default and with null, nothing is ever deleted; with lake_days, raw files of
days before the window go and newer ones stay; with db_days, older events, runs and metrics go and newer ones stay;
every purge is reported as last_purge. Through the API, on a temporary lake.

    uv run --with pytest pytest tests/app/test_retention.py -q
"""
from __future__ import annotations

import datetime as dt

from _lake import make_lake
LAKE = make_lake("retention", disable="news,entities,netlog,ai")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db  # noqa: E402
from osinthub.api import app  # noqa: E402

db.connect()
C = TestClient(app, base_url="http://localhost")   # the full app: Host must be allowed
ORIGIN = {"Origin": "http://localhost"}
NOW = dt.datetime.now(dt.UTC)
OLD, NEW = NOW - dt.timedelta(days=40), NOW - dt.timedelta(days=2)


def _day(t: dt.datetime):
    d = config.RAW_DIR / "cisa_kev" / t.strftime("%Y/%m/%d")
    d.mkdir(parents=True, exist_ok=True)
    (d / "120000.records.ndjson.gz").write_bytes(b"x" * 100)
    return d


@pytest.fixture(scope="module")
def days():
    out = {"old": _day(OLD), "new": _day(NEW)}
    for name, t in (("old", OLD), ("new", NEW)):
        db.execute("INSERT INTO events (id, source, kind, ts, title, ingested_at) VALUES (?, 'cisa_kev', 'kev', ?, ?, ?)",
                   [f"ev-{name}", t, name, t])
        db.execute("INSERT INTO runs (source, started, finished, ok, items) VALUES ('cisa_kev', ?, ?, true, 1)", [t, t])
        db.execute("INSERT INTO metrics VALUES (?, 'test.retention', 1.0)", [t])
    return out


def _left():
    return {"events": sorted(r["id"] for r in db.query("SELECT id FROM events")),
            "runs": db.query("SELECT count(*) AS n FROM runs")[0]["n"],
            "metrics": db.query("SELECT count(*) AS n FROM metrics WHERE name = 'test.retention'")[0]["n"]}


def put(**body):
    return C.put("/api/settings/retention", json=body, headers=ORIGIN)


def test_off_and_null_keep_everything(days):
    assert C.get("/api/settings").json() == {"retention": {"lake_days": None, "db_days": None}, "last_purge": None}
    r = put(lake_days=None, db_days=0)                            # 0 and null both mean "keep forever"
    assert r.status_code == 200 and r.json() == {"retention": {"lake_days": None, "db_days": None}, "last_purge": None}
    assert all(d.exists() for d in days.values())
    assert _left() == {"events": ["ev-new", "ev-old"], "runs": 2, "metrics": 2}
    for bad in ({"lake_days": "a week"}, {"db_days": 36501}, {"lake_days": -1}):
        assert C.put("/api/settings/retention", json=bad, headers=ORIGIN).status_code == 400, bad
    assert _left()["events"] == ["ev-new", "ev-old"]


def test_lake_days_and_db_days_purge_old_and_keep_new(days):
    r = put(lake_days=30, db_days=30)
    assert r.status_code == 200, r.text
    p = r.json()["last_purge"]
    assert p["lake_days"] == 30 and p["db_days"] == 30 and p["lake_files"] == 1 and p["lake_bytes"] == 100
    assert p["events"] == 1
    assert not days["old"].exists() and days["new"].exists()
    if OLD.strftime("%Y/%m") != NEW.strftime("%Y/%m"):
        assert not (config.RAW_DIR / "cisa_kev" / OLD.strftime("%Y/%m")).exists()   # emptied folders go too
    assert _left() == {"events": ["ev-new"], "runs": 1, "metrics": 1}
    got = C.get("/api/settings").json()
    assert got["retention"] == {"lake_days": 30, "db_days": 30} and got["last_purge"]["at"] == p["at"]
    put(lake_days=None, db_days=None)                              # back to off: nothing more is deleted
    assert days["new"].exists() and _left()["events"] == ["ev-new"]
