"""Map layers: /api/geo/points?spread=1 samples evenly across the whole window instead of keeping only the newest
points (so Cinema's ALL never looks shorter than 30D), and a missing reference layer (cables, landings, countries) is
an empty layer that says so, never an error.

    uv run --with pytest pytest tests/app/test_geo.py -q
"""
from __future__ import annotations

from _lake import make_lake
LAKE = make_lake("geo")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db  # noqa: E402
from osinthub.api import app  # noqa: E402

db.connect()
C = TestClient(app, base_url="http://localhost")
# 200 located events, one per 6 hours over 50 days (documentation addresses only)
for i in range(200):
    db.execute("""INSERT INTO events (id, source, kind, ts, title, severity, lat, lon, ip)
                  VALUES (?, 'dshield_top', 'attack', now() - to_hours(?), ?, 0.5, 10.0, 20.0, ?)""",
               [f"g{i:03d}", i * 6, f"event {i}", f"198.51.100.{i % 250}"])


def span_days(rows):
    ts = [r[7] for r in rows]
    return (max(ts) - min(ts)) / 86400


def test_default_keeps_newest():
    r = C.get("/api/geo/points", params={"limit": 40}).json()["rows"]
    assert len(r) == 40 and span_days(r) < 10   # the newest 40: the last ten days only


def test_spread_covers_whole_span():
    r = C.get("/api/geo/points", params={"limit": 40, "spread": 1}).json()["rows"]
    assert 35 <= len(r) <= 40
    assert span_days(r) > 45                    # first to last of the 50 days
    ts = [x[7] for x in r]
    assert ts == sorted(ts, reverse=True)       # still newest first
    # ALL (no window) is never shorter than 30 days when 30 days of data exist
    r30 = C.get("/api/geo/points", params={"limit": 40, "spread": 1, "since_hours": 720}).json()["rows"]
    assert span_days(r) >= span_days(r30) > 25


def test_spread_under_the_cap_returns_everything():
    r = C.get("/api/geo/points", params={"limit": 1000, "spread": 1}).json()["rows"]
    assert len(r) == 200


@pytest.mark.parametrize("name,path", [("cables", config.CABLES_GEOJSON), ("landings", config.LANDINGS_GEOJSON),
                                       ("countries", config.COUNTRIES_GEOJSON)])
def test_missing_reference_is_an_empty_layer(name, path):
    assert not path.exists()
    r = C.get(f"/api/geo/{name}")
    assert r.status_code == 200
    assert r.json() == {"type": "FeatureCollection", "features": [], "missing": True, "file": path.name}


def test_present_reference_is_served_as_is():
    p = config.CABLES_GEOJSON
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('{"type": "FeatureCollection", "features": []}')
    try:
        r = C.get("/api/geo/cables")
        assert r.status_code == 200 and "missing" not in r.json()
    finally:
        p.unlink()
