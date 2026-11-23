"""Entity list and graph parameters: the time window narrows the list, its total and its per-type counts (the
counts ignore the text filter, not the window); graph confidence, collapse and limit values out of range are 4xx,
the limit is a hard cap including IP groups, and an unknown sort is refused.

    uv run --with pytest pytest tests/entities/test_entity_api.py -q
"""
from __future__ import annotations

from datetime import datetime, timedelta, UTC

from _lake import make_lake
LAKE = make_lake("entity-api")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db  # noqa: E402
from osinthub.entities import api, store  # noqa: E402

db.connect()
store.ensure_schema()
if not db.query("SELECT 1 FROM entities WHERE id = 'actor:test-graph-params'"):
    db.execute("INSERT INTO entities (id, type, name) VALUES ('actor:test-graph-params', 'actor', 'Graph Params')")
_app = FastAPI()
_app.include_router(api.router)
C = TestClient(_app)


def test_min_confidence_range():  # followB issue 3: NaN, inf and out-of-range values were accepted
    p = {"id": "actor:test-graph-params"}
    for v in ("nan", "NaN", "inf", "-inf", "Infinity", "-0.1", "1.5", "2", "1e400", "abc"):
        r = C.get("/api/entities/graph", params={**p, "min_confidence": v})
        assert r.status_code == 422 and "min_confidence" in r.text, (v, r.status_code)
    for v in ("0", "0.5", "1"):
        r = C.get("/api/entities/graph", params={**p, "min_confidence": v})
        assert r.status_code == 200 and r.json()["nodes"][0]["id"] == p["id"], v
    assert C.get("/api/entities/graph", params=p).status_code == 200


def test_collapse_over_range():  # followB rework: negative collapse_over was accepted
    p = {"id": "actor:test-graph-params"}
    for v in ("-1", "-999999", "100001", "nan", "abc"):
        r = C.get("/api/entities/graph", params={**p, "collapse_over": v})
        assert r.status_code == 422 and "collapse_over" in r.text, (v, r.status_code)
    for v in ("0", "15", "100000"):
        assert C.get("/api/entities/graph", params={**p, "collapse_over": v}).status_code == 200, v


def _seed_ip_fanout():
    """An actor using 6 IPs in two ASNs and 3 malware families: with collapse_over=2 the IPs become 2 ASN bubbles."""
    root = "actor:test-graph-cap"
    if db.query("SELECT 1 FROM entities WHERE id = ?", [root]):
        return root
    db.execute("INSERT INTO entities (id, type, name) VALUES (?, 'actor', 'Graph Cap')", [root])
    for i in range(6):
        ip = f"ip:192.0.2.{i + 1}"
        db.execute("INSERT INTO entities (id, type, name, attrs) VALUES (?, 'ip', ?, ?)",
                   [ip, ip[3:], f'{{"asn": "AS6450{i % 2}"}}'])
        db.execute("INSERT INTO claims (id, subj, predicate, obj, origin, confidence) VALUES (?, ?, 'uses', ?, 'reported', ?)",
                   [f"cap-ip-{i}", root, ip, 0.9 - i * 0.01])
    for i in range(3):
        m = f"malware:test-cap-{i}"
        db.execute("INSERT INTO entities (id, type, name) VALUES (?, 'malware', ?)", [m, m])
        db.execute("INSERT INTO claims (id, subj, predicate, obj, origin, confidence) VALUES (?, ?, 'uses', ?, 'reported', ?)",
                   [f"cap-mw-{i}", root, m, 0.5])
    return root


def test_limit_is_a_hard_cap_including_ip_groups():  # api-probe-r2-002: ASN bubbles were added after the cap
    root = _seed_ip_fanout()
    full = C.get("/api/entities/graph", params={"id": root, "collapse_over": 2}).json()
    assert sum(n["type"] == "ip-group" for n in full["nodes"]) == 2 and len(full["nodes"]) == 6   # root, 2 bubbles, 3 malware
    for limit in range(0, 8):
        g = C.get("/api/entities/graph", params={"id": root, "collapse_over": 2, "limit": limit}).json()
        ids = {n["id"] for n in g["nodes"]}
        assert len(g["nodes"]) <= max(limit, 1), (limit, [n["id"] for n in g["nodes"]])
        assert g["nodes"][0]["id"] == root
        assert all(e["source"] in ids and e["target"] in ids for e in g["edges"]), limit
    # the bubbles rank where their best-confidence IPs were found: before the lower-confidence malware links
    g = C.get("/api/entities/graph", params={"id": root, "collapse_over": 2, "limit": 3}).json()
    assert [n["type"] for n in g["nodes"]] == ["actor", "ip-group", "ip-group"]


def test_list_sort_is_validated():  # api-probe-r2-006: an unknown sort silently fell back to the default
    r = C.get("/api/entities", params={"sort": "first_seen"})
    assert r.status_code == 400 and "mentions, last_seen, name, claims" in r.json()["detail"]
    for s in ("mentions", "last_seen", "name", "claims"):
        assert C.get("/api/entities", params={"sort": s, "limit": 2}).status_code == 200, s


NOW = datetime.now(UTC)
ROWS = [  # made-up names; one seen an hour ago, one three days ago, one 40 days ago, one reference row never seen
    {"id": "actor:rgfresh", "type": "actor", "name": "RgFresh", "last_seen": NOW - timedelta(hours=1)},
    {"id": "actor:rgweek", "type": "actor", "name": "RgWeek", "last_seen": NOW - timedelta(days=3)},
    {"id": "malware:rgold", "type": "malware", "name": "RgOld", "last_seen": NOW - timedelta(days=40)},
    {"id": "malware:rgref", "type": "malware", "name": "RgRef"},
]
store.upsert_entities([{**r, "first_seen": r.get("last_seen")} for r in ROWS])


def _get(**p):
    r = C.get("/api/entities", params={"type": "actor,malware", "q": "rg", "limit": 50, **p})
    assert r.status_code == 200, r.text
    return r.json()


def test_all_time_lists_everything_and_counts_every_type():
    d = _get()
    assert {x["id"] for x in d["items"]} == {r["id"] for r in ROWS}
    assert d["total"] == 4
    assert d["counts"]["actor"] >= 2 and d["counts"]["malware"] >= 2


def test_window_narrows_items_total_and_counts():
    day = _get(since_hours=24)
    assert [x["id"] for x in day["items"]] == ["actor:rgfresh"] and day["total"] == 1
    assert day["counts"] == {"actor": 1}   # the rail's counts follow the window (reference rows have no last_seen)
    week = _get(since_hours=168)
    assert {x["id"] for x in week["items"]} == {"actor:rgfresh", "actor:rgweek"}
    assert week["counts"] == {"actor": 2}
    month = _get(since_hours=720)
    assert month["total"] == 2 and "malware" not in month["counts"]


def test_counts_ignore_the_text_filter_but_not_the_window():
    # counts are per type for the whole window (the rail), not for the typed filter
    d = C.get("/api/entities", params={"type": "actor", "q": "rgfresh", "since_hours": 168}).json()
    assert d["total"] == 1 and d["counts"]["actor"] == 2


def test_bad_window_is_a_400():
    assert C.get("/api/entities", params={"since_hours": -1}).status_code == 400
    assert C.get("/api/entities", params={"since_hours": "nan"}).status_code == 400
