"""The core HTTP API on a temporary lake with synthetic events: parameter handling (paging over tied timestamps,
limits, offsets and windows that are 4xx never 500, the SQL console's refusals), Cyber Pulse being honest about
missing data (no score from nothing, no made-up churn, stale inputs shown as stale), and the optional AI helper
being an error only when it was expected (AI_HELPER) or answered during this run. No network, no AI helper.

    uv run --with pytest pytest tests/app/test_core_api.py -q
"""
from __future__ import annotations

import os

os.environ.pop("AI_HELPER", None)
from _lake import make_lake
LAKE = make_lake("core-api", disable="news,entities,netlog,ai", OSINTHUB_SQL_CONSOLE="1")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import analytics, db  # noqa: E402
from osinthub.ai import client  # noqa: E402
from osinthub.api import app  # noqa: E402

db.connect()


# ---------------------------------------------------------------- parameters
# 30 events sharing one timestamp (ties), plus a few at known ages.
def test_core_api_params():
    for i in range(30):
        db.execute("INSERT INTO events (id, source, kind, ts, title, severity) VALUES (?, 'cisa_kev', 'kev', now() - INTERVAL 2 DAY, ?, 0.5)",
                   [f"tie{i:02d}", f"tied event {i}"])
    for eid, minutes, title in [("m20", 20, "twenty minutes ago"), ("m80", 80, "eighty minutes ago"), ("m200", 200, "200 minutes")]:
        db.execute("INSERT INTO events (id, source, kind, ts, title) VALUES (?, 'otx', 'otx', now() - to_minutes(?), ?)", [eid, minutes, title])
    c = TestClient(app, base_url="http://localhost")   # no `with`: the lifespan (scheduler, sources) does not start
    fails = []


    def check(name, cond, detail=""):
        print(("PASS " if cond else "FAIL ") + name + (f"  {detail}" if not cond else ""))
        if not cond:
            fails.append(name)


    def status(path, **p):
        return c.get(path, params=p).status_code


    ids = []
    for off in range(0, 30, 7):
        ids += [r["id"] for r in c.get("/api/events", params={"kinds": "kev", "limit": 7, "offset": off}).json()]
    check("paging over tied timestamps returns each row once", sorted(ids) == [f"tie{i:02d}" for i in range(30)], ids)

    for path in ("/api/events", "/api/geo/points", "/api/stats/top", "/api/sources/cisa_kev/runs"):
        check(f"{path} negative limit is a 422", status(path, limit=-1) == 422)
    check("/api/events negative offset is a 422", status("/api/events", offset=-1) == 422)
    for off in ("9223372036854775808", "99999999999999999999"):
        check(f"/api/events offset={off} (past int64) is a 422", status("/api/events", offset=off) == 422)
    check("/api/events offset=2^63-1 is an empty page", c.get("/api/events", params={"offset": 2 ** 63 - 1}).json() == [])
    for v in ("nan", "inf", "-inf", "-1"):
        for path, name in (("/api/events", "since_hours"), ("/api/stats/summary", "since_hours"), ("/api/stats/timeline", "hours"),
                           ("/api/stats/countries", "since_hours"), ("/api/geo/points", "since_hours"), ("/api/metrics", "minutes")):
            p = {name: v, **({"names": "x"} if path == "/api/metrics" else {})}
            check(f"{path} {name}={v} is a 400", status(path, **p) == 400)
    for v in ("1e10", "1e300"):
        check(f"since_hours={v} means all history", len(c.get("/api/events", params={"since_hours": v, "limit": 5000}).json()) == 33)
        check(f"summary since_hours={v} counts every row as recent",
              all(k["recent"] == k["total"] for k in c.get("/api/stats/summary", params={"since_hours": v}).json()["kinds"]))
        check(f"metrics minutes={v} is fine", status("/api/metrics", names="x", minutes=v) == 200)

    check("runs of an unknown source is a 404", status("/api/sources/nonexistent/runs") == 404)
    check("runs of a known source", status("/api/sources/cisa_kev/runs") == 200)


    def otx(**p):
        return sorted(r["id"] for r in c.get("/api/events", params={"kinds": "otx", "limit": 100, **p}).json())


    check("since_hours=0.5 is 30 minutes", otx(since_hours=0.5) == ["m20"], otx(since_hours=0.5))
    check("since_hours=1.5 is 90 minutes, not 1 hour", otx(since_hours=1.5) == ["m20", "m80"], otx(since_hours=1.5))
    check("since_hours=0 is an empty window", otx(since_hours=0) == [], otx(since_hours=0))
    check("no since_hours is all history", otx() == ["m20", "m200", "m80"], otx())
    check("timeline hours=0 is empty", c.get("/api/stats/timeline", params={"hours": 0}).json() == [])
    db.execute("INSERT INTO events (id, source, kind, ts, title) VALUES ('pct', 'otx', 'otx', now(), 'up 50% this week'), "
               "('und', 'otx', 'otx', now(), 'snake_case name')")
    check("q '%' matches only a literal percent sign", otx(q="%") == ["pct"], otx(q="%"))
    check("q '_' matches only a literal underscore", otx(q="_") == ["und"], otx(q="_"))
    check("q '50%' still a contains-text match", otx(q="50%") == ["pct"], otx(q="50%"))

    from osinthub.api import _sql_value
    check("sql: integers past 2^53 - 1 are exact strings", [_sql_value(x) for x in (2 ** 53, -(2 ** 53) - 1, 2 ** 127 - 1)]
          == ["9007199254740992", "-9007199254740993", str(2 ** 127 - 1)])
    check("sql: safe integers and bools stay JSON numbers", [_sql_value(x) for x in (0, -7, 2 ** 53 - 1, True)] == [0, -7, 2 ** 53 - 1, True])
    check("sql: big integers inside lists and structs", _sql_value({"a": [1, 2 ** 60]}) == {"a": [1, str(2 ** 60)]})
    r = c.post("/api/sql", json={"sql": "SELECT 18446744073709551615::UBIGINT AS u, 42 AS n"}).json()
    check("sql endpoint sends UBIGINT max as a string", r["rows"] == [["18446744073709551615", 42]], r)

    def sql(q):
        return c.post("/api/sql", json={"sql": q})

    # api-audit-r2-003: keywords and ';' inside string literals, quoted identifiers and comments are data
    db.execute("INSERT INTO events (id, source, kind, ts, title) VALUES ('upd', 'otx', 'otx', now(), 'Chrome update; patch now')")
    for q, want in [("SELECT count(*) AS n FROM events WHERE title ILIKE '%update%'", [[1]]),
                    ("SELECT count(*) AS n FROM events WHERE title LIKE '%;%'", [[1]]),
                    ("SELECT 'drop' AS a, 'set' AS b, 'call' AS c, 'import' AS d", [["drop", "set", "call", "import"]]),
                    ("SELECT 'it''s; drop' AS q", [["it's; drop"]]),
                    ('SELECT 1 AS "update"', [[1]]),
                    ("SELECT 1 AS x -- a trailing comment; drop", [[1]]),
                    ("SELECT 1 AS x /* update */;", [[1]])]:
        r = sql(q)
        check(f"sql allows {q!r}", r.status_code == 200 and r.json()["rows"] == want, r.text)
    for q in ["SELECT 1; DROP TABLE events", "SELECT 1; SELECT 2", "SET threads = 1", "CALL pragma_version()", "CHECKPOINT",
              "UPDATE events SET title = 'x'", "WITH x AS (SELECT 1) DELETE FROM events", "SELECT 1 AS x; ATTACH 'x.db'",
              "SELECT e'a\\';drop' AS x; DROP TABLE events", "SELECT $$a$$; DROP TABLE events", "SELECT 1 -- c\n; DROP TABLE events",
              "SELECT 'x' AS y; INSTALL httpfs", "PRAGMA version", "COPY events TO 'x.csv'"]:
        check(f"sql refuses {q!r}", sql(q).status_code == 400)
    check("events table untouched", sql("SELECT count(*) AS n FROM events").json()["rows"] == [[36]])

    # api-probe-r2-007: infinite dates are 'infinity' / '-infinity', and real extreme dates stay dates
    r = sql("SELECT 'infinity'::TIMESTAMP t, '-infinity'::DATE d, 'infinity'::TIMESTAMPTZ tz, 1 AS n, "
            "DATE '9999-12-31' dmax, TIMESTAMP '9999-12-31 23:59:59.999999' tmax, NULL::DATE z").json()
    check("sql infinity dates", r["rows"] == [["infinity", "-infinity", "infinity", 1, "9999-12-31", "9999-12-31T23:59:59.999999", None]], r)
    check("sql infinity column names", r["columns"] == ["t", "d", "tz", "n", "dmax", "tmax", "z"], r)
    r = sql("SELECT [DATE '2024-01-02', NULL] l, {'a': DATE '2024-01-03'} s, '-infinity'::TIMESTAMP_NS t").json()
    check("sql infinity next to date lists and structs", r["rows"] == [[["2024-01-02", None], {"a": "2024-01-03"}, "-infinity"]], r)

    # api-probe-r2-006: an unknown order is a 400 naming the allowed values, not the default ordering
    r = c.get("/api/events", params={"order": "severty"})
    check("events order=severty is a 400", r.status_code == 400 and "ts, severity" in r.json()["detail"], r.text)
    check("events order=severity works", status("/api/events", order="severity") == 200)

    print("ALL PASS" if not fails else f"{len(fails)} FAILED")
    assert not fails, f"{len(fails)} failed: {fails}"


# ---------------------------------------------------------------- Cyber Pulse
@pytest.fixture(autouse=True)
def clean():
    for t in ("events", "metrics", "source_state"):
        db.execute(f"DELETE FROM {t}")
    # RIS Live (the routing input) is off by default since v1.2 and runs only with a routing watchlist: these tests
    # model a lake that has both
    db.execute("INSERT INTO source_state (id, enabled) VALUES ('ris_live', true)")
    db.set_setting("routing.watchlist", [{"id": "AS64500", "kind": "asn", "value": "AS64500", "label": "test"}])
    yield


def ok_run(sid: str, hours_ago: float, enabled=None):
    db.execute("INSERT OR REPLACE INTO source_state (id, enabled, status, last_ok) "
               f"VALUES (?, ?, 'ok', now() - INTERVAL ({hours_ago}) HOUR)", [sid, enabled])


def event(eid: str, source: str, kind: str, hours_ago: float, severity=0.5):
    db.execute("INSERT INTO events (id, source, kind, ts, title, severity, ingested_at) "
               f"VALUES (?, ?, ?, now() - INTERVAL ({hours_ago}) HOUR, ?, ?, now() - INTERVAL ({hours_ago}) HOUR)",
               [eid, source, kind, eid, severity])


def metric(name: str, minutes_ago: float, value: float):
    db.execute(f"INSERT INTO metrics VALUES (now() - INTERVAL ({minutes_ago}) MINUTE, ?, ?)", [name, value])


def ix(p, k):
    return next(i for i in p["indices"] if i["id"] == k)


def test_empty_lake_is_warming_with_no_score():
    p = analytics.pulse()
    assert p["state"] == "warming"
    assert p["score"] is None and p["level"] is None and p["change_24h"] is None
    assert p["current"] == 0 and p["total"] == 5
    assert p["label"].startswith("Warming up")
    for i in p["indices"]:
        assert i["value"] is None and i["active"] is False
        assert i["status"] in ("waiting", "off")


def test_no_made_up_churn():
    """Routing used to be 25 from nothing (churn plugged at 50). With no metrics and no events it is 0 from data,
    and it is not current, so it has no value at all."""
    assert analytics._indices(0)["routing"] == 0.0
    assert ix(analytics.pulse(), "routing")["value"] is None


def test_stale_inputs_give_no_score_and_say_stale():
    ok_run("cisa_kev", 24 * 5)       # last good run 5 days ago (interval 6h)
    ok_run("ioda_outages", 24 * 3)
    event("k1", "cisa_kev", "kev", 24 * 5)
    metric("bgp.withdrawals_per_s", 60 * 30, 2.0)   # stream last spoke 30h ago
    p = analytics.pulse()
    assert p["state"] == "stale"
    assert p["score"] is None and p["level"] is None
    assert p["label"] == "Stale — 0 of 5 inputs current"
    assert ix(p, "exploitation")["status"] == "stale" and ix(p, "exploitation")["value"] is None
    assert ix(p, "routing")["status"] == "stale"
    assert ix(p, "exploitation")["last_data"]


def test_current_inputs_score_over_themselves_only():
    ok_run("cisa_kev", 1)
    ok_run("ioda_outages", 0.1)
    metric("bgp.withdrawals_per_s", 2, 1.0)
    metric("bgp.withdrawals_per_s", 120, 1.0)
    event("k1", "cisa_kev", "kev", 2)
    p = analytics.pulse()
    assert p["current"] == 3 and p["state"] == "partial"
    assert p["score"] is not None and p["level"]
    weights = {i["id"]: i["weight"] for i in p["indices"]}
    assert weights["chatter"] == 0 and weights["ransomware"] == 0
    assert abs(sum(weights.values()) - 1) < 0.01
    assert ix(p, "chatter")["value"] is None
    assert ix(p, "exploitation")["value"] > 0


def test_two_current_is_not_enough_but_values_show():
    ok_run("cisa_kev", 1)
    ok_run("ioda_outages", 0.1)
    ok_run("nvd_recent", 24 * 4)
    p = analytics.pulse()
    assert p["state"] == "warming" and p["score"] is None   # nothing that delivered before has stopped
    assert ix(p, "exploitation")["value"] is not None
    db.execute("INSERT OR REPLACE INTO source_state (id, enabled) VALUES ('ris_live', true)")
    metric("bgp.updates_per_s", 60 * 48, 10.0)                # routing delivered before, now silent
    assert analytics.pulse()["state"] == "stale"


def test_disabled_feed_is_off_not_stale():
    ok_run("ransomware_live", 24 * 10, enabled=False)
    assert ix(analytics.pulse(), "ransomware")["status"] == "off"


def test_all_current_is_ok():
    for sid in ("cisa_kev", "ioda_outages"):
        ok_run(sid, 0.5)
    ok_run("ransomware_live", 0.2, enabled=True)
    metric("bgp.updates_per_s", 1, 10.0)
    metric("bluesky.posts_per_s", 1, 3.0)
    p = analytics.pulse()
    assert p["state"] == "ok" and p["label"] is None and p["current"] == 5


# ---------------------------------------------------------------- the AI helper
def test_not_running_helper_is_neither_configured_nor_ever_up():
    assert client.health(timeout=0.3) is None
    st = client.status()
    assert st["configured"] is False and st["ever_up"] is False


def test_ai_helper_setting_marks_it_expected(monkeypatch):
    monkeypatch.setenv("AI_HELPER", "required")
    assert client.status()["configured"] is True


def test_an_answer_marks_ever_up(monkeypatch):
    class R:
        status_code = 200
        def json(self): return {"ok": True}
    class C:
        def get(self, *a, **k): return R()
    monkeypatch.setattr(client, "_client", lambda: C())
    assert client.health() == {"ok": True}
    assert client.status()["ever_up"] is True
