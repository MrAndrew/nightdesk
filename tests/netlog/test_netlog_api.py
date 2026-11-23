"""Netlog API details on a temporary lake with a few synthetic rows (no network).

    uv run --with pytest pytest tests/netlog/test_netlog_api.py -q
"""
import os

from _lake import make_lake
LAKE = make_lake("netlog-api")

from osinthub import db  # noqa: E402
from osinthub.netlog import api  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
# Run alone or with the other netlog tests (one process shares one lake): count only these rows.
F = api.LogFilter(query="file_id:test-api-small")
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
# 10 external peers, peer i gets i+1 connections of 100 bytes each
for i in range(10):
    for j in range(i + 1):
        db.execute("""INSERT INTO netlog (rk, file_id, ts, log_type, orig_h, resp_h, resp_p, orig_bytes, resp_bytes)
                      VALUES (?, 'test-api-small', now(), 'conn', '192.168.1.10', ?, 443, 40, 60)""", [i * 100 + j, f"203.0.113.{i + 1}"])


def test_country_breakdown_counts_every_peer():  # api-audit-013
    full = api.stats_top(field="countries", limit=50, f=F)
    assert sum(r["ips"] for r in full) == 10 and sum(r["conns"] for r in full) == 55
    old = api.PEER_GEO_CAP
    api.PEER_GEO_CAP = 3
    try:
        for field in ("countries", "asns"):
            capped = api.stats_top(field=field, limit=50, f=F)
            assert sum(r["ips"] for r in capped) == 10, field
            assert sum(r["conns"] for r in capped) == 55 and sum(r["bytes"] for r in capped) == 5500, field
            other = next(r for r in capped if r["key"] == "other")
            assert other["ips"] == 7 and other["conns"] == 1 + 2 + 3 + 4 + 5 + 6 + 7
    finally:
        api.PEER_GEO_CAP = old


# ---------------------------------------------------------------- HTTP-level details
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

_app = FastAPI()
_app.include_router(api.router)
C = TestClient(_app)
Q = {"query": "file_id:test-api-small"}


def test_aggregate_groups_total_past_last_page():  # api-probe-015
    full = C.get("/api/netlog/aggregate", params={"group": "resp_h", "limit": 3, **Q}).json()
    assert full["groups_total"] == 10
    for off in (9, 10, 11, 100):
        r = C.get("/api/netlog/aggregate", params={"group": "resp_h", "limit": 3, "offset": off, **Q}).json()
        assert r["groups_total"] == 10 and r["total"] == 55, off
        assert len(r["groups"]) == (1 if off == 9 else 0)
    two = C.get("/api/netlog/aggregate", params={"group": "resp_h,resp_p", "limit": 3, "offset": 50, **Q}).json()
    assert two["groups_total"] == 10 and two["groups"] == []
    assert C.get("/api/netlog/aggregate", params={"group": "resp_h", "offset": -1}).status_code == 422
    none = C.get("/api/netlog/aggregate", params={"group": "resp_h", "query": "file_id:nothing-here", "offset": 5}).json()
    assert none["groups_total"] == 0 and none["total"] == 0


def _alert(aid, sev, rule, device, indicator, status="new"):
    db.execute("""INSERT INTO alerts (id, ts, last_ts, severity, device, indicator, source, rule, direction, title, count,
                  evidence, status) VALUES (?, now(), now(), ?, ?, ?, 'test', ?, 'out', 't', 2, '{}', ?)""",
               [aid, sev, device, indicator, rule, status])


_alert("tA1", "high", "ti-ip", "dev1", "198.51.100.1")
_alert("tA2", "low", "ti-ip", "dev2", "198.51.100.1", "ack")
_alert("tA3", "medium", "ti-domain", "dev1", "bad.example")


def test_alerts_aggregate_parent_shape():  # api-probe-016
    one = C.get("/api/netlog/alerts/aggregate", params={"group": "rule", "source": "test"}).json()
    two = C.get("/api/netlog/alerts/aggregate", params={"group": "rule,severity", "source": "test"}).json()
    assert [g["key"] for g in two["groups"]] == [g["key"] for g in one["groups"]] == ["ti-ip", "ti-domain"]
    for g1, g2 in zip(one["groups"], two["groups"]):
        assert {k: v for k, v in g2.items() if k != "children"} == g1      # same fields, same values
    ip = two["groups"][0]
    assert ip["count"] == 2 and ip["rows"] == 4 and ip["high"] == 1 and ip["low"] == 1 and ip["open"] == 1
    assert ip["devices"] == 2 and ip["indicators"] == 1 and ip["max_severity"] == "high" and "bytes" not in ip
    assert [c["key"] for c in ip["children"]] == ["high", "low"] and ip["children"][0]["devices"] == 1
    assert two["total"] == one["total"] == 3
    capped = C.get("/api/netlog/alerts/aggregate", params={"group": "rule,severity", "source": "test", "limit": 1,
                                                           "sublimit": 1}).json()
    assert len(capped["groups"]) == 1 and len(capped["groups"][0]["children"]) == 1
    assert capped["groups"][0]["key"] == "ti-ip" and capped["groups"][0]["children"][0]["key"] == "high"
    assert capped["total"] == 3                                            # the total counts every alert, not the cap
    flat = C.get("/api/netlog/alerts/aggregate", params={"group": "rule", "source": "test", "limit": 1}).json()
    assert [g["key"] for g in flat["groups"]] == ["ti-ip"] and flat["total"] == 3
    every = C.get("/api/netlog/alerts/aggregate", params={"group": "rule,severity", "source": "test", "limit": 0,
                                                         "sublimit": 0}).json()      # 0: no cap
    assert every == two


def test_alerts_unknown_min_severity_is_400():  # api-probe-017
    assert C.get("/api/netlog/alerts", params={"min_severity": "bogus"}).status_code == 400
    assert C.get("/api/netlog/alerts/aggregate", params={"min_severity": "bogus"}).status_code == 400
    ok = C.get("/api/netlog/alerts", params={"min_severity": "medium", "source": "test"})
    assert ok.status_code == 200 and sorted(a["id"] for a in ok.json()) == ["tA1", "tA3"]
    for v in ("Medium", "MEDIUM", " medium "):  # followB issue 3: any case
        for path in ("/api/netlog/alerts", "/api/netlog/alerts/timeline"):
            r = C.get(path, params={"min_severity": v, "source": "test"})
            assert r.status_code == 200, (path, v)
        r = C.get("/api/netlog/alerts", params={"min_severity": v, "source": "test"})
        assert sorted(a["id"] for a in r.json()) == ["tA1", "tA3"], v
        agg = C.get("/api/netlog/alerts/aggregate", params={"min_severity": v, "source": "test"}).json()
        assert agg["total"] == 2, v


def test_settings_home_prefixes_deduped():  # api-probe-019
    from osinthub.netlog import util
    db.set_setting(util.SETTINGS_KEY, {"home_prefixes": ["2001:db8:3200:630::/64", "2001:db8:3200:630::/64",
                                                         "192.168.1.0/24"]})
    r = C.get("/api/netlog/settings").json()
    assert r["home_prefixes"] == ["2001:db8:3200:630::/64", "192.168.1.0/24"]
    assert r["effective_prefixes"] == r["home_prefixes"]
    try:
        r = C.put("/api/netlog/settings", json={"home_prefixes": ["192.168.0.0/16", "192.168.1.3/16", "192.168.0.0/16 "]})
        assert r.status_code == 200, r.text
        assert r.json()["home_prefixes"] == ["192.168.0.0/16"]
        assert db.get_setting(util.SETTINGS_KEY)["home_prefixes"] == ["192.168.0.0/16"]
    finally:
        db.set_setting(util.SETTINGS_KEY, {})


def test_settings_prefixes_matching_no_ips():  # followB issue 1: was a 500 and kept the prefixes
    from osinthub.netlog import util
    db.set_setting(util.SETTINGS_KEY, {"home_prefixes": ["192.168.1.0/24"]})
    try:
        assert C.put("/api/netlog/settings", json={}).status_code == 200
        assert db.query("SELECT count(*) AS n FROM devices WHERE id = 'ip:192.168.1.10'")[0]["n"] == 1
        r = C.put("/api/netlog/settings", json={"home_prefixes": ["198.18.0.0/24", "2001:db8:ffff::/64"]})
        assert r.status_code == 200, r.text
        assert r.json()["applied"]["devices"] == {"devices": 0, "home_ips": 0}
        assert db.get_setting(util.SETTINGS_KEY)["home_prefixes"] == ["198.18.0.0/24", "2001:db8:ffff::/64"]
    finally:
        db.set_setting(util.SETTINGS_KEY, {})


def test_settings_save_is_atomic(monkeypatch):  # followB issue 1: a failed apply keeps the previous settings
    from osinthub.netlog import matcher, util
    db.set_setting(util.SETTINGS_KEY, {"home_prefixes": ["192.168.1.0/24"]})
    try:
        assert C.put("/api/netlog/settings", json={}).status_code == 200
        before = db.query("SELECT id FROM devices ORDER BY id")
        real = matcher.match
        calls = []

        def boom(*a, **k):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("simulated failure")
            return real(*a, **k)
        monkeypatch.setattr(matcher, "match", boom)
        r = C.put("/api/netlog/settings", json={"home_prefixes": ["198.18.0.0/24"], "grace_seconds": 99})
        assert r.status_code == 500 and "previous settings" in r.json()["detail"]
        saved = db.get_setting(util.SETTINGS_KEY)
        assert saved["home_prefixes"] == ["192.168.1.0/24"] and saved.get("grace_seconds", 0) != 99
        assert db.query("SELECT id FROM devices ORDER BY id") == before  # devices rebuilt from the old prefixes
        assert len(calls) == 2
    finally:
        db.set_setting(util.SETTINGS_KEY, {})


def test_devices_rebuild_failure_rolls_back(monkeypatch):  # a failure part-way leaves the previous devices
    from osinthub.netlog import devices, util
    db.set_setting(util.SETTINGS_KEY, {"home_prefixes": ["192.168.1.0/24"]})
    try:
        devices.rebuild()
        before = db.query("SELECT id FROM devices ORDER BY id")
        assert before

        def fail(cur, ev):
            cur.execute("DELETE FROM devices")
            raise RuntimeError("simulated")
        monkeypatch.setattr(devices, "_stats", fail)
        try:
            devices.rebuild()
            raise AssertionError("rebuild should have raised")
        except RuntimeError:
            pass
        assert db.query("SELECT id FROM devices ORDER BY id") == before
        assert db.query("SELECT count(*) AS n FROM netlog_ipdev WHERE ip = '192.168.1.10'")[0]["n"] == 1
    finally:
        db.set_setting(util.SETTINGS_KEY, {})


def test_bad_numbers_are_4xx_not_500():  # followB issue 2: no parameter value gives a 500
    aid = "tA1"
    bad_counts = ("-1", "-9223372036854775809", "9223372036854775808", "abc")
    paths = {"/api/netlog/files": ["limit"], "/api/netlog/devices": ["limit"], "/api/netlog/indicators?source=x": ["limit"],
             "/api/netlog/connections": ["limit", "offset"], "/api/netlog/aggregate?group=resp_h": ["limit", "offset", "sublimit"],
             "/api/netlog/stats/top": ["limit"], "/api/netlog/stats/timeline?split=log_type": ["split_limit"],
             "/api/netlog/alerts": ["limit", "offset"], "/api/netlog/alerts/aggregate": ["limit", "sublimit"],
             "/api/netlog/alerts/timeline": ["split_limit"], f"/api/netlog/alerts/{aid}/uids": ["limit", "offset"],
             f"/api/netlog/alerts/{aid}": ["rows_limit", "rows_offset"]}
    def get(path, **params):  # TestClient drops a query string in the path when params are given
        path, _, qs = path.partition("?")
        return C.get(path, params={**dict(x.split("=") for x in qs.split("&") if x), **params})
    for path, names in paths.items():
        for n in names:
            for v in bad_counts:
                assert get(path, **{n: v}).status_code == 422, (path, n, v)
    windowed = ["/api/netlog/connections", "/api/netlog/aggregate?group=resp_h", "/api/netlog/stats/top",
                "/api/netlog/stats/timeline", "/api/netlog/alerts", "/api/netlog/alerts/aggregate", "/api/netlog/alerts/timeline"]
    for path in windowed:
        for v in ("nan", "inf", "-inf", "-1"):
            r = get(path, **{"since_hours": v})
            assert r.status_code == 400 and "since_hours" in r.text, (path, v)
        assert get(path, **{"since_hours": "1e10"}).status_code == 200, path      # beyond ~200 years: all history
        for t in ("99999999999999999", "1" * 40, "nonsense", "2026-13-01"):
            assert get(path, **{"since": t}).status_code == 400, (path, t)
            assert get(path, **{"until": t}).status_code == 400, (path, t)
        for v in (" ", ",", ",,"):
            assert get(path, **{"device": v}).status_code == 200, (path, v)
    assert C.get("/api/netlog/connections", params={"offset": 2**63 - 1, "limit": 1}).status_code == 200
    assert C.get("/api/netlog/aggregate", params={"group": "resp_h", "distinct": "device"}).status_code == 200


def test_since_hours_fractions_count():  # 0.5 h is 30 minutes (INTERVAL (0.5) HOUR truncated it)
    db.execute("""INSERT INTO netlog (rk, file_id, ts, log_type, orig_h, resp_h, resp_p, orig_bytes, resp_bytes)
                  VALUES (90001, 'test-api-small-frac', now() - INTERVAL 20 MINUTE, 'conn', '192.168.1.10', '203.0.113.99', 1, 0, 0)""")
    try:
        q = {"query": "file_id:test-api-small-frac"}
        assert C.get("/api/netlog/connections", params={**q, "since_hours": 0.5}).json()["total"] == 1
        assert C.get("/api/netlog/connections", params={**q, "since_hours": 0.25}).json()["total"] == 0
        assert C.get("/api/netlog/connections", params={**q, "since_hours": 0}).json()["total"] == 0
    finally:
        db.execute("DELETE FROM netlog WHERE file_id = 'test-api-small-frac'")


def test_settings_numbers_must_be_finite_and_in_range():  # api-probe-r2-001
    from osinthub.netlog import util
    db.set_setting(util.SETTINGS_KEY, {})
    try:
        for k in util.NUMERIC:
            for v in ("inf", "-inf", "nan", "Infinity", 1e20, True, False, -1, "abc", [1], {"a": 1}):
                r = C.put("/api/netlog/settings", json={k: v})
                assert r.status_code == 400, (k, v, r.status_code, r.text)
                assert C.get("/api/netlog/settings").status_code == 200, (k, v)
        assert db.get_setting(util.SETTINGS_KEY) == {}  # nothing invalid was saved
        r = C.put("/api/netlog/settings", json={"rehunt_days": "7", "grace_seconds": 2.5, "ti_poll_seconds": 30})
        assert r.status_code == 200, r.text
        assert (r.json()["rehunt_days"], r.json()["grace_seconds"], r.json()["ti_poll_seconds"]) == (7.0, 2.5, 30.0)
    finally:
        db.set_setting(util.SETTINGS_KEY, {})


def test_settings_get_survives_bad_saved_values():  # api-probe-r2-001: values saved by an older version
    from osinthub.netlog import matcher, util
    db.set_setting(util.SETTINGS_KEY, {"rehunt_days": float("inf"), "grace_seconds": float("nan"),
                                       "ti_poll_seconds": True, "inbox_poll_seconds": 1e20})
    try:
        r = C.get("/api/netlog/settings")
        assert r.status_code == 200, r.text
        s = r.json()
        assert (s["rehunt_days"], s["grace_seconds"], s["ti_poll_seconds"], s["inbox_poll_seconds"]) == (30, 0, 60, 86400)
        db.set_setting(util.SETTINGS_KEY, {"rehunt_days": 1e20, "grace_seconds": -5})
        s = C.get("/api/netlog/settings").json()
        assert s["rehunt_days"] == 36500 and s["grace_seconds"] == 0
        assert matcher.rehunt()["days"] == 36500
        # old builds saved 0 for NaN or negative input: 0 means the default, never a 1-second poll
        db.set_setting(util.SETTINGS_KEY, {"rehunt_days": 0, "grace_seconds": 0, "ti_poll_seconds": 0.0,
                                           "inbox_poll_seconds": 0.5})
        s = C.get("/api/netlog/settings").json()
        assert (s["rehunt_days"], s["grace_seconds"], s["ti_poll_seconds"], s["inbox_poll_seconds"]) == (30, 0, 60, 15)
        assert matcher.rehunt()["days"] == 30
    finally:
        db.set_setting(util.SETTINGS_KEY, {})


def test_paging_with_shared_timestamps_is_disjoint():  # api-audit-r2-002
    ts = "2001-02-03 04:05:06.789+00"
    for i in range(60):
        db.execute("""INSERT INTO netlog (rk, uid, file_id, ts, log_type, orig_h, resp_h, resp_p, orig_bytes, resp_bytes,
                      duration) VALUES (?, ?, 'test-api-small-tie', ?::TIMESTAMPTZ, 'conn', '192.168.1.10', ?, ?, 5, 5, 1.0)""",
                   [70000 + (i * 7919) % 1000, f"Ctie{i}", ts, f"203.0.113.{i % 3}", 1000 + i % 2])
    for i in range(30):
        _alert(f"tie{i:02d}", "medium", "ti-ip", "devT", "198.51.100.9")
    db.execute("UPDATE alerts SET ts = '2001-01-01', last_ts = '2001-01-01' WHERE id LIKE 'tie%'")
    try:
        q = {"query": "file_id:test-api-small-tie"}
        for order in ("desc", "asc", "bytes", "-duration", "resp_p:asc", "resp_h"):
            seen = []
            for off in range(0, 63, 3):
                seen += [r["uid"] for r in C.get("/api/netlog/connections",
                                                 params={**q, "limit": 3, "offset": off, "order": order}).json()["rows"]]
            assert len(seen) == 60 and len(set(seen)) == 60, order
            full = C.get("/api/netlog/connections", params={**q, "limit": 0, "order": order}).json()["rows"]
            assert [r["uid"] for r in full] == seen, order  # the same order as one big page
        ids = []
        for off in range(0, 33, 4):
            ids += [a["id"] for a in C.get("/api/netlog/alerts", params={"device": "devT", "limit": 4, "offset": off}).json()]
        assert sorted(ids) == [f"tie{i:02d}" for i in range(30)]
    finally:
        db.execute("DELETE FROM netlog WHERE file_id = 'test-api-small-tie'")
        db.execute("DELETE FROM alerts WHERE id LIKE 'tie%'")


def test_limit_zero_is_all_rows_and_keeps_offset():  # api-probe-r2-003, api-probe-r2-004
    db.execute("INSERT INTO netlog_files (id, path, imported_at) VALUES ('test-api-small-f0', 'x.log', now())")
    db.execute("""INSERT INTO indicator_intervals (source, kind, value, "start", "end", key, category, meta)
                  VALUES ('t0', 'ip', '198.51.100.77', now(), NULL, 'k0', 'c', '{}')""")
    try:
        for path, extra in (("/api/netlog/files", {}), ("/api/netlog/indicators", {"source": "t0"}),
                            *[("/api/netlog/stats/top", {**Q, "field": f}) for f in
                              ("talkers", "countries", "asns", "ports", "dests", "resp_h", "service")]):
            assert C.get(path, params={**extra, "limit": 0}).json(), (path, extra)
        db.execute("INSERT INTO devices (id) VALUES ('test-dev-limit0')")
        try:
            assert any(d["id"] == "test-dev-limit0" for d in C.get("/api/netlog/devices", params={"limit": 0}).json())
        finally:
            db.execute("DELETE FROM devices WHERE id = 'test-dev-limit0'")
        dests = C.get("/api/netlog/stats/top", params={**Q, "field": "dests", "limit": 0}).json()
        assert len(dests) == 10
        full = C.get("/api/netlog/connections", params={**Q, "limit": 0}).json()
        assert full["total"] == 55 and len(full["rows"]) == 55
        off = C.get("/api/netlog/connections", params={**Q, "limit": 0, "offset": 50}).json()["rows"]
        assert off == full["rows"][50:]
        al = C.get("/api/netlog/alerts", params={"source": "test", "limit": 0}).json()
        assert C.get("/api/netlog/alerts", params={"source": "test", "limit": 0, "offset": 1}).json() == al[1:]
        db.execute("INSERT INTO netlog_matches (alert_id, rk, uid, ts) SELECT 'tA1', rk, 'U' || rk, ts FROM netlog "
                   "WHERE file_id = 'test-api-small' LIMIT 6")
        try:
            u = C.get("/api/netlog/alerts/tA1/uids", params={"limit": 0}).json()
            assert u["total"] == 6 and C.get("/api/netlog/alerts/tA1/uids", params={"limit": 0, "offset": 4}).json()["uids"] == u["uids"][4:]
            d = C.get("/api/netlog/alerts/tA1", params={"rows_limit": 0}).json()
            assert d["rows_total"] == 6 and len(d["rows"]) == 6
            assert C.get("/api/netlog/alerts/tA1", params={"rows_limit": 0, "rows_offset": 2}).json()["rows"] == d["rows"][2:]
        finally:
            db.execute("DELETE FROM netlog_matches WHERE alert_id = 'tA1'")
    finally:
        db.execute("DELETE FROM netlog_files WHERE id = 'test-api-small-f0'")
        db.execute("DELETE FROM indicator_intervals WHERE source = 't0'")


def test_devices_unknown_sort_is_400():  # api-probe-r2-006 (netlog part)
    for s in ("bogus", "", "BYTES", "-bytes"):
        r = C.get("/api/netlog/devices", params={"sort": s})
        assert r.status_code == 400 and "sort must be one of bytes, last_seen, rows, alerts" in r.text, (s, r.text)
    for s in ("alerts", "bytes", "last_seen", "rows"):   # every value the Devices view sends (web/js/views/net/devices.js)
        assert C.get("/api/netlog/devices", params={"sort": s}).status_code == 200, s
    assert C.get("/api/netlog/devices").status_code == 200   # default: bytes


def test_rehunt_days_validated():  # api-probe-r2-001
    for d in ("1e20", "nan", "inf", "-5", "0", "0.5"):
        assert C.post("/api/netlog/rehunt", params={"days": d}).status_code == 400, d
    assert C.put("/api/netlog/settings", json={"rehunt_days": 0}).status_code == 400  # 0 would mean 30
    assert C.put("/api/netlog/settings", json={"inbox_poll_seconds": 0}).status_code == 400
    r = C.post("/api/netlog/rehunt", params={"days": "7"})
    assert r.status_code == 200 and r.json()["days"] == 7.0
    from osinthub.netlog import matcher
    assert matcher.rehunt(float("nan"))["days"] == 30.0 and matcher.rehunt(1e20)["days"] == 36500
    assert matcher.rehunt(0)["days"] == 30.0 and matcher.rehunt(1)["days"] == 1.0


def test_inbox_imports_synced_subfolders_but_not_live_current():  # a Zeek tree synced as <sensor>/<date>/*.log.gz
    import gzip, json as _json, time as _time
    from osinthub.netlog import importer, util
    util.save_inbox_settings(delete_after_import=True)   # v1.2 behaviour; off (keep files) is tested in test_v12_f_inbox.py
    root = importer.INBOX / "sensor-t"
    day, cur = root / "2001-02-03", root / "current"
    day.mkdir(parents=True, exist_ok=True)
    cur.mkdir(parents=True, exist_ok=True)
    rec = {"ts": 981173106.5, "uid": "Cinboxnest1", "id.orig_h": "192.0.2.13", "id.orig_p": 5000,
           "id.resp_h": "198.51.100.7", "id.resp_p": 443, "proto": "tcp"}
    (day / "conn.04:00:00-04:03:00.log.gz").write_bytes(gzip.compress(_json.dumps(rec).encode()))
    (cur / "conn.log").write_text(_json.dumps({**rec, "uid": "Cinboxlive1"}))
    old = _time.time() - 600   # settled: with delete on a file must be unchanged for 2 minutes
    for f in (day / "conn.04:00:00-04:03:00.log.gz", cur / "conn.log"):
        os.utime(f, (old, old))
    try:
        res = importer.scan_inbox()
        assert [r.get("inserted") for r in res if r.get("name", "").startswith("conn.04")] == [1], res
        assert not day.exists()                               # imported, and the emptied folder tidied
        assert (cur / "conn.log").exists()                    # Zeek's live folder is never touched
        assert db.query("SELECT count(*) AS n FROM netlog WHERE uid = 'Cinboxlive1'")[0]["n"] == 0
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)
        util.save_inbox_settings(delete_after_import=False)
