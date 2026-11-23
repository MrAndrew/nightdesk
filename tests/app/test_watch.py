"""Watch: the one last-seen marker, the deterministic briefing and the setup checklist, on a temporary lake.

    uv run --with pytest pytest tests/app/test_watch.py -q
"""
from __future__ import annotations

import datetime as dt
import gzip
import json
from pathlib import Path

from _lake import make_lake
LAKE = make_lake("watch")

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db  # noqa: E402
from osinthub.news.api import router as news_router  # noqa: E402
from osinthub.news.common import ensure_schema  # noqa: E402
from osinthub.watch import marker  # noqa: E402
from osinthub.watch.api import router  # noqa: E402

db.connect()
ensure_schema()
try:
    from osinthub.netlog.schema import SCHEMA_SQL
    from osinthub.netlog.devices import AGG_SQL
    db.cursor().execute(SCHEMA_SQL + AGG_SQL)
except Exception:   # pragma: no cover
    pass

app = FastAPI()
app.include_router(router)
app.include_router(news_router)
c = TestClient(app)

NOW = dt.datetime.now(dt.UTC)
iso = lambda t: t.isoformat()   # noqa: E731
ago = lambda **kw: NOW - dt.timedelta(**kw)   # noqa: E731


@pytest.fixture(autouse=True)
def clean():
    for t in ("events", "source_state", "epss", "stories", "articles", "mentions", "entities", "settings"):
        db.execute(f"DELETE FROM {t}")
    for t in ("alerts", "netlog_files"):
        try:
            db.execute(f"DELETE FROM {t}")
        except Exception:
            pass
    yield


# ------------------------------------------------------------------ marker
def test_no_marker_is_a_first_visit_of_one_day():
    m = c.get("/api/marker").json()
    assert m["last_seen"] is None and m["previous"] is None
    w = m["window"]
    assert w["first_visit"] and not w["capped"]
    assert abs((marker.parse(w["since"]) - ago(hours=24)).total_seconds()) < 60


def test_old_news_marker_value_is_read_and_kept_in_step():
    db.set_setting("news.last_seen", "2026-11-09T21:40:00Z")   # the v1.0 setting: a bare ISO string
    assert c.get("/api/marker").json()["last_seen"].startswith("2026-11-09T21:40:00")
    assert c.get("/api/news/marker").json()["last_seen"].startswith("2026-11-09T21:40:00")   # same marker
    r = c.put("/api/marker", json={}).json()
    assert r["previous"].startswith("2026-11-09T21:40:00")
    assert db.get_setting("news.last_seen") == r["last_seen"]   # old readers see the move too


def test_caught_up_keeps_previous_and_steps_back():
    c.put("/api/marker", json={"last_seen": iso(ago(days=2))})
    first = c.get("/api/marker").json()["last_seen"]
    r = c.put("/api/marker", json={}).json()          # "Caught up"
    assert r["previous"] == first and marker.parse(r["last_seen"]) > ago(minutes=1)
    assert r["set_at"]
    n = c.put("/api/news/marker", json={}).json()      # "Mark all as read" in News is the same action
    assert n["previous"] == first                      # (pressed within minutes: the older previous is kept)
    b = c.put("/api/marker", json={"back": True}).json()   # "Show since <previous> again", for good
    assert b["last_seen"] == first and b["previous"] is None
    assert c.put("/api/marker", json={"last_seen": "not a time"}).status_code == 400


def test_step_back_without_previous_is_a_conflict():
    assert c.put("/api/marker", json={"back": True}).status_code == 409


def test_window_is_capped_at_seven_days():
    c.put("/api/marker", json={"last_seen": iso(ago(days=30))})
    w = c.get("/api/marker").json()["window"]
    assert w["capped"] and w["cap_days"] == 7
    assert abs((marker.parse(w["since"]) - ago(days=7)).total_seconds()) < 60
    assert marker.parse(w["asked"]) < ago(days=29)
    # the old KEV entry dated 20 days ago is outside what Watch shows
    kev_event("CVE-2026-0001", ago(days=20), "Acme", "Router")
    kev_event("CVE-2026-0002", ago(days=3), "Acme", "Gateway")
    d = c.get("/api/watch").json()
    assert [i["cve"] for i in sec(d, "kev")["items"]] == ["CVE-2026-0002"]


def test_previous_view_does_not_move_the_marker():
    c.put("/api/marker", json={"last_seen": iso(ago(days=3))})
    c.put("/api/marker", json={})
    kev_event("CVE-2026-0003", ago(days=1), "Acme", "Router")
    now_view = c.get("/api/watch").json()
    assert sec(now_view, "kev")["count"] == 0
    prev = c.get("/api/watch", params={"since": "previous"}).json()
    assert prev["viewing_previous"] and sec(prev, "kev")["count"] == 1
    assert c.get("/api/marker").json()["last_seen"] == now_view["marker"]["last_seen"]


def test_news_new_since_uses_the_shared_marker():
    db.execute("""INSERT INTO stories (id, title, first_seen, last_seen, article_count, source_count)
                  VALUES ('story:a', 'Example story', ?, ?, 1, 1)""", [ago(hours=2), ago(hours=2)])
    c.put("/api/marker", json={"last_seen": iso(ago(hours=5))})
    r = c.get("/api/news/stories", params={"new_since": "marker"}).json()
    assert r["new_since"] == c.get("/api/marker").json()["last_seen"] and r["stories"][0]["is_new"]
    c.put("/api/marker", json={})
    r = c.get("/api/news/stories", params={"new_since": "marker"}).json()
    assert not r["stories"][0]["is_new"]


# ------------------------------------------------------------------ briefing
def kev_event(cve, added, vendor, product, ransom=False, stored=None):
    tags = [vendor, product] + (["ransomware"] if ransom else [])
    db.execute("""INSERT INTO events (id, source, kind, category, ts, title, summary, tags, url, stored_at)
                  VALUES (?, 'cisa_kev', 'kev', 'vuln', ?, ?, ?, ?, ?, ?)""",
               [f"cisa_kev:{cve}", added, f"{cve} · {vendor} {product}", f"{vendor} {product} Flaw. Bad things.",
                tags, f"https://nvd.nist.gov/vuln/detail/{cve}", stored or added])


def sec(d, sid):
    return next((s for s in d["sections"] if s["id"] == sid), None)


def test_sections_come_in_the_fixed_order_and_say_when_empty():
    d = c.get("/api/watch").json()
    ids = [s["id"] for s in d["sections"]]
    assert ids[:5] == ["network", "touches", "kev", "follow", "stories"]
    assert ids in (ids[:5], ids[:5] + ["health"])
    for s in d["sections"][:5]:
        assert s["count"] == 0 and s["items"] == [] and s["link"]["href"].startswith("#")
        assert s["empty"]   # a plain sentence; "{since}" is filled in by the client
    assert "{since}" in sec(d, "network")["empty"]
    assert d["total"] == 0


def test_newly_exploited_sorted_by_epss_with_due_date():
    c.put("/api/marker", json={"last_seen": iso(ago(days=2))})
    kev_event("CVE-2026-1001", ago(hours=20), "Acme", "Router")
    kev_event("CVE-2026-1002", ago(hours=10), "Example", "VPN", ransom=True)
    kev_event("CVE-2026-1003", ago(hours=5), "Example", "Mail")
    kev_event("CVE-2025-0009", ago(days=40), "Old", "Thing")                          # long ago
    kev_event("CVE-2026-1004", ago(days=2, hours=12), "Late", "Stored", stored=ago(hours=1))  # stored after the marker
    db.execute("INSERT INTO epss (cve, epss, percentile) VALUES ('CVE-2026-1001', 0.02, 0.5), "
               "('CVE-2026-1002', 0.81, 0.99), ('CVE-2026-1003', 0.10, 0.9)")
    raw = Path(config.RAW_DIR) / "cisa_kev" / "2026" / "11" / "10"
    raw.mkdir(parents=True, exist_ok=True)
    with gzip.open(raw / "x.records.ndjson.gz", "wt") as fh:
        fh.write(json.dumps({"op": "put", "key": "CVE-2026-1002", "data": {"cveID": "CVE-2026-1002", "dueDate": "2026-12-01"}}) + "\n")
    k = sec(c.get("/api/watch").json(), "kev")
    assert [i["cve"] for i in k["items"]] == ["CVE-2026-1002", "CVE-2026-1003", "CVE-2026-1001", "CVE-2026-1004"]
    top = k["items"][0]
    assert top["vendor"] == "Example" and top["product"] == "VPN" and top["ransomware"] and top["due"] == "2026-12-01"
    assert top["name"] == "Flaw" and top["id"] == "cisa_kev:CVE-2026-1002"


def test_touches_you_kev_matching_a_followed_vendor_and_cve():
    c.put("/api/marker", json={"last_seen": iso(ago(days=1))})
    c.put("/api/news/watchlist", json={"keywords": ["ExampleVPN"], "entities": ["cve:cve-2026-2002"]})
    kev_event("CVE-2026-2001", ago(hours=3), "Acme", "ExampleVPN")
    kev_event("CVE-2026-2002", ago(hours=3), "Other", "Thing")
    kev_event("CVE-2026-2003", ago(hours=3), "Nobody", "Cares")
    t = sec(c.get("/api/watch").json(), "touches")
    got = {i["cve"]: i for i in t["items"]}
    assert set(got) == {"CVE-2026-2001", "CVE-2026-2002"}
    assert got["CVE-2026-2001"]["why"] == "follow" and got["CVE-2026-2001"]["matched"] == ["keyword:ExampleVPN"]
    assert got["CVE-2026-2002"]["matched"] == ["cve:cve-2026-2002"]


def alert(aid, indicator, severity="high", status="new", ts=None, device="mac:02:00:00:00:00:01", rule="c2_outbound"):
    ts = ts or ago(hours=1)
    db.execute("""INSERT INTO alerts (id, ts, last_ts, severity, device, indicator, source, rule, direction, title, count,
                                      evidence, status, created_at, updated_at)
                  VALUES (?, ?, ?, ?, ?, ?, 'feodo_c2', ?, 'outbound', ?, 1, ?, ?, ?, ?)""",
               [aid, ts, ts, severity, device, indicator, rule, f"device contacted {indicator}",
                json.dumps({"indicator": {"value": indicator, "category": "c2"}}), status, ts, ts])


def test_touches_you_story_naming_an_address_seen_on_your_network():
    c.put("/api/marker", json={"last_seen": iso(ago(days=1))})
    alert("al1", "203.0.113.50")
    db.execute("""INSERT INTO stories (id, title, first_seen, last_seen, article_count, source_count)
                  VALUES ('story:x', 'Botnet uses 203.0.113.50', ?, ?, 2, 2), ('story:y', 'Unrelated', ?, ?, 1, 1)""",
               [ago(hours=4), ago(hours=3), ago(hours=4), ago(hours=3)])
    db.execute("INSERT INTO articles (id, url, source, title, story_id, status) VALUES "
               "('ax', 'https://example.org/x', 'Example', 'x', 'story:x', 'ok'), ('ay', 'https://example.org/y', 'Example', 'y', 'story:y', 'ok')")
    db.execute("INSERT INTO entities VALUES ('ip:203.0.113.50', 'ip', '203.0.113.50', [], '{}', now(), now())")
    db.execute("INSERT INTO mentions VALUES ('ip:203.0.113.50', 'article', 'ax', 'mentioned', 'regex', 0.9, now())")
    t = sec(c.get("/api/watch").json(), "touches")
    assert [(i["type"], i["id"], i["why"], i["indicator"]) for i in t["items"]] == [("story", "story:x", "network", "203.0.113.50")]
    assert t["items"][0]["href"] == "#news/story/story:x"


def test_big_stories_by_source_count_since_the_marker():
    c.put("/api/marker", json={"last_seen": iso(ago(hours=12))})
    rows = [("s1", 2, ago(hours=2)), ("s2", 6, ago(hours=3)), ("s3", 1, ago(hours=1)), ("s4", 9, ago(days=2)), ("s5", 4, ago(hours=6))]
    for sid, n, t in rows:
        db.execute("INSERT INTO stories (id, title, first_seen, last_seen, article_count, source_count) VALUES (?, ?, ?, ?, ?, ?)",
                   [f"story:{sid}", sid, t, t, n, n])
    s = sec(c.get("/api/watch").json(), "stories")
    assert [i["id"] for i in s["items"]] == ["story:s2", "story:s5", "story:s1"] and s["count"] == 3


def test_news_you_follow_is_the_watchlist_digest_since_the_marker():
    c.put("/api/marker", json={"last_seen": iso(ago(hours=12))})
    d0 = sec(c.get("/api/watch").json(), "follow")
    assert not d0["following"] and "don't follow" in d0["empty"]
    c.put("/api/news/watchlist", json={"keywords": ["ExampleGate"]})
    db.execute("INSERT INTO stories (id, title, first_seen, last_seen, article_count, source_count) VALUES "
               "('story:g', 'ExampleGate exploited', ?, ?, 1, 1)", [ago(hours=2), ago(hours=2)])
    db.execute("INSERT INTO articles (id, url, source, title, text, story_id, status, published) VALUES "
               "('ag', 'https://example.org/g', 'Example', 'ExampleGate exploited', 'text', 'story:g', 'ok', ?)", [ago(hours=2)])
    f = sec(c.get("/api/watch").json(), "follow")
    assert [i["id"] for i in f["items"]] == ["story:g"] and f["items"][0]["matched"] == ["keyword:ExampleGate"]


def test_feed_health_only_when_something_is_wrong(monkeypatch):
    monkeypatch.setattr(config, "OFFLINE", False)
    from osinthub.sources import SOURCES
    from osinthub import scheduler
    for s in SOURCES.values():   # every enabled batch source fetched just now: nothing wrong
        if scheduler.is_enabled(s) and not s.unavailable():
            db.execute("INSERT OR REPLACE INTO source_state (id, status, last_ok) VALUES (?, 'ok', ?)", [s.id, NOW])
    d = c.get("/api/watch").json()
    assert sec(d, "health") is None and d["feeds"]["fresh"] == d["feeds"]["enabled"]
    db.execute("UPDATE source_state SET status = 'error', message = 'HTTP 503' WHERE id = 'cisa_kev'")
    db.execute("UPDATE source_state SET last_ok = ? WHERE id = 'nvd_recent'", [ago(days=3)])
    db.execute("INSERT OR REPLACE INTO source_state (id, enabled, status) VALUES ('epss', false, 'disabled')")
    h = sec(c.get("/api/watch").json(), "health")
    probs = {i["id"]: i["problem"] for i in h["items"]}
    assert probs == {"cisa_kev": "failing", "nvd_recent": "stale", "epss": "off"}
    assert [s["id"] for s in c.get("/api/watch").json()["sections"]][-1] == "health"


def test_feed_health_offline_is_one_line():
    h = sec(c.get("/api/watch").json(), "health")
    assert [i["id"] for i in h["items"]] == ["offline"]


# ------------------------------------------------------------------ network (needs the incidents layer)
def test_network_lists_needs_you_incidents_new_since_the_marker():
    c.put("/api/marker", json={"last_seen": iso(ago(hours=6))})
    alert("new-high", "198.51.100.7", "high", ts=ago(hours=1))
    alert("new-med", "198.51.100.8", "medium", ts=ago(hours=2), device="mac:02:00:00:00:00:02")
    alert("new-low", "198.51.100.9", "low", ts=ago(hours=2), device="mac:02:00:00:00:00:03")
    alert("old-high", "198.51.100.10", "high", ts=ago(days=3), device="mac:02:00:00:00:00:04")
    alert("acked", "198.51.100.11", "high", status="ack", ts=ago(hours=1), device="mac:02:00:00:00:00:05")
    from osinthub.netlog import incidents as inc
    inc._ready.clear()
    n = sec(c.get("/api/watch").json(), "network")
    assert n["available"] and not n["demo"]
    assert [i["id"] for i in n["items"]] == ["new-high", "new-med"]
    assert n["items"][0]["href"] == "#network/alerts/new-high" and n["items"][0]["severity"] == "high"
    assert n["needs_you"] == 3   # the old high one still needs you; it is just not new


# ------------------------------------------------------------------ setup status
def test_setup_status_from_real_state():
    s = c.get("/api/setup/status").json()
    by = {i["id"]: i for i in s["items"]}
    assert list(by) == ["feeds", "demo", "logs", "abusech", "watchlist", "ai"]
    assert s["first_run"] and not s["has_data"] and not s["complete"] and not s["dismissed"]
    assert not by["feeds"]["done"] and "Offline" in by["feeds"]["detail"]
    assert not by["demo"]["done"] and by["demo"]["action"]["api"] == "/api/netlog/demo"
    assert by["logs"]["action"]["href"] == "#network/import"
    assert by["abusech"]["optional"] and by["ai"]["optional"] and not by["ai"]["done"]
    for i in s["items"]:
        assert i["title"] and i["detail"] and i["action"]
    # data arrives, a vendor is followed, logs are imported
    db.execute("INSERT INTO source_state (id, status, last_ok) VALUES ('cisa_kev', 'ok', now())")
    kev_event("CVE-2026-3001", ago(hours=1), "Acme", "Router")
    assert by["watchlist"]["suggest"] == [] and c.get("/api/setup/status").json()["items"][4]["suggest"] == ["Acme"]
    c.put("/api/news/watchlist", json={"keywords": ["Acme"]})
    db.execute("INSERT INTO netlog_files (id, name, origin) VALUES ('f1', 'conn.log', 'upload')")
    s = c.get("/api/setup/status").json()
    by = {i["id"]: i for i in s["items"]}
    assert by["feeds"]["done"] and by["watchlist"]["done"] and by["logs"]["done"]
    assert by["demo"]["done"] and "Not needed" in by["demo"]["detail"]
    assert s["complete"] and not s["first_run"] and s["done"] == s["required"] == 4


def test_setup_checklist_dismiss_and_bring_back():
    assert c.put("/api/setup/dismiss", json={}).json() == {"dismissed": True}
    assert c.get("/api/setup/status").json()["dismissed"]
    c.put("/api/setup/dismiss", json={"dismissed": False})
    assert not c.get("/api/setup/status").json()["dismissed"]


def test_briefing_is_deterministic():
    c.put("/api/marker", json={"last_seen": iso(ago(days=2))})
    kev_event("CVE-2026-4001", ago(hours=3), "Acme", "Router")
    a, b = c.get("/api/watch").json(), c.get("/api/watch").json()
    a.pop("now"), b.pop("now")
    assert a == b


def test_network_shows_demo_incidents_only_without_real_ones():
    from osinthub.netlog import incidents as inc
    c.put("/api/marker", json={"last_seen": iso(ago(hours=6))})
    alert("demo-high", "192.0.2.77", "high", ts=ago(hours=1))
    inc._ready.clear()
    inc.ensure()
    db.execute("UPDATE alerts SET demo = true WHERE id = 'demo-high'")
    n = sec(c.get("/api/watch").json(), "network")
    assert n["demo"] and [(i["id"], i["demo"]) for i in n["items"]] == [("demo-high", True)]
    assert n["needs_you"] == 0   # demo never counts
    alert("real-med", "198.51.100.20", "medium", ts=ago(hours=1), device="mac:02:00:00:00:00:09")
    inc._ready.clear()
    n = sec(c.get("/api/watch").json(), "network")
    assert not n["demo"] and [i["id"] for i in n["items"]] == ["real-med"]


def test_second_caught_up_within_minutes_keeps_the_older_previous():
    c.put("/api/marker", json={"last_seen": iso(ago(days=2))})
    old = c.get("/api/marker").json()["last_seen"]
    a = c.put("/api/marker", json={}).json()
    b = c.put("/api/marker", json={}).json()           # double press, or a second tab
    n = c.put("/api/news/marker", json={}).json()      # and Mark all as read right after
    assert a["previous"] == b["previous"] == n["previous"] == old
    assert marker.parse(n["last_seen"]) >= marker.parse(a["last_seen"])
    assert c.get("/api/watch", params={"since": "previous"}).json()["window"]["since"] == old


def test_marker_in_the_future_is_refused_on_both_endpoints():
    c.put("/api/marker", json={"last_seen": iso(ago(days=1))})
    before = c.get("/api/marker").json()["last_seen"]
    for path in ("/api/marker", "/api/news/marker"):
        r = c.put(path, json={"last_seen": "2030-01-01T00:00:00Z"})
        assert r.status_code == 400 and "future" in r.json()["detail"]
        assert c.put(path, json={"last_seen": iso(NOW + dt.timedelta(hours=1))}).status_code == 400
    assert c.get("/api/marker").json()["last_seen"] == before
    assert c.put("/api/marker", json={"last_seen": iso(NOW + dt.timedelta(minutes=2))}).status_code == 200   # clock skew


def test_open_needs_you_incidents_stay_visible_when_nothing_is_new():
    from osinthub.netlog import incidents as inc
    alert("open-old", "198.51.100.30", "high", ts=ago(days=2))
    alert("low-old", "198.51.100.31", "low", ts=ago(days=2), device="mac:02:00:00:00:00:07")
    inc._ready.clear()
    c.put("/api/marker", json={})                      # caught up just now: nothing is new
    d = c.get("/api/watch").json()
    n = sec(d, "network")
    assert d["total"] == 0 and d["needs_you"] == 1 and n["count"] == 0
    assert [(i["id"], i["still_open"]) for i in n["still_open"]] == [("open-old", True)] and n["still_open_count"] == 1
    db.execute("UPDATE alerts SET status = 'ack' WHERE id = 'open-old'")
    d = c.get("/api/watch").json()
    assert d["needs_you"] == 0 and sec(d, "network")["still_open"] == []


# ------------------------------------------------------------------ Undo of "Mark all as seen" puts the one marker back
def strip(m):
    return {k: m[k] for k in ("last_seen", "previous")}


def test_undo_restores_no_marker_at_all():
    before = c.get("/api/news/marker").json()
    assert before["last_seen"] is None
    r = c.put("/api/marker", json={}).json()           # Mark all as seen
    assert r["last_seen"] and r["undo"]["last_seen"] is None
    u = c.put("/api/marker", json={"restore": r["undo"]})
    assert u.status_code == 200
    after = c.get("/api/news/marker").json()
    assert strip(after) == strip(before)
    assert after["window"]["first_visit"] is True


def test_undo_restores_an_earlier_marker_and_its_history():
    t1 = (NOW - dt.timedelta(days=3)).isoformat()
    t2 = (NOW - dt.timedelta(days=1)).isoformat()
    c.put("/api/marker", json={"last_seen": t1})
    c.put("/api/marker", json={"last_seen": t2})
    before = marker.get()
    r = c.put("/api/news/marker", json={}).json()       # News' "Mark all as read" is the same move
    assert r["undo"]["last_seen"] == before["last_seen"]
    c.put("/api/marker", json={"restore": r["undo"]})
    assert marker.get() == before
    assert c.put("/api/marker", json={"back": True}).json()["last_seen"].startswith(t1[:16])   # history kept


GOOD = lambda **kw: {"last_seen": (NOW - dt.timedelta(days=1)).isoformat(), "previous": None,   # noqa: E731
                      "set_at": NOW.isoformat(), "history": [], **kw}
FUT = (NOW + dt.timedelta(days=2)).isoformat()
BAD = {
    "null": None, "string": "2026-11-01T00:00:00Z", "number": 5, "list": [GOOD()], "empty object": {},
    "missing key": {k: v for k, v in GOOD().items() if k != "history"}, "extra key": GOOD(extra=1),
    "bad last_seen": GOOD(last_seen="not a time"), "future last_seen": GOOD(last_seen=FUT),
    "numeric last_seen": GOOD(last_seen=1700000000), "bad previous": GOOD(previous="yesterday"),
    "history not a list": GOOD(history="2026-11-01T00:00:00Z"), "history dict": GOOD(history={"a": 1}),
    "history item not a time": GOOD(history=["nope"]), "history item null": GOOD(history=[None]),
    "history item number": GOOD(history=[3]), "set_at number": GOOD(set_at=12), "set_at not a time": GOOD(set_at="soon"),
    "set_at object": GOOD(set_at={"t": 1}), "set_at future": GOOD(set_at=FUT),
}


def test_restore_refuses_anything_but_the_undo_shape():
    c.put("/api/marker", json={"last_seen": (NOW - dt.timedelta(days=3)).isoformat()})
    before = marker.get()
    for name, bad in BAD.items():
        r = c.put("/api/marker", json={"restore": bad})
        assert r.status_code == 400, (name, r.status_code, r.text)
        assert marker.get() == before, name   # never wiped or changed on bad input


def test_restore_accepts_its_own_undo_shape_with_nulls():
    r = c.put("/api/marker", json={"restore": GOOD(previous=None, set_at=None)})
    assert r.status_code == 200
