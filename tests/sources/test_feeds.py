"""Batch ingest edge cases on a temporary lake (no network: feeds are served by httpx.MockTransport).

    uv run --with pytest pytest tests/sources -q
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json

from _lake import make_lake
LAKE = make_lake("sources")

import httpx  # noqa: E402

from osinthub import config, db, scheduler  # noqa: E402
from osinthub.sources import SOURCES  # noqa: E402
from osinthub.sources.base import now  # noqa: E402

db.connect()

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>Story one</title><link>https://ok.example/1</link><pubDate>Mon, 09 Nov 2026 10:00:00 +0000</pubDate></item>
</channel></rss>"""


def _run(src, handler):
    """run_batch against a mock transport, with offline mode lifted for this call only."""
    async def go():
        scheduler._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            return await scheduler.run_batch(src)
        finally:
            await scheduler._client.aclose()
            scheduler._client = None
    old = config.OFFLINE
    config.OFFLINE = False
    try:
        return asyncio.run(go())
    finally:
        config.OFFLINE = old


def _last_run(sid):
    return db.query("SELECT * FROM runs WHERE source = ? ORDER BY started DESC LIMIT 1", [sid])[0]


# ---------------------------------------------------------------- api-audit-002: RSS fetch failures
def test_single_feed_http_error_is_a_failed_run():
    src = SOURCES["news_helpnetsecurity"]
    res = _run(src, lambda req: httpx.Response(503, text="busy"))
    assert res["ok"] is False
    assert "503" in res["error"]
    st = scheduler.state(src.id)
    assert st["status"] == "error" and "503" in st["message"]
    r = _last_run(src.id)
    assert r["ok"] is False and "503" in r["error"]


def test_partial_feed_failure_is_recorded():
    src = SOURCES["security_news"]

    def handler(req):
        if "krebsonsecurity" in str(req.url):
            return httpx.Response(503, text="busy")
        return httpx.Response(200, content=RSS)

    res = _run(src, handler)
    assert res["ok"] is True and res["items"] >= 1      # the working feeds still load
    st = scheduler.state(src.id)
    assert st["status"] == "error" and "Krebs on Security" in st["message"] and "503" in st["message"]
    r = _last_run(src.id)
    assert "Krebs on Security" in (r["error"] or "")


def test_non_feed_body_counts_as_failure():
    src = SOURCES["news_therecord"]
    res = _run(src, lambda req: httpx.Response(200, text="<html><body>Access denied</body></html>"))
    assert res["ok"] is False and "not a feed" in res["error"]


def test_healthy_feed_clears_error():
    src = SOURCES["news_helpnetsecurity"]
    res = _run(src, lambda req: httpx.Response(200, content=RSS))
    assert res["ok"] is True
    assert scheduler.state(src.id)["status"] == "ok"
    assert _last_run(src.id)["error"] is None


def test_each_feed_is_parsed_once_per_run(monkeypatch):
    """fetch() checks each body is a feed; records() and parse() reuse that result instead of parsing it again."""
    import feedparser
    from osinthub.sources import feeds
    src = SOURCES["security_news"]
    calls = []
    real = feedparser.parse
    monkeypatch.setattr(feeds.feedparser, "parse", lambda body, *a, **k: calls.append(1) or real(body, *a, **k))
    res = _run(src, lambda req: httpx.Response(200, content=RSS))
    assert res["ok"] is True and res["items"] >= 1
    assert len(calls) == len(src.feeds)
    raw = json.dumps({"A feed": RSS.decode().replace("Story one", "Story two")})   # a body this run never fetched
    assert [e.title for e in src.parse(raw)] == ["Story two"] and len(calls) == len(src.feeds) + 1


# ---------------------------------------------------------------- api-audit-008: ransomware posting time
def test_ransomware_event_time_is_posting_time():
    src = SOURCES["ransomware_live"]
    raw = json.dumps([
        {"group": "settra", "victim": "ar500armor.com", "attackdate": "2026-09-29 00:00:00",
         "discovered": "2026-11-08 20:12:33.123456", "description": "Leak of 40 GB", "country": "us"},
        {"group": "x", "victim": "no-discovered", "attackdate": "2026-10-01"},
    ]).encode()
    a, b = src.parse(raw)
    assert a.ts.isoformat().startswith("2026-11-08T20:12:33")
    assert a.summary.startswith("attack date 2026-09-29") and "Leak of 40 GB" in a.summary
    assert b.ts.date().isoformat() == "2026-10-01"   # no posting time: fall back to the attack date


def test_ransomware_pulse_counts_postings():
    from osinthub import analytics
    src = SOURCES["ransomware_live"]
    t = now()
    posted = (t - dt.timedelta(hours=1)).isoformat()
    raw = json.dumps([{"group": "g", "victim": f"v{i}", "attackdate": "2026-09-01", "discovered": posted}
                      for i in range(5)]).encode()
    scheduler._load(src, scheduler._rows(src.parse(raw), None, t), None)
    assert analytics._count("kind = 'ransomware' AND source = 'ransomware_live'", 24, 0) == 5


# ---------------------------------------------------------------- api-audit-003: stream reconnect backoff
def _stream_delays(healthy_s, n=8):
    from osinthub.sources.base import Source

    class Flaky(Source):
        id, name, provider, mode = "test_stream", "test", "test", "stream"

        async def stream(self, sink):
            return  # the connection ends (server closed it)

    delays = []
    real_sleep = asyncio.sleep

    async def fake_sleep(s):
        delays.append(s)
        if len(delays) >= n:
            raise asyncio.CancelledError
        await real_sleep(0)

    old = (config.OFFLINE, scheduler.STREAM_HEALTHY_S)
    config.OFFLINE, scheduler.STREAM_HEALTHY_S = False, healthy_s
    asyncio.sleep = fake_sleep
    try:
        asyncio.run(scheduler._stream_loop(Flaky()))
    except asyncio.CancelledError:
        pass
    finally:
        asyncio.sleep = real_sleep
        config.OFFLINE, scheduler.STREAM_HEALTHY_S = old
    return delays


def test_stream_backoff_resets_after_healthy_session():
    assert _stream_delays(healthy_s=0) == [2] * 8          # every session counted as healthy


def test_stream_backoff_grows_when_flapping():
    assert _stream_delays(healthy_s=3600) == [2, 4, 8, 16, 32, 64, 120, 120]


# ---------------------------------------------------------------- api-audit-004: to_ts
def test_to_ts_shapes():
    from osinthub.sources.base import to_ts
    real = dt.datetime(2025, 11, 3, 10, 0, tzinfo=dt.UTC)
    for v in ("Mon, 03 Nov 2025 10:00:00 GMT", "Mon, 03 Nov 2025 10:00:00 +0000", "Mon, 03 Nov 2025 05:00:00 -0500",
              "1762164000", 1762164000, 1762164000.0, 1762164000000, "1762164000000", 1762164000000000,
              "2025-11-03T10:00:00Z", "2025-11-03 10:00:00", "2025-11-03T10:00:00.000000000Z"):
        assert to_ts(v) == real, v
    assert to_ts("20251103") == dt.datetime(2025, 11, 3, tzinfo=dt.UTC)
    assert to_ts("2025/11/03") == dt.datetime(2025, 11, 3, tzinfo=dt.UTC)
    # unparseable or missing: the collection time (which content_hash treats as app-stamped), never an exception
    for v in ("03/11/2026", "garbage", None, "", 1e30):
        assert abs((to_ts(v) - now()).total_seconds()) < 5, v


# ---------------------------------------------------------------- api-audit-007: IODA null score
def test_ioda_null_score_does_not_fail_the_run():
    src = SOURCES["ioda_outages"]
    rows = [{"location": "country/IR", "location_name": "Iran", "start": 1762164000, "duration": 7200,
             "datasource": "bgp", "score": 125000.0},
            {"location": "country/SY", "location_name": "Syria", "start": 1762164000, "duration": None,
             "datasource": "ping-slash24", "score": None},
            {"location": None, "start": 1762164000, "datasource": "gtr"}]
    raw = json.dumps({"country": {"data": rows}, "region": {"data": []}}).encode()
    evs = src.parse(raw)
    assert len(evs) == 3
    assert evs[0].summary == "bgp signal drop · 2.0h · score 125,000" and evs[0].value == 125000.0
    assert evs[1].summary == "ping-slash24 signal drop · 0.0h · score 0" and evs[1].value is None
    assert evs[1].severity == 0.25
    assert len(src.records(raw)) == 3


# ---------------------------------------------------------------- api-audit-r2-001: partial RSS failure
def test_partial_feed_failure_keeps_the_dead_feeds_records():
    """A feed that failed to fetch was not seen, not changed: when it recovers, its unchanged items are not
    written to the lake again."""
    src = SOURCES["security_news"]
    rss = lambda req: httpx.Response(200, content=RSS.replace(b"ok.example", req.url.host.encode()))   # noqa: E731
    _run(src, rss)                                                  # baseline: every feed up
    keys = set(db.record_hashes(src.id))
    assert any(k.startswith("Krebs on Security|") for k in keys)

    def krebs_down(req):
        return httpx.Response(503, text="busy") if "krebsonsecurity" in str(req.url) else rss(req)
    res = _run(src, krebs_down)
    assert res["ok"] and res["records_changed"] == 0 and res["records_removed"] == 0
    assert set(db.record_hashes(src.id)) == keys                    # the dead feed's hashes are kept
    res = _run(src, rss)                                            # it comes back with the same items
    assert res["ok"] and res["records_changed"] == 0, res           # was: its items re-written as changed
    assert _last_run(src.id)["records_changed"] == 0


def test_partial_list_fetch_removes_only_seen_parts():
    """Same rule for a list source (removals are stored): a key of the failed part is never counted as removed;
    a key of a part that did load and no longer lists it still is."""
    class Lst:
        id, windowed = "test_partial_list", False
    db.replace_record_hashes(Lst.id, {"A|a": ("h1", now()), "B|b": ("h2", now()), "A|gone": ("h3", now())})
    part_b_failed = lambda k: k.startswith("B|")   # noqa: E731
    puts, dels, new = scheduler._record_delta(Lst, [("A|a", {"x": 1})], now(), part_b_failed)
    assert dels == ["A|gone"] and set(new) == {"A|a", "B|b"} and [k for k, _ in puts] == ["A|a"]
    puts, dels, new = scheduler._record_delta(Lst, [("A|a", {"x": 1})], now(), lambda k: True)   # can't tell: keep all
    assert dels == [] and set(new) == {"A|a", "B|b", "A|gone"}
    puts, dels, new = scheduler._record_delta(Lst, [("A|a", {"x": 1})], now())
    assert sorted(dels) == ["A|gone", "B|b"] and set(new) == {"A|a"}    # a full fetch still stores the removal


def test_stored_hashes_do_not_grow_while_a_feed_stays_down():
    """Only the dead feed's keys are carried: the healthy feeds' items that rolled out of their feeds drop as usual."""
    src = SOURCES["security_news"]
    turn = {"n": 0}

    def rolling(req):   # every live feed lists 3 fresh items each run; Krebs is down for good
        if "krebsonsecurity" in str(req.url):
            return httpx.Response(503, text="busy")
        items = "".join(f"<item><title>Item {turn['n']}-{i}</title><link>https://{req.url.host}/{turn['n']}/{i}</link></item>"
                        for i in range(3))
        return httpx.Response(200, content=f"<?xml version='1.0'?><rss version='2.0'><channel><title>t</title>{items}</channel></rss>".encode())
    rss = lambda req: httpx.Response(200, content=RSS.replace(b"ok.example", req.url.host.encode()))   # noqa: E731
    _run(src, rss)                                                  # baseline: Krebs has one item
    krebs = {k for k in db.record_hashes(src.id) if k.startswith("Krebs on Security|")}
    assert krebs
    sizes = []
    for n in range(6):
        turn["n"] = n
        assert _run(src, rolling)["ok"]
        keys = set(db.record_hashes(src.id))
        assert krebs <= keys                                        # the dead feed's hashes survive
        sizes.append(len(keys))
    assert len(set(sizes)) == 1, sizes                              # 3 live feeds x 3 items + Krebs's: constant


# ---------------------------------------------------------------- api-audit-r2-005: overlapping runs
def test_overlapping_runs_of_one_source_are_refused():
    src = SOURCES["news_helpnetsecurity"]
    calls = []

    async def slow(req):
        calls.append(req.url)
        await asyncio.sleep(0.3)
        return httpx.Response(200, content=RSS)

    async def go():
        scheduler._client = httpx.AsyncClient(transport=httpx.MockTransport(slow))
        try:
            return await asyncio.gather(scheduler.run_batch(src), scheduler.run_batch(src))
        finally:
            await scheduler._client.aclose()
            scheduler._client = None
    old = config.OFFLINE
    config.OFFLINE = False
    try:
        first, second = asyncio.run(go())
    finally:
        config.OFFLINE = old
    assert first["ok"] is True
    assert second == {"ok": False, "skipped": True, "running": True, "error": "already running"}
    assert len(calls) == 1                                          # one fetch, one delta
    assert not scheduler.is_running(src)                            # the guard is released after the run
    assert _run(src, lambda req: httpx.Response(200, content=RSS))["ok"] is True


def _stop_mid_run(src, patch_name, slow, run_now):
    """A 'scheduled' run whose step `patch_name` is slow (a worker thread); the source is stopped during that step,
    then (run_now) Run now is tried at once. Returns (Run now result, guard held right after, final state)."""
    started = __import__("threading").Event()
    orig = getattr(type(src), patch_name)

    def patched(self, *a):
        started.set()
        __import__("time").sleep(slow)
        return orig(self, *a)
    setattr(src, patch_name, patched.__get__(src))

    async def go():
        scheduler._client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=RSS)))
        try:
            scheduler._tasks[src.id] = asyncio.create_task(scheduler.run_batch(src))
            while not started.is_set():
                await asyncio.sleep(0.01)
            await scheduler.stop_source(src)
            again = await scheduler.run_batch(src) if run_now else None   # while the stopped run's thread is busy
            held = scheduler.is_running(src)
            while scheduler.is_running(src):
                await asyncio.sleep(0.05)
            await asyncio.sleep(0.2)
            return again, held, await asyncio.to_thread(scheduler.state, src.id)
        finally:
            await scheduler._client.aclose()
            scheduler._client = None
    old = config.OFFLINE
    config.OFFLINE = False
    try:
        return asyncio.run(go())
    finally:
        config.OFFLINE = old
        delattr(src, patch_name)


def test_stopping_mid_run_ends_disabled_and_waits_for_the_tail():
    """api-audit-r2-004 round 2: a stopped run's thread work keeps going after the cancel; none of its state writes
    may land after 'disabled', and the run guard holds until that work is done (no overlap with a new run)."""
    src = SOURCES["news_helpnetsecurity"]
    # stopped during a data step (default pool): Run now is refused until that thread is done
    again, held, st = _stop_mid_run(src, "commit", 0.5, run_now=True)
    assert again.get("running") is True and held, again
    assert st["status"] == "disabled" and st["message"] == "", st
    # stopped during the end-of-run bookkeeping (slow between its state writes): its later writes are dropped
    _, _, st = _stop_mid_run(src, "stored_count", 0.5, run_now=False)
    assert st["status"] == "disabled" and st["message"] == "", st


def test_run_now_while_running_is_a_409():
    from fastapi import HTTPException

    from osinthub import api
    src = SOURCES["news_helpnetsecurity"]
    scheduler._running.add(src.id)
    try:
        asyncio.run(api.run_source(src.id))
        raise AssertionError("expected a 409")
    except HTTPException as e:
        assert e.status_code == 409 and e.detail == "already running"
    finally:
        scheduler._running.discard(src.id)
