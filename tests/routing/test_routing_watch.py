"""Routing watch: validation, presets, settings, the API, detection rules and de-duplication, the data-limit pause,
the Radar token never returned, and no routing traffic at all while offline or with an empty watchlist.

Offline lake; no network. Fixtures use documentation ASNs (AS64496-64511) and prefixes (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) only. The fake-server tests are in test_v12_routing_sources.py.

    uv run --with pytest pytest tests/routing/test_routing_watch.py -q
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
import os

os.environ.pop("CLOUDFLARE_RADAR_TOKEN", None)
from _lake import make_lake
LAKE = make_lake("routing", disable="news,entities,netlog,ai")

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db, feed_terms, scheduler  # noqa: E402
from osinthub.api import app  # noqa: E402
from osinthub.routing import api as rapi, detect, usage, watchlist  # noqa: E402
from osinthub.sources import SOURCES  # noqa: E402

ROUTING = ("rpki_roas", "cf_radar_bgp", "ripestat", "ris_live")
TOKEN = "testtoken_" + "x" * 30
C = TestClient(app, base_url="http://localhost")
ORIGIN = {"Origin": "http://localhost"}


@pytest.fixture(scope="module", autouse=True)
def _app():
    with C:   # the app's lifespan (scheduler started, offline), so toggles and sync() have its loop
        yield


@pytest.fixture(autouse=True)
def _fresh():
    watchlist.ALLOW_DOCUMENTATION = True
    rapi.KICK_DELAY_S = 3600
    db.set_setting(watchlist.KEY, [])
    db.set_setting(detect.STATE_KEY, {})
    db.set_setting(detect.ROAS_KEY, {})
    db.set_setting(watchlist.SETTINGS_KEY, {})
    db.execute("DELETE FROM source_state")
    watchlist.set_token(None)
    usage.reset_for_tests()
    yield
    watchlist.ALLOW_DOCUMENTATION = True


def _wl(*vals):
    watchlist.ALLOW_DOCUMENTATION = True
    return watchlist.save([{"value": v, "label": f"test {v}"} for v in vals])


# ---------------------------------------------------------------- validation and presets
VALID = [
    ("AS64500", "AS64500"), ("as64500", "AS64500"), ("64500", "AS64500"), ("AS 64500", "AS64500"),
    ("192.0.2.0/24", "192.0.2.0/24"), ("192.0.2.77/24", "192.0.2.0/24"), ("2001:db8::/32", "2001:db8::/32"),
    ("2001:db8:1::/48", "2001:db8:1::/48"),
]
REFUSED = [
    ("", "Type an AS number"), ("AS0", "1 to 4294967295"), ("AS4294967296", "1 to 4294967295"),
    ("AS64512", "private AS number"), ("AS4200000000", "private"), ("AS23456", "reserved"), ("AS65535", "reserved"),
    ("AS64496", "documentation"), ("AS65540", "documentation"),
    ("10.0.0.0/8", "private range"), ("192.168.1.0/24", "private range"), ("172.16.0.0/12", "private range"),
    ("fd00::/16", "private range"), ("127.0.0.0/8", "not routed"), ("100.64.0.0/10", "not routed"),
    ("169.254.0.0/16", "not routed"), ("224.0.0.0/8", "not routed"), ("fe80::/16", "not routed"),
    ("192.0.2.0/24", "documentation"), ("198.51.100.0/24", "documentation"), ("203.0.113.0/24", "documentation"),
    ("2001:db8::/32", "documentation"), ("0.0.0.0/0", "too large"), ("8.0.0.0/7", "too large"),
    ("1.0.0.0/7", "1.0.0.0/7 is too large"),
    ("8.8.8.8/32", "8.8.8.0/24"), ("8.8.8.8", "8.8.8.0/24"), ("2606:4700::/64", "/48"), ("not a network", "not an AS number"),
    ("1.2.3.0/33", "not a valid network"),
]


def test_entries_normalise_or_say_why_they_are_refused():
    watchlist.ALLOW_DOCUMENTATION = True
    bad = [(t, watchlist.parse(t)["id"], want) for t, want in VALID if watchlist.parse(t)["id"] != want]
    watchlist.ALLOW_DOCUMENTATION = False
    for typed, words in REFUSED:
        with pytest.raises(watchlist.Invalid) as e:
            watchlist.parse(typed)
        if words not in str(e.value):
            bad.append((typed, str(e.value), words))
    assert not bad, bad


def test_presets_are_real_public_networks_and_validate():
    watchlist.ALLOW_DOCUMENTATION = False
    ids = [watchlist.parse(p["value"])["id"] for p in watchlist.PRESETS]
    assert {"AS13335", "AS15169", "AS16509", "AS8075", "AS19281", "1.1.1.0/24", "8.8.8.0/24", "9.9.9.0/24"} <= set(ids)
    wl = watchlist.save([{"value": "AS13335"}, {"value": "1.1.1.0/24"}])
    assert [w["label"] for w in wl] == ["Cloudflare", "Cloudflare DNS (1.1.1.1)"]   # a preset keeps its name


def test_watchlist_cap_and_duplicates():
    many = [{"value": f"AS{64496 + i}"} for i in range(16)] + [{"value": f"AS{65536 + i}"} for i in range(16)]
    watchlist.ALLOW_DOCUMENTATION = True
    with pytest.raises(watchlist.Invalid, match="up to 25"):
        watchlist.save(many[:26])
    wl = watchlist.save([{"value": "AS64500"}, {"value": "as64500"}, {"value": "198.51.100.0/24"}])
    assert [w["id"] for w in wl] == ["AS64500", "198.51.100.0/24"]


def test_saved_watches_are_not_rechecked_on_save():
    watchlist.ALLOW_DOCUMENTATION = True
    watchlist.save([{"value": "AS64500", "label": "lab"}])
    watchlist.ALLOW_DOCUMENTATION = False   # e.g. a rule that got stricter in a later version
    wl = watchlist.save([{"value": "AS64500"}, {"value": "AS13335"}])
    assert [(w["id"], w["label"]) for w in wl] == [("AS64500", "lab"), ("AS13335", "Cloudflare")]
    with pytest.raises(watchlist.Invalid):
        watchlist.save([{"value": "AS64501"}])


def test_settings_choices_and_limits():
    assert watchlist.settings() == {"every": 21600, "limit_mb": 50}   # the defaults
    assert watchlist.set_settings(every=3600, limit_mb=10) == {"every": 3600, "limit_mb": 10}
    assert watchlist.set_settings(every=900)["every"] == 900          # the advanced choice
    for bad in (60, 7200, "x"):
        with pytest.raises(watchlist.Invalid):
            watchlist.set_settings(every=bad)
    for bad in (0, 100_000, "lots"):
        with pytest.raises(watchlist.Invalid):
            watchlist.set_settings(limit_mb=bad)


# ---------------------------------------------------------------- API
def test_api_get_put_and_validate():
    d = C.get("/api/routing").json()
    assert d["watchlist"] == [] and d["settings"] == {"every": 21600, "limit_mb": 50}
    assert [s["id"] for s in d["sources"]] == list(ROUTING)
    on = lambda d: {s["id"]: s["enabled"] for s in d["sources"]}   # noqa: E731
    assert on(d) == dict.fromkeys(ROUTING, False)          # everything off for a new user
    assert all(s["unavailable"] for s in d["sources"])   # nothing can run with an empty watchlist
    assert C.get("/api/routing/validate", params={"value": "AS64500"}).json()["id"] == "AS64500"
    watchlist.ALLOW_DOCUMENTATION = False
    v = C.get("/api/routing/validate", params={"value": "10.1.0.0/16"}).json()
    assert v["ok"] is False and "private" in v["error"]
    watchlist.ALLOW_DOCUMENTATION = True
    r = C.put("/api/routing/watchlist", json={"watches": [{"value": "AS64500", "label": "Lab AS"}, {"value": "203.0.113.0/24"}]}, headers=ORIGIN)
    assert r.status_code == 200, r.text
    assert [w["id"] for w in r.json()["watchlist"]] == ["AS64500", "203.0.113.0/24"]
    # a watchlist switches nothing on by itself: the RPKI file (no stated terms) is asked about once; Radar waits for a
    # token, RIPE and RIS Live stay off
    assert on(r.json()) == {"rpki_roas": False, "cf_radar_bgp": False, "ripestat": False, "ris_live": False}
    assert r.json()["ask"] == ["rpki_roas"]
    r = C.put("/api/routing/source", json={"id": "rpki_roas", "enabled": True}, headers=ORIGIN)
    assert on(r.json())["rpki_roas"] is True and r.json()["ask"] == []
    r = C.put("/api/routing/settings", json={"radar_token": TOKEN}, headers=ORIGIN)
    assert on(r.json())["cf_radar_bgp"] is True
    C.post("/api/sources/rpki_roas/enable?enabled=false", headers=ORIGIN)
    r = C.put("/api/routing/watchlist", json={"watches": ["AS64500"]}, headers=ORIGIN)
    assert on(r.json())["rpki_roas"] is False               # a source the user turned off stays off
    assert C.put("/api/routing/watchlist", json={"watches": ["AS64512"]}, headers=ORIGIN).status_code == 400
    C.put("/api/routing/watchlist", json={"watches": ["AS64500", "203.0.113.0/24"]}, headers=ORIGIN)
    r = C.put("/api/routing/settings", json={"every": 3600, "limit_mb": 25}, headers=ORIGIN)
    assert r.json()["settings"] == {"every": 3600, "limit_mb": 25}
    assert C.put("/api/routing/settings", json={"every": 5}, headers=ORIGIN).status_code == 400
    cards = C.get("/api/routing/watches").json()["cards"]
    assert [c["id"] for c in cards] == ["AS64500", "203.0.113.0/24"]
    assert cards[0]["label"] == "Lab AS" and cards[0]["state"] == "unchecked" and "Offline" in cards[0]["sentence"]


def test_radar_token_is_never_returned_or_logged(caplog):
    caplog.set_level(logging.DEBUG)
    r = C.put("/api/routing/settings", json={"radar_token": TOKEN}, headers=ORIGIN)
    assert r.status_code == 200 and TOKEN not in r.text
    radar = next(s for s in r.json()["sources"] if s["id"] == "cf_radar_bgp")
    assert radar["token"] == "saved"
    p = config.DB_PATH.parent / "radar.token"
    assert p.read_text() == TOKEN and (p.stat().st_mode & 0o777) == 0o600
    for path in ("/api/routing", "/api/routing/watches", "/api/sources", "/api/settings/sources-choice"):
        assert TOKEN not in C.get(path).text, path
    assert TOKEN not in str(db.query("SELECT * FROM settings"))   # the SQL console cannot read it either
    assert TOKEN not in caplog.text
    assert C.put("/api/routing/settings", json={"radar_token": "short"}, headers=ORIGIN).status_code == 400
    C.put("/api/routing/settings", json={"radar_token": ""}, headers=ORIGIN)
    assert not p.exists() and watchlist.token() is None


def test_feed_terms_for_the_new_sources():
    assert feed_terms.row("cf_radar_bgp")["licence"] == "CC BY-NC 4.0" and feed_terms.row("cf_radar_bgp")["badge"]
    assert feed_terms.row("rpki_roas")["licence"] == "No terms stated"
    assert "redistribution" in feed_terms.row("ripestat")["terms"]
    assert feed_terms.row("ripestat")["local_default"] == "ask" and feed_terms.row("ris_live")["local_default"] == "ask"
    choice = {s["id"]: s for s in C.get("/api/settings/sources-choice").json()["sources"]}
    assert choice["rpki_roas"]["needs"] == "watchlist" and choice["cf_radar_bgp"]["needs"] == "key"


def test_ris_live_is_off_advanced_and_watchlist_only():
    s = SOURCES["ris_live"]
    assert s.default_enabled is False and s.category == "advanced"
    wl = _wl("AS64500", "198.51.100.0/24", "2001:db8:100::/48")
    subs = s.subscriptions(wl, "rrc00")
    assert subs == [
        {"type": "ris_subscribe", "data": {"type": "UPDATE", "host": "rrc00", "path": "64500$"}},
        {"type": "ris_subscribe", "data": {"type": "UPDATE", "host": "rrc00", "prefix": "198.51.100.0/24", "moreSpecific": True}},
        {"type": "ris_subscribe", "data": {"type": "UPDATE", "host": "rrc00", "prefix": "2001:db8:100::/48", "moreSpecific": True}},
    ]
    assert all("prefix" in x["data"] or "path" in x["data"] for x in subs)   # never an unfiltered subscription


# ---------------------------------------------------------------- nothing runs offline or without a watchlist
class _Counting(httpx.AsyncBaseTransport):
    def __init__(self):
        self.seen = []

    async def handle_async_request(self, request):
        self.seen.append(request)
        raise httpx.ConnectError("test: no network", request=request)


def _with_client(coro_fn):
    t = _Counting()
    old = scheduler._client
    scheduler._client = httpx.AsyncClient(transport=t)
    try:
        res = asyncio.run(coro_fn())
    finally:
        scheduler._client = old
    return t, res


def test_offline_mode_makes_zero_requests():
    _wl("AS64500", "198.51.100.0/24")
    watchlist.set_token(TOKEN)
    db.execute("INSERT OR REPLACE INTO source_state (id, enabled) VALUES ('ripestat', true)")
    assert config.OFFLINE

    async def go():
        out = [await scheduler.run_batch(SOURCES[sid]) for sid in ("rpki_roas", "cf_radar_bgp", "ripestat")]
        await SOURCES["ris_live"].stream(None)   # returns at once offline, never connects
        return out
    t, res = _with_client(go)
    assert t.seen == [] and all(r.get("skipped") and r["error"] == "offline mode" for r in res)
    db.execute("DELETE FROM source_state WHERE id = 'ripestat'")


def test_empty_watchlist_makes_zero_requests_even_with_ris_live_on(monkeypatch):
    """A lake where RIS Live (the old firehose) was switched on must not connect with no watchlist."""
    monkeypatch.setattr(config, "OFFLINE", False)
    db.execute("INSERT OR REPLACE INTO source_state (id, enabled) VALUES ('ris_live', true), ('ripestat', true)")
    watchlist.set_token(TOKEN)
    for sid in ROUTING:
        assert SOURCES[sid].unavailable() == watchlist.WAITING, sid
        with pytest.raises(ValueError):
            scheduler.start_source(SOURCES[sid])   # never started

    async def go():
        await rapi.sync(kick=True)
        return [await scheduler.run_batch(SOURCES[sid]) for sid in ("rpki_roas", "cf_radar_bgp", "ripestat")]
    t, res = _with_client(go)
    assert t.seen == [] and all(r.get("skipped") for r in res)
    assert not any(sid in scheduler._tasks and not scheduler._tasks[sid].done() for sid in ROUTING)
    assert scheduler.state("ris_live")["status"] == "needs_key"
    db.execute("DELETE FROM source_state WHERE id IN ('ris_live', 'ripestat')")


def test_ripestat_never_runs_unless_opted_in(monkeypatch):
    monkeypatch.setattr(config, "OFFLINE", False)
    _wl("AS64500")
    assert SOURCES["ripestat"].default_enabled is False and not scheduler.is_enabled(SOURCES["ripestat"])

    async def go():
        return await scheduler.run_batch(SOURCES["ripestat"])   # e.g. a stray "Run now"
    t, res = _with_client(go)
    assert t.seen == [] and res["ok"] is False and "off" in res["error"]


def test_data_limit_pauses_every_routing_source(monkeypatch):
    monkeypatch.setattr(config, "OFFLINE", False)
    _wl("AS64500", "198.51.100.0/24")
    watchlist.set_settings(limit_mb=1)
    watchlist.set_token(TOKEN)
    db.execute("INSERT OR REPLACE INTO source_state (id, enabled) VALUES ('ripestat', true)")
    usage.add("ris_live", 1_000_001)

    async def go():
        return [await scheduler.run_batch(SOURCES[sid]) for sid in ("rpki_roas", "cf_radar_bgp", "ripestat")]
    t, res = _with_client(go)
    assert t.seen == [] and all(r.get("paused") for r in res), res
    for sid in ("rpki_roas", "cf_radar_bgp", "ripestat"):
        st = scheduler.state(sid)
        assert st["status"] == "paused" and "daily data limit of 1 MB" in st["message"]
    d = C.get("/api/routing").json()
    assert "Paused for today" in d["paused"] and d["usage"]["bytes"]["ris_live"] == 1_000_001
    cards = C.get("/api/routing/watches").json()
    assert "Paused for today" in cards["paused"]
    db.execute("DELETE FROM source_state WHERE id = 'ripestat'")


# ---------------------------------------------------------------- detection rules
def _states():
    return db.get_setting(detect.STATE_KEY, {})


def _open(wid):
    return {e["kind"]: e for e in detect.open_events(wid)}


ROAS = [["198.51.100.0/24", 24, 64500, "test"], ["203.0.113.0/24", 24, 64501, "test"]]


def test_rpki_invalid_and_unexpected_origin_with_dedupe_and_clearing():
    _wl("198.51.100.0/24")
    detect.ingest_rpki(ROAS)
    ok = {"ok": True, "hours": 6, "status": {"origins": [{"origin": 64500}],
                                             "visibility": {"v4": {"ris_peers_seeing": 300, "total_ris_peers": 310}}}}
    detect.ingest_ripestat({"198.51.100.0/24": ok})
    assert _open("198.51.100.0/24") == {}
    card = detect.cards({"ripestat": {"on": True, "interval": 21600}})[0]
    assert card["state"] == "normal" and "AS64500" in card["sentence"] and "97%" in card["sentence"]
    # a more-specific announced by another AS: RPKI-invalid (the ROA allows only AS64500 up to /24)
    bad = {**ok, "status": {**ok["status"], "more_specifics": [{"prefix": "198.51.100.0/25", "origin": 64502}]}}
    detect.ingest_ripestat({"198.51.100.0/24": bad})
    ev = _open("198.51.100.0/24")
    assert set(ev) == {"rpki_invalid"} and ev["rpki_invalid"]["level"] == "needs_you"
    assert "AS64502 announced 198.51.100.0/25" in ev["rpki_invalid"]["summary"]
    first = ev["rpki_invalid"]["opened"]
    detect.ingest_ripestat({"198.51.100.0/24": bad})   # seen again: still one open event, same opening time
    evs = [e for e in _states()["198.51.100.0/24"]["events"] if e["kind"] == "rpki_invalid"]
    assert len(evs) == 1 and evs[0]["opened"] == first and not evs[0]["cleared"]
    assert detect.cards({"ripestat": {"on": True, "interval": 21600}})[0]["state"] == "changed"
    detect.ingest_ripestat({"198.51.100.0/24": ok})     # gone: cleared by the source that opened it
    assert _open("198.51.100.0/24") == {}
    assert _states()["198.51.100.0/24"]["events"][0]["cleared"]


def test_unexpected_origin_without_rpki():
    _wl("198.51.100.0/24")
    base = {"ok": True, "hours": 6, "status": {"origins": [{"origin": 64500}]}}
    detect.ingest_ripestat({"198.51.100.0/24": base})   # first check learns the usual origin
    two = {**base, "status": {"origins": [{"origin": 64500}, {"origin": 64511}]}}
    detect.ingest_ripestat({"198.51.100.0/24": two})
    ev = _open("198.51.100.0/24")["unexpected_origin"]
    assert ev["level"] == "needs_you" and "AS64511" in ev["summary"] and "usually announced by AS64500" in ev["summary"]


def test_ris_live_announcements_raise_and_auto_clear():
    _wl("203.0.113.0/24", "AS64500")
    detect.ingest_rpki(ROAS)
    detect.observe_announcements([("203.0.113.0/24", "203.0.113.0/24", 64501)])
    assert _open("203.0.113.0/24") == {}
    detect.observe_announcements([("203.0.113.0/24", "203.0.113.0/24", 64509), ("AS64500", "198.51.100.0/24", 64500)])
    ev = _open("203.0.113.0/24")["rpki_invalid"]
    assert ev["source"] == "ris_live"
    st = _states()
    st["203.0.113.0/24"]["events"][0]["seen"] = (dt.datetime.now(dt.UTC) - dt.timedelta(days=2)).isoformat()
    db.set_setting(detect.STATE_KEY, st)
    detect.sweep()
    assert _open("203.0.113.0/24") == {}   # a stream event not seen for a day clears


def test_radar_matching_levels_and_local_filtering():
    _wl("AS64500", "198.51.100.0/24", "AS64510")
    hijacks = [
        {"id": 1, "confidence_score": 9, "hijacker_asn": 64509, "victim_asns": [64500], "prefixes": ["192.0.2.0/24"],
         "min_hijack_ts": "2026-11-17T01:00:00", "max_hijack_ts": "2026-11-17T02:00:00"},
        {"id": 2, "confidence_score": 4, "hijacker_asn": 64508, "victim_asns": [64507], "prefixes": ["198.51.100.128/25"]},
        {"id": 3, "confidence_score": 10, "hijacker_asn": 64506, "victim_asns": [64505], "prefixes": ["203.0.113.0/24"]},
    ]
    leaks = [{"id": 7, "leak_asn": 64504, "leak_seg": [64503, 64504, 64510], "prefix_count": 12, "origin_count": 3},
             {"id": 8, "leak_asn": 64502, "leak_seg": [64501, 64502], "prefix_count": 1, "origin_count": 1}]
    matched = detect.ingest_radar(hijacks, leaks)
    assert sorted((m["watch"], m["id"]) for m in matched) == [("198.51.100.0/24", 2), ("AS64500", 1), ("AS64510", 7)]
    assert _open("AS64500")["radar_hijack"]["level"] == "needs_you"           # confidence 9
    assert _open("198.51.100.0/24")["radar_hijack"]["level"] == "info"        # confidence 4
    assert _open("AS64510")["radar_leak"]["level"] == "info"            # leaks are information (owner's list)
    detect.ingest_radar([], [])
    assert not detect.open_events()


def test_informational_rules_use_the_watchs_own_baseline():
    _wl("AS64500", "198.51.100.0/24")
    nb = lambda *ups: {"neighbours": [{"asn": u, "type": "left"} for u in ups] + [{"asn": 64509, "type": "right"}]}
    quiet = {"updates": [{"announcements": 20, "withdrawals": 4}]}
    for _ in range(6):
        detect.ingest_ripestat({"AS64500": {"ok": True, "hours": 6, "status": {"announced_space": {"v4": {"prefixes": 10}}},
                                            "neighbours": nb(64501, 64502), "updates": quiet}})
    assert _open("AS64500") == {}
    detect.ingest_ripestat({"AS64500": {"ok": True, "hours": 6, "status": {"announced_space": {"v4": {"prefixes": 20}, "v6": {"prefixes": 2}}},
                                        "neighbours": nb(64501, 64503), "updates": {"updates": [{"announcements": 3000, "withdrawals": 600}]}}})
    ev = _open("AS64500")
    assert set(ev) == {"upstream_change", "update_spike", "new_prefixes"} and all(e["level"] == "info" for e in ev.values())
    assert "new: AS64503" in ev["upstream_change"]["summary"] and "gone: AS64502" in ev["upstream_change"]["summary"]
    assert "600 routing updates an hour" in ev["update_spike"]["summary"]
    # visibility drop and not visible, for a prefix
    seen = lambda n: {"ok": True, "hours": 6, "status": {"origins": [{"origin": 64500}],
                                                         "visibility": {"v4": {"ris_peers_seeing": n, "total_ris_peers": 300}}}}
    for _ in range(4):
        detect.ingest_ripestat({"198.51.100.0/24": seen(290)})
    detect.ingest_ripestat({"198.51.100.0/24": seen(90)})
    assert _open("198.51.100.0/24")["visibility_drop"]["level"] == "info"
    gone_since = (dt.datetime.now(dt.UTC) - dt.timedelta(hours=5)).isoformat()
    detect.ingest_ripestat({"198.51.100.0/24": {"ok": True, "hours": 6, "status": {"origins": [], "last_seen": {"time": gone_since}}}})
    ev = _open("198.51.100.0/24")
    assert ev["not_visible"]["level"] == "needs_you" and "about 5 hours" in ev["not_visible"]["summary"]
    assert "visibility_drop" not in ev


def test_cards_states_and_failed_checks():
    _wl("AS64500", "198.51.100.0/24")
    on = {"rpki_roas": {"on": True, "interval": 86400}}
    cards = {c["id"]: c for c in detect.cards(on)}
    assert cards["AS64500"]["state"] == "pending" and "Checking" in cards["AS64500"]["sentence"]
    assert detect.cards({})[0]["state"] == "unchecked"   # no source on
    detect.ingest_rpki(ROAS + [["198.51.100.0/22", 24, 64500, "t"]])
    cards = {c["id"]: c for c in detect.cards(on)}
    assert cards["198.51.100.0/24"]["state"] == "normal" and "igned with RPKI for AS64500" in cards["198.51.100.0/24"]["sentence"]
    assert "2 RPKI records name it" in cards["AS64500"]["sentence"]
    detect.note_check("rpki_roas", False, "the signed-route file could not be downloaded (could not connect)")
    card = detect.cards(on)[0]
    assert card["state"] == "unchecked" and "Couldn't check" in card["sentence"]
    assert detect.rpki_status("198.51.100.0/23", 64500, ROAS) == "unknown"
    assert detect.rpki_status("198.51.100.0/24", 64500, ROAS) == "valid"
    assert detect.rpki_status("198.51.100.0/25", 64500, ROAS) == "invalid"   # longer than maxLength


def test_stream_never_sets_the_reference_origin():
    """RIS Live alone (no RPKI record, RIPEstat off): its first sighting is not "usual"; several origins are
    information only, with no reference yet. With a reference from RIPEstat, a new origin needs you."""
    _wl("198.51.100.0/24")
    detect.observe_announcements([("198.51.100.0/24", "198.51.100.0/24", 64509)])   # perhaps the hijacker
    st = _states()["198.51.100.0/24"]
    assert "origins" not in st["base"] and _open("198.51.100.0/24") == {}
    card = detect.cards({"ris_live": {"on": True, "interval": 0}})[0]
    assert "no reference origin yet" in card["sentence"]
    detect.observe_announcements([("198.51.100.0/24", "198.51.100.0/24", 64500)])
    ev = _open("198.51.100.0/24")["unexpected_origin"]
    assert ev["level"] == "info" and "no reference origin" in ev["summary"]
    # RIPEstat gives the reference: from then on a new origin seen by the stream needs you
    detect.ingest_ripestat({"198.51.100.0/24": {"ok": True, "hours": 6, "status": {"origins": [{"origin": 64500}]}}})
    detect.observe_announcements([("198.51.100.0/24", "198.51.100.0/25", 64511)])
    ev = _open("198.51.100.0/24")["unexpected_origin"]
    assert ev["level"] == "needs_you" and "usually announced by AS64500" in ev["summary"]


def test_card_shows_the_worst_source():
    _wl("198.51.100.0/24")
    detect.note_check("ris_live", True)
    detect.note_check("rpki_roas", False, "the signed-route file could not be downloaded (could not connect)")
    on = {"ris_live": {"on": True, "interval": 0}, "rpki_roas": {"on": True, "interval": 86400}}
    c = detect.cards(on)[0]
    assert c["state"] == "unchecked" and "Couldn't check with RPKI file" in c["sentence"]
    assert {k["source"]: k["state"] for k in c["checks"]} == {"ris_live": "ok", "rpki_roas": "failed"}
    detect.note_check("rpki_roas", True)
    assert detect.cards(on)[0]["state"] == "normal"
    # a source that has not looked at a new watch yet ranks worse than ok: no false "Normal"
    _wl("198.51.100.0/24", "203.0.113.0/24")
    detect.note_check("ris_live", True)
    new = {c["id"]: c for c in detect.cards(on)}["203.0.113.0/24"]
    st = _states()
    st["203.0.113.0/24"]["checks"].pop("rpki_roas", None)
    db.set_setting(detect.STATE_KEY, st)
    new = {c["id"]: c for c in detect.cards(on)}["203.0.113.0/24"]
    assert new["state"] == "pending" and "Checking… RPKI file has not looked at it yet" in new["sentence"]


def test_a_watchlist_change_refilters_rpki_at_once_and_emptying_it_drops_the_cache(monkeypatch):
    from osinthub.sources import routing_rpki
    _wl("AS64500")
    db.execute("INSERT OR REPLACE INTO source_state (id, enabled, last_ok) VALUES ('rpki_roas', true, now())")
    kicked = []
    monkeypatch.setattr(rapi, "_kick", lambda src, delay=None: kicked.append((src.id, delay)))
    C.put("/api/routing/watchlist", json={"watches": ["AS64500", "AS64501"]}, headers=ORIGIN)
    assert ("rpki_roas", rapi.QUICK_KICK_S) in kicked
    cache = routing_rpki.cache_path()
    assert cache.parent.name == "cache" and cache.parent.parent == config.LAKE
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(b"x" * 100)
    import osinthub.api as A
    A._LAKE_CACHE.clear()
    assert C.get("/api/lake").json()["parts"]["cache"]["bytes"] == 100    # counted in Data and retention
    C.put("/api/routing/watchlist", json={"watches": []}, headers=ORIGIN)
    assert not cache.exists()


def test_raising_the_limit_lets_paused_sources_go_again(monkeypatch):
    _wl("AS64500")
    # checked recently, so its loop would wait a day: only a kick makes it look again now
    db.execute("INSERT OR REPLACE INTO source_state (id, enabled, last_ok) VALUES ('rpki_roas', true, now())")
    kicked = []
    monkeypatch.setattr(rapi, "_kick", lambda src, delay=None: kicked.append((src.id, delay)))
    C.put("/api/routing/settings", json={"limit_mb": 10}, headers=ORIGIN)
    assert kicked == []                                  # lowering does not kick
    C.put("/api/routing/settings", json={"limit_mb": 100}, headers=ORIGIN)
    assert ("rpki_roas", rapi.QUICK_KICK_S) in kicked       # at once, not after the 45 s edit pause


def test_a_paused_batch_loop_looks_again_soon(monkeypatch):
    """The loop waits PAUSED_RETRY_S (not a whole day) after a paused run, so it resumes after midnight or a raised
    limit; while still paused it makes no request (the check is local)."""
    sleeps = []

    async def fake_run(src):
        return {"ok": False, "skipped": True, "paused": True}

    async def fake_sleep(s):
        sleeps.append(s)
        raise asyncio.CancelledError

    monkeypatch.setattr(scheduler, "run_batch", fake_run)
    monkeypatch.setattr(config, "OFFLINE", False)
    monkeypatch.setattr(scheduler.asyncio, "sleep", fake_sleep)
    db.execute("INSERT OR REPLACE INTO source_state (id, last_ok) VALUES ('rpki_roas', NULL)")
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(scheduler._batch_loop(SOURCES["rpki_roas"]))
    assert sleeps == [scheduler.PAUSED_RETRY_S]
