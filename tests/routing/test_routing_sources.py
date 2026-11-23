"""Routing watch sources against fake servers on 127.0.0.1: the RPKI file (local filtering, conditional GET and the
304 path, fallback, the data limit), Cloudflare Radar (no ASN or prefix in any request, paging, local matching, the
token only in the header), RIPEstat (sourceapp, at most 4 requests at once, retries, the daily request cap) and RIS
Live (watchlist-only subscriptions on one connection, bytes counted, no connection without a watchlist).

Offline mode is off in this file so the fetch code runs, but every request goes through a transport that refuses
any host other than 127.0.0.1, every URL points at a local fake server, and the app's scheduler (which would start
the real sources) is never started. Documentation ASNs and prefixes only.

    uv run --with pytest pytest tests/routing/test_routing_sources.py -q
"""
from __future__ import annotations

import asyncio
import gzip
import json
import logging
import os
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

os.environ.pop("CLOUDFLARE_RADAR_TOKEN", None)
for k in ("OSINTHUB_RPKI_URL", "OSINTHUB_RPKI_FALLBACK_URL", "OSINTHUB_RIPESTAT_URL", "OSINTHUB_RISLIVE_URL"):
    os.environ[k] = "http://127.0.0.1:9/never"   # nothing real, even before a test points it at its fake server
from _lake import make_lake  # noqa: E402
LAKE = make_lake("routing-src", offline=False, disable="news,entities,netlog,ai,watch,notes,stack,help")

import httpx  # noqa: E402
import pytest  # noqa: E402
import websockets  # noqa: E402

from osinthub import config, db, scheduler  # noqa: E402
from osinthub.routing import api as rapi, detect, usage, watchlist  # noqa: E402
from osinthub.sources import SOURCES, routing_radar, routing_ripestat, routing_rpki, streams  # noqa: E402

assert not config.OFFLINE
TOKEN = "radar_test_token_" + "q" * 24


# ---------------------------------------------------------------- the fake HTTP server
class Fake:
    def __init__(self):
        self.reqs: list[dict] = []
        self.routes: dict = {}
        self.active = self.max_active = 0
        self.delay = 0.0
        self.lock = threading.Lock()
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                u = urllib.parse.urlsplit(self.path)
                req = {"path": u.path, "query": dict(urllib.parse.parse_qsl(u.query)), "raw_query": u.query,
                       "headers": {k.lower(): v for k, v in self.headers.items()}}
                with fake.lock:
                    fake.reqs.append(req)
                    fake.active += 1
                    fake.max_active = max(fake.max_active, fake.active)
                try:
                    time.sleep(fake.delay)
                    fn = fake.routes.get(u.path)
                    status, hdrs, body = fn(req) if fn else (404, {}, b"not found")
                    self.send_response(status)
                    for k, v in hdrs.items():
                        self.send_header(k, v)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                finally:
                    with fake.lock:
                        fake.active -= 1

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def take(self):
        with self.lock:
            r, self.reqs = self.reqs, []
        return r


FAKE = Fake()


class LoopbackOnly(httpx.AsyncBaseTransport):
    """Every request of these tests: refused unless it goes to the local fake server."""

    def __init__(self):
        self.inner = httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request):
        assert request.url.host == "127.0.0.1", f"test tried to reach {request.url.host}"
        return await self.inner.handle_async_request(request)


def run(coro_fn):
    async def go():
        scheduler._client = httpx.AsyncClient(transport=LoopbackOnly())
        try:
            return await coro_fn()
        finally:
            await scheduler._client.aclose()
    return asyncio.run(go())


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    watchlist.ALLOW_DOCUMENTATION = True
    for k in (watchlist.KEY, detect.STATE_KEY, detect.ROAS_KEY, watchlist.SETTINGS_KEY, routing_rpki.META_KEY):
        db.execute("DELETE FROM settings WHERE key = ?", [k])
    db.execute("DELETE FROM source_state")
    db.execute("DELETE FROM record_hashes")
    watchlist.set_token(None)
    routing_rpki.cache_path().unlink(missing_ok=True)
    usage.reset_for_tests()
    FAKE.take()
    FAKE.routes.clear()
    FAKE.delay = 0.0
    FAKE.max_active = 0
    monkeypatch.setattr(routing_rpki, "URL", f"{FAKE.base}/cf/rpki.json")
    monkeypatch.setattr(routing_rpki, "FALLBACK_URL", f"{FAKE.base}/console/rpki.json")
    monkeypatch.setattr(routing_radar, "BASE", f"{FAKE.base}/client/v4/radar/bgp")
    monkeypatch.setattr(routing_ripestat, "BASE", f"{FAKE.base}/data")

    async def nosleep(_s):
        return None
    monkeypatch.setattr(routing_ripestat, "_sleep", nosleep)
    yield


def _wl(*vals):
    return watchlist.save([{"value": v} for v in vals])


# ---------------------------------------------------------------- RPKI file
WANTED = [  # [prefix, maxLength, asn]
    ["198.51.100.0/24", 24, 64500], ["198.51.100.0/22", 24, 64501], ["198.51.100.128/25", 25, 64502],
    ["192.0.2.0/24", 24, 64500], ["2001:db8:100::/48", 48, 64503],
]
NOISE = [[f"192.0.2.{i}/32", 32, 64496 + i % 4] for i in range(256)] + \
        [[f"2001:db8:{i:x}::/48", 48, 64497] for i in range(0x200, 0x2ff)] + [["203.0.113.0/24", 24, 64511]] * 2000


def rpki_json(rows, asn_text=False):
    roas = [{"prefix": p, "maxLength": m, "asn": f"AS{a}" if asn_text else a, "ta": "test"} for p, m, a in rows]
    return json.dumps({"metadata": {"counts": len(roas), "generated": 1763337600}, "roas": roas}).encode()


def serve_rpki(path, rows, etag='"v1"', asn_text=False, status=200):
    body = gzip.compress(rpki_json(rows, asn_text))

    def h(req):
        if status != 200:
            return status, {}, b"unavailable"
        if req["headers"].get("if-none-match") == etag:
            return 304, {"ETag": etag}, b""
        return 200, {"Content-Type": "application/json", "Content-Encoding": "gzip", "ETag": etag,
                     "Last-Modified": "Mon, 16 Nov 2026 00:00:00 GMT"}, body
    FAKE.routes[path] = h
    return body


def test_rpki_filters_locally_then_conditional_get_gives_304():
    _wl("AS64500", "198.51.100.0/24", "2001:db8:100::/48")
    body = serve_rpki("/cf/rpki.json", WANTED + NOISE)
    src = SOURCES["rpki_roas"]
    res = run(lambda: scheduler.run_batch(src))
    assert res["ok"] and res["records_changed"] == 5, res
    r1 = FAKE.take()
    assert len(r1) == 1 and "if-none-match" not in r1[0]["headers"] and r1[0]["query"] == {}
    kept = detect.roas()
    assert kept["AS64500"]["count"] == 2                                   # both ROAs naming AS64500
    assert {tuple(r) for r in kept["198.51.100.0/24"]["roas"]} == {("198.51.100.0/24", 24, 64500), ("198.51.100.0/22", 24, 64501), ("198.51.100.128/25", 25, 64502)}
    assert kept["2001:db8:100::/48"]["count"] == 1
    # the lake holds only the relevant records, never the file
    raw = [p for p in (config.RAW_DIR / "rpki_roas").rglob("*.gz")]
    text = b"".join(gzip.decompress(p.read_bytes()) for p in raw)
    assert b"203.0.113.0/24" not in text and b"192.0.2.7/32" not in text and text.count(b"198.51.100.0/24") >= 1
    assert len(body) <= usage.used("rpki_roas") <= len(body) + 1000          # compressed bytes counted
    assert routing_rpki.cache_path().exists()            # the working cache next to the database, not the lake
    # run again within the day, same watchlist: nothing is due, no request at all
    res = run(lambda: scheduler.run_batch(src))
    assert res.get("unchanged") and FAKE.take() == []
    # a new watch: filtered again from the cached file, no download
    used = usage.used("rpki_roas")
    _wl("AS64500", "198.51.100.0/24", "2001:db8:100::/48", "AS64501")
    res = run(lambda: scheduler.run_batch(src))
    assert res["ok"] and FAKE.take() == [] and usage.used("rpki_roas") == used
    assert detect.roas()["AS64501"]["count"] == 1
    # the daily check is due: a conditional GET, answered 304
    meta = db.get_setting(routing_rpki.META_KEY)
    meta["downloaded"] = "2026-01-01T00:00:00+00:00"
    db.set_setting(routing_rpki.META_KEY, meta)
    res = run(lambda: scheduler.run_batch(src))
    r2 = FAKE.take()
    assert res.get("unchanged") and len(r2) == 1 and r2[0]["headers"]["if-none-match"] == '"v1"'
    assert r2[0]["headers"]["if-modified-since"] == "Mon, 16 Nov 2026 00:00:00 GMT"
    assert scheduler.state("rpki_roas")["status"] == "ok"


def test_rpki_falls_back_to_the_second_url_and_reads_its_format():
    _wl("198.51.100.0/24")
    serve_rpki("/cf/rpki.json", WANTED, status=503)
    serve_rpki("/console/rpki.json", WANTED, asn_text=True)
    res = run(lambda: scheduler.run_batch(SOURCES["rpki_roas"]))
    assert res["ok"] and [r["path"] for r in FAKE.take()] == ["/cf/rpki.json", "/console/rpki.json"]
    assert detect.roas()["198.51.100.0/24"]["count"] == 3
    assert db.get_setting(routing_rpki.META_KEY)["url"].endswith("/console/rpki.json")


def test_rpki_download_stops_at_the_data_limit():
    _wl("198.51.100.0/24")
    watchlist.set_settings(limit_mb=1)
    big = rpki_json(WANTED + NOISE * 12)
    assert len(big) > 1_200_000
    FAKE.routes["/cf/rpki.json"] = lambda req: (200, {"Content-Type": "application/json"}, big)
    FAKE.routes["/console/rpki.json"] = FAKE.routes["/cf/rpki.json"]
    res = run(lambda: scheduler.run_batch(SOURCES["rpki_roas"]))
    assert res.get("paused") and scheduler.state("rpki_roas")["status"] == "paused"
    assert len(FAKE.take()) == 1                                            # no second download
    assert 1_000_000 <= usage.used() < len(big)
    res = run(lambda: scheduler.run_batch(SOURCES["rpki_roas"]))
    assert res.get("paused") and FAKE.take() == []                          # paused: nothing more today


def test_offline_mode_stops_the_fake_server_requests_too(monkeypatch):
    monkeypatch.setattr(config, "OFFLINE", True)
    _wl("198.51.100.0/24")
    serve_rpki("/cf/rpki.json", WANTED)
    res = run(lambda: scheduler.run_batch(SOURCES["rpki_roas"]))
    assert res["error"] == "offline mode" and FAKE.take() == []


# ---------------------------------------------------------------- Cloudflare Radar
def _radar_routes():
    hij = [{"id": i, "confidence_score": 9 if i == 5 else 3, "hijacker_asn": 64509, "victim_asns": [64500 if i == 5 else 64497],
            "prefixes": ["198.51.100.0/24" if i == 5 else "192.0.2.0/24"], "min_hijack_ts": "2026-11-17T01:00:00Z",
            "max_hijack_ts": "2026-11-17T02:00:00Z"} for i in range(150)]
    leaks = [{"id": 900, "leak_asn": 64505, "leak_seg": [64504, 64505, 64500], "prefix_count": 4, "origin_count": 2}]

    def hijacks(req):
        page, per = int(req["query"]["page"]), int(req["query"]["per_page"])
        chunk = hij[(page - 1) * per: page * per]
        return 200, {"Content-Type": "application/json"}, json.dumps({"success": True, "result": {"events": chunk, "total_monitors": 400},
                                                                     "result_info": {"page": page, "per_page": per, "count": len(chunk), "total_count": len(hij)}}).encode()
    FAKE.routes["/client/v4/radar/bgp/hijacks/events"] = hijacks
    FAKE.routes["/client/v4/radar/bgp/leaks/events"] = lambda req: (200, {}, json.dumps({"success": True, "result": {"events": leaks}, "result_info": {"total_count": 1}}).encode())


def test_radar_lists_without_naming_any_network_and_matches_locally(caplog):
    caplog.set_level(logging.DEBUG)
    _wl("AS64500", "198.51.100.0/24")
    assert SOURCES["cf_radar_bgp"].unavailable()            # no token: never runs
    watchlist.set_token(TOKEN)
    _radar_routes()
    res = run(lambda: scheduler.run_batch(SOURCES["cf_radar_bgp"]))
    assert res["ok"], res
    reqs = FAKE.take()
    assert [r["path"].rsplit("/", 2)[1] for r in reqs] == ["hijacks", "hijacks", "leaks"]   # paged
    for r in reqs:
        assert set(r["query"]) <= {"dateRange", "sortBy", "sortOrder", "page", "per_page", "format"}, r["query"]
        assert r["query"]["sortBy"] == "TIME" and r["query"]["dateRange"] == "1d"
        assert "64500" not in r["raw_query"] and "198.51.100" not in r["raw_query"] and TOKEN not in r["raw_query"]
        assert r["headers"]["authorization"] == f"Bearer {TOKEN}"
    ev = {e["kind"]: e for e in detect.open_events("AS64500")}
    assert ev["radar_hijack"]["level"] == "needs_you" and ev["radar_leak"]["level"] == "info"
    assert {e["kind"] for e in detect.open_events("198.51.100.0/24")} == {"radar_hijack"}
    assert res["records_changed"] == 3                       # only the matched events go to the lake
    assert TOKEN not in caplog.text


def test_radar_refused_token_is_reported_without_the_token(caplog):
    caplog.set_level(logging.DEBUG)
    _wl("AS64500")
    watchlist.set_token(TOKEN)
    FAKE.routes["/client/v4/radar/bgp/hijacks/events"] = lambda req: (403, {}, json.dumps({"success": False}).encode())
    res = run(lambda: scheduler.run_batch(SOURCES["cf_radar_bgp"]))
    assert not res["ok"] and "refused the token (HTTP 403)" in res["error"] and TOKEN not in res["error"]
    rows = db.query("SELECT * FROM runs WHERE source = 'cf_radar_bgp'")
    assert rows and TOKEN not in json.dumps(rows, default=str)
    assert TOKEN not in json.dumps(scheduler.state("cf_radar_bgp"), default=str)
    assert TOKEN not in caplog.text
    card = detect.cards({"cf_radar_bgp": {"on": True, "interval": 21600}})[0]
    assert card["state"] == "unchecked" and "refused the token" in card["sentence"]


# ---------------------------------------------------------------- RIPEstat
def _ripestat_routes():
    def status(req):
        res = req["query"]["resource"]
        if res.startswith("AS"):
            d = {"announced_space": {"v4": {"prefixes": 12, "ips": 3072}, "v6": {"prefixes": 2}}}
        else:
            d = {"origins": [{"origin": 64500}], "more_specifics": [],
                 "visibility": {"v4": {"ris_peers_seeing": 300, "total_ris_peers": 320}, "v6": {"ris_peers_seeing": 290, "total_ris_peers": 300}}}
        return 200, {}, json.dumps({"status": "ok", "data": d}).encode()
    FAKE.routes["/data/routing-status/data.json"] = status
    FAKE.routes["/data/asn-neighbours/data.json"] = lambda req: (200, {}, json.dumps({"data": {"neighbours": [
        {"asn": 64501, "type": "left"}, {"asn": 64502, "type": "right"}]}}).encode())
    FAKE.routes["/data/bgp-update-activity/data.json"] = lambda req: (200, {}, json.dumps({"data": {"updates": [
        {"starttime": "2026-11-17T00:00:00", "announcements": 30, "withdrawals": 2}]}}).encode())
    FAKE.routes["/data/rpki-validation/data.json"] = lambda req: (200, {}, json.dumps({"data": {"status": "valid"}}).encode())


def _optin():
    db.execute("INSERT OR REPLACE INTO source_state (id, enabled) VALUES ('ripestat', true)")


def test_ripestat_is_polite_sourceapp_concurrency_and_request_count():
    wl = [{"id": f"AS{64496 + i}", "kind": "asn", "value": f"AS{64496 + i}", "label": "t"} for i in range(6)] + \
         [{"id": p, "kind": "prefix", "value": p, "label": "t"} for p in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
                                                                          "2001:db8:1::/48", "2001:db8:2::/48", "2001:db8:3::/48")]
    db.set_setting(watchlist.KEY, wl)
    _optin()
    _ripestat_routes()
    FAKE.delay = 0.02                      # long enough that the workers overlap (max_active below)
    res = run(lambda: scheduler.run_batch(SOURCES["ripestat"]))
    assert res["ok"], res
    FAKE.delay = 0.0
    reqs = FAKE.take()
    assert all(r["query"].get("sourceapp") == "night-desk" for r in reqs)
    assert 2 <= FAKE.max_active <= routing_ripestat.CONCURRENCY == 4
    # no local RPKI file: prefix watches also ask rpki-validation once per origin -> 3 requests per watch
    assert len(reqs) == 12 * 3, [r["path"] for r in reqs]
    assert usage.requests("ripestat") == 36
    # with the local RPKI file loaded, 2-3 per watch: 25 watches every 6 h stay well under 1,000 a day
    db.set_setting(detect.ROAS_KEY, {"_meta": {"at": "2026-11-17T00:00:00+00:00"}})
    run(lambda: scheduler.run_batch(SOURCES["ripestat"]))
    per_watch = len(FAKE.take()) / 12
    assert per_watch <= 3 and 25 * per_watch * (86400 / watchlist.DEFAULTS["every"]) <= 300
    cards = {c["id"]: c for c in detect.cards({"ripestat": {"on": True, "interval": 21600}})}
    assert cards["198.51.100.0/24"]["state"] == "normal" and "94%" in cards["198.51.100.0/24"]["sentence"]
    assert "announces 14 prefixes through 1 upstream network" in cards["AS64496"]["sentence"].lower()


def test_ripestat_retries_after_429_then_stops_at_the_daily_cap(monkeypatch):
    _wl("AS64500", "198.51.100.0/24")
    _optin()
    _ripestat_routes()
    hits = {"n": 0}
    ok = FAKE.routes["/data/routing-status/data.json"]

    def flaky(req):
        hits["n"] += 1
        return (429, {}, b"slow down") if hits["n"] == 1 else ok(req)
    FAKE.routes["/data/routing-status/data.json"] = flaky
    res = run(lambda: scheduler.run_batch(SOURCES["ripestat"]))
    assert res["ok"] and not scheduler.state("ripestat")["message"].count("could not")
    assert hits["n"] == 3                                  # one 429, retried, then the second watch
    FAKE.take()
    usage.add("ripestat", 0, requests=routing_ripestat.DAILY_CAP)
    res = run(lambda: scheduler.run_batch(SOURCES["ripestat"]))
    st = scheduler.state("ripestat")
    assert FAKE.take() == [] and res.get("paused") and st["status"] == "paused" and "daily allowance" in st["message"]


def test_ripestat_cap_is_exact_and_the_limit_mid_run_is_a_pause():
    wl = [{"id": f"AS{64496 + i}", "kind": "asn", "value": f"AS{64496 + i}", "label": "t"} for i in range(12)]
    db.set_setting(watchlist.KEY, wl)
    _optin()
    _ripestat_routes()
    FAKE.delay = 0.02
    usage.add("ripestat", 0, requests=routing_ripestat.DAILY_CAP - 5)
    res = run(lambda: scheduler.run_batch(SOURCES["ripestat"]))
    assert len(FAKE.take()) == 5 and usage.requests("ripestat") == routing_ripestat.DAILY_CAP   # not one more
    st = scheduler.state("ripestat")
    assert res.get("paused") and st["status"] == "paused" and "allowance" in st["message"]
    # the data limit crossed during a run: paused, not an error
    usage.reset_for_tests()
    watchlist.set_settings(limit_mb=1)
    usage.add("rpki_roas", 999_000)
    res = run(lambda: scheduler.run_batch(SOURCES["ripestat"]))
    st = scheduler.state("ripestat")
    assert res.get("paused") and st["status"] == "paused" and "daily data limit" in st["message"]
    assert not db.query("SELECT * FROM runs WHERE source = 'ripestat' AND error IS NOT NULL AND started > now() - INTERVAL 1 MINUTE")


def test_ripestat_does_nothing_unless_opted_in():
    _wl("AS64500")
    _ripestat_routes()
    res = run(lambda: scheduler.run_batch(SOURCES["ripestat"]))
    assert not res["ok"] and FAKE.take() == []


# ---------------------------------------------------------------- RIS Live (fake websocket server)
class WS:
    def __init__(self, messages=(), close_after=False):
        self.close_after = close_after
        self.connections = 0
        self.subs: list[dict] = []
        self.messages = list(messages)
        self.closed = asyncio.Event()
        self.ready = asyncio.Event()     # got the expected subscriptions and sent its messages

    async def handler(self, ws):
        self.connections += 1
        try:
            n = 0
            async for raw in ws:
                self.subs.append(json.loads(raw))
                n += 1
                if n == self.expect:
                    for m in self.messages:
                        await ws.send(json.dumps(m))
                    self.ready.set()
                    if self.close_after:
                        await ws.close()
        except websockets.ConnectionClosed:
            pass
        finally:
            self.closed.set()


def _msg(prefix, path):
    return {"type": "ris_message", "data": {"timestamp": time.time(), "peer_asn": 64499, "host": "rrc00", "path": path,
                                            "announcements": [{"next_hop": "192.0.2.1", "prefixes": [prefix]}], "withdrawals": []}}


class Sink(scheduler.StreamSink):
    def __init__(self, src):
        async def flush(s, evs):
            return None
        super().__init__(src, flush)

    def metric(self, name, value):
        pass


def test_ris_live_subscribes_to_the_watchlist_only_and_counts_bytes(monkeypatch):
    _wl("AS64500", "198.51.100.0/24")
    db.set_setting(detect.ROAS_KEY, {"_meta": {"at": "x"}, "198.51.100.0/24": {"count": 1, "roas": [["198.51.100.0/24", 24, 64500]]}})
    msgs = [_msg("198.51.100.0/24", [64499, 64500]), _msg("198.51.100.0/25", [64499, 64507, 64508]),
            _msg("192.0.2.0/24", [64499, 64500])]
    srv = WS(msgs, close_after=True)
    srv.expect = 2

    async def go():
        async with websockets.serve(srv.handler, "127.0.0.1", 0) as s:
            port = s.sockets[0].getsockname()[1]
            monkeypatch.setattr(streams, "RIS_URL", f"ws://127.0.0.1:{port}/v1/ws/?client=night-desk")
            await asyncio.wait_for(SOURCES["ris_live"].stream(Sink(SOURCES["ris_live"])), 5)
    asyncio.run(go())
    assert srv.connections == 1
    assert [s["data"] for s in srv.subs] == [{"type": "UPDATE", "host": "rrc00", "path": "64500$"},
                                             {"type": "UPDATE", "host": "rrc00", "prefix": "198.51.100.0/24", "moreSpecific": True}]
    assert usage.used("ris_live") > 300
    ev = detect.open_events("198.51.100.0/24")   # AS64508 announced a /25 the ROA does not allow
    assert [e["kind"] for e in ev] == ["rpki_invalid"] and "AS64508 announced 198.51.100.0/25" in ev[0]["summary"]
    assert ev[0]["source"] == "ris_live"
    st = db.get_setting(detect.STATE_KEY)
    assert st["AS64500"]["facts"]["ris_live"]["prefixes_seen"] == 2 and st["AS64500"]["checks"]["ris_live"]["ok"]


def test_ris_live_disconnects_at_the_data_limit(monkeypatch):
    _wl("198.51.100.0/24")
    watchlist.set_settings(limit_mb=1)
    usage.add("rpki_roas", 999_000)
    # a dozen messages: about four go over the limit, and fewer than the client's receive queue (16) holds, so its
    # close handshake is not stuck behind unread data (that would cost its 2 s close timeout)
    srv = WS([_msg("198.51.100.0/24", [64499, 64500, 1000 + i]) for i in range(12)])
    srv.expect = 1
    paused = []

    async def fake_pause(self, why):
        paused.append(why)
    monkeypatch.setattr(streams.RisLive, "_pause", fake_pause)

    async def go():
        async with websockets.serve(srv.handler, "127.0.0.1", 0) as s:
            port = s.sockets[0].getsockname()[1]
            monkeypatch.setattr(streams, "RIS_URL", f"ws://127.0.0.1:{port}/")
            await asyncio.wait_for(SOURCES["ris_live"].stream(Sink(SOURCES["ris_live"])), 5)
            await asyncio.wait_for(srv.closed.wait(), 5)
    asyncio.run(go())
    assert usage.over() and paused and "daily data limit of 1 MB" in paused[0]


def test_ris_live_previously_on_with_empty_watchlist_never_connects(monkeypatch):
    """An existing lake where the firehose was on: no watchlist, no connection; a watchlist makes it subscribe to
    exactly that list; emptying it again closes the connection."""
    db.execute("INSERT OR REPLACE INTO source_state (id, enabled) VALUES ('ris_live', true)")
    srv = WS()
    srv.expect = 1

    async def go():
        scheduler._client = httpx.AsyncClient(transport=LoopbackOnly())
        async with websockets.serve(srv.handler, "127.0.0.1", 0) as s:
            port = s.sockets[0].getsockname()[1]
            monkeypatch.setattr(streams, "RIS_URL", f"ws://127.0.0.1:{port}/")
            await rapi.sync()
            assert "ris_live" not in scheduler._tasks
            with pytest.raises(asyncio.TimeoutError):   # even called directly, the stream does not connect
                await asyncio.wait_for(SOURCES["ris_live"].stream(Sink(SOURCES["ris_live"])), 0.2)
            assert srv.connections == 0
            _wl("AS64500")
            await rapi.sync()
            await asyncio.wait_for(srv.ready.wait(), 1)
            assert srv.connections == 1 and [x["data"].get("path") for x in srv.subs] == ["64500$"]
            _wl()
            await rapi.sync()
            await asyncio.wait_for(srv.closed.wait(), 1)
            assert scheduler.state("ris_live")["status"] == "needs_key"
            await scheduler.stop_all()
    asyncio.run(go())


def _stream_task(monkeypatch, srv, body):
    async def go():
        async with websockets.serve(srv.handler, "127.0.0.1", 0) as s:
            port = s.sockets[0].getsockname()[1]
            monkeypatch.setattr(streams, "RIS_URL", f"ws://127.0.0.1:{port}/")
            task = asyncio.create_task(SOURCES["ris_live"].stream(Sink(SOURCES["ris_live"])))
            try:
                return await body(task)
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
    return asyncio.run(go())


async def _until(cond, timeout=1.0):
    """Wait (at most `timeout` s) until cond() is true; the stream runs on this event loop meanwhile."""
    end = time.monotonic() + timeout
    while not cond():
        assert time.monotonic() < end, "timed out"
        await asyncio.sleep(0.01)


ROA_1 = {"_meta": {"at": "x"}, "198.51.100.0/24": {"count": 1, "roas": [["198.51.100.0/24", 24, 64500]]}}


def test_ris_live_flags_a_single_announcement_on_a_quiet_prefix(monkeypatch):
    """B1: one hijack announcement, then silence (the connection stays open): the flush timer (FLUSH_S, shortened
    here) hands it to the rules without another message."""
    _wl("198.51.100.0/24")
    db.set_setting(detect.ROAS_KEY, ROA_1)
    monkeypatch.setattr(streams, "FLUSH_S", 0.05)
    srv = WS([_msg("198.51.100.0/25", [64499, 64507, 64508])])
    srv.expect = 1

    async def body(task):
        await _until(lambda: detect.open_events("198.51.100.0/24"))
        return True
    assert _stream_task(monkeypatch, srv, body)
    assert [e["kind"] for e in detect.open_events("198.51.100.0/24")] == ["rpki_invalid"]


def test_ris_live_cancel_mid_pending_loses_nothing(monkeypatch):
    """A restart (every watchlist edit) cancels the stream: what it had matched is still handed to the rules."""
    _wl("198.51.100.0/24")
    db.set_setting(detect.ROAS_KEY, ROA_1)
    monkeypatch.setattr(streams, "FLUSH_S", 3600.0)   # the timer never fires in this test
    srv = WS([_msg("198.51.100.0/25", [64499, 64507, 64508])])
    srv.expect = 1

    seen = usage.used("ris_live")

    async def body(task):
        await asyncio.wait_for(srv.ready.wait(), 1)
        await _until(lambda: usage.used("ris_live") > seen)   # received and matched (no await between), still pending
        assert not detect.open_events("198.51.100.0/24")
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return True
    _stream_task(monkeypatch, srv, body)
    assert [e["kind"] for e in detect.open_events("198.51.100.0/24")] == ["rpki_invalid"]


def test_ris_live_closes_its_socket_before_pausing_when_another_source_hits_the_limit(monkeypatch):
    _wl("198.51.100.0/24")
    watchlist.set_settings(limit_mb=1)
    srv = WS()
    srv.expect = 1
    seen = []

    async def fake_pause(self, why):   # by now the client has left the connection (the old code kept it open)
        try:
            await asyncio.wait_for(srv.closed.wait(), 1)
        except TimeoutError:
            pass
        seen.append((srv.closed.is_set(), scheduler.state("ris_live").get("status")))
    monkeypatch.setattr(streams.RisLive, "_pause", fake_pause)
    monkeypatch.setattr(streams, "FLUSH_S", 0.05)    # the background check that notices the limit

    async def body(task):
        await asyncio.wait_for(srv.ready.wait(), 1)    # connected, quiet
        usage.add("rpki_roas", 1_000_001)             # another source uses up the limit
        await asyncio.wait_for(task, 1)               # the stream ends by itself
        return True
    _stream_task(monkeypatch, srv, body)
    assert seen == [(True, "paused")]                 # socket already closed, status paused, then the wait


def test_a_cancelled_ris_live_never_waits_with_its_socket_open(monkeypatch):
    _wl("198.51.100.0/24")
    usage.add("rpki_roas", 999_000)
    watchlist.set_settings(limit_mb=1)
    srv = WS()
    srv.expect = 1
    paused = []

    async def fake_pause(self, why):
        paused.append(why)
    monkeypatch.setattr(streams.RisLive, "_pause", fake_pause)
    monkeypatch.setattr(streams, "FLUSH_S", 3600.0)

    async def body(task):
        await asyncio.wait_for(srv.ready.wait(), 1)
        usage.add("rpki_roas", 10_000)                # over the limit, then a restart cancels the stream
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.wait_for(srv.closed.wait(), 1)
        return True
    assert _stream_task(monkeypatch, srv, body)
    assert paused == []                                # the cancelled task did not stay behind to wait
