"""Pre-alpha terms items (okf/project/pre-alpha-release.md, "Terms and licences"): TeleGeography's cable data is opt-in
(never fetched at start, downloaded once on request, refused offline); online basemaps only with the user's own CARTO
key (no Esri, no keyless CARTO, CSP to match); Bluesky offered, its author deletes recorded and the posts kept; the shipped files (LICENSE, NOTICE, the glyph OFL,
NASA textures with their sources; no echarts-gl, no three-globe images, no Tranco-derived lists).
Offline, temporary lake, no network.

    uv run --with pytest pytest tests/app/test_v12_terms.py -q
"""
from __future__ import annotations

import asyncio
import json
import re
import types

from _lake import ROOT, make_lake
LAKE = make_lake("terms", disable="news,entities,netlog,ai")

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import api, bootstrap, config  # noqa: E402
from osinthub.sources import SOURCES, caps  # noqa: E402
from osinthub.sources.base import make_id  # noqa: E402

client = TestClient(api.app, base_url="http://localhost")
ORIGIN = {"Origin": "http://localhost"}   # a same-origin write
FAKE = "user-" + "example"                # stands in for the user's CARTO key


def _policy(header: str) -> dict:
    return {d.split()[0]: d.split()[1:] for d in header.split("; ")}


# ------------------------------------------------------------------ cables: opt-in
def test_cable_files_are_not_fetched_at_start():
    paths = {p for p, _, _ in bootstrap.REFERENCE}
    assert config.CABLES_GEOJSON not in paths and config.LANDINGS_GEOJSON not in paths
    assert not any("submarinecablemap" in u for _, urls, _ in bootstrap.REFERENCE for u in urls)
    assert set(bootstrap.CABLES) == {config.CABLES_GEOJSON, config.LANDINGS_GEOJSON}


def test_missing_cables_answer_an_empty_layer():
    for p in bootstrap.CABLES:
        p.unlink(missing_ok=True)
    d = client.get("/api/geo/cables").json()
    assert d["features"] == [] and d["missing"] is True


def test_cable_download_is_refused_offline():
    assert config.OFFLINE
    r = client.post("/api/geo/cables/fetch", headers=ORIGIN)
    assert r.status_code == 409 and "Offline" in r.json()["detail"]
    assert not bootstrap.cables_present()


def test_cable_download_saves_both_files_once(monkeypatch):
    for p in bootstrap.CABLES:
        p.unlink(missing_ok=True)
    calls = []

    async def fake_get(client, url, sid, *, cap=None, **kw):
        calls.append((url, sid, cap))
        body = json.dumps({"type": "FeatureCollection", "features": [{"type": "Feature", "properties": {"id": "c1", "name": "Cable"},
                                                                      "geometry": {"type": "LineString", "coordinates": [[0, 0], [1, 1]]}}]})
        return httpx.Response(200, content=body.encode(), request=httpx.Request("GET", url))

    monkeypatch.setattr(config, "OFFLINE", False)
    monkeypatch.setattr(caps, "get", fake_get)
    assert asyncio.run(bootstrap.fetch_cables()) is True
    assert bootstrap.cables_present() and len(calls) == 2
    assert all(cap == bootstrap.CABLES_CAP for _, _, cap in calls)            # capped like every other download
    assert asyncio.run(bootstrap.fetch_cables()) is False and len(calls) == 2   # already here: nothing fetched
    assert client.get("/api/geo/cables").json()["features"][0]["properties"]["id"] == "c1"


def test_failed_cable_download_stores_nothing(monkeypatch):
    for p in bootstrap.CABLES:
        p.unlink(missing_ok=True)

    async def broken(client, url, sid, **kw):
        return httpx.Response(200, content=b"<html>not json</html>", request=httpx.Request("GET", url))

    monkeypatch.setattr(config, "OFFLINE", False)
    monkeypatch.setattr(caps, "get", broken)
    r = client.post("/api/geo/cables/fetch", headers=ORIGIN)
    assert r.status_code == 502 and "TeleGeography" in r.json()["detail"]
    assert not any(p.exists() for p in bootstrap.CABLES)
    assert not any(p.with_name(p.name + ".part").exists() for p in bootstrap.CABLES)


# ------------------------------------------------------------------ basemaps: only with the user's CARTO key
def test_no_online_basemap_without_a_key(monkeypatch):
    monkeypatch.setattr(config, "OFFLINE", False)
    monkeypatch.setattr(config, "CARTO_API_KEY", None)
    assert client.get("/api/geo/basemaps").json() == {"carto_key": None}
    on = _policy(api.csp(offline=False))
    assert not any("cartocdn" in o or "arcgis" in o for o in on["connect-src"] + on["img-src"])


def test_carto_with_the_users_key(monkeypatch):
    monkeypatch.setattr(config, "OFFLINE", False)
    monkeypatch.setattr(config, "CARTO_API_KEY", FAKE)
    assert client.get("/api/geo/basemaps").json() == {"carto_key": FAKE}
    on = _policy(api.csp(offline=False))
    assert {"https://basemaps.cartocdn.com", "https://*.basemaps.cartocdn.com"} <= set(on["connect-src"])
    assert not any("arcgis" in o for o in on["connect-src"])
    off = api.csp(offline=True)
    assert "cartocdn" not in off
    monkeypatch.setattr(config, "OFFLINE", True)
    assert client.get("/api/geo/basemaps").json() == {"carto_key": None}   # offline: no online basemap at all


def test_map_client_has_no_keyless_or_esri_basemap():
    js = (ROOT / "web" / "js" / "panels" / "world-map.js").read_text()
    assert "arcgisonline" not in js and "Esri" not in js.replace("the Esri imagery", "")
    assert re.findall(r"basemaps\.cartocdn\.com/gl/\$\{name\}-gl-style/style\.json\?key=", js)
    assert "carto.com/attribution" in js and "openstreetmap.org/copyright" in js


# ------------------------------------------------------------------ Bluesky: deletes are recorded, posts kept
def _commit(op, did, rkey, text=None, time_us=1_763_640_000_000_000):
    c = {"rev": "r", "operation": op, "collection": "app.bsky.feed.post", "rkey": rkey}
    if text is not None:
        c["record"] = {"$type": "app.bsky.feed.post", "text": text, "langs": ["en"], "createdAt": "2026-11-20T10:00:00Z"}
    return {"did": did, "time_us": time_us, "kind": "commit", "commit": c}


def test_bluesky_is_offered_with_its_terms():
    b = SOURCES["bluesky_cyber"]
    assert not b.withheld and not b.unavailable()
    row = {s["id"]: s for s in client.get("/api/settings/sources-choice").json()["sources"]}["bluesky_cyber"]
    assert row["terms"] == "Bluesky developer guidelines." and row["local_default"] == "ask"


def test_author_deletes_are_recorded_and_the_post_stays():
    from osinthub import db
    from osinthub.sources.base import now
    b = SOURCES["bluesky_cyber"]
    text = "CVE-2026-12345 is being exploited by a ransomware crew against exposed VPN appliances right now."
    ev = b.post_event(_commit("create", "did:plc:example1", "3kexamplea", text))
    assert ev is not None
    row = ev.to_row(None)
    db.execute("INSERT OR REPLACE INTO events (id, source, kind, ts, title, url) VALUES (?, ?, ?, ?, ?, ?)",
               [row["id"], row["source"], row["kind"], row["ts"], row["title"], row["url"]])
    stored, when = b.deletion(_commit("delete", "did:plc:example1", "3kexamplea"))
    assert stored == row["id"] and when.isoformat() == "2025-11-20T12:00:00+00:00"   # Jetstream's time_us
    never_kept = b.deletion(_commit("delete", "did:plc:example2", "3kexampleb"))
    assert db.record_deletion_requests(b.id, [(stored, when), never_kept, (stored, now())]) == 1
    assert db.record_deletion_requests(b.id, [(stored, now())]) == 0           # a repeat keeps the first request
    marks = db.query("SELECT * FROM deletion_requests")
    assert [(m["event_id"], m["url"]) for m in marks] == [(row["id"], row["url"])]
    assert marks[0]["requested_at"] == when
    assert db.query("SELECT count(*) AS n FROM events WHERE id = ?", [row["id"]])[0]["n"] == 1   # not removed
    assert db.record_deletion_requests(b.id, []) == 0


def test_the_stream_marks_deletes_after_storing_the_posts(monkeypatch):
    """A post created and deleted within one flush window is stored first, then marked."""
    import osinthub.sources.streams as streams
    b = SOURCES["bluesky_cyber"]
    text = "Botnet operators are pushing new ransomware via CVE-2026-23456 in exposed routers, patch now please."
    msgs = [_commit("create", "did:plc:example3", "3kexamplec", text),
            {"kind": "identity", "did": "did:plc:example3"},
            _commit("delete", "did:plc:example3", "3kexamplec"),
            _commit("delete", "did:plc:example4", "3kexampled")]
    order = []

    class WS:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        def __aiter__(self):
            async def gen():
                for m in msgs:
                    yield json.dumps(m)
            return gen()

    ticks = iter(range(0, 10_000, 100))   # every message is a new flush window (only the stream's clock is faked)
    monkeypatch.setattr(config, "OFFLINE", False)
    monkeypatch.setattr(streams.websockets, "connect", lambda *a, **k: WS())
    monkeypatch.setattr(streams, "time", types.SimpleNamespace(monotonic=lambda: float(next(ticks))))
    monkeypatch.setattr(streams, "fix_encoded_events", lambda *a: 0)

    class Sink:
        buf = []
        def emit(self, ev): self.buf.append(ev)
        async def metric(self, *a): pass
        async def flush(self): order.append(("flush", [e.key for e in self.buf])); self.buf.clear()

    async def record(self_, gone):
        order.append(("deletes", [g[0] for g in gone]))
        return []
    monkeypatch.setattr(type(b), "record_deletions", record)
    asyncio.run(b.stream(Sink()))
    flushed = [x for x in order if x[0] == "flush" and x[1]]
    assert flushed and flushed[0][1] == [("did:plc:example3", "3kexamplec")]
    marked = [i for x in order if x[0] == "deletes" for i in x[1]]
    assert marked == [make_id(b.id, "did:plc:example3", "3kexamplec"), make_id(b.id, "did:plc:example4", "3kexampled")]
    first_mark = next(i for i, x in enumerate(order) if x[0] == "deletes" and x[1])
    assert order.index(flushed[0]) < first_mark            # stored first, then marked


# ------------------------------------------------------------------ shipped files
def test_licence_and_notice_files():
    lic = (ROOT / "LICENSE").read_text()
    assert lic.startswith("Required Notice: Copyright 2026 The Night Desk authors\n")
    assert "# PolyForm Noncommercial License 1.0.0" in lic
    notice = (ROOT / "NOTICE").read_text()
    assert "DRAFT" not in notice and "<owner>" not in notice
    for gone in ("ECharts GL", "Tranco list**", "Esri", "| Bluesky |"):
        assert gone not in notice, gone
    assert "The Apache Software Foundation (https://www.apache.org/)." in notice   # ECharts' NOTICE, verbatim
    assert "SIL Open Font License" in (ROOT / "web" / "vendor" / "glyphs" / "OFL.txt").read_text()


def test_vendor_tree_after_the_terms_review():
    vendor = ROOT / "web" / "vendor"
    assert not list(vendor.glob("echarts-gl@*")) and not list(vendor.glob("three-globe@*"))
    nasa = vendor / "nasa"
    for f in ("blue-marble.jpg", "black-marble.jpg", "topography.png"):
        assert (nasa / f).stat().st_size > 100_000, f
        assert f in (nasa / "SOURCES.md").read_text()
    cinema = (ROOT / "web" / "js" / "views" / "cinema.js").read_text()
    assert "vendor/nasa/" in cinema and "night-sky" not in cinema


def test_no_tranco_derived_list_is_shipped():
    fx = ROOT / "osinthub" / "netlog" / "fixtures"
    assert not (fx / "tranco200.json").exists()
    top = (fx / "top-domains.txt").read_text()
    assert "tranco-list.eu" not in top and len([l for l in top.splitlines() if l and not l.startswith("#")]) < 400
