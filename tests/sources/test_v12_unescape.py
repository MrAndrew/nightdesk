"""HTML entities in the non-RSS sources (lane v12-unescape): NVD descriptions, Bluesky posts and ransomware.live victims
are stored as plain text, decoded by the one shared decoder (osinthub/sources/text.py), while keys, URLs and the raw
provider records keep what the provider sent. Decoding changes a stored event once and then never again, events
stored before the fix are decoded in place on the source's next run, and decoded markup stays text all the way to the
API (the client escapes it where it is shown). Fixtures: tests/sources/fixtures/unescape (no network).

    uv run --with pytest pytest tests/sources/test_v12_unescape.py -q
"""
from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import json
from pathlib import Path

from _lake import make_lake
LAKE = make_lake("unescape", disable="news,entities,netlog,ai")

import httpx  # noqa: E402

from osinthub import config, db, scheduler  # noqa: E402
from osinthub.sources import SOURCES  # noqa: E402
from osinthub.sources import streams  # noqa: E402
from osinthub.sources.base import Event, StreamSink, make_id, record_hash  # noqa: E402
from osinthub.sources.text import fix_encoded_events, unentity  # noqa: E402

db.connect()
FX = Path(__file__).parent / "fixtures" / "unescape"
NVD = (FX / "nvd_cves.json").read_bytes()
JET = [ln for ln in (FX / "jetstream.ndjson").read_text().splitlines() if ln.strip()]
RW = (FX / "ransomware.json").read_bytes()

CVE1 = ("The vendor's \"Example Gate\" R&D build lets a remote attacker inject <script>alert(1)</script> "
        "through the name field.")
CVE2 = "AT&T Example routers and the Q&notes app: a && b, &copy law, price &pound5 and &foo; stay as written."
CVE3 = "Smith & Sons portal renders <img src=x onerror=alert(1)> from the\nsearch box (double-encoded by the CNA)."
ENTITY = ("&amp;", "&#39;", "&quot;", "&lt;", "&gt;", "&#")


def _run(src, body: bytes):
    """One scheduled run of a batch source against a fixed payload (MockTransport), offline lifted for the call."""
    async def go():
        scheduler._client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=body)))
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


def _rows(source: str) -> dict[str, dict]:
    return {r["id"]: r for r in db.query("SELECT id, title, summary, url, content_hash FROM events WHERE source = ?",
                                         [source])}


def _legacy_load(src, events: list[Event]) -> None:
    """Store events the way a run before this fix stored them (encoded text, its content hash)."""
    started = dt.datetime.now(dt.UTC)
    scheduler._load(src, scheduler._rows(events, None, started), None)


# ---------------------------------------------------------------- NVD
def test_nvd_descriptions_are_plain_text():
    evs = {e.key[0]: e for e in SOURCES["nvd_recent"].parse(NVD)}
    assert set(evs) == {"CVE-2026-90001", "CVE-2026-90002", "CVE-2026-90003"}, "rejected CVEs stay out"
    assert evs["CVE-2026-90001"].summary == CVE1
    assert evs["CVE-2026-90002"].summary == CVE2, "an '&' that is not a well-formed entity stays as written"
    assert evs["CVE-2026-90003"].summary == CVE3, "double encoding decoded, line breaks kept"
    assert evs["CVE-2026-90001"].title == "CVE-2026-90001 · CVSS 9.8"
    assert evs["CVE-2026-90001"].url == "https://nvd.nist.gov/vuln/detail/CVE-2026-90001"


def test_nvd_raw_records_keep_the_provider_text():
    """The lake keeps what NVD sent: records (and their hashes) are not decoded, reference URLs included."""
    recs = dict(SOURCES["nvd_recent"].records(NVD))
    raw = json.loads(NVD)["vulnerabilities"]
    assert recs["CVE-2026-90001"] == raw[0]
    assert "&#39;" in recs["CVE-2026-90001"]["cve"]["descriptions"][0]["value"]
    assert recs["CVE-2026-90001"]["cve"]["references"][0]["url"] == "https://vendor.example/advisory?id=1&amp;lang=en"
    assert record_hash(recs["CVE-2026-90001"]) == record_hash(raw[0])


def test_nvd_old_rows_change_once_then_stay_put():
    """A lake from before the fix: CVEs still in NVD's window (stored encoded) and one that left it. prepare() decodes
    every stored row in place and gives it the content hash parse() gives today, so the same run's parse() finds
    nothing changed (no event delta is written for text alone), and a second run changes nothing either."""
    src = SOURCES["nvd_recent"]
    sent = {i["cve"]["id"]: i["cve"]["descriptions"][0]["value"] for i in json.loads(NVD)["vulnerabilities"]}
    legacy = [dataclasses.replace(e, summary=sent[e.key[0]][:600]) for e in src.parse(NVD)]   # stored as sent
    old = Event(source=src.id, kind="cve", key=("CVE-2026-80000",), ts=dt.datetime(2026, 9, 1, tzinfo=dt.UTC),
                title="CVE-2026-80000 · CVSS 7.5", summary="Out of the window: the server&#39;s\n&quot;admin&quot; page",
                category="vuln", severity=0.75, value=7.5, url="https://nvd.nist.gov/vuln/detail/CVE-2026-80000")
    _legacy_load(src, legacy + [old])
    before = _rows(src.id)

    first = _run(src, NVD)
    assert first["ok"] and first["items"] == 3
    assert first["changed"] == 0, "prepare() already stored the decoded text with parse()'s own content hash"
    rows = _rows(src.id)
    today = {r["id"]: r["content_hash"] for r in scheduler._rows(src.parse(NVD), None, dt.datetime.now(dt.UTC))}
    for cid in ("CVE-2026-90001", "CVE-2026-90003"):
        eid = make_id(src.id, cid)
        assert rows[eid]["content_hash"] == today[eid] != before[eid]["content_hash"]
    assert rows[make_id(src.id, "CVE-2026-90001")]["summary"] == CVE1
    assert rows[make_id(src.id, "CVE-2026-90003")]["summary"] == CVE3
    assert rows[make_id(src.id, "CVE-2026-90002")]["content_hash"] == before[make_id(src.id, "CVE-2026-90002")]["content_hash"]
    assert rows[make_id(src.id, "CVE-2026-80000")]["summary"] == "Out of the window: the server's\n\"admin\" page"
    for r in rows.values():
        assert not any(x in (r["summary"] or "") for x in ENTITY), r

    second = _run(src, NVD)
    assert second["ok"] and second["changed"] == 0 and second["records_changed"] == 0
    assert _rows(src.id) == rows
    assert fix_encoded_events(src.id, squash=False) == 0, "nothing left to fix: parse() output is a fixed point"

    # CVE search documents read the raw records from the lake: their description text is decoded the same way
    from osinthub.ai.docs import lake_details
    det = lake_details()
    assert det["CVE-2026-90001"]["description"] == CVE1 and det["CVE-2026-90002"]["description"] == CVE2


def test_fixed_rows_are_relinked_once():
    """The entity linker relinks an event when its content hash moves: a row decoded in place gets a new hash, so its
    mentions are extracted again from the decoded text, once."""
    from osinthub.entities import link, store
    store.ensure_schema()
    src = SOURCES["nvd_recent"]
    ev = Event(source=src.id, kind="cve", key=("CVE-2026-80001",), ts=dt.datetime(2026, 9, 2, tzinfo=dt.UTC),
               title="CVE-2026-80001", summary="See https://vendor.example/a?b=1&amp;c=2 for the fix", category="vuln",
               url="https://nvd.nist.gov/vuln/detail/CVE-2026-80001")
    _legacy_load(src, [ev])
    eid = make_id(src.id, "CVE-2026-80001")
    old = db.query("SELECT content_hash FROM events WHERE id = ?", [eid])[0]["content_hash"]
    store.mark_linked("event", [(eid, old)])                       # linked before the fix
    assert eid not in {e["id"] for e in link.pending_events(10_000)}
    assert fix_encoded_events(src.id, squash=False) >= 1
    new = db.query("SELECT summary, content_hash FROM events WHERE id = ?", [eid])[0]
    assert new["summary"] == "See https://vendor.example/a?b=1&c=2 for the fix" and new["content_hash"] != old
    assert eid in {e["id"] for e in link.pending_events(10_000)}, "relinked once"
    store.mark_linked("event", [(eid, new["content_hash"])])
    assert eid not in {e["id"] for e in link.pending_events(10_000)}
    assert fix_encoded_events(src.id, squash=False) == 0


def test_prefilter_finds_upper_case_hex_entities():
    src = SOURCES["ransomware_live"]
    ev = Event(source=src.id, kind="ransomware", key=("g", "upper hex"), ts=dt.datetime(2026, 9, 3, tzinfo=dt.UTC),
               title="g claims O&#X27;Brien Ltd", summary=None, category="threat")
    _legacy_load(src, [ev])
    assert fix_encoded_events(src.id, squash=False) >= 1
    assert db.query("SELECT title FROM events WHERE id = ?", [make_id(src.id, "g", "upper hex")])[0]["title"] == "g claims O'Brien Ltd"


# ---------------------------------------------------------------- Bluesky
def _jet(i: int) -> dict:
    return json.loads(JET[i])


def test_bluesky_posts_are_plain_text():
    src = SOURCES["bluesky_cyber"]
    ev = src.post_event(_jet(1))
    text = ("Patch now: CVE-2026-90001 in Example Gate's R&D build is exploited, payload <script>alert(1)</script>\n"
            "via the name field.")
    assert ev.summary == text and ev.title == text[:140]
    assert ev.key == ("did:plc:exampleuser0000000000001", "3kexample01")
    assert ev.url == "https://bsky.app/profile/did:plc:exampleuser0000000000001/post/3kexample01"
    assert "CVE-2026-90001" in ev.tags and ev.severity == 0.55
    plain = src.post_event(_jet(2))
    assert plain.summary == "AT&T says the outage was not a cyberattack and no data breach happened &foo; today."
    assert src.post_event(_jet(3)) is None, "short casual post"
    assert src.post_event(_jet(4)) is None, "not English"


def test_bluesky_stream_stores_decoded_posts_and_fixes_old_ones(monkeypatch):
    """The stream loop on a fake Jetstream socket: posts stored before the fix are decoded when the stream connects
    (line breaks kept), new posts arrive decoded, and storing the same posts again changes nothing."""
    src = SOURCES["bluesky_cyber"]
    stale = Event(source=src.id, kind="social", key=("did:plc:exampleuser0000000000002", "3kold"),
                  ts=dt.datetime(2026, 11, 1, tzinfo=dt.UTC), title="Old &amp; encoded",
                  summary="Old &amp; encoded\nsecond line &#39;quoted&#39;", category="social",
                  url="https://bsky.app/profile/did:plc:exampleuser0000000000002/post/3kold")
    _legacy_load(src, [stale])

    class FakeSocket:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        def __aiter__(self):
            async def gen():
                for ln in JET:
                    yield ln
            return gen()

    monkeypatch.setattr(streams.websockets, "connect", lambda *a, **kw: FakeSocket())
    published = []
    monkeypatch.setattr(streams.bus, "publish", lambda topic, msg: published.append((topic, msg)))
    sink = StreamSink(src, None)
    monkeypatch.setattr(config, "OFFLINE", False)
    asyncio.run(src.stream(sink))
    evs = sink.drain()
    assert [e.key[1] for e in evs] == ["3kexample01", "3kexample02"]
    assert "<script>alert(1)</script>" in evs[0].summary and not any(x in evs[0].summary for x in ENTITY)
    assert [m["title"] for t, m in published if t == "social"] == [evs[0].title, evs[1].title]

    old = db.query("SELECT title, summary FROM events WHERE source = ? AND title LIKE 'Old%'", [src.id])[0]
    assert old == {"title": "Old & encoded", "summary": "Old & encoded\nsecond line 'quoted'"}

    started = dt.datetime.now(dt.UTC)
    n, changed = scheduler._load(src, scheduler._rows(evs, None, started), None)
    assert (n, changed) == (2, 2)
    n, changed = scheduler._load(src, scheduler._rows(evs, None, started), None)
    assert (n, changed) == (2, 0), "the same posts again: nothing new"
    assert fix_encoded_events(src.id, squash=False) == 0


# ---------------------------------------------------------------- ransomware.live
def test_ransomware_victims_are_plain_text_with_stable_ids():
    src = SOURCES["ransomware_live"]
    a, b = src.parse(RW)
    assert a.title == "examplegroup claims Smith & Sons Ltd"
    assert a.summary == "attack date 2026-11-01 · Leak of 40 GB – HR & finance files <b>soon</b>"
    assert a.key == ("examplegroup", "Smith &amp; Sons Ltd"), "the id keeps the provider's text: no duplicate victim"
    assert a.url == "https://leak.example/post?id=7&amp;x=1", "URLs are never decoded"
    assert a.tags == ["examplegroup"]
    assert b.title == "othergroup claims AT&T Example Co" and b.summary == "plain text, nothing encoded"
    assert dict(src.records(RW))["examplegroup|Smith &amp; Sons Ltd"]["victim"] == "Smith &amp; Sons Ltd"


def test_ransomware_runs_change_once():
    src = SOURCES["ransomware_live"]
    legacy = src.parse(RW)
    legacy[0].title, legacy[0].summary = "examplegroup claims Smith &amp; Sons Ltd", "attack date 2026-11-01 · Leak"
    _legacy_load(src, legacy)
    first = _run(src, RW)
    assert first["ok"] and first["items"] == 2 and first["changed"] == 1
    rows = _rows(src.id)
    assert rows[make_id(src.id, "examplegroup", "Smith &amp; Sons Ltd")]["title"] == "examplegroup claims Smith & Sons Ltd"
    second = _run(src, RW)
    assert second["ok"] and second["changed"] == 0 and second["records_changed"] == 0
    assert _rows(src.id) == rows


# ---------------------------------------------------------------- markup stays text
def test_decoded_markup_is_text_in_the_api():
    """'&lt;script&gt;' is stored as the text '<script>' and the API returns it as a JSON string. That the client shows
    it as text (escaped, never run) is the E2E journey tests/e2e/test_escaping.py."""
    from fastapi.testclient import TestClient

    from osinthub.api import app
    c = TestClient(app, base_url="http://localhost")   # no `with`: the lifespan (scheduler, sources) does not start
    r = c.get("/api/events", params={"sources": "nvd_recent", "limit": 50})
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
    by = {e["id"]: e for e in r.json()}
    e = by[make_id("nvd_recent", "CVE-2026-90001")]
    assert "<script>alert(1)</script>" in e["summary"]
    assert "\\u003cscript" in r.text or "<script>alert(1)</script>" in r.text   # JSON text, never markup
    one = c.get(f"/api/events/{e['id']}")
    assert one.status_code == 200 and one.json()["summary"] == CVE1


def test_shared_decoder_rules():
    """The one decoder every source uses: well-formed entities only, decoded to a fixed point, no control characters."""
    assert unentity("R&amp;D &#39;x&#39; &lt;b&gt;") == "R&D 'x' <b>"
    assert unentity("AT&T Q&notes a && b &foo;") == "AT&T Q&notes a && b &foo;"
    assert unentity("Smith &amp;amp; Sons") == "Smith & Sons"
    assert unentity(None) == ""
    assert unentity(unentity("&amp;lt;tag&amp;gt;")) == unentity("&amp;lt;tag&amp;gt;") == "<tag>"
