"""Feed parsers on fixed payloads (no network): RSS titles and summaries are plain text (double-encoded entities
decoded at ingest, events stored before that fixed on the source's next run, ix-code-r2-004), and IODA outages are
null-safe with a stable stored `value` (hence content_hash).

    uv run --with pytest pytest tests/sources/test_feed_parsing.py -q
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import json

from _lake import make_lake
LAKE = make_lake("feed-entities")

from osinthub import db  # noqa: E402
from osinthub.sources import SOURCES  # noqa: E402
from osinthub.sources.base import content_hash  # noqa: E402
from osinthub.sources.text import fix_encoded_events as _fix_encoded_events  # noqa: E402

db.connect()
XML = """<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>Incidents Move Too Fast for Pen &amp;amp; Paper</title><link>https://x.example/a</link>
<description>Risks &amp;amp; rewards &lt;b&gt;bold&lt;/b&gt; CVE-2000-0411 &amp;#x5b;CVE&amp;#x5d;. &amp;#xd more</description>
<pubDate>Mon, 09 Nov 2026 10:00:00 GMT</pubDate></item>
<item><title>AT&amp;T and R&amp;D stay as they are</title><link>https://x.example/b</link>
<pubDate>Mon, 09 Nov 2026 11:00:00 GMT</pubDate></item>
</channel></rss>"""


def test_parse_decodes_entities():
    src = SOURCES["news_darkreading"]
    evs = {e.url: e for e in src.parse(json.dumps({src.label: XML}).encode())}
    a, b = evs["https://x.example/a"], evs["https://x.example/b"]
    assert a.title == "Incidents Move Too Fast for Pen & Paper"
    assert "&amp;" not in a.summary and "&#x" not in a.summary and "Risks & rewards" in a.summary
    assert "[CVE]" in a.summary and "bold" in a.summary
    assert b.title == "AT&T and R&D stay as they are"


def test_only_well_formed_entities_are_decoded():
    from osinthub.sources.text import unentity as _unentity
    cases = {
        "Why &amp;amp; breaks parsers": "Why & breaks parsers",          # real double encoding
        "Pen &amp; Paper": "Pen & Paper",
        "YARA-X&#x26;#39&#x26;#x3b;s 1.22": "YARA-X's 1.22",            # three levels (SANS)
        "Q&#x26;A &#39;quoted&#39; &#x5b;CVE&#x5d;": "Q&A 'quoted' [CVE]",
        "observe. &#xd more": "observe.   more",                         # numeric without ';', CR -> space
        "Q&notes": "Q&notes", "R&D &copy law": "R&D &copy law", "price &pound5": "price &pound5",
        "AT&T &para &times &reg &not": "AT&T &para &times &reg &not",     # legacy names without ';' stay
        "a &foo; b": "a &foo; b", "&": "&", "&;": "&;", "&#; x": "&#; x", "": "",
        "nul &#0; bell &#7; ok": "nul � bell  ok",   # no control characters come out
    }
    for raw, want in cases.items():
        assert _unentity(raw) == want, (raw, _unentity(raw), want)
    assert _unentity(None) == ""


def test_stored_encoded_events_are_fixed_on_the_next_run():
    now = dt.datetime(2026, 11, 9, tzinfo=dt.UTC)
    for i, (sid, title, summary) in enumerate([
            ("news_darkreading", "Pen &amp; Paper", "Q&amp;A &#xd  with  spaces"),
            ("news_darkreading", "AT&T plain", "YARA-X&#x26;#39&#x26;#x3b;s 1.22"),
            ("news_therecord", "Other &amp; source", "x")]):
        db.execute("INSERT INTO events (id, source, kind, category, ts, title, summary) VALUES (?, ?, 'news', 'news', ?, ?, ?)",
                   [f"{sid}:t{i}", sid, now, title, summary])
    assert _fix_encoded_events("news_darkreading") == 2
    rows = {r["id"]: r for r in db.query("SELECT id, title, summary FROM events")}
    assert rows["news_darkreading:t0"]["title"] == "Pen & Paper" and rows["news_darkreading:t0"]["summary"] == "Q&A with spaces"
    assert rows["news_darkreading:t1"]["title"] == "AT&T plain" and rows["news_darkreading:t1"]["summary"] == "YARA-X's 1.22"
    assert rows["news_therecord:t2"]["title"] == "Other &amp; source", "only the running source is touched"
    assert _fix_encoded_events("news_darkreading") == 0, "idempotent"
    SOURCES["news_therecord"].prepare(b"{}", now)   # the scheduler calls prepare() before parse() on each run
    assert db.query("SELECT title FROM events WHERE id = 'news_therecord:t2'")[0]["title"] == "Other & source"


# ---------------------------------------------------------------- IODA outages
# Shaped like api.ioda.inetintel.cc.gatech.edu/v2/outages/events rows (as the fetcher combines them): scores
# are JSON ints when whole and floats otherwise (stored IODA events have both, e.g. 1200 and 1178910.0687285224).
ROWS = {
    "country": {"type": "outages.events", "error": None, "data": [
        {"location": "country/IR", "location_name": "Iran", "start": 1762250400, "duration": 7200, "uncertainty": None,
         "status": 0, "fraction": None, "score": 1200, "overlaps": [], "datasource": "ping-slash24"},
        {"location": "country/SY", "location_name": "Syria", "start": 1762254000, "duration": 3600, "uncertainty": None,
         "status": 0, "fraction": None, "score": 1178910.0687285224, "overlaps": [], "datasource": "bgp"},
        {"location": "country/CU", "location_name": "Cuba", "start": 1762257600, "duration": None, "uncertainty": None,
         "status": 0, "fraction": None, "score": None, "overlaps": [], "datasource": "merit-nt"},
    ]},
    "region": {"type": "outages.events", "error": None, "data": [
        {"location": "region/1234", "location_name": "Tehran", "start": 1762250400, "duration": 1800, "uncertainty": None,
         "status": 0, "fraction": None, "score": 15, "overlaps": [], "datasource": "gtr"},
    ]},
}
RAW = json.dumps(ROWS).encode()
COLLECTED = dt.datetime(2026, 11, 9, tzinfo=dt.UTC)


def _events():
    return {e.key[0]: e for e in SOURCES["ioda_outages"].parse(RAW)}


def test_value_keeps_the_providers_number():  # followB issue 4
    ev = _events()
    assert ev["country/IR"].value == 1200 and type(ev["country/IR"].value) is int
    assert ev["region/1234"].value == 15 and type(ev["region/1234"].value) is int
    assert ev["country/SY"].value == 1178910.0687285224
    assert ev["country/CU"].value is None and ev["country/CU"].severity == 0.25   # null score: no value, lowest band


def test_content_hash_matches_the_original_parser():  # an integer score must not re-store its event
    by_row = {r["location"]: r for scope in ROWS.values() for r in scope["data"]}
    for loc, e in _events().items():
        original = dataclasses.replace(e, value=by_row[loc]["score"])   # the original parser stored r.get("score")
        assert content_hash(e, COLLECTED) == content_hash(original, COLLECTED), loc
    # the float form hashes differently: what made integer-scored events count as changed
    e = _events()["country/IR"]
    assert content_hash(dataclasses.replace(e, value=1200.0), COLLECTED) != content_hash(e, COLLECTED)


def test_odd_scores_do_not_crash():
    odd = {"country": {"data": [
        {"location": "country/XX", "start": 1762250400, "score": "250.5", "duration": "60", "datasource": "bgp"},
        {"location": None, "start": 1762250400, "score": "n/a", "duration": "x", "datasource": None},
        {"location": "country/YY", "start": 1762250400, "score": True, "datasource": "bgp"},
    ]}}
    ev = SOURCES["ioda_outages"].parse(json.dumps(odd).encode())
    assert [e.value for e in ev] == [250.5, None, 1.0]
