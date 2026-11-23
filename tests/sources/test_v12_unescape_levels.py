"""Text encoded many times over (4 and 6 levels) on a lake built by the v1.2 code: the decoder is a fixed point, so
after the first run of the new code nothing churns. prepare() fixes nothing more, parse() changes no event, and no
further events delta goes to the lake. Covers nvd_recent, ransomware_live and an RSS source (news_darkreading), which
share the decode and fix path. No network: payloads are served by httpx.MockTransport.

    uv run --with pytest pytest tests/sources/test_v12_unescape_levels.py -q
"""
from __future__ import annotations

import asyncio
import datetime as dt
import html
import itertools
import json

from _lake import make_lake
LAKE = make_lake("unescape-levels", disable="news,entities,netlog,ai")

import httpx  # noqa: E402
import pytest  # noqa: E402

from osinthub import config, db, scheduler  # noqa: E402
from osinthub.sources import SOURCES, feeds, text  # noqa: E402
import osinthub.news.sources  # noqa: E402,F401  (registers the RSS news sources)

db.connect()


def enc(s: str, n: int) -> str:
    for _ in range(n):
        s = html.escape(s, quote=False)
    return s


def v12_unentity(s):
    """The v1.2 decoder, at most three levels (what a v1.2 lake's RSS events were decoded with)."""
    s = s or ""
    for _ in range(3):
        if "&" not in s:
            break
        d = text._ENTITY.sub(lambda m: html.unescape(m.group(0) if m.group(0).endswith(";") else m.group(0) + ";"),
                             text._SEMI.sub(r"\1;", s))
        if d == s:
            break
        s = d
    return text._CTRL.sub(" ", s)


NVD = json.dumps({"vulnerabilities": [
    {"cve": {"id": f"CVE-2026-9100{i}", "published": "2026-11-16T10:15:00.000", "vulnStatus": "Received",
             "descriptions": [{"lang": "en", "value": v}],
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]}}}
    for i, v in enumerate([enc("Four & levels <b>bold</b>", 4), enc("Six 'levels' & <i>more</i>", 6),
                           "Plain AT&T text, nothing to decode"])]}).encode()
RW = json.dumps([
    {"group": "examplegroup", "victim": enc("Smith & Sons", 4), "discovered": "2026-11-15 08:00:00",
     "description": enc("HR & finance <files>", 6)},
    {"group": "othergroup", "victim": "AT&T Example Co", "discovered": "2026-11-15 09:00:00", "description": "plain"},
]).encode()
RSS = f"""<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>{enc("Pen & Paper <b>four</b>", 5)}</title><link>https://x.example/l4</link>
<description>{enc("Risks & rewards", 7)}</description><pubDate>Mon, 16 Nov 2026 10:00:00 GMT</pubDate></item>
<item><title>Plain R&amp;D headline</title><link>https://x.example/plain</link>
<pubDate>Mon, 16 Nov 2026 11:00:00 GMT</pubDate></item>
</channel></rss>""".encode()


def _run(src, body: bytes):
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


def _delta_files(sid: str) -> set:
    return set((config.RAW_DIR / sid).rglob("*.events.ndjson.gz")) if (config.RAW_DIR / sid).exists() else set()


@pytest.mark.parametrize("sid,body", [("nvd_recent", NVD), ("ransomware_live", RW), ("news_darkreading", RSS)])
def test_many_levels_decode_once_then_stay_put(monkeypatch, sid, body):
    src = SOURCES[sid]
    clock = itertools.count()
    base = dt.datetime.now(dt.UTC)
    monkeypatch.setattr(scheduler, "now", lambda: base + dt.timedelta(seconds=2 * next(clock)))  # one file name per run

    # 1. the lake as the v1.2 code left it: NVD and ransomware.live text undecoded, RSS decoded at most 3 levels
    with monkeypatch.context() as m:
        m.setattr(feeds, "unentity", v12_unentity if sid.startswith("news_") else (lambda s: s or ""))
        m.setattr(feeds, "fix_encoded_events", lambda *a, **k: 0)
        legacy = _run(src, body)
    assert legacy["ok"] and legacy["changed"] == legacy["items"] > 0
    assert any(text.unentity(r["title"]) != r["title"] or text.unentity(r["summary"]) != r["summary"]
               for r in db.query("SELECT title, summary FROM events WHERE source = ?", [sid])), "the legacy lake is encoded"
    files0 = _delta_files(sid)

    # 2. five runs of the new code on the same payload
    fixes = []
    real_fix = text.fix_encoded_events
    monkeypatch.setattr(feeds, "fix_encoded_events", lambda *a, **k: fixes.append(real_fix(*a, **k)) or fixes[-1])
    runs = [_run(src, body) for _ in range(5)]
    assert all(r["ok"] for r in runs), runs
    changed = [r["changed"] for r in runs]
    assert len(fixes) == 5 and fixes[0] > 0 and fixes[1:] == [0, 0, 0, 0], fixes
    assert changed[1:] == [0, 0, 0, 0], changed
    assert [r["records_changed"] for r in runs] == [0] * 5
    assert len(_delta_files(sid) - files0) <= 1, sorted(_delta_files(sid) - files0)

    rows = db.query("SELECT title, summary FROM events WHERE source = ?", [sid])
    for r in rows:   # nothing left that the decoder would still change: a fixed point
        assert text.unentity(r["title"]) == r["title"] and text.unentity(r["summary"] or "") == (r["summary"] or ""), r
    joined = " ".join(f"{r['title']} {r['summary']}" for r in rows)
    assert "&amp;" not in joined and "&lt;" not in joined and "&#" not in joined, joined


def test_decoder_is_a_fixed_point():
    for n in range(1, 12):
        s = enc("A & B <c> 'd' \"e\"", n)
        once = text.unentity(s)
        assert once == "A & B <c> 'd' \"e\"" and text.unentity(once) == once, (n, once)
    for s in ("AT&T Q&notes &copy law &pound5 &foo; a && b", "&#39&#x3b;x", "&amp;#39&amp;#x3b;s", "nul &#0; bell &#7;"):
        assert text.unentity(text.unentity(s)) == text.unentity(s), s
    assert text.unentity("AT&T Q&notes &copy law &foo;") == "AT&T Q&notes &copy law &foo;"


def _plain_amp_rss() -> bytes:
    """Fresh-lake RSS items with plain '&' text (AT&T, R&D) and summaries longer than parse()'s 500-character cut,
    with the cut landing at every position of a word boundary (the fix round 3 churn repro)."""
    items = []
    for k in range(8):
        desc = "AT&amp;T and R&amp;D teams were hit. " + " ".join(["ordinary words follow"] * 30) + "x" * k
        items.append(f"<item><title>Telecom attack hits AT&amp;T customers {k}</title><link>https://x.example/att{k}</link>"
                     f"<description>{desc}</description><pubDate>Mon, 16 Nov 2026 1{k}:00:00 GMT</pubDate></item>")
    return f"""<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>{''.join(items)}</channel></rss>""".encode()


def test_plain_ampersand_long_summary_does_not_churn(monkeypatch):
    sid = "news_securityweek" if "news_securityweek" in SOURCES else "news_darkreading"
    src = SOURCES[sid]
    db.execute("DELETE FROM events WHERE source = ?", [sid])
    clock = itertools.count(1000)
    base = dt.datetime.now(dt.UTC)
    monkeypatch.setattr(scheduler, "now", lambda: base + dt.timedelta(seconds=2 * next(clock)))
    files0 = _delta_files(sid)
    fixes = []
    real_fix = text.fix_encoded_events
    monkeypatch.setattr(feeds, "fix_encoded_events", lambda *a, **k: fixes.append(real_fix(*a, **k)) or fixes[-1])
    body = _plain_amp_rss()
    runs = [_run(src, body) for _ in range(5)]
    assert all(r["ok"] for r in runs), runs
    assert runs[0]["changed"] == 8 and [r["changed"] for r in runs[1:]] == [0, 0, 0, 0], [r["changed"] for r in runs]
    assert fixes == [0] * 5, fixes
    assert len(_delta_files(sid) - files0) == 1
