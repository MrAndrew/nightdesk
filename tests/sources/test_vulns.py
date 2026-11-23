"""FIRST EPSS and CISA CSAF advisories on a temporary lake, from real excerpts in tests/sources/fixtures/
(no network: the providers are served by httpx.MockTransport, through the real scheduler run).

    uv run --with pytest pytest tests/sources/test_vulns.py -q
"""
from __future__ import annotations

import asyncio
import copy
import datetime as dt
import gzip
import json
from pathlib import Path

from _lake import make_lake
LAKE = make_lake("vulns")

import httpx  # noqa: E402
import pytest  # noqa: E402

from osinthub import config, db, scheduler  # noqa: E402
from osinthub.sources import SOURCES, vulns  # noqa: E402
from osinthub.sources.base import make_id  # noqa: E402

db.connect()
FX = Path(__file__).parent / "fixtures"
FIXED_NOW = dt.datetime(2026, 11, 9, 18, 0, tzinfo=dt.UTC)
vulns.now = lambda: FIXED_NOW          # the CSAF window is relative to "now"; fixtures are from 2026-11-09
vulns.EPSS_MIN_ROWS = 10               # the excerpts are small; the real floor is 100,000 rows
EPSS = SOURCES["epss"]
ADV = SOURCES["cisa_advisories"]
DAY1, DAY2 = (FX / "epss_day1.csv").read_bytes(), (FX / "epss_day2.csv").read_bytes()


def _run(src, handler):
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


def _epss_server(day: str, body: bytes, seen: list):
    def handler(req):
        seen.append(str(req.url))
        if req.url.path.endswith("epss_scores-current.csv.gz"):
            return httpx.Response(302, headers={"location": f"epss_scores-{day}.csv.gz"})
        if req.url.path.endswith(f"epss_scores-{day}.csv.gz"):
            return httpx.Response(200, content=gzip.compress(body))
        return httpx.Response(404)
    return handler


def _csv_rows(raw: bytes) -> dict:
    lines = raw.decode().splitlines()[2:]
    return {l.split(",")[0]: float(l.split(",")[1]) for l in lines}


def _seed_kev(cves):
    """KEV events for a few CVEs (the app's own CVEs that EPSS events are made for)."""
    kev = {"vulnerabilities": [{"cveID": c, "vendorProject": "Example", "product": "Gate", "vulnerabilityName": "Example flaw",
                                "dateAdded": "2026-11-01", "shortDescription": "x", "knownRansomwareCampaignUse": "Unknown"}
                               for c in cves]}
    res = _run(SOURCES["cisa_kev"], lambda req: httpx.Response(200, json=kev))
    assert res["ok"], res


# ---------------------------------------------------------------- EPSS parsing
def test_parse_epss_rejects_junk():
    raw = DAY2 + b"CVE-BAD,0.1,0.2\nCVE-2024-0001,1.5,0.2\nCVE-2024-0002,0.1\nCVE-2021-44228,0.5,0.5\n"
    meta, rows = vulns.parse_epss(raw)
    assert meta["model_version"] == "v2026.06.15"
    assert meta["score_date"].startswith("2026-11-09T12:00:23")
    assert meta["rejected"] == 4                       # bad id, out of range, short row, duplicate
    assert len(rows) == len(_csv_rows(DAY2))
    assert all(0 <= e <= 1 and 0 <= p <= 1 for _, e, p in rows)
    assert dict((c, e) for c, e, _ in rows)["CVE-2021-44228"] == _csv_rows(DAY2)["CVE-2021-44228"]   # the first copy wins
    with pytest.raises(ValueError, match="header"):
        vulns.parse_epss(b"cve,epss,percentile\nCVE-2024-0001,0.1,0.2\n")
    old = vulns.EPSS_MIN_ROWS
    vulns.EPSS_MIN_ROWS = 100_000
    try:
        with pytest.raises(ValueError, match="first load"):   # nothing loaded yet: the absolute floor applies
            EPSS.records(DAY2 + b"\n")
    finally:
        vulns.EPSS_MIN_ROWS = old
    assert vulns.epss_pct(0.97) == "97.0%" and vulns.epss_pct(0.04753) == "4.75%" and vulns.epss_pct(0.00046) == "0.05%"


def _totals():
    return db.query("SELECT count(*) n, max(ingested_at) i FROM events")[0]["n"]


# ---------------------------------------------------------------- EPSS through the scheduler
def test_epss_runs_store_only_changed_scores_and_make_no_events():
    _seed_kev(["CVE-2021-44228", "CVE-2024-3400"])
    before = _totals()
    d1, d2 = _csv_rows(DAY1), _csv_rows(DAY2)
    seen: list = []
    r1 = _run(EPSS, _epss_server("2026-11-08", DAY1, seen))
    assert r1["ok"], r1
    assert r1["records_changed"] == len(d1) + 1                  # every CVE once, plus the #meta record
    assert r1["items"] == 0 and r1["changed"] == 0                # enrichment, not activity: no events at all
    assert db.query("SELECT count(*) n FROM epss")[0]["n"] == len(d1)
    assert _totals() == before
    st = scheduler.state("epss")
    assert st["items_total"] == len(d1) and st["message"].startswith(f"{len(d1):,} records")

    r2 = _run(EPSS, _epss_server("2026-11-09", DAY2, seen))
    assert r2["ok"], r2
    changed = {c for c in d2 if c not in d1 or d1[c] != d2[c]}
    assert r2["records_changed"] == len(changed) + 1               # changed or new CVEs, plus #meta (new score date)
    assert r2["records_removed"] == len(set(d1) - set(d2))
    rows = {r["cve"]: r for r in db.query("SELECT * FROM epss")}
    assert len(rows) == len(d2)
    moved = next(c for c in changed if c in d1)
    same = next(c for c in d2 if c in d1 and d1[c] == d2[c])
    assert rows[moved]["prev_epss"] == d1[moved] and rows[moved]["since"].date() == dt.date(2026, 11, 9)
    assert rows[same]["prev_epss"] is None and rows[same]["since"].date() == dt.date(2026, 11, 8)
    assert all(0 <= r["percentile"] <= 1 for r in rows.values())
    # the lake holds the probability only (the percentile is a rank that moves daily for almost every CVE)
    rec = db.query("SELECT raw_path FROM runs WHERE source = 'epss' ORDER BY started DESC LIMIT 1")[0]["raw_path"]
    with gzip.open(rec, "rt") as fh:
        lines = [json.loads(l) for l in fh]
    puts = {l["key"]: l["data"] for l in lines if l["op"] == "put"}
    assert set(puts) == changed | {"#meta"} and puts[moved] == {"epss": d2[moved]}
    assert _totals() == before
    assert not db.query("SELECT 1 FROM events WHERE source = 'epss' OR kind = 'epss'")

    n_runs = db.query("SELECT count(*) n FROM runs WHERE source = 'epss'")[0]["n"]
    seen.clear()
    r3 = _run(EPSS, _epss_server("2026-11-09", DAY2, seen))     # same day again: no download at all
    assert r3["ok"] and r3.get("unchanged"), r3
    assert len(seen) == 1 and seen[0].endswith("epss_scores-current.csv.gz")
    assert db.query("SELECT count(*) n FROM runs WHERE source = 'epss'")[0]["n"] == n_runs + 1
    assert scheduler.state("epss")["status"] == "ok"


def _day(raw: bytes, day: str) -> bytes:
    return raw.replace(b"score_date:2026-11-09T12:00:23Z", f"score_date:{day}T12:00:00Z".encode())


def test_epss_failure_mid_run_leaves_state_consistent_and_retry_reloads(monkeypatch):
    from osinthub import lake
    d3 = _day(DAY2.replace(b"CVE-2021-44228,0.99999", b"CVE-2021-44228,0.95"), "2026-11-10")
    assert d3 != _day(DAY2, "2026-11-10")
    real = lake.write_records

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(lake, "write_records", boom)
    r = _run(EPSS, _epss_server("2026-11-10", d3, []))
    assert not r["ok"] and "disk full" in r["error"]
    assert vulns.epss_latest_date() == dt.date(2026, 11, 9)        # the table did not move
    monkeypatch.setattr(lake, "write_records", real)
    # a failure in the last step (the table swap) also leaves the table as it was
    monkeypatch.setattr(type(EPSS), "commit", lambda self, raw, at: (_ for _ in ()).throw(RuntimeError("swap failed")))
    r = _run(EPSS, _epss_server("2026-11-10", d3, []))
    assert not r["ok"] and vulns.epss_latest_date() == dt.date(2026, 11, 9)
    monkeypatch.undo()
    r = _run(EPSS, _epss_server("2026-11-10", d3, []))              # retried for real, not "already loaded"
    assert r["ok"] and not r.get("unchanged"), r
    assert vulns.epss_latest_date() == dt.date(2026, 11, 10)
    assert db.query("SELECT epss FROM epss WHERE cve = 'CVE-2021-44228'")[0]["epss"] == 0.95
    # the changed score is in the lake exactly once (written by the run whose record step succeeded)
    puts = []
    for f in (config.RAW_DIR / "epss").rglob("*.records.ndjson.gz"):
        with gzip.open(f, "rt") as fh:
            puts += [json.loads(l) for l in fh if '"CVE-2021-44228"' in l]
    assert [p["data"]["epss"] for p in puts if p["op"] == "put"].count(0.95) == 1


def test_epss_partial_or_mismatched_file_is_refused():
    head = b"\n".join(DAY2.splitlines()[:12]) + b"\n"               # header + 10 rows of ~42 loaded
    r = _run(EPSS, _epss_server("2026-11-11", _day(head, "2026-11-11"), []))
    assert not r["ok"] and "partial download" in r["error"], r
    r = _run(EPSS, _epss_server("2026-11-11", _day(DAY2, "2026-11-12"), []))
    assert not r["ok"] and "server named 2026-11-11" in r["error"], r
    assert vulns.epss_latest_date() == dt.date(2026, 11, 10)
    assert db.query("SELECT count(*) n FROM epss")[0]["n"] == len(_csv_rows(DAY2))


def test_epss_older_file_does_not_regress_table():
    before = db.query("SELECT max(score_date) d, count(*) n FROM epss")[0]
    EPSS._expected_date = None
    EPSS.commit(DAY1, FIXED_NOW)
    after = db.query("SELECT max(score_date) d, count(*) n FROM epss")[0]
    assert after == before


def test_purge_removes_round1_epss_events_and_mentions():
    from osinthub.entities import store
    store.ensure_schema()
    db.execute("""INSERT INTO events (id, source, kind, category, ts, title, value) VALUES
                  ('epss:abc', 'epss', 'epss', 'vuln', '2026-11-09T12:00:00Z', 'CVE-2006-1547 · EPSS 1.00%', 0.01)""")
    db.execute("INSERT INTO entities VALUES ('cve:cve-2006-1547', 'cve', 'CVE-2006-1547', [], '{}', '2022-01-01', '2026-11-09')")
    db.execute("INSERT INTO mentions VALUES ('cve:cve-2006-1547', 'event', 'kev:1', 'subject', 'field', 1.0, '2022-01-01')")
    db.execute("INSERT INTO mentions VALUES ('cve:cve-2006-1547', 'event', 'epss:abc', 'subject', 'field', 1.0, '2026-11-09')")
    db.execute("INSERT INTO entity_linked VALUES ('event', 'epss:abc', 'h', now())")
    assert vulns.purge_epss_events() == 2
    assert not db.query("SELECT 1 FROM events WHERE source = 'epss'")
    assert not db.query("SELECT 1 FROM mentions WHERE ref_id LIKE 'epss:%'")
    assert not db.query("SELECT 1 FROM entity_linked WHERE ref_id LIKE 'epss:%'")
    e = db.query("SELECT last_seen FROM entities WHERE id = 'cve:cve-2006-1547'")[0]
    assert e["last_seen"].year == 2022                              # no longer "seen today" because of a score
    assert vulns.purge_epss_events() == 0


# ---------------------------------------------------------------- CSAF advisories
def _csaf_files():
    files = {}
    for f in FX.glob("csaf_*_changes.csv"):
        files[f"{f.name.split('_')[1]}/white/changes.csv"] = f.read_bytes()
    for f in FX.glob("csaf_*_*_*.json"):
        _, folder, year, name = f.name.split("_", 3)
        files[f"{folder}/white/{year}/{name}"] = f.read_bytes()
    return files


def _csaf_server(files: dict, seen: list):
    def handler(req):
        p = req.url.path.split("/csaf_files/", 1)[-1]
        seen.append(p)
        if p in files:
            return httpx.Response(200, content=files[p])
        return httpx.Response(404, text="Not Found")
    return handler


def test_csaf_advisories_dedupe_update_and_cache():
    files = _csaf_files()
    seen: list = []
    r = _run(ADV, _csaf_server(files, seen))
    assert r["ok"], r
    evs = {e["title"].split(":")[0]: e for e in db.query("SELECT * FROM events WHERE source = 'cisa_advisories'")}
    # VA-26-267-01 is in both IT/ and VA/: one event, the later revision (IT/)
    assert set(evs) == {"ICSA-26-307-01", "ICSA-25-275-02", "VA-26-294-01", "VA-26-267-01", "ICSMA-26-295-01"}
    assert len(db.query("SELECT * FROM events WHERE source = 'cisa_advisories'")) == 5
    e = evs["ICSA-26-307-01"]
    assert e["id"] == make_id("cisa_advisories", "ICSA-26-307-01")
    assert e["kind"] == "advisory" and e["category"] == "news"
    assert e["url"] == "https://www.cisa.gov/news-events/ics-advisories/icsa-26-307-01"
    assert e["ts"] == dt.datetime(2026, 11, 3, 6, tzinfo=dt.UTC)
    assert e["value"] == 9.0 and e["severity"] == 0.9
    assert {"CVE-2026-63017", "CVE-2026-63774", "Subnet Solutions", "ICS advisory"} <= set(e["tags"])
    assert "IT" not in evs["VA-26-294-01"]["tags"]           # never a bare "IT" (read as Italy's country code)
    assert evs["VA-26-294-01"]["url"].startswith("https://github.com/cisagov/CSAF/blob/develop/csaf_files/IT/white/")
    upd = evs["ICSA-25-275-02"]                               # revised in 2026: ts is the latest revision
    assert upd["ts"].date() == dt.date(2026, 10, 29) and "first published 2025-09-30" in upd["summary"]
    va = db.query("SELECT * FROM advisory_cves WHERE advisory = 'VA-26-267-01'")
    assert len(va) == 1 and va[0]["cvss"] == 5.5
    rows = db.query("SELECT * FROM advisory_cves WHERE advisory = 'ICSA-26-307-01' ORDER BY cve")
    assert [x["cve"] for x in rows] == ["CVE-2026-63017", "CVE-2026-63774"]
    assert rows[0]["vendors"] == ["Subnet Solutions"] and rows[0]["products"] == ["Subnet Solutions PowerSYSTEM Center"]   # 2020/2024/2026 editions: one family

    # second run: documents come from the cache, nothing is stored again
    seen.clear()
    r2 = _run(ADV, _csaf_server(files, seen))
    assert r2["ok"] and r2["records_changed"] == 0 and r2["changed"] == 0, r2
    assert all(p.endswith("changes.csv") for p in seen), seen

    # CISA revises an advisory: changes.csv moves, the document is fetched again and the same event is updated
    doc = json.loads(files["OT/white/2026/icsa-26-307-01.json"])
    doc2 = copy.deepcopy(doc)
    doc2["document"]["title"] += " (Update A)"
    doc2["document"]["tracking"]["version"] = "2"
    doc2["document"]["tracking"]["current_release_date"] = "2026-11-06T06:00:00.000000Z"
    files2 = dict(files)
    files2["OT/white/2026/icsa-26-307-01.json"] = json.dumps(doc2).encode()
    files2["OT/white/changes.csv"] = files["OT/white/changes.csv"].replace(
        b'"2026/icsa-26-307-01.json","2026-11-03T06:00:00.000000Z"', b'"2026/icsa-26-307-01.json","2026-11-06T06:00:00.000000Z"')
    seen.clear()
    r3 = _run(ADV, _csaf_server(files2, seen))
    assert r3["ok"] and r3["records_changed"] == 1 and r3["changed"] == 1, r3
    assert [p for p in seen if p.endswith(".json")] == ["OT/white/2026/icsa-26-307-01.json"]
    rows = db.query("SELECT * FROM events WHERE source = 'cisa_advisories' AND title LIKE 'ICSA-26-307-01%'")
    assert len(rows) == 1 and rows[0]["title"].endswith("(Update A)") and rows[0]["ts"].date() == dt.date(2026, 11, 6)
    assert db.query("SELECT count(*) n FROM events WHERE source = 'cisa_advisories'")[0]["n"] == 5


def test_csaf_partial_failure_keeps_the_rest():
    files = _csaf_files()
    files.pop("OT/white/2026/icsma-26-295-01.json")
    import shutil
    shutil.rmtree(vulns._csaf_cache(), ignore_errors=True)    # force downloads
    r = _run(ADV, _csaf_server(files, []))
    assert r["ok"], r
    st = scheduler.state("cisa_advisories")
    assert st["status"] == "error" and "icsma-26-295-01" in st["message"]
    assert db.query("SELECT count(*) n FROM events WHERE source = 'cisa_advisories'")[0]["n"] == 5   # nothing lost


def test_parse_changes_skips_junk():
    rows = vulns.parse_changes('"2026/a.json","2026-11-03T06:00:00Z"\n../x.json,2026-11-03T06:00:00Z\nnot,a,row\n'
                               '2026/b.json,not-a-date\n2026/c.json,2026-11-04T06:00:00Z\n')
    assert [p for p, _ in rows] == ["2026/a.json", "2026/c.json"]


# ---------------------------------------------------------------- enrichment, drawer context, API
def test_cve_enrichment_epss_and_advisories():
    from osinthub.news.api import cve_enrichment
    out = {c["id"]: c for c in cve_enrichment(["CVE-2026-63017", "cve-2021-44228", "CVE-1900-0001"])}
    a = out["CVE-2026-63017"]
    d2 = _csv_rows(DAY2)
    assert a["epss"] == d2["CVE-2026-63017"] and a["epss_status"] == "ok" and 0 <= a["epss_percentile"] <= 1
    assert a["cvss"] == 9.0 and a["cvss_status"] == "from CISA advisory" and a["severity"] == "critical"
    assert [x["id"] for x in a["advisories"]] == ["ICSA-26-307-01"]
    assert out["CVE-2021-44228"]["kev"] and out["CVE-2021-44228"]["epss"] == 0.95 and out["CVE-2021-44228"]["epss_prev"] == d2["CVE-2021-44228"]
    assert out["CVE-1900-0001"]["epss_status"] == "not scored" and out["CVE-1900-0001"]["epss"] is None


def test_event_drawer_context_and_story_link():
    from osinthub.news.common import ensure_schema
    ensure_schema()
    db.execute("""INSERT INTO articles (id, url, source, title, text, published, status, tier, role, story_id)
                  VALUES ('art1', 'https://news.example/ics', 'SecurityWeek', 'ICS Patch Tuesday',
                          'CISA published ICSA-26-307-01 for Subnet Solutions PowerSYSTEM Center.', '2026-11-04T10:00:00Z',
                          'ok', 'B', 'news', 'st1')""")
    db.execute("""INSERT INTO stories (id, title, first_seen, last_seen, article_count, source_count)
                  VALUES ('st1', 'ICS Patch Tuesday', '2026-11-04T10:00:00Z', '2026-11-04T10:00:00Z', 1, 1)""")
    # the advisory's own page queued as an article (from its news-category event) is not coverage of itself
    db.execute("""INSERT INTO articles (id, url, source, title, text, published, status, tier, role, story_id, source_id)
                  VALUES ('art2', 'https://www.cisa.gov/news-events/ics-advisories/icsa-26-307-01', 'CISA',
                          'ICSA-26-307-01: Subnet Solutions PowerSYSTEM Center', '', '2026-11-03T06:00:00Z', 'ok', 'A', 'news', 'st2',
                          'cisa_advisories')""")
    db.execute("""INSERT INTO stories (id, title, first_seen, last_seen, article_count, source_count)
                  VALUES ('st2', 'ICSA-26-307-01: Subnet Solutions PowerSYSTEM Center', '2026-11-03T06:00:00Z', '2026-11-03T06:00:00Z', 1, 1)""")
    e = db.query("SELECT * FROM events WHERE source = 'cisa_advisories' AND title LIKE 'ICSA-26-307-01%'")[0]
    ctx = vulns.event_vuln_context(e)
    assert ctx["advisory_id"] == "ICSA-26-307-01"
    assert [c["id"] for c in ctx["cves"]] == ["CVE-2026-63017", "CVE-2026-63774"]
    assert [s["id"] for s in ctx["stories"]] == ["st1"] and ctx["stories"][0]["matched"] == ["ICSA-26-307-01"]
    k = db.query("SELECT * FROM events WHERE source = 'cisa_kev' AND title LIKE 'CVE-2021-44228%'")[0]
    assert [c["id"] for c in vulns.event_vuln_context(k)["cves"]] == ["CVE-2021-44228"]
    assert vulns.event_vuln_context({"kind": "c2", "title": "x"}) == {}


def test_api_event_and_bulk_epss():
    from fastapi.testclient import TestClient
    from osinthub.api import app
    c = TestClient(app, base_url="http://127.0.0.1")
    e = db.query("SELECT id FROM events WHERE source = 'cisa_advisories' AND title LIKE 'ICSA-26-307-01%'")[0]["id"]
    j = c.get(f"/api/events/{e}").json()
    assert [x["id"] for x in j["cves"]] == ["CVE-2026-63017", "CVE-2026-63774"] and j["stories"][0]["id"] == "st1"
    r = c.post("/api/news/epss", json={"ids": ["CVE-2021-44228", "not-a-cve", "CVE-1900-0001"]}).json()
    assert set(r["scores"]) == {"CVE-2021-44228"} and r["model_version"] == "v2026.06.15"
    assert c.post("/api/news/epss", json={"ids": "CVE-2021-44228"}).status_code == 400
    cv = c.get("/api/news/cves", params={"ids": "CVE-2026-63017"}).json()[0]
    assert cv["epss_status"] == "ok" and cv["advisories"][0]["id"] == "ICSA-26-307-01"


def test_entities_link_advisory_products_and_claims():
    try:
        from osinthub.entities import link
    except Exception as ex:  # entities extension unavailable
        pytest.skip(f"entities package: {ex}")
    link.link_pending(5000)
    adv = db.query("SELECT id FROM events WHERE source = 'cisa_advisories' AND title LIKE 'ICSA-26-307-01%'")[0]["id"]
    ments = {r["entity_id"] for r in db.query("SELECT entity_id FROM mentions WHERE ref_type = 'event' AND ref_id = ?", [adv])}
    assert {"cve:cve-2026-63017", "cve:cve-2026-63774", "vendor:subnet-solutions"} <= ments
    assert not any(m.startswith("country:it") for m in ments)
    cl = db.query("SELECT subj, predicate, obj, origin FROM claims WHERE subj = 'cve:cve-2026-63017' AND predicate = 'affects'")
    assert cl and all(c["origin"] == "observed" for c in cl)
    made = db.query("SELECT obj FROM claims WHERE predicate = 'made-by' AND subj = ?", [cl[0]["obj"]])
    assert made and made[0]["obj"] == "vendor:subnet-solutions"
    # model numbers collapse to the product family: one product per family, not per SKU
    prods = db.query("SELECT obj FROM claims WHERE subj = 'cve:cve-2026-63017' AND predicate = 'affects'")
    assert [p["obj"] for p in prods] == ["product:subnet-solutions-powersystem-center"]
    assert not db.query("SELECT 1 FROM mentions WHERE ref_id LIKE 'epss:%'")
    from osinthub.entities.api import detail
    d = detail("cve:cve-2026-63017", evidence=5, bucket="day")
    assert d["attrs"]["epss"] == _csv_rows(DAY2)["CVE-2026-63017"] and d["attrs"]["advisories"][0]["id"] == "ICSA-26-307-01"


# ---------------------------------------------------------------- default flip
def test_default_flip_clears_saved_off_once():
    db.execute("DELETE FROM settings WHERE key = 'sources.default_flips'")
    scheduler._set_state("cisa_advisories", enabled=False)
    scheduler._apply_default_flips()
    assert scheduler.state("cisa_advisories")["enabled"] is None and scheduler.is_enabled(ADV)
    scheduler._set_state("cisa_advisories", enabled=False)           # the user turns it off afterwards: kept
    scheduler._apply_default_flips()
    assert scheduler.state("cisa_advisories")["enabled"] is False
