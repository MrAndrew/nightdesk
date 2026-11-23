"""abuse.ch data linked into the rest of the app: entities and claims (families through Malpedia ids and aliases),
the AI exclusion (brief facts, embeddings), "listed by" on story IoCs and entity pages, the Sources API gate and
one-per-IP counting on the map and ranked panels.

    uv run --with pytest pytest tests/sources/test_abusech_links.py -q
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

os.environ.pop("ABUSECH_AUTH_KEY", None)
from _lake import make_lake
LAKE = make_lake("abusech-links", disable="news,netlog,ai")

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db, scheduler  # noqa: E402
from osinthub.entities import link, refdata, searcher, store  # noqa: E402
from osinthub.netlog import intervals  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402
from osinthub.sources import SOURCES  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
store.ensure_schema()

FX = Path(__file__).parent / "fixtures" / "abusech"
REF = Path(LAKE) / "test-ref"
REF.mkdir()
# A five-family slice of the MISP Malpedia galaxy (same shape as ref/misp-malpedia.json).
(REF / "misp-malpedia.json").write_text(json.dumps({"values": [
    {"value": v, "uuid": f"u-{i}", "description": "", "meta": {"refs": [f"https://malpedia.caad.fkie.fraunhofer.de/details/{m}"],
                                                             "synonyms": syn}}
    for i, (v, m, syn) in enumerate([("Dridex", "win.dridex", []), ("QakBot", "win.qakbot", ["Qbot", "Quakbot"]),
                                     ("Mozi", "elf.mozi", []), ("PureLogs Stealer", "win.purelogs", []),
                                     ("Cobalt Strike", "win.cobalt_strike", ["CobaltStrike", "BEACON"])])]}))
refdata.REF = REF
refdata._CAT = None

FEODO = json.dumps([{"ip_address": "198.51.100.23", "port": 443, "status": "online", "as_number": 64500,
                     "as_name": "EXAMPLE-AS", "country": "NL", "first_seen": "2026-11-01 10:00:00",
                     "last_online": "2026-11-09", "malware": "Dridex"}]).encode()


def _run(src, body: bytes):
    async def go():
        scheduler._client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=body)))
        try:
            return await scheduler.run_batch(src)
        finally:
            await scheduler._client.aclose()
            scheduler._client = None
    old, oldk = config.OFFLINE, config.ABUSECH_AUTH_KEY
    config.OFFLINE, config.ABUSECH_AUTH_KEY = False, "k-test"
    try:
        return asyncio.run(go())
    finally:
        config.OFFLINE, config.ABUSECH_AUTH_KEY = old, oldk


for sid, f in (("feodo_c2", None), ("threatfox", "threatfox_get_iocs.json"), ("urlhaus", "urlhaus_recent.json"),
               ("sslbl", "sslblacklist.csv")):
    assert _run(SOURCES[sid], FEODO if f is None else (FX / f).read_bytes())["ok"]
intervals.refresh()
while link.link_pending():
    pass


def _claims(subj=None, obj=None):
    return db.query("SELECT subj, predicate, obj, origin, sources FROM claims WHERE (? IS NULL OR subj = ?) AND (? IS NULL OR obj = ?)",
                    [subj, subj, obj, obj])


def test_families_resolve_through_malpedia_ids_and_aliases():
    # ThreatFox's win.dridex and Feodo's "Dridex" are one family; the C2 claim is corroborated by both lists
    c = [x for x in _claims("ip:198.51.100.23", "malware:dridex") if x["predicate"] == "hosts-malware"]
    assert len(c) == 1 and sorted(c[0]["sources"]) == ["feodo_c2", "threatfox"]
    cs = db.query("SELECT id FROM entities WHERE type = 'malware' AND name = 'Cobalt Strike'")[0]["id"]
    pl = db.query("SELECT id, attrs FROM entities WHERE type = 'malware' AND name = 'PureLogs Stealer'")[0]
    # SSLBL certificates are indicators, not activity: no hash entity, mention or claim per certificate; the family
    # ("PureLogsStealer C&C" resolves to PureLogs Stealer) gets one aggregated fact and at most one mention
    assert not db.query("SELECT 1 FROM entities WHERE type = 'hash' AND id IN ('hash:e8e1ee53a4b01fe4d284f3edf82c0dfd5b6c63cf', 'hash:abc4b076eb276da57cf8a36e7eeca9df713dd83c')")
    assert not db.query("SELECT 1 FROM claims WHERE list_contains(sources, 'sslbl')")
    assert json.loads(pl["attrs"])["sslbl_certificates"] == 5
    assert db.query("""SELECT count(*) AS n FROM mentions WHERE entity_id = ? AND ref_type = 'event'
                       AND split_part(ref_id, ':', 1) = 'sslbl'""", [pl["id"]])[0]["n"] == 1
    assert not db.query("SELECT 1 FROM entities WHERE name IN ('PureLogsStealer', 'OffLoader', 'Malware distribution')")
    # ThreatFox family per IOC: claims, but no family mention per IOC (mentions drive rankings)
    assert not db.query("""SELECT 1 FROM mentions WHERE entity_id = 'malware:dridex' AND split_part(ref_id, ':', 1) = 'threatfox'""")
    # URLhaus: the URL delivers Mozi (family from its tags), and the host IP is an indicator entity
    assert db.query("""SELECT 1 FROM claims WHERE subj LIKE 'url:%mozi.m' AND predicate = 'delivers' AND obj = 'malware:mozi'
                       AND list_contains(sources, 'urlhaus')""")
    # a ThreatFox C2 domain hosts Cobalt Strike (resolved by its Malpedia id win.cobalt_strike)
    assert _claims("domain:c2-panel.badcorp.example", cs)


def test_unknown_families_are_created_but_never_embedded():
    rows = db.query("SELECT id, attrs FROM entities WHERE type = 'malware' AND name = 'Lumma Stealer'")
    assert rows and json.loads(rows[0]["attrs"])["ai_excluded"]
    texts = []
    from osinthub import vectors
    from osinthub.ai import client
    old_embed, old_up = client.embed, vectors.upsert
    client.embed = lambda t, kind="document": texts.extend(t) or [[0.0] * 4 for _ in t]
    vectors.upsert = lambda *a, **k: None
    try:
        searcher.embed_pending(batch=500, max_batches=50)
    finally:
        client.embed, vectors.upsert = old_embed, old_up
    assert texts and not any("Lumma" in t for t in texts)
    assert any(t.startswith("malware: Dridex") for t in texts)          # catalogue families still embed


def test_brief_facts_leave_out_abusech_claims():
    from osinthub.news import brief
    ab = {"threatfox", "urlhaus", "sslbl", "feodo_c2"}   # Feodo too since the terms review (ToS s7.3: no AI use)
    cl = brief._claims("ip:198.51.100.23")
    assert all(not ab & set(c["sources"] or []) for c in cl)
    assert all(e.get("source") not in ab for c in cl for e in c["evidence"])
    assert not brief._claims("domain:c2-panel.badcorp.example")         # ThreatFox only: nothing reaches the LLM
    assert brief.trend("domain:c2-panel.badcorp.example")["total"] == 0


def test_listed_by_for_story_iocs_and_entity_pages():
    got = intervals.listed([("ip", "198.51.100.23"), ("domain", "x.c2-panel.badcorp.example"),
                            ("url", "hxxp://203.0.113.77:8080/bins/mozi.m"), ("hash", "ABC4B076EB276DA57CF8A36E7EECA9DF713DD83C"),
                            ("ip", "192.0.2.99")])
    assert {x["source"] for x in got[("ip", "198.51.100.23")]} == {"feodo_c2", "threatfox"}
    assert got[("ip", "198.51.100.23")][0]["active"] is True
    assert got[("domain", "x.c2-panel.badcorp.example")][0]["malware"] == "Cobalt Strike"   # parent domain listed
    assert {x["source"] for x in got[("url", "hxxp://203.0.113.77:8080/bins/mozi.m")]} == {"threatfox", "urlhaus"}
    assert got[("hash", "ABC4B076EB276DA57CF8A36E7EECA9DF713DD83C")][0]["source"] == "sslbl"
    assert ("ip", "192.0.2.99") not in got
    from osinthub.api import app
    c = TestClient(app, base_url="http://127.0.0.1")
    d = c.get("/api/entities/ip:198.51.100.23").json()
    assert {x["source"] for x in d["listed_by"]} == {"feodo_c2", "threatfox"}


def test_sources_api_shows_the_key_gate():
    from osinthub.api import app
    c = TestClient(app, base_url="http://127.0.0.1")
    s = {x["id"]: x for x in c.get("/api/sources").json()}
    for sid in ("threatfox", "urlhaus"):
        # the reason is plain words (v1.2 pf-ui); the setting's name is needs_key (Sources › Technical details)
        assert s[sid]["needs_key"] == "ABUSECH_AUTH_KEY" and "abuse.ch Auth-Key" in s[sid]["unavailable"]
        assert s[sid]["enabled"] is False and s[sid]["ai_ok"] is False and s[sid]["key_set"] is False
        r = c.post(f"/api/sources/{sid}/enable", params={"enabled": True})
        assert r.status_code == 409 and "abuse.ch Auth-Key" in r.json()["detail"]
    assert s["sslbl"]["unavailable"] is None and s["sslbl"]["needs_key"] is None
    assert "k-test" not in json.dumps(s)


def test_map_and_panels_count_each_ip_once():
    from osinthub.api import app
    c = TestClient(app, base_url="http://127.0.0.1")
    ip_events = db.query("SELECT id, source, ip FROM events WHERE ip = '198.51.100.23'")
    assert len(ip_events) == 3                                            # Feodo + two ThreatFox IOCs (two ports)
    # (the temporary lake has no GeoIP database, so /api/geo/points is empty here; it uses the same filter)
    top = {r["key"]: r["n"] for r in c.get("/api/stats/top", params={"field": "ip", "limit": 100}).json()}
    assert top.get("198.51.100.23") == 1
    # an address only ThreatFox and URLhaus carry (the Mozi host) also counts once
    assert top.get("203.0.113.77") == 1
    # the event list (Explorer) still shows every event
    ev = c.get("/api/events", params={"sources": "threatfox", "limit": 100}).json()
    assert len([e for e in ev if e["ip"] == "198.51.100.23"]) == 2


def test_brief_merged_claim_carries_no_abusech_numbers():
    from osinthub.news import brief
    stored = db.query("""SELECT confidence, sources FROM claims WHERE subj = 'ip:198.51.100.23' AND obj = 'malware:dridex'""")[0]
    assert sorted(stored["sources"]) == ["feodo_c2", "threatfox"]
    # both are abuse.ch (ai_ok = False), so the merged claim stays out of the brief entirely
    assert not [x for x in brief._claims("ip:198.51.100.23") if x["obj"] == "malware:dridex"]
    # a claim merged from an allowed source and an excluded one: the allowed part stays, without the merged numbers
    db.execute("""INSERT INTO claims VALUES ('test-merged', 'ip:198.51.100.23', 'hosts-malware', 'malware:test-merged',
                  'observed', ['et_compromised', 'threatfox'], 0.93, '2026-11-01T00:00:00Z', '2026-11-12T00:00:00Z', ?)""",
               [json.dumps([{"source": "threatfox", "ref_type": "event", "ref_id": "threatfox:x", "ts": "2026-11-01T00:00:00+00:00"},
                            {"source": "et_compromised", "ref_type": "event", "ref_id": "et_compromised:y", "ts": "2026-11-05T00:00:00+00:00"},
                            {"source": "threatfox", "ref_type": "event", "ref_id": "threatfox:z", "ts": "2026-11-12T00:00:00+00:00"}])])
    try:
        c = [x for x in brief._claims("ip:198.51.100.23") if x["obj"] == "malware:test-merged"][0]
        assert c["sources"] == ["et_compromised"] and c["confidence"] is None    # the merged score includes ThreatFox
        assert [e["source"] for e in c["evidence"]] == ["et_compromised"]
        assert c["first_seen"] == c["last_seen"] == "2026-11-05T00:00:00+00:00"  # dates from the allowed evidence only
    finally:
        db.execute("DELETE FROM claims WHERE id = 'test-merged'")


def test_event_drawer_links_to_ioc_and_family():
    from osinthub.api import app
    c = TestClient(app, base_url="http://127.0.0.1")
    eid = db.query("SELECT id FROM events WHERE source = 'threatfox' AND title LIKE 'Cobalt Strike C2%'")[0]["id"]
    ents = {x["id"]: x for x in c.get(f"/api/events/{eid}").json()["entities"]}
    assert "domain:c2-panel.badcorp.example" in ents
    cs = db.query("SELECT id FROM entities WHERE type = 'malware' AND name = 'Cobalt Strike'")[0]["id"]
    assert ents[cs]["role"] == "hosts-malware"
