"""abuse.ch ThreatFox, URLhaus and SSLBL: parsing, keys, the Auth-Key gate, and netlog matching end to end.

    uv run --with pytest pytest tests/sources/test_abusech.py -q

Fixtures (tests/sources/fixtures/abusech/): sslblacklist.csv is a trimmed real download (2026-11-09);
the ThreatFox and URLhaus payloads are synthetic, built from abuse.ch's documented response formats,
because no Auth-Key was available. No network: fetches go to httpx.MockTransport.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import gzip
import io
import json
import sys
import time
from pathlib import Path

KEY = "test-auth-key-6f1d2c9a0b7e"
from _lake import make_lake  # noqa: E402
LAKE = make_lake("abusech", ABUSECH_AUTH_KEY=KEY)

import httpx  # noqa: E402

from osinthub import config, db, scheduler  # noqa: E402
from osinthub.netlog import importer, intervals  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402
from osinthub.sources import SOURCES, abusech  # noqa: E402
from osinthub.sources.base import make_id  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _abusech_ref  # noqa: E402

_abusech_ref.install(LAKE)

FX = Path(__file__).parent / "fixtures" / "abusech"
TF = (FX / "threatfox_get_iocs.json").read_bytes()
UH = (FX / "urlhaus_recent.json").read_bytes()
SSL = (FX / "sslblacklist.csv").read_bytes()
FEODO = json.dumps([{"ip_address": "198.51.100.23", "port": 443, "status": "online", "hostname": None,
                     "as_number": 64500, "as_name": "EXAMPLE-AS", "country": "NL", "first_seen": "2026-11-01 10:00:00",
                     "last_online": "2026-11-09", "malware": "Dridex"}]).encode()
CERT = "abc4b076eb276da57cf8a36e7eeca9df713dd83c"           # PureLogsStealer C&C in the SSLBL fixture
SAMPLE = "0c3f8d6e2a1b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5"   # ThreatFox sha256 IOC
SEEN: list[httpx.Request] = []

# Record files are named by the second (sources/base.raw_path_for), so two runs in one second would share a name. Each
# run here gets its own second instead of the test waiting for the clock: run n is named n seconds after it started.
_RUNS = iter(range(1, 10_000))
_real_raw_path_for = scheduler.raw_path_for
_shift: dict = {}


def _ordered_raw_path_for(source_id, ext, ts=None):
    ts = ts or scheduler.now()
    return _real_raw_path_for(source_id, ext, ts + dt.timedelta(seconds=_shift.setdefault(ts, next(_RUNS))))


scheduler.raw_path_for = _ordered_raw_path_for


def _run(src, body: bytes, status: int = 200):
    def handler(req):
        SEEN.append(req)
        return httpx.Response(status, content=body)

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


# ---------------------------------------------------------------- parsing and keys
def test_threatfox_parse_rejects_junk_and_dedups():
    s = SOURCES["threatfox"]
    evs = s.parse(TF)
    recs = s.records(TF)
    ids = [e.key[0] for e in evs]
    assert len(ids) == len(set(ids)) == 8                      # 12 rows: 3 junk, 1 duplicate id
    assert sorted(k for k, _ in recs) == sorted(ids)
    assert len({make_id("threatfox", *e.key) for e in evs}) == 8
    by = {e.key[0]: e for e in evs}
    e = by["1610001"]
    assert e.kind == "malware_ioc" and e.ip == "198.51.100.23" and e.title == "Dridex C2 198.51.100.23:443"
    assert e.ts.isoformat() == "2026-11-09T08:12:44+00:00"   # provider first_seen, UTC
    assert e.severity == 0.85 and e.value == 100 and e.url == "https://threatfox.abuse.ch/ioc/1610001/"
    assert e.tags == ["Dridex", "botnet_cc"]                  # "dridex" tag folded into the family
    assert by["1610007"].ip == "2001:db8:4::17" and by["1610007"].title.endswith("[2001:db8:4::17]:4444")
    assert by["1610007"].title.startswith("Unknown malware") and "Unknown malware" not in by["1610007"].tags
    assert by["1610008"].title.endswith("maliciousdomain.example")   # lower-cased, trailing dot gone
    assert 0 < min(x.severity for x in evs) and max(x.severity for x in evs) <= 1


def test_threatfox_keys_are_stable_across_runs():
    s = SOURCES["threatfox"]
    assert s.records(TF) == s.records(TF)
    assert [e.key for e in s.parse(TF)] == [e.key for e in s.parse(TF)]


def test_threatfox_api_errors():
    s = SOURCES["threatfox"]
    assert s.records(b'{"query_status": "no_result", "data": "Your search did not yield any results"}') == []
    try:
        s.records(b'{"query_status": "unknown_auth_key"}')
    except RuntimeError as e:
        assert "unknown_auth_key" in str(e)
    else:
        raise AssertionError("an API error must fail the run")


def test_urlhaus_parse():
    s = SOURCES["urlhaus"]
    evs = s.parse(UH)
    assert [e.key[0] for e in evs] == ["3300001", "3300002", "3300003", "3300004"]   # junk + duplicate dropped
    by = {e.key[0]: e for e in evs}
    assert by["3300001"].ip == "203.0.113.77" and by["3300001"].severity == 0.7
    assert by["3300001"].tags == ["32-bit", "elf", "mips", "Mozi", "online"]
    assert by["3300002"].ip is None and "Spamhaus DBL abused_legit_malware" in by["3300002"].summary
    assert by["3300003"].severity == 0.4                       # offline
    assert by["3300004"].ip == "2001:db8:5::9"
    assert abusech.uh_family(["32-bit", "elf", "mips", "Mozi"]) == "Mozi"
    assert abusech.uh_family(["cve-2017-11882", "base64", "geofenced", "Qbot"]) == "QakBot"   # through the catalogue
    for junk in (["exe", "zip"], ["cve-2017-11882", "Formbook"], ["base64", "AsyncRAT"], ["phishing", "html", "trojan"],
                 ["wordpress", "hacked", "geofenced", "ransomware", "obfuscated"]):
        assert abusech.uh_family(junk) is None, junk      # never a wrong family; unknown names are not families


def test_sslbl_parse():
    s = SOURCES["sslbl"]
    recs = s.records(SSL)
    assert len(recs) == 22 and all(len(k) == 40 for k, _ in recs)
    assert (CERT, {"listing_date": "2026-11-09 10:16:33", "sha1": CERT, "reason": "PureLogsStealer C&C"}) in recs
    evs = s.parse(SSL)
    # certificates are indicators, not activity: one summary event per family listed in the last year
    by = {e.key[0]: e for e in evs}
    assert by["purelogsstealer"].value == 5 and by["purelogsstealer"].title.startswith("PureLogsStealer: 5 C2 TLS")
    assert by["purelogsstealer"].tags == ["PureLogsStealer"] and "c2_cert" not in by["purelogsstealer"].tags
    assert "shylock" not in by and "dridex" not in by and "quakbot" not in by            # nothing listed this year
    assert len(evs) == len(by) < 15
    assert abusech.sslbl_family("Quakbot C&C") == "Quakbot" and abusech.sslbl_family("Malware C&C") is None
    for junk in ("Malware distribution", "doxbin.cy C&C", "Malware C&C", "", "some very long reason text here"):
        assert abusech.sslbl_family(junk) is None, junk
    junk = SSL + b"\nnot,a,row\n2026-01-01 00:00:00,XYZ,bad hash\n"
    assert len(s.records(junk)) == 22


def test_norm_url_matches_zeek_shape():
    assert abusech.norm_url("http://203.0.113.77:8080/bins/mozi.m") == ("ip", "203.0.113.77", "203.0.113.77/bins/mozi.m")
    assert abusech.norm_url("https://Compromised-Shop.Example/wp/inv.zip?id=7#x")[2] == "compromised-shop.example/wp/inv.zip?id=7"
    assert abusech.norm_url("http://[2001:DB8:5::9]/x86")[1] == "2001:db8:5::9"
    assert abusech.norm_url("not a url at all") is None
    assert abusech.norm_url("http://203.0.113.9/x?")[2] == "203.0.113.9/x?"          # Zeek keeps a bare "?"
    assert abusech.split_ip_port("2001:db8::1:443", expect_port=True) == ("2001:db8::1", 443)
    assert abusech.split_ip_port("[2001:db8::1]:443") == ("2001:db8::1", 443)
    assert abusech.split_ip_port("2001:db8::1") == ("2001:db8::1", None)


# ---------------------------------------------------------------- the Auth-Key gate
def test_keyed_sources_are_off_and_never_fetch_without_a_key():
    tf = SOURCES["threatfox"]
    assert tf.default_enabled is False and tf.needs_key == "ABUSECH_AUTH_KEY" and tf.ai_ok is False
    old = config.ABUSECH_AUTH_KEY
    config.ABUSECH_AUTH_KEY = None
    try:
        assert "abuse.ch Auth-Key" in tf.unavailable()   # plain words; the setting is tf.needs_key
        n = len(SEEN)
        res = _run(tf, TF)
        assert res["ok"] is False and res.get("skipped") and len(SEEN) == n        # no request at all
        assert scheduler.state("threatfox")["status"] == "needs_key"
        assert not db.query("SELECT 1 FROM runs WHERE source = 'threatfox'")      # no failed-run spam
        assert tf.describe()["unavailable"] and tf.describe()["key_set"] is False
        assert SOURCES["sslbl"].unavailable() is None                              # SSLBL is keyless
    finally:
        config.ABUSECH_AUTH_KEY = old


def test_keyed_fetch_never_follows_a_redirect():
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(302, headers={"Location": "https://elsewhere.example/steal"})

    async def go():
        scheduler._client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)
        try:
            return await scheduler.run_batch(SOURCES["threatfox"])
        finally:
            await scheduler._client.aclose()
            scheduler._client = None
    old = config.OFFLINE
    config.OFFLINE = False
    try:
        res = asyncio.run(go())
    finally:
        config.OFFLINE = old
    assert res["ok"] is False and "redirect" in res["error"] and KEY not in res["error"]
    assert [r.url.host for r in seen] == ["threatfox-api.abuse.ch"]           # the Location was never requested


def test_threatfox_window_covers_gaps():
    import datetime as dt
    tf = SOURCES["threatfox"]
    orig = scheduler.state
    try:
        scheduler.state = lambda sid: {}
        assert tf.window_days() == 3
        scheduler.state = lambda sid: {"last_ok": abusech.now() - dt.timedelta(hours=1)}
        assert tf.window_days() == 1
        scheduler.state = lambda sid: {"last_ok": abusech.now() - dt.timedelta(days=2, hours=5)}
        assert tf.window_days() == 3
        scheduler.state = lambda sid: {"last_ok": abusech.now() - dt.timedelta(days=30)}
        assert tf.window_days() == 7
    finally:
        scheduler.state = orig
    body = json.loads(SEEN[-1].content) if SEEN and SEEN[-1].method == "POST" else None
    assert body is None or body["query"] == "get_iocs"


def test_refused_key_is_reported_without_leaking_it():
    res = _run(SOURCES["urlhaus"], b"Unauthorized", status=401)
    assert res["ok"] is False and "refused the Auth-Key" in res["error"] and KEY not in res["error"]


# ---------------------------------------------------------------- pipeline + netlog
def _ingest_all():
    assert _run(SOURCES["feodo_c2"], FEODO)["ok"]
    for sid, body in (("threatfox", TF), ("urlhaus", UH), ("sslbl", SSL)):
        res = _run(SOURCES[sid], body)
        assert res["ok"], res
    intervals.refresh()


def _zeek(t0: float) -> bytes:
    home, c2, mozi = "192.0.2.10", "198.51.100.23", "203.0.113.77"
    rows = [
        {"_path": "conn", "ts": t0, "uid": "Cc2", "id.orig_h": home, "id.orig_p": 50001, "id.resp_h": c2, "id.resp_p": 443,
         "proto": "tcp", "conn_state": "SF", "orig_bytes": 900, "resp_bytes": 4000, "duration": 3.0, "service": "ssl"},
        {"_path": "http", "ts": t0 + 1, "uid": "Cmozi", "id.orig_h": home, "id.orig_p": 50002, "id.resp_h": mozi,
         "id.resp_p": 8080, "trans_depth": 1, "method": "GET", "host": f"{mozi}:8080", "uri": "/bins/mozi.m", "status_code": 200},
        {"_path": "http", "ts": t0 + 2, "uid": "Cgh", "id.orig_h": home, "id.orig_p": 50003, "id.resp_h": "192.0.2.200",
         "id.resp_p": 443, "trans_depth": 1, "method": "GET", "host": "files.github.com",
         "uri": "/attacker/repo/raw/main/stage2.exe", "status_code": 200},
        {"_path": "http", "ts": t0 + 3, "uid": "Cgh2", "id.orig_h": home, "id.orig_p": 50004, "id.resp_h": "192.0.2.200",
         "id.resp_p": 443, "trans_depth": 1, "method": "GET", "host": "files.github.com", "uri": "/benign/readme", "status_code": 200},
        {"_path": "files", "ts": t0 + 4, "fuid": "Fcert", "uid": "Ccert", "id.orig_h": home, "id.resp_h": "198.51.100.99",
         "source": "SSL", "mime_type": "application/x-x509-user-cert", "sha1": CERT.upper()},
        {"_path": "files", "ts": t0 + 5, "fuid": "Fexe", "uid": "Cexe", "id.orig_h": home, "id.resp_h": "198.51.100.98",
         "source": "HTTP", "mime_type": "application/x-dosexec", "sha256": SAMPLE},
        {"_path": "dns", "ts": t0 + 6, "uid": "Cdns", "id.orig_h": home, "id.orig_p": 53001, "id.resp_h": "192.0.2.1",
         "id.resp_p": 53, "proto": "udp", "query": "c2-panel.badcorp.example", "qtype_name": "A", "rcode_name": "NOERROR",
         "answers": ["198.51.100.50"]},
    ]
    return ("\n".join(json.dumps(r) for r in rows) + "\n").encode()


def test_end_to_end_one_alert_per_observation_citing_every_list():
    _ingest_all()
    req = [r for r in SEEN if r.url.host in ("threatfox-api.abuse.ch", "urlhaus-api.abuse.ch")]
    assert req and all(r.headers.get("Auth-Key") == KEY and KEY not in str(r.url) for r in req)

    iv = db.query("""SELECT source, kind, value, category FROM indicator_intervals
                     WHERE source IN ('threatfox', 'urlhaus', 'sslbl') AND "end" IS NULL""")
    have = {(r["source"], r["kind"], r["value"], r["category"]) for r in iv}
    assert ("threatfox", "ip", "198.51.100.23", "c2") in have
    assert ("threatfox", "domain", "c2-panel.badcorp.example", "reputation") in have    # C2 at confidence 50: medium
    assert ("threatfox", "domain", "maliciousdomain.example", "c2") in have             # confidence 90
    assert ("threatfox", "ip", "2001:db8:4::17", "reputation") in have          # C2 at confidence 25: not high
    assert ("threatfox", "url", "203.0.113.77/bins/mozi.m", "reputation") in have
    assert ("threatfox", "ip", "203.0.113.77", "reputation") in have            # the URL's host
    assert ("threatfox", "url", "files.github.com/attacker/repo/raw/main/stage2.exe", "reputation") in have
    assert not any(v == "files.github.com" for _, _, v, _ in have)             # shared hosting: URL only
    # intervals start at the provider's own listing time, not at our fetch
    st = db.query("""SELECT "start" FROM indicator_intervals WHERE source = 'threatfox' AND key = '1610001'""")[0]["start"]
    assert st.astimezone(abusech.UTC).isoformat() == "2026-11-09T08:12:44+00:00"
    assert ("threatfox", "hash", SAMPLE, "malware") in have
    assert ("urlhaus", "domain", "compromised-shop.example", "reputation") in have
    assert not any("discordapp" in v for _, _, v, _ in have)                    # offline URL: not listed
    assert ("sslbl", "hash", CERT, "c2") in have
    assert sum(1 for s, *_ in have if s == "sslbl") == 22
    old = db.query("""SELECT "start" FROM indicator_intervals WHERE source = 'sslbl' AND value = '86d6aade4ba1414a91b1e7fb3cdd7d503692f410'""")
    assert old[0]["start"].year == 2014                                         # SSLBL listing date

    res = importer.import_fileobj(io.BytesIO(_zeek(time.time() + 120)), "abusech-test.log")
    assert res.get("rows") == 7, res
    alerts = db.query("SELECT id, severity, source, indicator, title, evidence, count FROM alerts")
    by_ind = {}
    for a in alerts:
        a["evidence"] = json.loads(a["evidence"])
        by_ind.setdefault(a["indicator"], []).append(a)

    # Feodo + ThreatFox on the same C2 address: ONE alert, Feodo leads, ThreatFox corroborates
    c2 = by_ind["198.51.100.23"]
    assert len(c2) == 1, [a["title"] for a in c2]
    a = c2[0]
    assert a["severity"] == "high" and a["source"] == "feodo_c2"
    assert "also listed by ThreatFox" in a["title"]
    also = a["evidence"]["also_listed"]
    assert [x["source"] for x in also] == ["threatfox"] and also[0]["malware"] == "Dridex"
    assert a["evidence"]["sources"] == ["feodo_c2", "threatfox"]
    assert a["evidence"]["rows"] == 1 and a["count"] == 1                      # one contact, not one per list
    # the alert keeps the id the Feodo match alone would have had (main's key: rule, device, source, value, day)
    import hashlib
    day = db.query("SELECT strftime(ts, '%Y-%m-%d') AS d FROM netlog WHERE uid = 'Cc2'")[0]["d"]
    dev = db.query("SELECT device FROM netlog_matches WHERE alert_id = ? LIMIT 1", [a["id"]])[0]["device"] or "192.0.2.10"
    assert a["id"] == "nl-" + hashlib.md5("|".join(["c2_outbound", dev, "feodo_c2", "198.51.100.23", day]).encode()).hexdigest()[:20]
    assert not [x for x in alerts if x["indicator"] == "198.51.100.23" and x["source"] == "threatfox"]

    # the Mozi download: URL and host on ThreatFox and URLhaus, one row, one alert led by the URL
    mozi = [x for x in alerts if "mozi" in x["indicator"] or x["indicator"] == "203.0.113.77"]
    assert len(mozi) == 1, [x["title"] for x in mozi]
    m = mozi[0]
    assert m["indicator"] == "203.0.113.77/bins/mozi.m" and m["severity"] == "medium"
    assert m["source"] == "threatfox" and [x["source"] for x in m["evidence"]["also_listed"]] == ["urlhaus"]   # never itself
    assert m["evidence"]["indicator"]["meta"]["malware"] == "Mozi"

    # URL on shared hosting matches the exact URL only, never other paths on the host
    gh = [x for x in alerts if "files.github.com" in x["indicator"]]
    assert len(gh) == 1 and gh[0]["indicator"].endswith("stage2.exe")

    # C2 certificate (SSLBL SHA1 in files.log) and a ThreatFox malware sample hash
    cert = by_ind[CERT][0]
    assert cert["severity"] == "high" and cert["source"] == "sslbl" and "PureLogsStealer" in cert["title"]
    assert by_ind[SAMPLE][0]["severity"] == "high" and by_ind[SAMPLE][0]["source"] == "threatfox"

    # DNS lookup of a ThreatFox C2 domain reported at confidence 50: medium
    assert by_ind["c2-panel.badcorp.example"][0]["severity"] == "medium"

    # nothing anywhere holds the key
    assert KEY not in json.dumps(db.query("SELECT * FROM runs"), default=str)
    assert KEY not in json.dumps(db.query("SELECT * FROM source_state"), default=str)
    for p in Path(LAKE, "raw").rglob("*.gz"):
        assert KEY.encode() not in gzip.decompress(p.read_bytes())


def test_rerun_stores_nothing_new_and_dedups_events():
    before = db.query("SELECT source, count(*) AS n FROM events WHERE source IN ('threatfox','urlhaus','sslbl') GROUP BY 1")
    for sid, body in (("threatfox", TF), ("urlhaus", UH), ("sslbl", SSL)):
        res = _run(SOURCES[sid], body)
        assert res["ok"] and res["records_changed"] == 0 and res["records_removed"] == 0 and res["changed"] == 0, (sid, res)
    after = db.query("SELECT source, count(*) AS n FROM events WHERE source IN ('threatfox','urlhaus','sslbl') GROUP BY 1")
    assert sorted(before, key=str) == sorted(after, key=str)


def test_urlhaus_offline_closes_the_listing_and_ttl_expires():
    d = json.loads(UH)
    d["urls"][1]["url_status"] = "offline"
    assert _run(SOURCES["urlhaus"], json.dumps(d).encode())["ok"]
    intervals.refresh()
    rows = db.query("""SELECT kind, "end" FROM indicator_intervals WHERE source = 'urlhaus' AND key = '3300002'""")
    assert rows and all(r["end"] is not None for r in rows)
    # TTL: an open ThreatFox listing whose expiry has passed is closed on the next refresh
    db.execute("""UPDATE indicator_intervals SET meta = json_merge_patch(meta, '{"expires": "2000-01-01T00:00:00+00:00"}')
                  WHERE source = 'threatfox' AND value = 'c2-panel.badcorp.example'""")
    ch = intervals.refresh()
    assert ch.get("threatfox_expired") == 1
    assert db.query("""SELECT "end" FROM indicator_intervals WHERE source = 'threatfox'
                       AND value = 'c2-panel.badcorp.example'""")[0]["end"] is not None


def test_sslbl_removal_closes_the_listing():
    body = SSL.replace(CERT.encode(), b"")   # the row no longer parses: the cert left the list
    res = _run(SOURCES["sslbl"], body)
    assert res["ok"] and res["records_removed"] == 1
    intervals.refresh()
    assert db.query("""SELECT "end" FROM indicator_intervals WHERE source = 'sslbl' AND value = ?""", [CERT])[0]["end"]


def test_full_rebuild_gives_the_same_intervals():
    def snap():
        return sorted((r["source"], r["kind"], r["value"], r["category"], str(r["end"] is None)) for r in db.query(
            """SELECT source, kind, value, category, "end" FROM indicator_intervals WHERE source IN ('threatfox','urlhaus','sslbl')
               AND value <> 'c2-panel.badcorp.example'"""))   # its expiry was forced by hand above
    a = snap()
    intervals.refresh(full=True)
    assert snap() == a
