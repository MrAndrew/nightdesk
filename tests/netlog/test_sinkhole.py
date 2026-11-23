"""DNS sinkhole logs: Pi-hole (pihole.log, v6 /api/queries export) and AdGuard Home (querylog.json) are recognised by
content, become DNS rows with the sinkhole's verdict, dedupe like Zeek files, name devices and match threat lists.

    uv run --with pytest pytest tests/netlog/test_sinkhole.py -q
"""
from __future__ import annotations

import datetime as dt
import gzip
import io
import json
import time
from pathlib import Path

time.tzset()
from _lake import make_lake  # noqa: E402
LAKE = make_lake("netlog-sinkhole", TZ="UTC")

import pytest  # noqa: E402

from osinthub import config, db  # noqa: E402
from osinthub.netlog import importer, intervals, sinkhole, util  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
UTC = dt.UTC
FIX = Path(__file__).resolve().parents[2] / "osinthub" / "netlog" / "fixtures" / "sinkhole"
LISTED = dt.datetime(2026, 10, 1, tzinfo=UTC)       # the fixtures' queries are on 2026-10-14
INDICATOR = "c2-relay.example"


def _setup() -> None:
    p = config.RAW_DIR / "cins_army" / LISTED.strftime("%Y/%m/%d") / f"{LISTED.strftime('%H%M%S')}.records.ndjson.gz"
    p.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(p, "wt") as fh:
        fh.write(json.dumps({"key": INDICATOR, "op": "put", "data": INDICATOR}) + "\n")
    intervals.refresh()
    s = util.settings()
    s["home_prefixes"] = ["10.86.24.0/24", "fd4e:6400:d35c::/48"]
    util.save_settings(s)


_setup()


def imp(data: bytes, name: str) -> dict:
    return importer.import_any(io.BytesIO(data), name, origin="upload")


def rows_of(file_id: str) -> list[dict]:
    out = db.query("SELECT ts, uid, log_type, orig_h, orig_p, query, answers, hostname, mac, raw FROM netlog "
                   "WHERE file_id = ? ORDER BY ts, query", [file_id])
    for r in out:
        r["raw"] = json.loads(r["raw"])
    return out


def utc(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s).astimezone(UTC)


def syslog_year(month: int, day: int) -> int:
    """The year the importer gives a year-less stamp: the latest one not more than two days ahead of now."""
    now = dt.datetime.now(UTC)
    y = now.year + 1
    while dt.datetime(y, month, day, tzinfo=UTC) > now + dt.timedelta(days=2):
        y -= 1
    return y


# ------------------------------------------------------------------ detection
@pytest.mark.parametrize("fname,kind", [("pihole.log", "pihole-log"), ("pihole-extra.log", "pihole-log"),
                                        ("pihole-queries.json", "pihole-api"), ("adguard-querylog.json", "adguard")])
def test_detects_by_content(fname, kind):
    assert sinkhole.detect_text((FIX / fname).read_text()) == kind


def test_detection_ignores_other_logs():
    zeek = json.dumps({"ts": 1.0, "uid": "C1", "id.orig_h": "10.86.24.21", "query": "www.example.com", "qtype_name": "A"})
    assert sinkhole.detect_text(zeek + "\n") is None
    assert sinkhole.detect_text('[{"ts": 1, "uid": "C1"}]') is None
    assert sinkhole.detect_text("hello\nworld\n") is None
    assert sinkhole.detect_text("Oct 14 09:00:01 sshd[22]: Accepted publickey for alice\n") is None
    # just the query list of a Pi-hole export also counts
    qs = json.loads((FIX / "pihole-queries.json").read_text())["queries"]
    assert sinkhole.detect_text(json.dumps(qs)) == "pihole-api"


def test_detection_ignores_file_name():
    res = imp((FIX / "pihole-extra.log").read_bytes(), "conn.log")
    assert not res.get("error") and res["format"] == "pihole-log"
    assert res["log_types"] == {"dns": 3}


def test_unknown_text_is_rejected_plainly():
    res = imp(b"just some notes\nnothing to see\n", "notes.txt")
    assert "Pi-hole" in res["error"] and "AdGuard" in res["error"]


# ------------------------------------------------------------------ parsing into DNS rows
def test_pihole_log_rows():
    res = imp((FIX / "pihole.log").read_bytes(), "pihole.log")
    assert not res.get("error"), res
    assert res["format"] == "pihole-log" and res["log_types"] == {"dns": 9}
    assert res["sinkhole"] == {"source": "pihole", "format": "pihole-log", "label": "Pi-hole query log",
                               "queries": 9, "blocked": 3}
    rows = {(r["query"], r["raw"]["qtype_name"]): r for r in rows_of(res["file_id"])}
    y = syslog_year(10, 14)
    www = rows[("www.example.com", "A")]
    assert www["log_type"] == "dns" and www["orig_h"] == "10.86.24.21" and www["mac"] is None
    assert www["ts"] == dt.datetime(y, 10, 14, 9, 0, 1, tzinfo=UTC)
    assert www["answers"] == ["edge.example.net", "198.51.100.20", "198.51.100.21"]
    assert www["raw"]["sinkhole"] == "pihole" and www["raw"]["blocked"] is False and www["raw"]["verdict"] == "allowed"
    assert rows[("www.example.com", "AAAA")]["answers"] == ["edge.example.net", "2001:db8:20::20"]
    ads = rows[("ads.tracker.example", "A")]
    assert ads["raw"]["blocked"] is True and ads["raw"]["reason"] == "gravity blocked" and ads["answers"] is None
    assert ads["raw"]["sinkhole_answer"] == "0.0.0.0"
    assert rows[("metrics.telemetry.example", "HTTPS")]["raw"]["reason"] == "regex denied"
    assert rows[("beacon.c2-relay.example", "A")]["raw"]["blocked"] is True
    nx = rows[("nothere.example.org", "A")]
    assert nx["orig_h"] == "fd4e:6400:d35c::40" and nx["raw"]["rcode_name"] == "NXDOMAIN"
    assert rows[("pi.hole", "A")]["raw"]["blocked"] is False
    assert rows[("2.24.86.10.in-addr.arpa", "PTR")]["answers"] == ["pi.hole"]
    assert rows[("slow.example.org", "A")]["answers"] is None   # forwarded, no reply in the file: still a row


def test_pihole_log_extra_mode_ports_and_ids():
    y = syslog_year(10, 14)
    rows = db.query("SELECT orig_p, query, answers, raw FROM netlog n JOIN netlog_files f ON f.id = n.file_id "
                    "WHERE f.name = 'conn.log' ORDER BY query")
    got = {r["query"]: r for r in rows}
    assert got["www.example.com"]["orig_p"] == 50211 and got["www.example.com"]["answers"] == ["198.51.100.20"]
    assert json.loads(got["ads.tracker.example"]["raw"])["blocked"] is True
    assert got["beacon.c2-relay.example"]["answers"] == ["203.0.113.66"]
    assert json.loads(got["beacon.c2-relay.example"]["raw"])["blocked"] is False
    assert y >= 2026


def test_pihole_api_rows():
    res = imp((FIX / "pihole-queries.json").read_bytes(), "queries.json")
    assert not res.get("error"), res
    assert res["format"] == "pihole-api" and res["log_types"] == {"dns": 6} and res["sinkhole"]["blocked"] == 3
    rows = rows_of(res["file_id"])
    assert rows[0]["ts"] == dt.datetime.fromtimestamp(1791968401.512, UTC)
    by = {(r["query"], r["raw"]["status"]): r for r in rows}
    www = by[("www.example.com", "FORWARDED")]
    assert www["orig_h"] == "10.86.24.21" and www["hostname"] == "kitchen-tablet.lan"
    assert www["raw"]["client_name"] == "kitchen-tablet.lan" and www["raw"]["blocked"] is False
    ads = by[("ads.tracker.example", "GRAVITY")]
    assert ads["raw"]["blocked"] is True and ads["raw"]["list_id"] == 3 and ads["raw"]["reason"] == "on a blocklist"
    cn = by[("cdn.shop.example", "GRAVITY_CNAME")]
    assert cn["raw"]["blocked"] is True and cn["raw"]["blocked_cname"] == "tracker.cname-cloak.example"
    assert by[("beacon.c2-relay.example", "DENYLIST")]["raw"]["list_id"] == 12
    v6 = by[("nothere.example.org", "FORWARDED")]
    assert v6["hostname"] is None and v6["raw"]["rcode_name"] == "NXDOMAIN"   # a "name" that is just the IP is not a name


def test_adguard_gzip_rows_and_duplicate():
    data = (FIX / "adguard-querylog.json").read_bytes()
    res = imp(gzip.compress(data), "querylog.json.gz")
    assert not res.get("error"), res
    assert res["format"] == "adguard" and res["log_types"] == {"dns": 6} and res["sinkhole"]["blocked"] == 2
    rows = {(r["query"], r["raw"]["qtype_name"]): r for r in rows_of(res["file_id"])}
    www = rows[("www.example.com", "A")]
    assert www["ts"] == utc("2026-10-14T11:00:01.123456+02:00")
    assert www["answers"] == ["edge.example.net", "198.51.100.20"] and www["raw"]["sinkhole"] == "adguard"
    ads = rows[("ads.tracker.example", "A")]
    assert ads["raw"]["blocked"] is True and ads["raw"]["rule"] == "||tracker.example^" and ads["raw"]["list_id"] == 1
    assert ads["answers"] is None and ads["raw"]["sinkhole_answer"] == "0.0.0.0"
    bea = rows[("beacon.c2-relay.example", "A")]
    assert bea["hostname"] == "study-laptop" and bea["raw"]["client_proto"] == "doh"
    assert rows[("nothere.example.org", "AAAA")]["raw"]["rcode_name"] == "NXDOMAIN"
    allow = rows[("www.example.com", "AAAA")]
    assert allow["raw"]["blocked"] is False and allow["raw"]["reason"] == "allowed by an allowlist rule"
    assert rows[("nas.home.example", "A")]["raw"]["blocked"] is False          # a rewrite is not a block
    # the same content plain is the same file
    again = imp(data, "querylog.json")
    assert again["duplicate"] is True and again["inserted"] == 0


def test_overlapping_exports_dedupe_rows():
    data = (FIX / "adguard-querylog.json").read_bytes()
    extra = json.dumps({"T": "2026-10-14T11:05:00+02:00", "QH": "new.example.org", "QT": "A", "QC": "IN", "CP": "",
                        "IP": "10.86.24.21", "Result": {}, "Elapsed": 1000}) + "\n"
    res = imp(data + extra.encode(), "querylog.json.1")
    assert not res.get("error") and res["inserted"] == 1 and res["duplicates"] == 6
    pl = (FIX / "pihole.log").read_text()
    more = pl + "Oct 14 09:30:00 dnsmasq[812]: query[A] late.example.org from 10.86.24.21\n"
    res = imp(more.encode(), "pihole.log.1")
    assert not res.get("error") and res["inserted"] == 1 and res["duplicates"] == 9
    api = json.loads((FIX / "pihole-queries.json").read_text())
    api["queries"] = api["queries"][2:]     # a later page of the same export
    res = imp(json.dumps(api).encode(), "queries-page2.json")
    assert not res.get("error") and res["inserted"] == 0 and res["duplicates"] == 4


# ------------------------------------------------------------------ devices
def test_devices_by_ip_and_client_name_without_macs():
    devs = {d["id"]: d for d in db.query("SELECT id, identity, mac, hostnames FROM devices")}
    assert "ip:10.86.24.21" in devs and "ip:10.86.24.33" in devs and "ip:10.86.24.40" in devs
    assert all(d["mac"] is None and d["identity"] == "ip" for d in devs.values())
    assert "kitchen-tablet.lan" in devs["ip:10.86.24.21"]["hostnames"]
    assert "living-room-tv.lan" in devs["ip:10.86.24.33"]["hostnames"]
    assert "study-laptop" in devs["ip:10.86.24.40"]["hostnames"]
    # the sinkhole's client name is a readable device name (".lan" dropped), not filtered as junk
    from osinthub.netlog import devices
    names = devices.display_names(["ip:10.86.24.21", "ip:10.86.24.33", "ip:10.86.24.40"])
    assert names["ip:10.86.24.21"]["name"] == "kitchen-tablet"
    assert names["ip:10.86.24.33"]["name"] == "living-room-tv"
    assert names["ip:10.86.24.40"]["name"] == "study-laptop"


# ------------------------------------------------------------------ matching
def test_matching_raises_dns_alert_and_keeps_blocked_flag():
    alerts = db.query("SELECT id, severity, rule, device, direction, indicator, evidence FROM alerts WHERE indicator = ?",
                      [INDICATOR])
    assert alerts, "a client resolving a listed domain raises the normal DNS alert"
    assert {a["direction"] for a in alerts} == {"dns"}
    assert any(a["device"] == "ip:10.86.24.40" for a in alerts)
    m = db.query("""SELECT m.rk, m.role, json_extract_string(n.raw, '$.blocked') AS blocked,
                           json_extract_string(n.raw, '$.sinkhole') AS src
                    FROM netlog_matches m JOIN netlog n ON n.rk = m.rk WHERE m.value = ?""", [INDICATOR])
    assert {r["role"] for r in m} == {"name"}
    # blocked by Pi-hole (log and export) and AdGuard; allowed once (the extra-mode log): both kinds still match
    assert {(r["src"], r["blocked"]) for r in m} == {("pihole", "true"), ("pihole", "false"), ("adguard", "true")}


def test_blocked_query_still_matches_alone():
    """A file with only a blocked lookup still raises the alert, and its row says the sinkhole blocked it."""
    line = json.dumps({"T": "2026-10-15T08:00:00Z", "QH": "x1.c2-relay.example", "QT": "A", "QC": "IN", "CP": "",
                       "IP": "10.86.24.77", "Result": {"IsFiltered": True, "Reason": 3,
                                                       "Rules": [{"Text": "||c2-relay.example^", "FilterListID": 2}]},
                       "Elapsed": 5}) + "\n"
    res = imp(line.encode(), "querylog-blocked.json")
    assert not res.get("error") and res["match"]
    m = db.query("""SELECT json_extract_string(n.raw, '$.verdict') AS v, m.device FROM netlog_matches m
                    JOIN netlog n ON n.rk = m.rk WHERE n.file_id = ?""", [res["file_id"]])
    assert m and m[0]["v"] == "blocked" and m[0]["device"] == "ip:10.86.24.77"


def test_dns_wire_parser_is_safe_on_garbage():
    assert sinkhole.dns_answers(b"") == (None, [])
    assert sinkhole.dns_answers(b"\x00" * 11) == (None, [])
    rc, ans = sinkhole.dns_answers(b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\xc0\x0c")   # pointer loop
    assert rc == "NOERROR" and ans == []
