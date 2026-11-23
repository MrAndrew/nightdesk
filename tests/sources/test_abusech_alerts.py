"""abuse.ch and the alert list: other lists keep exactly their own alerts and statuses, abuse.ch matches fold in as
corroboration, statuses follow re-keyed matches, and the shared-infrastructure gate.

    uv run --with pytest pytest tests/sources/test_abusech_alerts.py -q
"""
from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import io
import json
from pathlib import Path

from _lake import make_lake
LAKE = make_lake("abusech-alerts")

from osinthub import db  # noqa: E402
from osinthub.netlog import importer, intervals, matcher  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
UTC = dt.UTC
T0 = dt.datetime.now(UTC) - dt.timedelta(hours=6)
HOME, BAD, SCAN = "192.0.2.10", "198.51.100.44", "198.51.100.45"


def write_rec(source: str, when: dt.datetime, lines: list[dict]) -> None:
    p = Path(LAKE) / "raw" / source / when.strftime("%Y/%m/%d") / f"{when.strftime('%H%M%S')}.records.ndjson.gz"
    p.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(p, "wt") as fh:
        for l in lines:
            fh.write(json.dumps(l) + "\n")


def tf(ioc_id, ioc, conf=25, tt="botnet_cc", ioc_type="ip:port"):
    return {"key": ioc_id, "op": "put", "data": {"id": ioc_id, "ioc": ioc, "ioc_type": ioc_type, "threat_type": tt,
                                                 "malware_printable": "Dridex", "confidence_level": conf,
                                                 "first_seen": (T0 - dt.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S UTC")}}


def alerts():
    return {a["id"]: a for a in db.query("""SELECT a.id, a.severity, a.source, a.indicator, a.rule, a.count, a.title,
                                                   a.status, a.evidence FROM alerts a""")}


def main_id(rule, device, source, value, ts):
    return "nl-" + hashlib.md5("|".join([rule, device, source, value, ts.strftime("%Y-%m-%d")]).encode()).hexdigest()[:20]


# two existing lists on one address, and a contact before one of them listed it (a "historical" alert)
write_rec("et_compromised", T0 - dt.timedelta(hours=1), [{"key": BAD, "op": "put", "data": BAD}])
write_rec("cins_army", T0 - dt.timedelta(hours=1), [{"key": BAD, "op": "put", "data": BAD}])
write_rec("dshield_top", T0 + dt.timedelta(hours=3), [{"key": SCAN, "op": "put", "data": {"ip": SCAN, "attacks": 9}}])
intervals.refresh()
ts1 = (T0 + dt.timedelta(hours=1)).timestamp()
LOG = "\n".join(json.dumps(r) for r in [
    {"_path": "conn", "ts": ts1, "uid": "Cx1", "id.orig_h": HOME, "id.orig_p": 50001, "id.resp_h": BAD, "id.resp_p": 443,
     "proto": "tcp", "conn_state": "SF", "orig_bytes": 100, "resp_bytes": 200, "duration": 1.0, "service": "ssl"},
    {"_path": "conn", "ts": ts1 + 5, "uid": "Cx2", "id.orig_h": HOME, "id.orig_p": 50002, "id.resp_h": SCAN, "id.resp_p": 443,
     "proto": "tcp", "conn_state": "SF", "orig_bytes": 100, "resp_bytes": 200, "duration": 1.0, "service": "ssl"},
]) + "\n"
importer.import_fileobj(io.BytesIO(LOG.encode()), "ab-alerts.log")
BEFORE = alerts()


def test_existing_lists_keep_their_own_alerts():
    by = {(a["source"], a["indicator"], a["rule"]) for a in BEFORE.values()}
    assert ("et_compromised", BAD, "compromised_outbound") in by
    assert ("cins_army", BAD, "bad_reputation_outbound") in by
    assert ("dshield_top", SCAN, "historical") in by                  # contacted before DShield listed it
    dev = db.query("SELECT device FROM netlog_matches WHERE source = 'et_compromised' LIMIT 1")[0]["device"] or HOME
    assert main_id("compromised_outbound", dev, "et_compromised", BAD, dt.datetime.fromtimestamp(ts1, UTC)) in BEFORE
    assert all("also_listed" not in json.loads(a["evidence"]) for a in BEFORE.values())   # main's evidence shape


def test_threatfox_folds_in_and_statuses_survive():
    cins = next(i for i, a in BEFORE.items() if a["source"] == "cins_army")
    hist = next(i for i, a in BEFORE.items() if a["rule"] == "historical")
    db.execute("INSERT OR REPLACE INTO netlog_alert_status (id, status, updated_at) VALUES (?, 'dismissed', now())", [cins])
    db.execute("UPDATE alerts SET status = 'dismissed' WHERE id = ?", [cins])
    db.execute("INSERT OR REPLACE INTO netlog_alert_status (id, status, updated_at) VALUES (?, 'ack', now())", [hist])
    db.execute("UPDATE alerts SET status = 'ack' WHERE id = ?", [hist])
    # ThreatFox now lists the same address (C2 at confidence 25: reputation, the same rule as CINS) and the scanner
    write_rec("threatfox", T0 - dt.timedelta(minutes=30), [tf("901", f"{BAD}:443"), tf("902", f"{SCAN}:443", conf=90)])
    intervals.refresh()
    matcher.rehunt()
    after = alerts()
    assert set(BEFORE) <= set(after)                                   # every existing alert id is still there
    for i, a in BEFORE.items():
        assert (after[i]["severity"], after[i]["rule"], after[i]["count"]) == (a["severity"], a["rule"], a["count"])
    assert after[cins]["status"] == "dismissed" and after[hist]["status"] == "ack"
    # ThreatFox folds into one list alert for that contact (the lowest id of the lists that hold it), as corroboration
    hosts = [i for i, a in after.items() if "also_listed" in json.loads(a["evidence"])]
    assert len(hosts) == 1 and after[hosts[0]]["source"] in ("et_compromised", "cins_army")
    ev = json.loads(after[hosts[0]]["evidence"])
    assert [x["source"] for x in ev["also_listed"]] == ["threatfox"] and "also listed by ThreatFox" in after[hosts[0]]["title"]
    assert hosts[0] == min(i for i, a in BEFORE.items() if a["indicator"] == BAD)
    # ThreatFox's own alerts: only where no list carried the same contact under the same rule
    extra = {i: a for i, a in after.items() if i not in BEFORE}
    assert {(a["source"], a["indicator"], a["severity"]) for a in extra.values()} == {("threatfox", SCAN, "high")}
    # no alert cites its own source
    for a in after.values():
        e = json.loads(a["evidence"])
        assert a["source"] not in [x["source"] for x in e.get("also_listed", [])]


def test_dismissal_never_passes_to_a_different_alert():
    # the user dismisses the ThreatFox scanner alert; then Feodo lists the scanner (backdated before the contact) and
    # the ThreatFox match folds into Feodo's alert: that is a different alert the user never saw, so it starts new
    tfa = next(i for i, a in alerts().items() if a["source"] == "threatfox")
    db.execute("INSERT OR REPLACE INTO netlog_alert_status (id, status, updated_at) VALUES (?, 'dismissed', now())", [tfa])
    db.execute("UPDATE alerts SET status = 'dismissed' WHERE id = ?", [tfa])
    # same rule needed: list the scanner on a c2 list too (Feodo), backdated before the contact
    write_rec("feodo_c2", T0 - dt.timedelta(hours=2), [{"key": f"{SCAN}:443", "op": "put",
                                                       "data": {"ip_address": SCAN, "port": 443, "malware": "Dridex"}}])
    intervals.refresh()
    matcher.rehunt()
    after = alerts()
    assert tfa not in after
    feo = next(a for a in after.values() if a["source"] == "feodo_c2")
    assert feo["status"] == "new"
    assert [x["source"] for x in json.loads(feo["evidence"])["also_listed"]] == ["threatfox"]


def test_shared_infrastructure_gate():
    write_rec("threatfox", T0, [tf("911", "8.8.8.8:53", conf=100), tf("912", "127.0.0.1:80", conf=100),
                                tf("913", "10.1.1.1:80", conf=100), tf("914", "github.com", conf=100, ioc_type="domain"),
                                tf("915", "http://127.0.0.1/x", conf=100, ioc_type="url", tt="payload_delivery"),
                                tf("916", "2001:db8:9::5:4444", conf=100)])
    intervals.refresh()
    vals = {r["value"] for r in db.query("SELECT value FROM indicator_intervals WHERE source = 'threatfox'")}
    assert not vals & {"8.8.8.8", "127.0.0.1", "10.1.1.1", "github.com", "127.0.0.1/x"}
    assert "2001:db8:9::5" in vals                                     # unbracketed IPv6 ip:port: port split off
    g = intervals.STATUS["abusech_gate"]
    assert g["dropped"] >= 5 and any(x["value"] == "8.8.8.8" for x in g["sample"])
    assert intervals.shared_domain("raw.githubusercontent.com") or intervals.shared_domain("github.com")


def test_carry_status_rule():
    new = {"source": "feodo_c2", "indicator": "198.51.100.1", "severity": "high"}
    same = {"id": "x", "status": "dismissed", "source": "feodo_c2", "indicator": "198.51.100.1", "severity": "high"}
    assert matcher.carry_status(new, [same]) == "dismissed"                       # same alert re-keyed (e.g. device)
    assert matcher.carry_status(new, [{**same, "status": "ack"}, same]) == "ack"
    assert matcher.carry_status(new, [{**same, "severity": "medium"}]) is None    # more severe now: new
    assert matcher.carry_status(new, [{**same, "source": "threatfox"}]) is None   # a different alert: new
    assert matcher.carry_status(new, [{**same, "indicator": "198.51.100.2"}]) is None


DROPIP = "203.0.113.9"


def test_drop_after_dismissed_threatfox_starts_new_and_stale_alert_goes():
    """The data critic's repro (round 2): a dismissed ThreatFox alert must not dismiss the Spamhaus DROP alert that
    later absorbs its match; and when DROP's listing is moved to end before the contact, the DROP alert must go."""
    t = T0 + dt.timedelta(hours=4)
    write_rec("threatfox", t - dt.timedelta(hours=1), [tf("921", f"http://{DROPIP}/p.exe", ioc_type="url",
                                                          tt="payload_delivery", conf=100)])
    intervals.refresh()
    log = json.dumps({"_path": "conn", "ts": (t + dt.timedelta(minutes=5)).timestamp(), "uid": "Cdrop",
                      "id.orig_h": HOME, "id.orig_p": 50010, "id.resp_h": DROPIP, "id.resp_p": 80, "proto": "tcp",
                      "conn_state": "SF", "orig_bytes": 100, "resp_bytes": 200, "duration": 1.0}) + "\n"
    importer.import_fileobj(io.BytesIO(log.encode()), "ab-drop.log")
    tfa = next(i for i, a in alerts().items() if a["indicator"] == DROPIP)
    assert alerts()[tfa]["source"] == "threatfox" and alerts()[tfa]["severity"] == "medium"
    db.execute("INSERT OR REPLACE INTO netlog_alert_status (id, status, updated_at) VALUES (?, 'dismissed', now())", [tfa])
    db.execute("UPDATE alerts SET status = 'dismissed' WHERE id = ?", [tfa])
    # Spamhaus DROP (tier A, high) lists the /24 before the contact
    write_rec("spamhaus_drop", t - dt.timedelta(hours=2), [{"key": "203.0.113.0/24", "op": "put",
                                                            "data": {"cidr": "203.0.113.0/24", "sblid": "SBL1"}}])
    intervals.refresh()
    matcher.rehunt()
    a = alerts()
    drop = [x for x in a.values() if x["source"] == "spamhaus_drop" and x["rule"] == "drop_outbound"]
    assert len(drop) == 1 and drop[0]["severity"] == "high"
    assert drop[0]["status"] == "new"                                  # never inherits the ThreatFox dismissal
    assert tfa not in a
    old_drop = drop[0]["id"]
    # DROP's listing turns out to have ended before the contact (a del file dated earlier): rebuild + rehunt
    write_rec("spamhaus_drop", t - dt.timedelta(hours=1), [{"key": "203.0.113.0/24", "op": "del"}])
    intervals.refresh()
    matcher.rehunt()
    a = alerts()
    assert old_drop not in a                                           # the stale high DROP alert is gone
    assert not db.query("SELECT 1 FROM netlog_matches WHERE alert_id = ?", [old_drop])
    for x in a.values():                                               # every alert still has matches
        assert db.query("SELECT 1 FROM netlog_matches WHERE alert_id = ? LIMIT 1", [x["id"]]), x["title"]


def test_severity_rise_reopens_a_triaged_alert():
    # a CINS-only contact (medium), dismissed; then ThreatFox lists it as C2 at confidence 90 (high) and folds in
    ip = "198.51.100.77"
    t = T0 + dt.timedelta(hours=5)
    write_rec("cins_army", t - dt.timedelta(hours=1), [{"key": ip, "op": "put", "data": ip}])
    intervals.refresh()
    log = json.dumps({"_path": "conn", "ts": (t + dt.timedelta(minutes=5)).timestamp(), "uid": "Ccins",
                      "id.orig_h": HOME, "id.orig_p": 50020, "id.resp_h": ip, "id.resp_p": 443, "proto": "tcp",
                      "conn_state": "SF", "orig_bytes": 100, "resp_bytes": 200, "duration": 1.0, "service": "ssl"}) + "\n"
    importer.import_fileobj(io.BytesIO(log.encode()), "ab-cins.log")
    cid = next(i for i, x in alerts().items() if x["indicator"] == ip)
    assert alerts()[cid]["severity"] == "medium"
    db.execute("INSERT OR REPLACE INTO netlog_alert_status (id, status, updated_at) VALUES (?, 'dismissed', now())", [cid])
    db.execute("UPDATE alerts SET status = 'dismissed' WHERE id = ?", [cid])
    matcher.rehunt()
    assert alerts()[cid]["status"] == "dismissed"                       # same severity: stays dismissed
    write_rec("threatfox", t - dt.timedelta(minutes=30), [tf("931", f"{ip}:443", conf=90)])
    intervals.refresh()
    matcher.rehunt()
    a = alerts()[cid]
    assert a["severity"] == "high" and a["status"] == "new"            # reopened
    ev = json.loads(a["evidence"])
    assert ev["reopened"] == {"was": "dismissed", "severity_from": "medium", "severity_to": "high"}
    assert db.query("SELECT status FROM netlog_alert_status WHERE id = ?", [cid])[0]["status"] == "new"


def test_gate_without_public_suffix_list_keeps_dynamic_dns():
    from osinthub.netlog import allowlist
    assert not (Path(LAKE) / "ref" / "public_suffix_list.dat").exists()
    intervals._psl.cache_clear()
    old = allowlist.domains
    allowlist.domains = lambda: frozenset({"duckdns.org", "github.io", "github.com", "githubusercontent.com"})
    try:
        assert intervals.shared_domain("evil.duckdns.org") is None         # bundled suffixes: separately registrable
        assert intervals.shared_domain("x.github.io") is None
        assert intervals.shared_domain("raw.githubusercontent.com") == "githubusercontent.com"
        assert intervals.shared_domain("github.com") == "github.com"
        assert "bundled" in intervals.STATUS["abusech_gate"]["psl"]
    finally:
        allowlist.domains = old
        intervals._psl.cache_clear()
