"""A user's ack or dismissal across settings round-trips (okf/data/netlog.md#alert-status).

A setting that lowers an alert's severity and is then changed back leaves an acked or dismissed alert as the user left
it: grace (an accepted big session just before the listing stops counting), home prefixes (the alert goes away and
comes back) and p2p_cap (the capped and uncapped alerts swap), each done twice. That holds for statuses set before
the triaged severity was stored (a lake from v1.2: the column is added with NULLs), even when a setting held the
alert low at the upgrade. A rise above the severity the user triaged it at still reopens it, also when the alert was
deleted in between, and a new indicator is a new alert.

    uv run --with pytest pytest tests/netlog/test_v12_pf_netlog.py -q
"""
from __future__ import annotations

import datetime as dt
import gzip
import json

from _lake import client, conn, make_lake, ndjson
LAKE = make_lake("pf-netlog")

from osinthub import config, db  # noqa: E402
from osinthub.netlog import api, importer, intervals, util  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
C = client(api.router)
UTC = dt.UTC
LISTED = (dt.datetime.now(UTC) - dt.timedelta(days=2)).replace(hour=11, minute=0, second=0, microsecond=0)
ATK = {k: f"198.51.100.{60 + i}" for i, k in enumerate(
    ["grace", "rise", "new", "legacy", "legacy_low", "legacy_rise", "gone", "p2p", "p2p_rev"])}
HOME = {k: f"192.0.2.{10 + i}" for i, k in enumerate(ATK)}
BIG, SMALL = 2_000_000, 20_000                  # an accepted inbound session: medium from 1 MB, else low
HOME_NET, AWAY_NET = ["192.0.2.0/24"], ["203.0.113.0/24"]


def rec(source: str, when: dt.datetime, lines: list[dict]) -> None:
    p = config.RAW_DIR / source / when.strftime("%Y/%m/%d") / f"{when.strftime('%H%M%S')}.records.ndjson.gz"
    p.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(p, "wt") as fh:
        for line in lines:
            fh.write(json.dumps(line) + "\n")


def inbound(k: str, at: dt.timedelta, size: int) -> dict:
    return conn((LISTED + at).timestamp(), ATK[k], HOME[k], 22, orig_bytes=size, resp_bytes=size)


def swarm(k: str) -> list[dict]:
    """A home address in a P2P swarm (16 high-port peers in one hour, no service) that also reaches a listed peer on
    high ports: that contact is capped at low while p2p_cap is on."""
    t = (LISTED + dt.timedelta(hours=2)).timestamp()
    peers = [conn(t + i, HOME[k], f"198.51.100.{200 + i}" if k == "p2p" else f"198.51.100.{220 + i}", 51413)
             for i in range(16)]
    return peers + [conn(t + 30, HOME[k], ATK[k], 51413)]


rec("blocklist_de", LISTED, [{"key": ip, "op": "put", "data": ip} for ip in ATK.values()])
intervals.refresh()
s = util.settings()
s.update(home_prefixes=HOME_NET, grace_seconds=3600, p2p_cap=True)
util.save_settings(s)
importer.import_any(ndjson([
    *(row for k in ("grace", "legacy", "legacy_low")
      for row in (inbound(k, dt.timedelta(minutes=-30), BIG),        # inside the 1 h grace: medium
                  inbound(k, dt.timedelta(hours=1), SMALL))),        # inside the listing: low
    *(inbound(k, dt.timedelta(hours=1), SMALL) for k in ("rise", "legacy_rise", "gone")),   # low
    *swarm("p2p"), *swarm("p2p_rev"),
]), "pf-netlog.log", origin="upload")


def alerts(k: str) -> list[dict]:
    return [a for a in db.query("SELECT id, severity, status, rule, evidence FROM alerts WHERE indicator = ?", [ATK[k]])
            if a["rule"] != "historical"]


def alert(k: str) -> dict:
    rows = alerts(k)
    assert len(rows) == 1, rows
    return rows[0]


def put(**body) -> None:
    r = C.put("/api/netlog/settings", json=body)
    assert r.status_code == 200, r.text


def triage(aid: str, status: str) -> None:
    r = C.post(f"/api/netlog/alerts/{aid}/status", json={"status": status})
    assert r.status_code == 200, r.text


def status_row(aid: str) -> dict:
    return db.query("SELECT status, severity FROM netlog_alert_status WHERE id = ?", [aid])[0]


# A lake from v1.2: the legacy alerts were dismissed / acked before netlog_alert_status had its severity column.
LEGACY = alert("legacy")
assert LEGACY["severity"] == "medium"
triage(LEGACY["id"], "dismissed")
triage(alert("legacy_rise")["id"], "ack")
db.execute("ALTER TABLE netlog_alert_status DROP COLUMN severity")          # the v1.2 table
assert [c["column_name"] for c in db.query("SELECT column_name FROM duckdb_columns() WHERE table_name = "
                                           "'netlog_alert_status' ORDER BY column_index")] == ["id", "status", "updated_at"]
db.cursor().execute(SCHEMA_SQL)                                             # what the upgrade runs at startup
assert status_row(LEGACY["id"]) == {"status": "dismissed", "severity": None}


def test_dismissed_alert_stays_dismissed_across_a_grace_round_trip():
    a = alert("grace")
    assert (a["rule"], a["severity"], a["status"]) == ("attacker_inbound_accepted", "medium", "new")
    triage(a["id"], "dismissed")
    assert status_row(a["id"]) == {"status": "dismissed", "severity": "medium"}   # the severity the user saw
    for _ in range(2):                                                          # twice: never "reopens once"
        put(grace_seconds=0)                                                    # the big session is now historical
        low = alert("grace")
        assert (low["id"], low["severity"], low["status"]) == (a["id"], "low", "dismissed")
        put(grace_seconds=3600)                                                 # and back
        back = alert("grace")
        assert (back["id"], back["severity"], back["status"]) == (a["id"], "medium", "dismissed")
        assert "reopened" not in json.loads(back["evidence"])
        assert status_row(a["id"])["status"] == "dismissed"


def test_acked_alert_stays_acked_across_a_home_prefix_round_trip():
    a = alert("grace")
    triage(a["id"], "ack")
    for _ in range(2):
        put(home_prefixes=["192.0.2.0/25"])       # the same device, still home: nothing changes
        put(home_prefixes=AWAY_NET)               # its home address is no longer home: the alert goes away
        assert not db.query("SELECT id FROM alerts WHERE id = ?", [a["id"]])
        put(home_prefixes=HOME_NET)               # and back
        back = alert("grace")
        assert (back["id"], back["severity"], back["status"]) == (a["id"], "medium", "ack")


def test_p2p_cap_round_trips_keep_the_status_both_ways():
    # dismissed while capped: the uncapped alert is another alert (new) while the cap is off, and goes away again
    capped = alert("p2p")
    assert (capped["severity"], capped["rule"].endswith("_p2p"), capped["status"]) == ("low", True, "new")
    triage(capped["id"], "dismissed")
    # dismissed while uncapped: the capped alert takes the status over, and the uncapped one gets it back
    put(p2p_cap=False)
    unc = alert("p2p_rev")
    assert (unc["severity"], unc["rule"].endswith("_p2p")) == ("medium", False)
    triage(unc["id"], "dismissed")
    for _ in range(2):
        put(p2p_cap=True)
        assert {(a["id"], a["status"]) for a in alerts("p2p")} == {(capped["id"], "dismissed")}
        assert [a["status"] for a in alerts("p2p_rev")] == ["dismissed"]
        put(p2p_cap=False)
        assert [a["status"] for a in alerts("p2p")] == ["new"] and capped["id"] not in {a["id"] for a in alerts("p2p")}
        assert {(a["id"], a["status"]) for a in alerts("p2p_rev")} == {(unc["id"], "dismissed")}
    put(p2p_cap=True)
    assert [a["status"] for a in alerts("p2p")] == ["dismissed"]


def test_a_status_from_before_the_upgrade_survives_settings_round_trips():
    for _ in range(2):
        put(grace_seconds=0)
        assert (alert("legacy")["severity"], alert("legacy")["status"]) == ("low", "dismissed")
        put(grace_seconds=3600)
        back = alert("legacy")
        assert (back["id"], back["severity"], back["status"]) == (LEGACY["id"], "medium", "dismissed")
        assert "reopened" not in json.loads(back["evidence"])
    assert status_row(LEGACY["id"]) == {"status": "dismissed", "severity": None}   # left as it was


def test_a_status_from_before_the_upgrade_held_low_by_a_setting_survives_it_being_undone():
    a = alert("legacy_low")
    triage(a["id"], "dismissed")                  # at medium
    put(grace_seconds=0)                          # low when the user upgrades...
    db.execute("UPDATE netlog_alert_status SET severity = NULL WHERE id = ?", [a["id"]])   # ...from v1.2
    put(grace_seconds=3600)                       # back to medium: the user saw medium, nothing reopens
    back = alert("legacy_low")
    assert (back["severity"], back["status"]) == ("medium", "dismissed")


def test_a_rise_above_the_triaged_severity_still_reopens():
    a = alert("rise")
    assert (a["severity"], a["status"]) == ("low", "new")
    triage(a["id"], "dismissed")                  # dismissed at low
    put(grace_seconds=0)
    put(grace_seconds=3600)                       # a round trip that changes nothing for it
    assert alert("rise")["status"] == "dismissed"
    importer.import_any(ndjson([inbound("rise", dt.timedelta(hours=2), BIG)]), "pf-rise.log", origin="upload")
    now = alert("rise")                           # new evidence: a big session
    assert (now["id"], now["severity"], now["status"]) == (a["id"], "medium", "new")
    assert json.loads(now["evidence"])["reopened"] == {"was": "dismissed", "severity_from": "low", "severity_to": "medium"}
    assert status_row(a["id"]) == {"status": "new", "severity": "medium"}


def test_new_evidence_still_reopens_a_status_from_before_the_upgrade():
    a = alert("legacy_rise")
    assert (a["severity"], a["status"]) == ("low", "ack")
    importer.import_any(ndjson([inbound("legacy_rise", dt.timedelta(hours=2), BIG)]), "pf-lrise.log", origin="upload")
    now = alert("legacy_rise")
    assert (now["severity"], now["status"]) == ("medium", "new")


def test_new_evidence_while_the_alert_was_gone_reopens_it():
    a = alert("gone")
    triage(a["id"], "dismissed")                  # at low
    put(home_prefixes=AWAY_NET)                   # the alert goes away (its status is kept by id)
    assert not db.query("SELECT id FROM alerts WHERE id = ?", [a["id"]])
    importer.import_any(ndjson([inbound("gone", dt.timedelta(hours=2), BIG)]), "pf-gone.log", origin="upload")
    put(home_prefixes=HOME_NET)                   # it comes back with the new big session: medium, above low
    back = alert("gone")
    assert (back["id"], back["severity"], back["status"]) == (a["id"], "medium", "new")
    assert json.loads(back["evidence"])["reopened"] == {"was": "dismissed", "severity_from": "low", "severity_to": "medium"}
    triage(a["id"], "dismissed")                  # dismissed again at medium: a further round trip keeps it
    put(home_prefixes=AWAY_NET)
    put(home_prefixes=HOME_NET)
    assert alert("gone")["status"] == "dismissed"


def test_a_new_indicator_is_a_new_alert():
    importer.import_any(ndjson([inbound("new", dt.timedelta(hours=3), SMALL)]), "pf-new.log", origin="upload")
    assert alert("new")["status"] == "new"
    assert alert("grace")["status"] == "ack"      # the others keep theirs
