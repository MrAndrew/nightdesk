"""v1.1 alerts: incidents across UTC midnight, "this is expected" rules, the one "needs you" count, demo and
found-later flags, migration of per-day alerts and their statuses.

    uv run --with pytest pytest tests/netlog/test_incidents.py -q
"""
from __future__ import annotations

import datetime as dt
import gzip
import io
import json
from pathlib import Path

from _lake import make_lake
LAKE = make_lake("netlog-v11-alerts")

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db  # noqa: E402
from osinthub.netlog import api, importer, incidents, intervals, matcher, util  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
UTC = dt.UTC
_app = FastAPI()
_app.include_router(api.router)
C = TestClient(_app)

# Yesterday 22:00 UTC: everything is listed well before the contacts.
MID = dt.datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)   # today 00:00 UTC
LISTED = MID - dt.timedelta(days=3)
C2, CMP, TOR, SCAN = "198.51.100.7", "198.51.100.20", "198.51.100.60", "203.0.113.9"
TV, LAPTOP, NAS = "192.0.2.30", "192.0.2.21", "192.0.2.50"


def rec(source: str, when: dt.datetime, lines: list[dict]) -> None:
    p = config.RAW_DIR / source / when.strftime("%Y/%m/%d") / f"{when.strftime('%H%M%S')}.records.ndjson.gz"
    p.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(p, "wt") as fh:
        for line in lines:
            fh.write(json.dumps(line) + "\n")


def conn(t: dt.datetime, uid: str, src: str, dst: str, dport: int = 443, state: str = "SF", mac: str | None = None) -> dict:
    r = {"ts": t.timestamp(), "uid": uid, "id.orig_h": src, "id.orig_p": 50000, "id.resp_h": dst, "id.resp_p": dport,
         "proto": "tcp", "conn_state": state, "orig_bytes": 300, "resp_bytes": 700, "duration": 1.0, "history": "ShADadFf"}
    if mac:
        r["orig_l2_addr"] = mac
    return r


def load(name: str, rows: list[dict]) -> dict:
    return importer.import_any(io.BytesIO("\n".join(json.dumps(r) for r in rows).encode()), name, origin="upload")


@pytest.fixture(scope="module")
def world():
    rec("feodo_c2", LISTED, [{"key": f"{C2}:443", "op": "put", "data": {"ip_address": C2, "port": 443, "malware": "QakBot"}}])
    rec("et_compromised", LISTED, [{"key": CMP, "op": "put", "data": CMP}])
    rec("tor_exits", LISTED, [{"key": TOR, "op": "put", "data": TOR}])
    rec("blocklist_de", LISTED, [{"key": SCAN, "op": "put", "data": SCAN}])
    intervals.refresh()
    s = util.settings()
    s["home_prefixes"] = util.unique_prefixes((s.get("home_prefixes") or []) + ["192.0.2.0/24"])
    util.save_settings(s)
    tvmac = "02:00:5e:00:53:30"
    # the TV beacons every 30 minutes from 23:00 to 01:30 UTC: one beacon across midnight
    beacon = [conn(MID + dt.timedelta(minutes=m), f"Cb{i}", TV, C2, mac=tvmac) for i, m in enumerate(range(-60, 91, 30))]
    # the laptop reaches a compromised host the day before yesterday and again yesterday (a daily habit)
    habit = [conn(MID - dt.timedelta(days=2, hours=-10), "Ch1", LAPTOP, CMP), conn(MID - dt.timedelta(days=1, hours=-9), "Ch2", LAPTOP, CMP)]
    # Tor from the laptop on two days far apart: two incidents
    tor = [conn(MID - dt.timedelta(days=3, hours=-12), "Ct1", LAPTOP, TOR), conn(MID + dt.timedelta(hours=1), "Ct2", LAPTOP, TOR)]
    # a scanner knocks on the NAS (refused), twice
    scan = [conn(MID - dt.timedelta(hours=5), "Cs1", SCAN, NAS, 22, "REJ"), conn(MID - dt.timedelta(hours=4), "Cs2", SCAN, NAS, 23, "REJ")]
    load("v11-world.log", beacon + habit + tor + scan)
    return True


def _alerts(indicator):
    return db.query("SELECT id, ts, status, incident FROM alerts WHERE indicator = ? ORDER BY ts", [indicator])


def _incs(**params):
    return C.get("/api/netlog/incidents", params={"limit": 0, **params}).json()


def test_midnight_beacon_is_one_incident(world):
    days = _alerts(C2)
    assert len(days) == 2, days                      # still one alert per UTC day underneath
    assert len({a["incident"] for a in days}) == 1   # but one incident
    inc = [i for i in _incs() if i["indicator"] == C2]
    assert len(inc) == 1
    i = inc[0]
    assert i["n_alerts"] == 2 and i["count"] == 6 and i["days"] == 2 and i["severity"] == "high"
    assert i["id"] == days[0]["id"] and sorted(i["alerts"]) == sorted(a["id"] for a in days)
    assert i["ts"] < MID.isoformat() < i["last_ts"]


def test_daily_habit_joins_but_far_apart_splits(world):
    assert len({a["incident"] for a in _alerts(CMP)}) == 1
    tor = _alerts(TOR)
    assert len(tor) == 2 and len({a["incident"] for a in tor}) == 2


def test_detail_carries_incident_and_all_rows(world):
    later = _alerts(C2)[1]["id"]
    d = C.get(f"/api/netlog/alerts/{later}").json()
    assert d["incident"]["id"] == _alerts(C2)[0]["id"] and d["incident"]["days"] == 2
    assert d["rows_total"] == 6 and len(d["rows"]) == 6   # the whole beacon, not just this day's rows


def test_ack_acts_on_the_whole_incident(world):
    first, second = (a["id"] for a in _alerts(C2))
    r = C.post(f"/api/netlog/alerts/{second}/status", json={"status": "ack"})
    assert r.status_code == 200
    assert {a["status"] for a in _alerts(C2)} == {"ack"}
    st = {r["id"]: r["status"] for r in db.query("SELECT * FROM netlog_alert_status")}
    assert st[first] == st[second] == "ack"             # survives a re-key like any status
    C.post("/api/netlog/incidents/status", json={"ids": [first], "status": "new"})
    assert {a["status"] for a in _alerts(C2)} == {"new"}


def test_statuses_survive_a_rehunt_and_old_alerts_migrate(world):
    first, second = (a["id"] for a in _alerts(C2))
    C.post(f"/api/netlog/alerts/{first}/status", json={"status": "dismissed"})
    # an older database: no incident column values yet
    db.execute("UPDATE alerts SET incident = NULL, demo = NULL")
    incidents._ready.clear()
    incidents.ensure()
    assert len({a["incident"] for a in _alerts(C2)}) == 1
    assert db.query("SELECT count(*) AS n FROM alerts WHERE demo IS NULL")[0]["n"] == 0
    matcher.match("true")
    assert {a["status"] for a in _alerts(C2)} == {"dismissed"}
    assert [i["state"] for i in _incs() if i["indicator"] == C2] == ["dismissed"]
    C.post(f"/api/netlog/alerts/{first}/status", json={"status": "new"})


def test_one_count_everywhere(world):
    c = C.get("/api/netlog/alerts/count").json()
    need = _incs(needs_you="true")
    assert c["needs_you"] == len(need) == c["high"] + c["medium"]
    assert all(i["state"] == "new" and i["severity"] in ("high", "medium") and not i["demo"] for i in need)
    s = C.get("/api/netlog/summary").json()
    assert s["needs_you"] == c["needs_you"] and s["alerts"]["high"] + s["alerts"]["medium"] == c["needs_you"]
    # the beacon counts once although it is two day-alerts
    assert sum(1 for i in need if i["indicator"] == C2) == 1


def test_expected_rule_hides_across_days_and_delete_restores(world):
    before = C.get("/api/netlog/alerts/count").json()
    a = _alerts(CMP)[-1]["id"]
    r = C.post("/api/netlog/rules", json={"from_alert": a, "scope": "device_indicator", "note": "the laptop's game launcher"})
    assert r.status_code == 200, r.text
    rule = r.json()
    assert rule["indicator"] == CMP and rule["device"] and rule["kind"] is None and rule["hits"]["alerts"] == 2
    inc = [i for i in _incs() if i["indicator"] == CMP]
    assert [i["state"] for i in inc] == ["expected"] and inc[0]["expected_rule"] == rule["id"]
    assert [i["indicator"] for i in _incs(status="expected")] == [CMP]
    assert not [i for i in _incs(status="new") if i["indicator"] == CMP]
    after = C.get("/api/netlog/alerts/count").json()
    assert after["needs_you"] == before["needs_you"] - 1 and after["expected"] == before["expected"] + 1
    # a future contact on a new day is hidden too
    load("v11-later.log", [conn(MID + dt.timedelta(hours=3), "Ch3", LAPTOP, CMP)])
    assert all(i["state"] == "expected" for i in _incs() if i["indicator"] == CMP)
    # edit, then delete: everything is back
    e = C.put(f"/api/netlog/rules/{rule['id']}", json={"note": "edited", "expires_days": 30}).json()
    assert e["note"] == "edited" and e["expires_at"]
    assert C.delete(f"/api/netlog/rules/{rule['id']}").status_code == 200
    assert all(i["state"] == "new" for i in _incs() if i["indicator"] == CMP)
    assert C.get("/api/netlog/alerts/count").json()["needs_you"] == before["needs_you"]
    assert C.delete(f"/api/netlog/rules/{rule['id']}").status_code == 404


def test_rule_scopes_and_expiry(world):
    a = _alerts(TOR)[0]["id"]
    bad = C.post("/api/netlog/rules", json={"device": "mac:x"})
    assert bad.status_code == 400
    assert C.post("/api/netlog/rules", json={"from_alert": "nl-nope", "scope": "indicator"}).status_code == 404
    r = C.post("/api/netlog/rules", json={"from_alert": a, "scope": "device_kind"}).json()
    assert r["kind"] == "tor:out" and r["indicator"] is None and r["hits"]["alerts"] == 2
    assert all(i["state"] == "expected" for i in _incs() if i["indicator"] == TOR)
    # an expiry in the past hides only contacts before it
    cut = (MID - dt.timedelta(days=1)).isoformat()
    C.put(f"/api/netlog/rules/{r['id']}", json={"expires_at": cut})
    st = sorted((i["ts"], i["state"]) for i in _incs() if i["indicator"] == TOR)
    assert [s for _, s in st] == ["expected", "new"]
    C.delete(f"/api/netlog/rules/{r['id']}")
    r2 = C.post("/api/netlog/rules", json={"from_alert": a, "scope": "indicator"}).json()
    assert r2["device"] is None and r2["indicator"] == TOR
    assert [x["id"] for x in C.get("/api/netlog/rules").json()] == [r2["id"]]
    C.delete(f"/api/netlog/rules/{r2['id']}")


def test_inbound_names_every_device_and_reads_right(world):
    a = db.query("SELECT * FROM alerts WHERE indicator = ?", [SCAN])
    assert a and a[0]["direction"] == "inbound"
    assert "connected to 1 home device" in a[0]["title"] and "blocklist" not in a[0]["title"].split(",")[0]
    t = db.query("SELECT title FROM alerts WHERE indicator = ?", [C2])[0]["title"]
    assert "a botnet controller (QakBot)" in t and "feodo_c2" not in t


def test_found_later_after_a_list_change(world):
    old = MID - dt.timedelta(hours=8)
    load("v11-before-listing.log", [conn(old, "Cf1", NAS, "198.51.100.99")])
    assert not db.query("SELECT 1 FROM alerts WHERE indicator = '198.51.100.99'")
    # the list adds it afterwards, with a grace window that reaches back over the contact
    rec("et_compromised", util.now() + dt.timedelta(minutes=5), [{"key": "198.51.100.99", "op": "put", "data": "198.51.100.99"}])
    intervals.refresh()
    s = util.settings(); s["grace_seconds"] = 86400; util.save_settings(s)
    try:
        matcher.rehunt()
        a = db.query("SELECT evidence FROM alerts WHERE indicator = '198.51.100.99'")
        assert a, "re-hunt found nothing"
        ev = json.loads(a[0]["evidence"])
        assert ev["found_later"]["imported_at"] < ev["found_later"]["listed_at"]
    finally:
        s["grace_seconds"] = 0; util.save_settings(s)
    # alerts raised at import carry no flag
    assert "found_later" not in json.loads(db.query("SELECT evidence FROM alerts WHERE indicator = ?", [C2])[0]["evidence"])


def test_demo_alerts_flagged_and_not_counted(world):
    before = C.get("/api/netlog/alerts/count").json()
    aid = _alerts(C2)[0]["id"]
    db.execute("UPDATE alerts SET demo = true WHERE indicator = ?", [C2])
    incidents.regroup(db.cursor())
    c = C.get("/api/netlog/alerts/count").json()
    assert c["needs_you"] == before["needs_you"] - 1 and c["demo"] == before["demo"] + 1
    assert [i["demo"] for i in _incs() if i["indicator"] == C2] == [True]
    assert not [i for i in _incs(needs_you="true") if i["indicator"] == C2]
    db.execute("UPDATE alerts SET demo = false WHERE indicator = ?", [C2])
    incidents.regroup(db.cursor())
    assert _alerts(C2)[0]["id"] == aid


def test_filters_on_incidents(world):
    assert C.get("/api/netlog/incidents", params={"status": "bogus"}).status_code == 400
    assert C.get("/api/netlog/incidents", params={"min_severity": "bogus"}).status_code == 400
    hi = _incs(severity="high")
    assert hi and all(i["severity"] == "high" for i in hi)
    q = _incs(q="QakBot")
    assert [i["indicator"] for i in q] == [C2]
    summ = C.get("/api/netlog/incidents/summary").json()
    assert summ["total"] == len(_incs()) and sum(summ["severity"].values()) == summ["total"]


def test_p2p_swarm_across_the_hour_is_capped(world):
    """A swarm of 19 peers over 27 minutes from HH:50 straddles two clock hours; it is still a swarm."""
    peer = "198.51.100.150"
    rec("cins_army", LISTED + dt.timedelta(minutes=1), [{"key": peer, "op": "put", "data": peer}])
    intervals.refresh()
    base = MID - dt.timedelta(hours=6, minutes=10)
    rows = []
    for k, p in enumerate([f"198.51.100.{160 + k}" for k in range(18)] + [peer]):
        r = conn(base + dt.timedelta(seconds=90 * k), f"Cp{k}", NAS, p, 40000 + k)
        r.update({"id.orig_p": 51413, "proto": "udp", "orig_bytes": 40000, "resp_bytes": 900000})
        rows.append(r)
    load("v11-swarm.log", rows)
    a = db.query("SELECT severity, rule FROM alerts WHERE indicator = ?", [peer])
    assert a and a[0]["severity"] == "low" and a[0]["rule"].endswith("_p2p"), a


SINK_FIX = Path(__file__).resolve().parents[2] / "osinthub" / "netlog" / "fixtures" / "sinkhole"


def _adguard(t: dt.datetime, client: str, name: str, blocked: bool) -> str:
    res = {"IsFiltered": True, "Reason": 3, "Rules": [{"Text": f"||{name}^", "FilterListID": 2}]} if blocked else {}
    return json.dumps({"T": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "QH": name, "QT": "A", "QC": "IN", "CP": "", "IP": client,
                       "Result": res, "Elapsed": 5})


def test_sinkhole_verdict_shown_and_all_blocked_lowers(world):
    dom = "c2-relay.example"
    rec("cins_army", LISTED + dt.timedelta(minutes=2), [{"key": dom, "op": "put", "data": dom}])
    intervals.refresh()
    s = util.settings()
    s["home_prefixes"] = util.unique_prefixes(s["home_prefixes"] + ["10.86.24.0/24"])
    util.save_settings(s)
    # the fixtures: Pi-hole and AdGuard logs that look the listed domain up (blocked and allowed)
    for f in ("adguard-querylog.json", "pihole-extra.log"):
        importer.import_any(io.BytesIO((SINK_FIX / f).read_bytes()), f, origin="upload")
    ev = [json.loads(a["evidence"]) for a in db.query("SELECT evidence FROM alerts WHERE indicator = ?", [dom])]
    assert ev and all("sinkhole" in e for e in ev)
    assert {x for e in ev for x in e["sinkhole"]["sources"]} <= {"pihole", "adguard"}
    # one device whose every lookup was blocked (two days), one that was allowed through
    t = MID - dt.timedelta(hours=2)
    load_lines = "\n".join([_adguard(t, "10.86.24.91", dom, True), _adguard(t + dt.timedelta(hours=3), "10.86.24.91", dom, True),
                            _adguard(t, "10.86.24.92", dom, False)])
    importer.import_any(io.BytesIO(load_lines.encode()), "querylog-v11.json", origin="upload")
    blocked = db.query("SELECT severity, title, evidence FROM alerts WHERE indicator = ? AND device = 'ip:10.86.24.91'", [dom])
    allowed = db.query("SELECT severity, evidence FROM alerts WHERE indicator = ? AND device = 'ip:10.86.24.92'", [dom])
    assert blocked and allowed
    sb, sa = json.loads(blocked[0]["evidence"])["sinkhole"], json.loads(allowed[0]["evidence"])["sinkhole"]
    assert sb["all_blocked"] and sb["blocked"] == sb["rows"] and sb["lowered_from"] == allowed[0]["severity"]
    order = ["info", "low", "medium", "high"]
    assert order.index(blocked[0]["severity"]) == order.index(allowed[0]["severity"]) - 1
    assert "blocked by AdGuard Home" in blocked[0]["title"]
    assert not sa["all_blocked"] and sa["allowed"] == 1 and "lowered_from" not in sa
    # the incident (both days) carries the lowered severity
    inc = [i for i in _incs() if i["indicator"] == dom and i["device"] == "ip:10.86.24.91"]
    assert len(inc) == 1 and inc[0]["severity"] == blocked[0]["severity"]


def test_two_lists_on_one_contact_are_one_incident(world):
    ip = "198.51.100.77"
    rec("blocklist_de", LISTED + dt.timedelta(minutes=3), [{"key": ip, "op": "put", "data": ip}])
    rec("spamhaus_drop", LISTED + dt.timedelta(minutes=3), [{"key": "198.51.100.64/26", "op": "put", "data": {"cidr": "198.51.100.64/26", "sblid": "SBL9"}}])
    intervals.refresh()
    load("v11-twolists.log", [conn(MID - dt.timedelta(hours=7), "Cl1", LAPTOP, ip)])
    days = db.query("SELECT id, source, incident FROM alerts WHERE json_extract_string(evidence, '$.indicator.observed[0]') = ?", [ip])
    assert {d["source"] for d in days} == {"blocklist_de", "spamhaus_drop"}
    assert len({d["incident"] for d in days}) == 1
    inc = [i for i in _incs() if i["id"] == days[0]["incident"]]
    assert len(inc) == 1 and set(inc[0]["sources"]) == {"blocklist_de", "spamhaus_drop"} and inc[0]["n_alerts"] == 2
    need = [i for i in _incs(needs_you="true") if set(i["alerts"]) & {d["id"] for d in days}]
    assert len(need) <= 1


def test_news_quote_is_plain_and_whole_words():
    t = "Intro words here. - [198.51.100.5\\[.\\]](https://example.com/x) | **C2** server | seen\nMore."
    q = api._quote(t, "198.51.100.5", intervals)
    assert q and "](" not in q and "**" not in q and "|" not in q and "\\" not in q and "198[.]51.100.5" in q
    long = "word " * 80 + "198.51.100.6 " + "tail " * 80
    q2 = api._quote(long, "198.51.100.6", intervals)
    assert q2.startswith("… word") and q2.endswith("tail…")


def test_new_rule_with_a_past_expiry_is_refused(world):
    a = _alerts(TOR)[0]["id"]
    r = C.post("/api/netlog/rules", json={"from_alert": a, "scope": "indicator", "expires_at": "2000-01-01T00:00:00Z"})
    assert r.status_code == 400


def test_device_counts_follow_the_count_rule(world):
    need = _incs(needs_you="true")
    devs = {d["id"]: d for d in C.get("/api/netlog/devices", params={"limit": 0}).json()}
    for i in need:
        if i["device"] in devs:
            assert devs[i["device"]]["alerts_high_medium"] >= 1
    assert sum(d["alerts_high_medium"] for d in devs.values()) == sum(1 for i in need if i["device"] in devs)
