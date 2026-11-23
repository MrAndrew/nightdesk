"""Demo data: every planted scenario raises the alert it should, ordinary demo traffic raises nothing high or
medium, and removing the demo leaves the user's own logs, devices, alerts and settings exactly as they were.

    uv run --with pytest pytest tests/netlog/test_demo.py -q
"""
from __future__ import annotations

import datetime as dt
import gzip
import io
import json
import re
from pathlib import Path

from _lake import make_lake
LAKE = make_lake("netlog-demo")

import pytest  # noqa: E402

from osinthub import config, db  # noqa: E402
from osinthub.netlog import api, demo, importer, intervals, util  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

from _lake import ROOT, client  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
C = client(api.router)
UTC = dt.UTC
NOW = dt.datetime.now(UTC)
LISTED = NOW - dt.timedelta(days=2)


def rec(source: str, when: dt.datetime, lines: list[dict]) -> None:
    p = config.RAW_DIR / source / when.strftime("%Y/%m/%d") / f"{when.strftime('%H%M%S')}.records.ndjson.gz"
    p.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(p, "wt") as fh:
        for line in lines:
            fh.write(json.dumps(line) + "\n")


def put(key, data):
    return {"key": key, "op": "put", "data": data}


def snapshot():
    return {"rows": db.query("SELECT count(*) AS n FROM netlog")[0]["n"],
            "alerts": sorted((a["id"], a["severity"], a["count"]) for a in db.query("SELECT id, severity, count FROM alerts")),
            "devices": sorted((d["id"], d["rows"]) for d in db.query("SELECT id, rows FROM devices")),
            "prefixes": util.settings()["home_prefixes"],
            "agg": db.query("SELECT sum(rows) AS r, sum(bo) AS bo FROM netlog_agg_ip")[0]}


def setup_world() -> dict:
    """Lists replayed from record files, and the user's own network: one device that also contacted an ET address."""
    rec("feodo_c2", LISTED, [put("45.13.0.10:443", {"ip_address": "45.13.0.10", "port": 443, "malware": "QakBot",
                                                    "first_seen": (NOW - dt.timedelta(days=200)).strftime("%Y-%m-%d %H:%M:%S"),
                                                    "last_online": (NOW - dt.timedelta(days=100)).strftime("%Y-%m-%d")})])
    rec("spamhaus_drop", LISTED, [put("45.13.8.0/24", {"cidr": "45.13.8.0/24", "sblid": "SBL1"})])
    rec("et_compromised", LISTED, [put("45.13.0.20", "45.13.0.20")])
    rec("blocklist_de", LISTED, [put("45.13.0.30", "45.13.0.30")])
    rec("dshield_top", LISTED, [put("45.13.0.40", {"ip": "45.13.0.40"}), put("45.13.0.41", {"ip": "45.13.0.41"})])
    rec("dshield_top", NOW - dt.timedelta(days=1), [{"key": "45.13.0.41", "op": "del"}])   # left the list: historical
    rec("cins_army", LISTED, [put("45.13.0.50", "45.13.0.50"), put("45.13.0.51", "45.13.0.51")])
    rec("tor_exits", LISTED, [put("45.13.0.60", "45.13.0.60")])
    rec("cisa_kev", LISTED, [put("CVE-2024-3400", {"vulnerabilityName": "PAN-OS command injection"})])
    rec("sslbl", LISTED, [put("a" * 40, {"sha1": "a" * 40, "reason": "QakBot C&C",
                                         "listing_date": LISTED.strftime("%Y-%m-%d %H:%M:%S")})])
    intervals.refresh()
    s = util.settings()
    s["home_prefixes"] = util.unique_prefixes((s.get("home_prefixes") or []) + ["192.0.2.0/24"])
    util.save_settings(s)
    own = "\n".join(json.dumps(r) for r in [
        {"ts": (NOW - dt.timedelta(hours=3)).timestamp(), "uid": "CdemoOwn1", "id.orig_h": "192.0.2.10", "id.orig_p": 50000,
         "id.resp_h": "45.13.0.20", "id.resp_p": 443, "proto": "tcp", "conn_state": "SF", "orig_bytes": 500,
         "resp_bytes": 900, "duration": 1.0, "history": "ShADadFf"},
        {"ts": (NOW - dt.timedelta(hours=2)).timestamp(), "uid": "CdemoOwn2", "id.orig_h": "192.0.2.10", "id.orig_p": 50001,
         "id.resp_h": "93.184.216.34", "id.resp_p": 443, "proto": "tcp", "conn_state": "SF", "orig_bytes": 500,
         "resp_bytes": 900, "duration": 1.0, "history": "ShADadFf"}]).encode()
    importer.import_any(io.BytesIO(own), "own-conn.log", origin="upload")
    return snapshot()


EXPECTED = {"feodo_c2", "feodo_retro", "drop_cidr", "et_compromised", "attacker_accepted", "scanner_probe", "cins_inbound",
            "p2p_cap", "tor_exit", "sslbl_cert", "kev_notice", "suricata_alert", "historical"}


@pytest.fixture(scope="module")
def world():
    return setup_world()


@pytest.fixture(scope="module")
def loaded(world):
    res = demo.load(seed=3)
    paths = [Path(f["path"]) for f in db.query("SELECT path FROM netlog_files WHERE origin = 'demo'")]
    assert paths and all(p.exists() for p in paths)   # stored copies exist while loaded
    res["_paths"] = paths
    yield res
    if demo.state():
        demo.unload()


def test_every_scenario_raises_its_alert(loaded):
    got = {s["id"]: s for s in loaded["scenarios"]}
    assert EXPECTED <= set(got), EXPECTED - set(got)
    bad = {k: (v["why"], v["alert"]) for k, v in got.items() if not v["ok"]}
    assert not bad, bad
    assert loaded["passed"] == loaded["total"]


def test_no_false_alarms_and_devices_recognised(loaded):
    assert loaded["false_positives"] == []
    assert loaded["devices"] == {"found": len(demo.DEVICES), "expected": len(demo.DEVICES)}
    laptop = db.query("SELECT ips FROM devices WHERE list_contains(hostnames, 'demo-laptop')")[0]
    assert demo.eui64(demo.DEV["demo-laptop"][2]) in laptop["ips"]   # IPv6 joined to the laptop by its MAC


def test_demo_prefixes_added_and_second_load_refused(loaded):
    assert set(demo.DEMO_PREFIXES) <= set(util.settings()["home_prefixes"])
    with pytest.raises(ValueError):
        demo.load()


def test_user_alerts_untouched_while_loaded(world, loaded):
    own = set(world["alerts"])
    now = {(a["id"], a["severity"], a["count"]) for a in db.query("SELECT id, severity, count FROM alerts")}
    assert own <= now


# ------------------------------------------------------------------ what the Network view reads from a loaded demo
def _ids_alert(loaded):
    for s in loaded["scenarios"]:
        if s["id"] == "suricata_alert" and s.get("alert"):
            return s["alert"]["id"]
    pytest.skip("the Suricata scenario was not planted")


def test_summary_demo_count_follows_the_range(loaded):
    """The Network header's demo count and its "new" count on one line come from the same range."""
    allr = C.get("/api/netlog/incidents/summary").json()
    cnt = C.get("/api/netlog/alerts/count").json()
    assert allr["demo_new"] == cnt["demo"]                      # all time: the badge's demo count
    old = C.get("/api/netlog/incidents/summary", params={"until": "2000-01-01T00:00:00Z"}).json()
    assert old["demo_new"] == 0 and old["state"].get("new", 0) == 0
    assert allr["demo_new"] <= allr["state"].get("new", 0)


def test_alert_count_takes_the_range(loaded):
    allr = C.get("/api/netlog/alerts/count").json()
    wide = C.get("/api/netlog/alerts/count", params={"since": "2000-01-01T00:00:00Z"}).json()
    old = C.get("/api/netlog/alerts/count", params={"until": "2000-01-01T00:00:00Z"}).json()
    for k in ("needs_you", "high", "medium", "low", "info", "demo", "open"):
        assert wide[k] == allr[k] and old[k] == 0, k
    inc = C.get("/api/netlog/incidents/summary", params={"since_hours": 24}).json()
    day = C.get("/api/netlog/alerts/count", params={"since_hours": 24}).json()
    assert day["demo"] == inc["demo_new"]                        # header demo == card demo for the same range


def test_ids_alert_and_its_rule_name_the_signature(loaded):
    """An intrusion alert names its signature in words; so does an "expected" rule made from it (sid in a tooltip)."""
    aid = _ids_alert(loaded)
    d = C.get(f"/api/netlog/alerts/{aid}").json()
    ind = d["evidence"]["indicator"]
    assert ind["kind"] == "signature" and d["indicator"].startswith("sid:")
    name = ind["observed"][0]
    assert name and not name.startswith("sid:") and " " in name
    r = C.post("/api/netlog/rules", json={"from_alert": aid, "scope": "indicator"})
    assert r.status_code == 200, r.text
    try:
        rule = [x for x in C.get("/api/netlog/rules").json() if x["id"] == r.json()["id"]][0]
        assert rule["indicator"].startswith("sid:") and " " in rule["indicator_label"]
    finally:
        C.delete(f"/api/netlog/rules/{r.json()['id']}")


def test_triage_of_a_removed_alert_reports_nothing_updated():
    r = C.post("/api/netlog/incidents/status", json={"ids": ["nl-does-not-exist"], "status": "ack"}).json()
    assert r["updated"] == 0                                    # the client says "no longer exists", never "done"


def test_every_skip_cause_has_a_card_line(loaded):
    """Every reason the demo gives for a scenario it left out has a plain-language line on the demo card."""
    js = (ROOT / "web/js/views/net/demo.js").read_text()
    keys = set(re.findall(r"(\w+): '", js[js.index("const LEFT_WHY"):js.index("export function leftOutLine")]))
    causes = set(re.findall(r'"cause": "(\w+)"', (ROOT / "osinthub/netlog/demo.py").read_text()))
    assert causes and causes <= keys, causes - keys
    assert {s["cause"] for s in loaded["skipped"]} <= keys


def test_unload_restores_everything(world, loaded):
    res = demo.unload()
    assert res["removed_rows"] > 1000 and res["removed_alerts"] >= len(EXPECTED) - 2
    assert snapshot() == world
    assert not db.query("SELECT 1 FROM netlog_files WHERE origin = 'demo'")
    assert not db.query("SELECT 1 FROM netlog_matches WHERE uid LIKE 'CND%' OR uid LIKE 'CNB%'")
    assert demo.verify() == {"loaded": False, "scenarios": []}
    assert not any(p.exists() for p in loaded["_paths"])


def test_bundle_is_importable_by_hand():
    files, plan = demo.build(seed=5)
    import tarfile
    with tarfile.open(fileobj=io.BytesIO(demo.bundle(files, plan))) as tf:
        names = {m.name.split("/")[-1] for m in tf.getmembers()}
    assert {"conn.log", "dns.log", "dhcp.log", "eve.json", ".README.txt", ".plan.json"} <= names
