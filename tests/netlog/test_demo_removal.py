"""v1.1 finisha: the demo never plants phantom devices, removing it leaves no residue (names, merges, rules made only
for it, its place in the new-device memory), every alert says whether it is still happening, and a note on an
incident shows the incident's title as it reads now.

    uv run --with pytest pytest tests/netlog/test_demo_removal.py -q
"""
from __future__ import annotations

import datetime as dt
import io
import ipaddress
import json

from _lake import make_lake
LAKE = make_lake("netlog-v11-finisha")

import pytest  # noqa: E402

from osinthub import db, search_all  # noqa: E402
from osinthub.netlog import api, demo, devices, importer, incidents, util  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402
from osinthub.notes import store  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
db.cursor().execute(store.SCHEMA)
devices.ensure_tables()
UTC = dt.UTC
REAL_MAC = "02:00:5e:10:00:01"
REAL_DEV = f"mac:{REAL_MAC}"   # a device of "yours" (documentation MAC block), never part of the demo


# ------------------------------------------------------------------ the generator never plants a private contact
def _demo_net(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return any(a in ipaddress.ip_network(p) for p in demo.DEMO_PREFIXES)


# The sites the demo browses sit on documentation addresses (the shipped list carries no real ones), clear of the
# demo's home: they read as remote, like public addresses.
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def _remote(a) -> bool:
    return a.is_global or any(a in n for n in DOC_NETS if n.version == a.version)


def test_popular_domains_answer_only_documentation_addresses():
    doms = demo.popular_domains()
    assert len(doms) >= 25 and all(d["a"] for d in doms)   # each device samples 25 sites
    for d in doms:
        for x in d["a"] + d["aaaa"]:
            a = ipaddress.ip_address(x)
            assert any(a in n for n in DOC_NETS if n.version == a.version) and not _demo_net(x), (d["domain"], x)


def test_no_seed_contacts_a_private_address():
    """Over 40 seeds every address is the demo's own home or a remote one (public or documentation), never another
    private network."""
    for seed in range(1, 41):
        files, _ = demo.build(seed=seed)
        for name in ("conn.log", "dns.log", "ssl.log"):
            for line in files.get(name, b"").decode().splitlines():
                r = json.loads(line)
                for ip in (r.get("id.orig_h"), r.get("id.resp_h"), *(r.get("answers") or [])):
                    if not ip or not any(c in ip for c in ".:"):
                        continue
                    try:
                        a = ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    assert _demo_net(ip) or _remote(a), (seed, name, ip)


# ------------------------------------------------------------------ F2: removing the demo leaves no residue
@pytest.fixture(scope="module")
def loaded():
    res = demo.load(seed=7)
    yield res
    if demo.state():
        demo.unload()


def _demo_alert() -> dict:
    incidents.ensure()
    return db.query("SELECT id, device, indicator FROM alerts WHERE coalesce(demo, false) ORDER BY id LIMIT 1")[0]


def test_demo_devices_are_real_devices_of_the_demo(loaded):
    ids = [r["id"] for r in db.query("SELECT id FROM devices")]
    assert ids and all(demo.is_demo_device(i) for i in ids), ids   # no phantom device on an empty lake
    assert not demo.is_demo_device(REAL_DEV) and not demo.is_demo_device("ip:192.0.2.10")


def test_status_and_still_happening_on_a_demo_alert(loaded):
    a = _demo_alert()
    d = api.alert_detail(a["id"], 50, 0)
    s = d["still"]
    assert s and s["state"] in ("ongoing", "stopped", "unknown") and s["source"] == "demo"
    assert s["source_label"] == "Suricata logs in the demo" and s["covered_to"]
    assert "likely" in s["text"] or s["text"].startswith("Can't tell")


def test_note_shows_the_incident_title_as_it_reads_now(loaded):
    a = _demo_alert()
    inc = db.query("SELECT coalesce(incident, id) AS i FROM alerts WHERE id = ?", [a["id"]])[0]["i"]
    n = store.create("incident", inc, "Looked at the doorbell firmware.", "Demo-doorbell did a thing (old title)")
    devices.set_label(a["device"], {"name": "Front door camera"})
    got = store.get(n["id"])
    assert "Front door camera" in got["title"] and got["incident"]["device_name"] == "Front door camera"
    assert "old title" not in got["title"]
    # the Notes list and global search find it by the new name, and the line under a title match is never empty
    assert [x["id"] for x in store.search("front door")["notes"]] == [n["id"]]
    items, total = search_all.notes_group("front door camera", search_all.Ctx("front door camera", 5))
    assert total == 1 and items[0]["incident"]["device_name"] == "Front door camera"
    assert items[0]["why"]["text"]


def _real_files(rows: list[dict], name: str) -> None:
    importer.import_any(io.BytesIO("\n".join(json.dumps(r) for r in rows).encode()), name, origin="upload")
    devices.rebuild()


def _real_conn(ts: dt.datetime, mac: str, ip: str, dst: str) -> dict:
    return {"ts": ts.timestamp(), "uid": f"Creal{ts.timestamp():.0f}{ip}", "id.orig_h": ip, "id.orig_p": 50000,
            "id.resp_h": dst, "id.resp_p": 443, "proto": "tcp", "conn_state": "SF", "orig_bytes": 500,
            "resp_bytes": 900, "duration": 1.0, "orig_l2_addr": mac}


def _ids(xs):
    return sorted(x["id"] for x in xs)


def test_removal_plan_decides_by_what_things_reference(loaded):
    """Evaluator round 1: a rule, merge or name is removed only when everything it references is demo-only."""
    s = util.settings()
    s["home_prefixes"] = util.unique_prefixes((s.get("home_prefixes") or []) + ["192.0.2.0/24"] + demo.DEMO_PREFIXES)
    util.save_settings(s)
    now = dt.datetime.now(UTC)
    _real_files([_real_conn(now - dt.timedelta(hours=2), REAL_MAC, "192.0.2.10", "198.51.100.7")], "real-conn.log")
    assert db.query("SELECT 1 FROM devices WHERE id = ?", [REAL_DEV])
    a = _demo_alert()
    demo_devs = [r["id"] for r in db.query("SELECT id FROM devices") if demo.is_demo_device(r["id"])]
    other = next(d for d in demo_devs if d != a["device"])
    # removed: demo-device rule; device-less rule on a demo-only indicator made from the alert AND typed by hand
    r_dev = incidents.create_rule({"from_alert": a["id"], "scope": "device_indicator"})
    r_ind = incidents.create_rule({"from_alert": a["id"], "scope": "indicator"})
    r_typed = incidents.create_rule({"indicator": a["indicator"]})
    # kept: scoped to your device; made ahead of time for an indicator seen nowhere
    r_real = incidents.create_rule({"device": REAL_DEV, "indicator": a["indicator"]})
    r_ahead = incidents.create_rule({"indicator": "198.51.100.99"})
    devices.merge(other, a["device"])            # demo + demo: removed
    devices.merge(REAL_DEV, a["device"])          # yours into a demo device: un-merged, not counted as a demo merge
    plan = demo.verify()["your_changes"]
    assert _ids(plan["remove"]["rules"]) == sorted([r_dev["id"], r_ind["id"], r_typed["id"]])
    assert _ids(plan["remove"]["merges"]) == [other]
    assert _ids(plan["unmerge"]) == [REAL_DEV]
    assert {r_real["id"], r_ahead["id"]}.isdisjoint(_ids(plan["remove"]["rules"]))
    # the confirmation reads in device names: "<demo> merged into <name>", "<yours> stands alone again", no raw MACs
    import re
    m_txt, u_txt = plan["remove"]["merges"][0]["text"], plan["unmerge"][0]["text"]
    assert " merged into " in m_txt and u_txt.endswith(" stands alone again")
    for t in (m_txt, u_txt):
        assert "mac:" not in t and not re.search(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", t), t
    a_, _, b_ = m_txt.partition(" merged into ")
    assert a_ != b_

    res = demo.unload()
    # the confirmation and the deletion are the same plan
    assert _ids(res["plan"]["remove"]["rules"]) == _ids(plan["remove"]["rules"]) and res["removed_rules"] == 3
    assert res["removed_merges"] == 1 and res["unmerged"] == 1
    left = {r["id"] for r in db.query("SELECT id FROM netlog_rules")}
    assert left == {r_real["id"], r_ahead["id"]}
    assert not db.query("SELECT 1 FROM netlog_device_merges")
    assert db.query("SELECT 1 FROM devices WHERE id = ?", [REAL_DEV])   # your device stands alone again
    assert not [r for r in db.query("SELECT id FROM netlog_device_labels") if demo.is_demo_device(r["id"])]
    assert not [r for r in db.query("SELECT id FROM netlog_known_devices") if demo.is_demo_device(r["id"])]
    for rid in left:
        incidents.delete_rule(rid)


def test_rule_whose_indicator_is_also_real_is_kept_and_real_incident_stays_hidden():
    """Evaluator round 1, case 1: a device-less rule made from a demo alert whose indicator ALSO matches your data."""
    now = dt.datetime.now(UTC)
    eve = {"timestamp": (now - dt.timedelta(hours=1)).isoformat(), "flow_id": 9_200_000_000_001, "event_type": "alert",
           "src_ip": "192.0.2.10", "src_port": 49000, "dest_ip": "198.51.100.8", "dest_port": 80, "proto": "TCP",
           "alert": {"action": "allowed", "gid": 1, "signature_id": 2099001, "rev": 1, "signature": "Same signature, your camera",
                     "category": "A Network Trojan was detected", "severity": 1}}
    _real_files([eve], "real-eve.json")
    real = db.query("SELECT id FROM alerts WHERE indicator = 'sid:2099001' AND NOT coalesce(demo, false)")
    assert real
    demo.load(seed=7)
    try:
        a = _demo_alert()
        assert a["indicator"] == "sid:2099001"
        r = incidents.create_rule({"from_alert": a["id"], "scope": "indicator"})
        plan = demo.verify()["your_changes"]
        assert r["id"] in _ids(plan["keep"]["rules"]) and r["id"] not in _ids(plan["remove"]["rules"])
    finally:
        res = demo.unload()
    assert res["removed_rules"] == 0 and res["kept_rules"] == 1
    assert db.query("SELECT 1 FROM netlog_rules WHERE id = ?", [r["id"]])
    st = db.query(incidents.incidents_sql("WHERE coalesce(incident, id) = (SELECT coalesce(incident, id) FROM alerts WHERE id = ?)"),
                  [real[0]["id"]])[0]["state"]
    assert st == "expected"   # the real incident did not reappear
    incidents.delete_rule(r["id"])


def test_next_demo_lands_on_a_counted_alert_again():
    if demo.state():
        demo.unload()
    res = demo.load(seed=7)
    try:
        row = db.query(incidents.incidents_sql("WHERE coalesce(incident, id) = (SELECT coalesce(incident, id) FROM alerts WHERE id = ?)"),
                       [res["top_alert"]])[0]
        assert row["state"] == "new"   # not silently hidden by a rule left over from the last demo
    finally:
        demo.unload()


# ------------------------------------------------------------------ still happening: the three states in words
def _file(fid: str, origin: str, ts_max: dt.datetime) -> None:
    db.execute("""INSERT OR REPLACE INTO netlog_files (id, name, path, origin, imported_at, ts_max, status)
                  VALUES (?, ?, '', ?, now(), ?, 'ok')""", [fid, fid, origin, ts_max])


def test_still_happening_states():
    now = dt.datetime.now(UTC)
    _file("f-current", "upload", now - dt.timedelta(minutes=20))
    s = api.still_happening(now - dt.timedelta(hours=3, minutes=20), ["upload"])
    assert s["state"] == "ongoing" and s["text"] == "Last contact 3 h before your logs end — likely ongoing"
    s = api.still_happening(now - dt.timedelta(days=2, hours=1), ["upload"])
    assert s["state"] == "stopped" and s["text"] == "No contact for 2 days; logs are current — likely stopped"
    _file("f-old", "inbox", now - dt.timedelta(days=3, hours=2))
    s = api.still_happening(now - dt.timedelta(days=3, hours=4), ["inbox"])
    assert s["state"] == "unknown" and s["text"].startswith("Can't tell: your logs are 3 days old")
    s = api.still_happening(now, ["push:nobody"])
    assert s["state"] == "unknown"
    s = api.still_happening(now - dt.timedelta(hours=1), ["upload"], device=True)
    assert s["text"].endswith("likely still on your network")
    db.execute("DELETE FROM netlog_files WHERE id IN ('f-current', 'f-old')")


def test_still_happening_uses_the_same_sensor_not_the_whole_source():
    """Nit, round 1: a newer upload of other logs must not make an old incident read 'logs are current'."""
    now = dt.datetime.now(UTC)
    _file("f-dns", "upload", now - dt.timedelta(days=3))
    _file("f-conn", "upload", now - dt.timedelta(minutes=5))
    db.execute("""INSERT INTO netlog (rk, file_id, ts, uid, log_type, orig_h, query) VALUES
                  (9900001, 'f-dns', ?, 'Dsens1', 'dns', '192.0.2.10', 'example.org'),
                  (9900002, 'f-conn', ?, 'Csens1', 'conn', '192.0.2.10', NULL)""",
               [now - dt.timedelta(days=3), now - dt.timedelta(minutes=5)])
    try:
        whole = api.still_happening(now - dt.timedelta(days=3, hours=1), ["upload"])
        same = api.still_happening(now - dt.timedelta(days=3, hours=1), ["upload"], log_types=["dns"])
        assert same["state"] == "unknown" and same["source_label"] == "DNS logs from files you uploaded"
        assert whole["covered_to"] != same["covered_to"]
    finally:
        db.execute("DELETE FROM netlog WHERE rk IN (9900001, 9900002)")
        db.execute("DELETE FROM netlog_files WHERE id IN ('f-dns', 'f-conn')")
