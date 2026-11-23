"""v1.1 drawer lane: the "seen on your network" lookup (GET/POST /api/netlog/seen) and the assessment fields on
entities (owner of an address, KEV due date and links). Temporary lake, synthetic Zeek logs on documentation
ranges, no network.

    uv run --with pytest pytest tests/netlog/test_seen.py -q
"""
from __future__ import annotations

import gzip
import io
import json
import time
from pathlib import Path

from _lake import make_lake
LAKE = make_lake("v11-drawer")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db  # noqa: E402
from osinthub.entities import api as eapi, store  # noqa: E402
from osinthub.netlog import api, devices, importer, incidents, seen, util  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
store.ensure_schema()
_app = FastAPI()
api.router.include_router(seen.router)
_app.include_router(api.router)
_app.include_router(eapi.router)
C = TestClient(_app)

MAC_A, MAC_B = "02:00:5e:00:00:0a", "02:00:5e:00:00:0b"
HOME_A, HOME_B = "192.0.2.10", "192.0.2.11"
T0 = time.time() - 2 * 86400
SHA1 = "ab" * 20


def ndjson(rows):
    return io.BytesIO("".join(json.dumps(r) + "\n" for r in rows).encode())


def conn(ts, src, dst, uid, mac=None, dport=443):
    r = {"ts": ts, "uid": uid, "id.orig_h": src, "id.orig_p": 50000, "id.resp_h": dst, "id.resp_p": dport, "proto": "tcp",
         "service": "ssl", "duration": 1.0, "orig_bytes": 500, "resp_bytes": 5000, "conn_state": "SF", "_path": "conn"}
    if mac:
        r["orig_l2_addr"] = mac
    return r


def dhcp(ts, mac, ip, name):
    return {"ts": ts, "uids": [f"D{mac[-2:]}"], "client_addr": ip, "server_addr": "192.0.2.1", "mac": mac,
            "host_name": name, "assigned_addr": ip, "lease_time": 86400.0, "msg_types": ["REQUEST", "ACK"], "_path": "dhcp"}


def world():
    s = util.settings()
    s["home_prefixes"] = ["192.0.2.0/24"]
    util.save_settings(s)
    rows = [dhcp(T0, MAC_A, HOME_A, "study-laptop"), dhcp(T0, MAC_B, HOME_B, "kitchen-speaker")]
    rows += [conn(T0 + 60 + i, HOME_A, "203.0.113.7", f"CA{i}", MAC_A) for i in range(3)]
    rows += [conn(T0 + 900, HOME_B, "203.0.113.7", "CB0", MAC_B)]
    rows += [conn(T0 + 120, HOME_B, "198.51.100.77", "CB1", MAC_B)]     # inside 198.51.100.64/26
    rows += [{"ts": T0 + 30, "uid": "N1", "id.orig_h": HOME_A, "id.orig_p": 5353, "id.resp_h": "192.0.2.1", "id.resp_p": 53,
              "proto": "udp", "query": "login.bad.example", "answers": ["203.0.113.99"], "_path": "dns"}]
    rows += [{"ts": T0 + 40, "uid": "S1", "id.orig_h": HOME_A, "id.orig_p": 50001, "id.resp_h": "203.0.113.50", "id.resp_p": 443,
              "server_name": "cdn.other.example", "_path": "ssl"}]
    rows += [{"ts": T0 + 41, "fuid": "F1", "uid": "S1", "tx_hosts": ["203.0.113.50"], "rx_hosts": [HOME_A], "conn_uids": ["S1"],
              "source": "SSL", "sha1": SHA1, "mime_type": "application/x-x509-user-cert", "_path": "files"}]
    rows += [{"ts": T0 + 50, "uid": "NT1", "id.orig_h": HOME_B, "id.orig_p": 445, "id.resp_h": "192.0.2.1", "id.resp_p": 50001,
              "note": "Software::Vulnerable_Version", "msg": "host runs a version vulnerable to CVE-2024-3400", "_path": "notice"}]
    assert importer.import_fileobj(ndjson(rows), "v11-drawer.log", origin="upload").get("inserted")
    # demo rows (origin "demo"): an address only the demo network contacted
    demo = [conn(T0 + 300, HOME_A, "203.0.113.200", "DM1", MAC_A), conn(T0 + 301, HOME_A, "203.0.113.7", "DM2", MAC_A)]
    assert importer.import_fileobj(ndjson(demo), "night-desk-demo-test.log", origin="demo").get("inserted")
    devices.rebuild()
    incidents.ensure()
    # one open incident on 203.0.113.7, one dismissed alert on the hash, and an alert whose rows are gone
    now = util.now()

    def alert(aid, ind, sev, status, device, observed=None, kind="ip"):
        ev = {"indicator": {"value": ind, "kind": kind, "category": "c2", "observed": [observed or ind]}}
        db.execute("""INSERT INTO alerts (id, ts, last_ts, severity, device, indicator, source, rule, direction, title, count,
                      evidence, status, created_at, updated_at, demo) VALUES (?, ?, ?, ?, ?, ?, 'feodo_c2', 'c2_outbound',
                      'outbound', ?, 1, ?, ?, ?, ?, false)""",
                   [aid, now, now, sev, device, ind, f"contact with {ind}", json.dumps(ev), status, now, now])
    alert("nl-test-open", "203.0.113.7", "high", "new", f"mac:{MAC_A}")
    alert("nl-test-dismissed", SHA1, "high", "dismissed", f"mac:{MAC_A}", kind="hash")
    alert("nl-test-gone", "198.51.100.200", "medium", "new", f"mac:{MAC_B}")
    alert("nl-test-cidr", "198.51.100.64/26", "medium", "ack", f"mac:{MAC_B}", observed="198.51.100.77", kind="cidr")
    with db._write_lock:
        incidents.regroup(db.cursor())


world()


def look(*vals, demo=False):
    db.set_setting("netlog_demo", {"status": "loaded"} if demo else None)
    r = C.get("/api/netlog/seen", params={"v": ",".join(vals)})
    assert r.status_code == 200, r.text
    return {i["value"]: i for i in r.json()["items"]}


def test_ip_seen_with_devices_and_open_incident():
    it = look("203.0.113.7")["203.0.113.7"]
    assert it["kind"] == "ip" and it["seen"] and it["rows"] == 4
    assert it["n_devices"] == 2 and {d["name"] for d in it["devices"]} == {"study-laptop", "kitchen-speaker"}
    assert it["incident"]["id"] == "nl-test-open" and it["incident"]["severity"] == "high"
    assert it["demo"] is False and it["demo_also"] is False      # demo not loaded: its row is ignored
    assert it["first"] < it["last"] and "conn" in it["log_types"]


def test_unseen_and_unknown_values():
    r = look("198.51.100.9", "not a value", "CVE-2099-0001")
    assert r["198.51.100.9"]["kind"] == "ip" and not r["198.51.100.9"]["seen"]
    assert r["not a value"]["kind"] == "unknown" and not r["not a value"]["seen"]
    assert r["CVE-2099-0001"]["kind"] == "cve" and not r["CVE-2099-0001"]["seen"]


def test_cidr_containment_and_dns_answers():
    r = look("198.51.100.64/26", "203.0.113.96/28", "198.51.100.0/27")
    c = r["198.51.100.64/26"]
    assert c["kind"] == "cidr" and c["seen"] and c["rows"] == 1 and c["devices"][0]["name"] == "kitchen-speaker"
    assert c["incident"]["id"] == "nl-test-cidr" and c["incident"]["state"] == "ack"   # acknowledged is still open
    assert r["203.0.113.96/28"]["seen"]          # 203.0.113.99 was only a DNS answer
    assert not r["198.51.100.0/27"]["seen"]
    # an address inside a listed range finds the range's alert through its observed value
    assert look("198.51.100.77")["198.51.100.77"]["incident"]["id"] == "nl-test-cidr"


def test_domain_matches_subdomains_sni_and_defanged_input():
    r = look("bad.example", "other[.]example", "domain:nothing.example", "hxxps://login.bad.example/path")
    assert r["bad.example"]["seen"] and r["bad.example"]["log_types"] == ["dns"]
    assert r["other[.]example"]["kind"] == "domain" and r["other[.]example"]["seen"]
    assert r["domain:nothing.example"]["normalized"] == "nothing.example" and not r["domain:nothing.example"]["seen"]
    assert r["hxxps://login.bad.example/path"]["normalized"] == "login.bad.example" and r["hxxps://login.bad.example/path"]["seen"]


def test_cert_hash_and_cve():
    r = look(SHA1.upper(), "cve-2024-3400")
    h = r[SHA1.upper()]
    assert h["kind"] == "hash" and h["seen"] and h["devices"][0]["name"] == "study-laptop"
    assert h["incident"] is None and h["alerts"] == 1        # dismissed: seen, but no open incident
    c = r["cve-2024-3400"]
    assert c["kind"] == "cve" and c["seen"] and c["log_types"] == ["notice"] and c["devices"][0]["name"] == "kitchen-speaker"


def test_alert_alone_is_seen():
    """Never a false "not on your network": an alert counts even when its rows are gone."""
    it = look("198.51.100.200")["198.51.100.200"]
    assert it["seen"] and it["rows"] == 0 and it["alerts"] == 1 and it["incident"]["id"] == "nl-test-gone"


def test_demo_rows_ignored_unless_loaded_then_marked():
    assert not look("203.0.113.200")["203.0.113.200"]["seen"]
    d = look("203.0.113.200", "203.0.113.7", demo=True)
    assert d["203.0.113.200"]["seen"] and d["203.0.113.200"]["demo"] is True
    assert d["203.0.113.7"]["demo"] is False and d["203.0.113.7"]["demo_also"] is True   # real data wins
    assert d["203.0.113.7"]["rows"] == 4
    db.set_setting("netlog_demo", None)


def test_post_batch_context_and_limits():
    r = C.post("/api/netlog/seen", json={"values": ["203.0.113.7", "203.0.113.7", "bad.example"], "context": True})
    assert r.status_code == 200
    j = r.json()
    assert len(j["items"]) == 2 and j["logs"]["rows"] > 0 and "ms" in j
    assert all("listed_by" in i and "owner" in i for i in j["items"])
    assert C.post("/api/netlog/seen", json={"values": "x"}).status_code == 400
    assert C.post("/api/netlog/seen", json={"values": [f"192.0.2.{i % 250}x{i}" for i in range(501)]}).status_code == 400


# ---------------------------------------------------------------- assessment fields on entities
def _ent(eid, attrs=None):
    t, name = eid.split(":", 1)
    db.execute("INSERT INTO entities (id, type, name, attrs) VALUES (?, ?, ?, ?)", [eid, t, name, json.dumps(attrs or {})])


def test_ip_owner_from_attributes():
    _ent("ip:203.0.113.7", {"asn": "AS64500", "as_name": "Example Hosting", "country": "NL"})
    d = C.get("/api/entities/ip:203.0.113.7").json()
    assert d["owner"] == {"asn": "AS64500", "name": "Example Hosting", "country": "NL"}


def test_cve_kev_due_date_and_links_from_the_record_file():
    _ent("cve:cve-2024-3400", {"kev": True})
    rel = "cisa_kev/2026/01/02/030405.records.ndjson.gz"
    p = Path(config.RAW_DIR) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    rec = {"cveID": "CVE-2024-3400", "vendorProject": "Example Vendor", "product": "Example OS", "dateAdded": "2024-04-12",
           "dueDate": "2024-04-19", "requiredAction": "Apply mitigations per vendor instructions.",
           "notes": "https://security.example.com/CVE-2024-3400 ; https://nvd.nist.gov/vuln/detail/CVE-2024-3400"}
    with gzip.open(p, "wt") as fh:
        fh.write(json.dumps({"key": "CVE-2024-3400", "op": "put", "data": rec}) + "\n")
    # recorded under another lake's path: resolved under this lake's raw/ folder
    db.execute("""INSERT INTO indicator_intervals (source, kind, value, "start", key, category, start_path)
                  VALUES ('cisa_kev', 'cve', 'CVE-2024-3400', now(), 'CVE-2024-3400', 'kev', ?)""", ["/Volumes/other/raw/" + rel])
    a = C.get("/api/entities/cve:cve-2024-3400").json()["attrs"]
    assert a["kev_due"] == "2024-04-19" and a["kev_vendor"] == "Example Vendor" and a["kev_product"] == "Example OS"
    assert a["kev_action"].startswith("Apply") and a["kev_links"][0] == "https://security.example.com/CVE-2024-3400"
    assert "epss_status" in a


def test_cve_without_record_file_has_no_due_date():
    _ent("cve:cve-2024-0001", {"kev": True})
    a = C.get("/api/entities/cve:cve-2024-0001").json()["attrs"]
    assert "kev_due" not in a


def test_home_address_names_its_own_device_not_the_gateway():
    it = look(HOME_A)[HOME_A]
    assert it["seen"] and [d["name"] for d in it["devices"]] == ["study-laptop"]


def test_ip_port_input_is_the_address():
    r = look("203.0.113.7:443", "[2001:db8::5]:8443")
    assert r["203.0.113.7:443"]["kind"] == "ip" and r["203.0.113.7:443"]["normalized"] == "203.0.113.7"
    assert r["203.0.113.7:443"]["seen"] and r["203.0.113.7:443"]["incident"]["id"] == "nl-test-open"
    assert r["[2001:db8::5]:8443"]["normalized"] == "2001:db8::5"
