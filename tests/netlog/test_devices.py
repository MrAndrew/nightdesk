"""Device names, types, merges and log freshness (v1.1 devices lane), on a temporary lake with synthetic Zeek logs.

    uv run --with pytest pytest tests/netlog/test_devices.py -q
"""
from __future__ import annotations

import io
import json
import time

from _lake import make_lake
LAKE = make_lake("netlog-v11-devices")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db  # noqa: E402
from osinthub.netlog import api, devices, importer, util  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
_app = FastAPI()
_app.include_router(api.router)
C = TestClient(_app)

MAC_A, MAC_B, MAC_C, MAC_D = "02:00:5e:00:00:0a", "02:00:5e:00:00:0b", "02:00:5e:00:00:0c", "02:00:5e:00:00:0d"
V6_LONE = "2001:db8::51a5:77"         # a privacy address with no MAC evidence
UUID_NAME = "0f8ce13d-bfa9-443c-9f7b-fef653ce1c8d"
T0 = time.time() - 3 * 86400          # three days ago: stale under the default 24 h threshold


def ndjson(rows: list[dict]) -> io.BytesIO:
    return io.BytesIO("".join(json.dumps(r) + "\n" for r in rows).encode())


def dhcp(ts, mac, ip, name):
    return {"ts": ts, "uids": [f"D{mac[-2:]}"], "client_addr": ip, "server_addr": "192.0.2.1", "mac": mac,
            "host_name": name, "assigned_addr": ip, "lease_time": 86400.0, "msg_types": ["REQUEST", "ACK"], "_path": "dhcp"}


def conn(ts, src, dst, uid, mac=None):
    r = {"ts": ts, "uid": uid, "id.orig_h": src, "id.orig_p": 50000, "id.resp_h": dst, "id.resp_p": 443, "proto": "tcp",
         "service": "ssl", "duration": 1.0, "orig_bytes": 500, "resp_bytes": 5000, "conn_state": "SF", "_path": "conn"}
    if mac:
        r["orig_l2_addr"] = mac
    return r


def dns(ts, src, query, answers, uid):
    return {"ts": ts, "uid": uid, "id.orig_h": src, "id.orig_p": 5353, "id.resp_h": "224.0.0.251", "id.resp_p": 5353,
            "proto": "udp", "query": query, "answers": answers, "_path": "dns"}


def world() -> None:
    s = util.settings()
    s["home_prefixes"] = ["192.0.2.0/24", "2001:db8::/64"]
    util.save_settings(s)
    rows = [dhcp(T0, MAC_A, "192.0.2.10", "kids-ipad"),
            dhcp(T0, MAC_B, "192.0.2.11", UUID_NAME),
            dhcp(T0, MAC_C, "192.0.2.12", "espressif"),
            dhcp(T0, MAC_D, "192.0.2.13", "espressif")]
    for i, (ip, mac) in enumerate((("192.0.2.10", MAC_A), ("192.0.2.11", MAC_B), ("192.0.2.12", MAC_C), ("192.0.2.13", MAC_D))):
        rows += [conn(T0 + 60 + j, ip, "203.0.113.5", f"C{i}{j}", mac) for j in range(3)]
    rows += [conn(T0 + 120 + j, V6_LONE, "2001:db8:ffff::1", f"V{j}") for j in range(2)]
    # two devices answer to the same Bonjour service name; one also has a reverse-DNS name
    rows += [dns(T0 + 5, "192.0.2.1", "_airplay._tcp.local", ["192.0.2.11", "192.0.2.12"], "N1"),
             dns(T0 + 6, "192.0.2.1", "a.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", ["192.0.2.11"], "N2")]
    res = importer.import_fileobj(ndjson(rows), "v11-devices.log", origin="upload")
    assert res.get("inserted"), res
    devices.rebuild()


world()


def dev(did):
    return C.get(f"/api/netlog/devices/{did}").json()


def listed():
    return {d["id"]: d for d in C.get("/api/netlog/devices", params={"limit": 0}).json()}


# ---------------------------------------------------------------- readable names
def test_junk_names_are_not_the_label():
    d = listed()
    assert d[f"mac:{MAC_A}"]["name"] == "kids-ipad" and d[f"mac:{MAC_A}"]["name_source"] == "device"
    b = d[f"mac:{MAC_B}"]   # UUID, a shared Bonjour service and an ip6.arpa name: none is a name
    assert b["name"].startswith("Unnamed device · ") and b["name"].endswith("00:0b") and b["name_source"] == "fallback"
    assert UUID_NAME in b["hostnames"] and UUID_NAME in b["naming"]["junk"]
    assert "Apple device" in b["name"]   # the _airplay service hints at the maker
    # a plain DHCP name two devices share is kept, told apart by a short id
    assert d[f"mac:{MAC_C}"]["name"] == "espressif · 00:0c" and d[f"mac:{MAC_D}"]["name"] == "espressif · 00:0d"
    assert d[f"mac:{MAC_C}"]["type"] == "iot" and d[f"mac:{MAC_C}"]["type_source"] == "guess"
    assert d[f"mac:{MAC_A}"]["type"] == "phone"


def test_clean_name_rules():
    assert devices.clean_name("living room (2)._meshcop._udp.local")[0] == "living room (2)"
    assert devices.clean_name("living-room-tv.local")[0] == "living-room-tv"
    assert devices.clean_name("_adisk._tcp.local") == (None, ["adisk"])
    assert devices.clean_name(f"{UUID_NAME}._asquic._udp.local")[0] is None
    assert devices.clean_name("6a21ea11d12409ca._trel._udp.local")[0] is None
    assert devices.clean_name("cpe-203-0-113-5.res.example.net")[0] is None
    assert devices.clean_name("1.2.0.192.in-addr.arpa")[0] is None


def test_lone_ipv6_is_a_fragment():
    d = listed()[f"ip:{V6_LONE}"]
    assert d["fragment"] is True and d["name"].startswith("Unnamed device · IPv6 address")
    assert not listed()[f"mac:{MAC_A}"]["fragment"]


# ---------------------------------------------------------------- labels
def test_rename_type_owner_survive_rebuild_and_reimport():
    did = f"mac:{MAC_B}"
    r = C.patch(f"/api/netlog/devices/{did}", json={"name": "  Living room   TV ", "type": "tv", "owner": "Family"})
    assert r.status_code == 200, r.text
    assert (r.json()["name"], r.json()["type"], r.json()["owner"], r.json()["name_source"]) == ("Living room TV", "tv", "Family", "you")
    devices.rebuild()
    # a re-import of new rows from the same device rebuilds devices again
    importer.import_fileobj(ndjson([conn(T0 + 999, "192.0.2.11", "203.0.113.9", "CRE", MAC_B)]), "v11-more.log", origin="upload")
    d = dev(did)
    assert (d["name"], d["type"], d["owner"]) == ("Living room TV", "tv", "Family")
    assert listed()[did]["name"] == "Living room TV"
    # search finds the user's name
    assert [x["id"] for x in C.get("/api/netlog/devices", params={"q": "living room"}).json()] == [did]
    # a key left out is kept; '' clears
    d = C.patch(f"/api/netlog/devices/{did}", json={"owner": ""}).json()
    assert d["owner"] is None and d["name"] == "Living room TV"


def test_label_validation():
    did = f"mac:{MAC_A}"
    assert C.patch(f"/api/netlog/devices/{did}", json={"type": "toaster"}).status_code == 400
    assert C.patch(f"/api/netlog/devices/{did}", json={"name": "x" * 61}).status_code == 400
    assert C.patch(f"/api/netlog/devices/{did}", json={"name": 5}).status_code == 400
    assert C.patch("/api/netlog/devices/mac:02:00:5e:ff:ff:ff", json={"name": "x"}).status_code == 404


def test_label_flows_into_alerts():
    did = f"mac:{MAC_A}"
    C.patch(f"/api/netlog/devices/{did}", json={"name": "Kids' iPad"})
    ev = {"device": {"id": did, "hostnames": ["kids-ipad"]}}
    db.execute("""INSERT INTO alerts (id, ts, last_ts, severity, device, indicator, source, rule, direction, title, count,
                  evidence, status) VALUES ('nl-v11-a', now(), now(), 'high', ?, '203.0.113.5', 'feodo_c2', 'c2_outbound',
                  'outbound', ?, 1, ?, 'new')""", [did, f"kids-ipad ({did}) contacted 203.0.113.5 (feodo_c2 c2)", json.dumps(ev)])
    a = C.get("/api/netlog/alerts/nl-v11-a").json()
    assert a["device_name"] == "Kids' iPad" and a["evidence"]["device"]["name"] == "Kids' iPad"
    assert a["title"].startswith("Kids' iPad contacted 203.0.113.5")
    assert next(x for x in C.get("/api/netlog/alerts").json() if x["id"] == "nl-v11-a")["device_name"] == "Kids' iPad"
    assert any(e["kind"] == "alert" and e["alert"] == "nl-v11-a" for e in dev(did)["events"])
    db.execute("DELETE FROM alerts WHERE id = 'nl-v11-a'")


# ---------------------------------------------------------------- merges
def test_merge_survives_rebuild_and_undo():
    src, dst = f"ip:{V6_LONE}", f"mac:{MAC_A}"
    r = C.post("/api/netlog/devices/merge", json={"src": src, "dst": dst})
    assert r.status_code == 200, r.text
    d = listed()
    assert src not in d and V6_LONE in d[dst]["ips"] and src in d[dst]["merged_from"]
    assert d[dst]["conns"] == 3 + 2
    devices.rebuild()
    importer.import_fileobj(ndjson([conn(T0 + 2000, V6_LONE, "2001:db8:ffff::2", "VRE")]), "v11-v6.log", origin="upload")
    d = listed()
    assert src not in d and V6_LONE in d[dst]["ips"] and d[dst]["conns"] == 3 + 3
    assert any(x["how"] == "merged" for x in dev(dst)["evidence"]["ips"])
    assert dev(dst)["merged_from_names"][src].startswith("Unnamed device · IPv6 address")
    # the old id still opens, as the device it is part of now
    assert dev(src)["id"] == dst and dev(src)["merged_into"] == dst
    # hunting by the merged device covers both addresses
    hunt = C.get("/api/netlog/connections", params={"query": f"device:{dst}", "limit": 0}).json()
    assert {r["orig_h"] for r in hunt["rows"]} >= {"192.0.2.10", V6_LONE}
    # refused: itself, a loop, unknown ids
    assert C.post("/api/netlog/devices/merge", json={"src": dst, "dst": dst}).status_code == 400
    assert C.post("/api/netlog/devices/merge", json={"src": dst, "dst": "mac:02:00:5e:ff:ff:ff"}).status_code == 404
    # undo
    assert C.post("/api/netlog/devices/unmerge", json={"src": src}).status_code == 200
    d = listed()
    assert src in d and V6_LONE not in d[dst]["ips"] and d[dst]["conns"] == 3
    assert C.post("/api/netlog/devices/unmerge", json={"src": src}).status_code == 404


def test_merge_chain_and_cycle():
    a, b, c = f"mac:{MAC_C}", f"mac:{MAC_D}", f"mac:{MAC_A}"
    assert C.post("/api/netlog/devices/merge", json={"src": a, "dst": b}).status_code == 200
    assert C.post("/api/netlog/devices/merge", json={"src": b, "dst": c}).status_code == 200
    d = listed()
    assert a not in d and b not in d and {"192.0.2.12", "192.0.2.13"} <= set(d[c]["ips"])
    # merging c into a (which now lives in c) would be a loop
    assert C.post("/api/netlog/devices/merge", json={"src": c, "dst": a}).status_code in (400, 404)
    for s in (b, a):
        assert C.post("/api/netlog/devices/unmerge", json={"src": s}).status_code == 200
    assert {a, b, c} <= set(listed())


def test_similar_names_suggest_a_merge():
    sim = dev(f"mac:{MAC_C}")["similar"]
    assert [x["id"] for x in sim] == [f"mac:{MAC_D}"] and sim[0]["shared"] == ["espressif"]
    assert dev(f"mac:{MAC_A}")["similar"] == []


# ---------------------------------------------------------------- freshness
def test_freshness_per_source_and_demo_excluded():
    f = C.get("/api/netlog/freshness").json()
    up = next(s for s in f["sources"] if s["source"] == "upload")
    assert up["label"] == "Files you uploaded" and up["newest"] and up["stale"] is True
    newest = db.query("SELECT max(ts_max) AS t FROM netlog_files WHERE origin = 'upload'")[0]["t"].timestamp()
    assert f["stale"] == ["upload"] and abs(f["age_s"] - (time.time() - newest)) < 120   # the newest uploaded record
    # newest RECORD time, not import time
    assert up["newest"] < up["last_import"]
    # demo files never count
    db.execute("""INSERT INTO netlog_files (id, name, origin, imported_at, rows, inserted, ts_max, status)
                  VALUES ('demo-x', 'demo.tar.gz', 'demo', now(), 1, 1, now(), 'ok')""")
    f2 = C.get("/api/netlog/freshness").json()
    assert f2["newest"] == f["newest"] and f2["demo"]["loaded"] is True
    assert all(s["source"] != "demo" for s in f2["sources"])
    # a recent push sender is fresh; its own threshold applies
    db.execute("""INSERT INTO netlog_files (id, name, origin, imported_at, rows, inserted, ts_max, status)
                  VALUES ('push-x', 'conn.log', 'push:Garage sensor', now(), 1, 1, now() - INTERVAL 5 MINUTE, 'ok')""")
    f3 = C.get("/api/netlog/freshness").json()
    g = next(s for s in f3["sources"] if s["source"] == "push:Garage sensor")
    assert g["label"] == "Garage sensor" and g["stale"] is False and f3["stale"] == ["upload"]
    db.execute("DELETE FROM netlog_files WHERE id IN ('demo-x', 'push-x')")


def test_stale_hours_setting():
    s = util.settings()
    s["stale_hours"] = 24 * 7
    util.save_settings(s)
    try:
        f = C.get("/api/netlog/freshness").json()
        assert f["stale"] == [] and f["stale_hours"] == 168
    finally:
        s["stale_hours"] = 24
        util.save_settings(s)
