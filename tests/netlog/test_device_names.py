"""v1.1 polish lane, netlog side: generic hostnames are hints not names, the type follows the name, silent IPv4-only
records fold under Unidentified, and alerts carry the unnamed device's hint for headlines.

    uv run --with pytest pytest tests/netlog/test_device_names.py -q
"""
from __future__ import annotations

import io
import json
import time
from collections import Counter

from _lake import make_lake
LAKE = make_lake("netlog-v11-polish")

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

MAC_MAC, MAC_PH, MAC_ESP = "02:00:5e:00:01:5f", "02:00:5e:00:01:0b", "02:00:5e:00:01:0c"
SILENT, TALKER = "192.0.2.40", "192.0.2.41"
T0 = time.time() - 3600


def ndjson(rows):
    return io.BytesIO("".join(json.dumps(r) + "\n" for r in rows).encode())


def dhcp(ts, mac, ip, name):
    return {"ts": ts, "uids": [f"D{mac[-2:]}"], "client_addr": ip, "server_addr": "192.0.2.1", "mac": mac,
            "host_name": name, "assigned_addr": ip, "lease_time": 86400.0, "msg_types": ["REQUEST", "ACK"], "_path": "dhcp"}


def conn(ts, src, dst, uid, mac=None, ob=500, rb=5000):
    r = {"ts": ts, "uid": uid, "id.orig_h": src, "id.orig_p": 50000, "id.resp_h": dst, "id.resp_p": 443, "proto": "tcp",
         "service": "ssl", "duration": 1.0, "orig_bytes": ob, "resp_bytes": rb, "conn_state": "SF", "_path": "conn"}
    if mac:
        r["orig_l2_addr"] = mac
    return r


def world():
    s = util.settings()
    s["home_prefixes"] = ["192.0.2.0/24"]
    util.save_settings(s)
    rows = [dhcp(T0, MAC_MAC, "192.0.2.20", "mac"), dhcp(T0, MAC_PH, "192.0.2.21", "alexs-iphone"),
            dhcp(T0, MAC_ESP, "192.0.2.22", "ESP_1A2B3C")]
    for i, (ip, mac) in enumerate((("192.0.2.20", MAC_MAC), ("192.0.2.21", MAC_PH), ("192.0.2.22", MAC_ESP))):
        rows += [conn(T0 + 60 + j, ip, "203.0.113.5", f"C{i}{j}", mac) for j in range(2)]
    rows += [conn(T0 + 90, SILENT, "203.0.113.6", "S0", ob=0, rb=0), conn(T0 + 91, TALKER, "203.0.113.6", "S1")]
    assert importer.import_fileobj(ndjson(rows), "v11-polish.log", origin="upload").get("inserted")
    devices.rebuild()


world()


def listed():
    return {d["id"]: d for d in C.get("/api/netlog/devices", params={"limit": 0}).json()}


def naming(*names, did="mac:02:00:5e:00:01:99"):
    return devices.auto_naming(did, [], devices.name_candidates(list(names)), Counter(), None)


def test_generic_names_are_hints():
    for raw, hint in (("mac", "Mac"), ("iPhone", "iPhone"), ("android", "Android"), ("localhost", None),
                      ("router", "router"), ("ESP_1A2B3C", "ESP chip (smart-home)"), ("esp-00ff12", "ESP chip (smart-home)"),
                      ("android-1a2b3c4d5e", "Android"), ("iPad", "iPad")):
        n = naming(raw)
        assert n["name"] is None, raw
        if hint:
            assert n["hint"] == hint, (raw, n["hint"])
    # a real name after a generic one still wins
    assert naming("iphone", "kitchen-ipad")["name"] == "kitchen-ipad"


def test_type_follows_the_name():
    cases = {"alexs-iphone": "phone", "kids-ipad": "phone", "living-room-tv": "tv", "roku-ultra": "tv",
             "chromecast-den": "tv", "dads-macbook": "laptop", "mac": "laptop", "office-pc": "laptop"}
    for raw, t in cases.items():
        assert naming(raw)["type_guess"] == t, raw
    # the shown name decides, even when the device also answers to another machine's name
    assert naming("alexs-iphone", "work-macbook-pro")["type_guess"] == "phone"
    assert naming("den-tv", "alexs-iphone")["type_guess"] == "tv"


def test_list_uses_fallback_for_generic_names():
    d = listed()
    m = d[f"mac:{MAC_MAC}"]
    assert m["name_source"] == "fallback" and m["name"] == "Unnamed device · Mac · 01:5f" and m["type"] == "laptop"
    e = d[f"mac:{MAC_ESP}"]
    assert e["name_source"] == "fallback" and "ESP chip" in e["name"] and e["type"] == "iot"
    p = d[f"mac:{MAC_PH}"]
    assert p["name"] == "alexs-iphone" and p["type"] == "phone"


def test_present_reads_old_evidence_with_new_rules():
    row = {"id": "mac:02:00:5e:00:01:98", "evidence": {"naming": {"name": "iphone", "type_guess": "laptop", "hint": None,
                                                                  "short": "01:98"}}}
    p = devices.present(row)
    assert p["name"] == "Unnamed device · iPhone · 01:98" and p["name_source"] == "fallback"
    row = {"id": "mac:02:00:5e:00:01:97", "evidence": {"naming": {"name": "alexs-iphone", "type_guess": "laptop",
                                                                  "short": "01:97"}}}
    assert devices.present(row)["type"] == "phone"


def test_silent_ipv4_folds_under_unidentified():
    d = listed()
    s, t = d[f"ip:{SILENT}"], d[f"ip:{TALKER}"]
    assert s["bytes_in"] + s["bytes_out"] == 0 and s["fragment"] is True
    assert t["fragment"] is False   # it moved data: stays in the main list
    # a label keeps it in the main list
    C.patch(f"/api/netlog/devices/ip:{SILENT}", json={"name": "Probe"})
    assert listed()[f"ip:{SILENT}"]["fragment"] is False
    C.patch(f"/api/netlog/devices/ip:{SILENT}", json={"name": None})
    # display_names (no traffic numbers) never claims a fold
    assert devices.display_names([f"ip:{SILENT}"])[f"ip:{SILENT}"]["name_source"] == "fallback"


def test_alert_carries_hint_for_headlines():
    did = f"mac:{MAC_MAC}"
    ev = {"device": {"id": did, "hostnames": ["mac"]}}
    db.execute("""INSERT INTO alerts (id, ts, last_ts, severity, device, indicator, source, rule, direction, title, count,
                  evidence, status) VALUES ('nl-pol-a', now(), now(), 'high', ?, '203.0.113.5', 'feodo_c2', 'c2_outbound',
                  'outbound', 'x', 1, ?, 'new')""", [did, json.dumps(ev)])
    a = C.get("/api/netlog/alerts/nl-pol-a").json()
    assert a["device_name_source"] == "fallback" and a["device_hint"] == "Mac"
    assert a["evidence"]["device"]["hint"] == "Mac" and a["evidence"]["device"]["name_source"] == "fallback"
    db.execute("DELETE FROM alerts WHERE id = 'nl-pol-a'")
