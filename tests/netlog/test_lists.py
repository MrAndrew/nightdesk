"""v1.1 netx: your own lists (upload, match like any list incl. older logs, rename, expiry, replace, delete) and the
new-device rule (learning period, first sightings by stable identity, merges, off switch, expected rules).

    uv run --with pytest pytest tests/netlog/test_lists.py -q
"""
from __future__ import annotations

import datetime as dt
import io
import json

from _lake import make_lake
LAKE = make_lake("netlog-v11-netx")

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db  # noqa: E402
from osinthub.netlog import api, devices, importer, newdev, ownlists, util  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
UTC = dt.UTC
api.router.include_router(ownlists.router)
api.router.include_router(newdev.router)
_app = FastAPI()
_app.include_router(api.router)
C = TestClient(_app)

T0 = dt.datetime.now(UTC).replace(microsecond=0) - dt.timedelta(days=12)
MAC = {k: f"02:00:5e:10:00:{i:02x}" for i, k in enumerate("ABCDEFGH", 1)}
IP = {k: f"192.0.2.{10 + i}" for i, k in enumerate("ABCDEFGH", 1)}
BAD_IP, BAD_NAME, BAD_NAME_IP, RANGE_HIT = "198.51.100.7", "bad.example.org", "198.51.100.80", "203.0.113.77"


def conn(t: dt.datetime, uid: str, who: str, dst: str, dport: int = 443) -> dict:
    return {"ts": t.timestamp(), "uid": uid, "id.orig_h": IP[who], "id.orig_p": 50000, "id.resp_h": dst, "id.resp_p": dport,
            "proto": "tcp", "conn_state": "SF", "orig_bytes": 300, "resp_bytes": 700, "duration": 1.0,
            "orig_l2_addr": MAC[who], "_path": "conn"}


def dhcp(t: dt.datetime, who: str, name: str) -> dict:
    return {"ts": t.timestamp(), "uids": [f"D{who}"], "client_addr": IP[who], "server_addr": "192.0.2.1", "mac": MAC[who],
            "host_name": name, "assigned_addr": IP[who], "lease_time": 86400.0, "msg_types": ["REQUEST", "ACK"], "_path": "dhcp"}


def dns(t: dt.datetime, uid: str, who: str, q: str, answers: list[str]) -> dict:
    return {"ts": t.timestamp(), "uid": uid, "id.orig_h": IP[who], "id.orig_p": 5353, "id.resp_h": "192.0.2.1",
            "id.resp_p": 53, "proto": "udp", "query": q, "answers": answers, "_path": "dns"}


def load(name: str, rows: list[dict]) -> dict:
    r = importer.import_any(io.BytesIO("\n".join(json.dumps(x) for x in rows).encode()), name, origin="upload")
    assert r.get("inserted"), r
    return r


def newdev_alerts() -> list[dict]:
    return db.query("SELECT id, device, title, status, severity, evidence FROM alerts WHERE rule = 'new_device' ORDER BY device")


@pytest.fixture(scope="module")
def world():
    s = util.settings()
    s["home_prefixes"] = ["192.0.2.0/24", "2001:db8::/64"]
    util.save_settings(s)
    t = T0
    load("first.log", [dhcp(t, "A", "office-laptop"), dhcp(t, "B", "kitchen-speaker"),
                       conn(t + dt.timedelta(minutes=5), "Ca1", "A", BAD_IP),
                       dns(t + dt.timedelta(minutes=6), "Na1", "A", BAD_NAME, [BAD_NAME_IP]),
                       conn(t + dt.timedelta(minutes=7), "Ca2", "A", RANGE_HIT),
                       conn(t + dt.timedelta(minutes=8), "Cb1", "B", "198.51.100.200")])
    # the rest of a historical first import: one file a day, a new device in most of them (the r1 flood)
    for day, who in ((1, "C"), (2, "D"), (4, "E"), (6, "G"), (9, "A")):
        t = T0 + dt.timedelta(days=day)
        load(f"day{day}.log", [dhcp(t, who, f"device-{who.lower()}"), conn(t + dt.timedelta(minutes=1), f"C{who}{day}", who, "198.51.100.201")])
    return True


def known_how(who: str) -> str:
    return db.query("SELECT how FROM netlog_known_devices WHERE id = ?", [f"mac:{MAC[who]}"])[0]["how"]


def end_learning() -> None:
    """Pretend the first import was two days ago (the logs already cover more than 7 days)."""
    st = newdev._state()
    st["baseline_at"] = (util.now() - dt.timedelta(days=2)).isoformat()
    db.set_setting(newdev.STATE_KEY, st)


NOW = util.now() - dt.timedelta(hours=1)


# ------------------------------------------------------------------ new devices
def test_a_historical_multi_file_first_import_never_floods(world):
    assert not newdev_alerts()                       # six files, five devices after the first: no incident
    st = C.get("/api/netlog/newdev").json()
    assert st["enabled"] and st["baseline_at"] and st["learning"]
    assert st["by_how"].get("baseline", 0) >= 2 and st["by_how"].get("learning", 0) >= 4
    assert st["logs_days"] >= 9 and st["learn_log_days"] == 7 and st["learn_wall_hours"] == 24 and st["learn_until_wall"]


def test_learning_needs_the_wall_clock_and_the_log_days(world):
    from osinthub.netlog.newdev import is_learning
    now = util.now()
    base = {"baseline_at": (now - dt.timedelta(days=2)).isoformat(), "first_log": (now - dt.timedelta(days=3)).isoformat()}
    assert is_learning(base, now, now)                                    # 3 days of logs: still learning
    assert not is_learning({**base, "first_log": (now - dt.timedelta(days=8)).isoformat()}, now, now)
    assert is_learning({**base, "baseline_at": (now - dt.timedelta(hours=3)).isoformat(),
                        "first_log": (now - dt.timedelta(days=8)).isoformat()}, now, now)   # 3 h since the first import
    assert is_learning({}, now, now)


def test_a_live_device_after_learning_raises_one_info_incident(world):
    end_learning()
    assert not C.get("/api/netlog/newdev").json()["learning"]
    t = NOW
    load("live.log", [dhcp(t, "D", "device-d"), dhcp(t, "F", "guest-phone"),
                      conn(t + dt.timedelta(minutes=1), "Cf1", "F", "198.51.100.202")])
    al = newdev_alerts()
    assert [a["device"] for a in al] == [f"mac:{MAC['F']}"]
    a = al[0]
    assert a["severity"] == "info" and a["title"] == "New device joined: guest-phone"
    ev = json.loads(a["evidence"])
    assert ev["kind"] == "new_device" and ev["device"]["mac"] == MAC["F"] and ev["device"]["home_ips"] == [IP["F"]]
    inc = [i for i in C.get("/api/netlog/incidents", params={"limit": 0}).json() if i["rule"] == "new_device"]
    assert len(inc) == 1 and inc[0]["kind"] == "newdev" and inc[0]["severity"] == "info"
    devices.rebuild()                                # a rebuild or a re-match never raises it again
    assert len(newdev_alerts()) == 1
    d = C.get(f"/api/netlog/alerts/{a['id']}").json()   # the detail works without log rows
    assert d["rule"] == "new_device" and d["incident"]["kind"] == "newdev"


def test_a_device_first_seen_in_older_logs_is_history(world):
    t = util.now() - dt.timedelta(days=5)
    load("late-old.log", [dhcp(t, "H", "old-printer"), conn(t + dt.timedelta(minutes=1), "Ch0", "H", "198.51.100.208")])
    assert f"mac:{MAC['H']}" not in {a["device"] for a in newdev_alerts()}
    assert known_how("H") == "history"


def test_new_device_is_not_counted_as_needing_you(world):
    ids = [i["id"] for i in C.get("/api/netlog/incidents", params={"needs_you": "true", "limit": 0}).json()]
    assert not any(i.startswith("nl-dev-") for i in ids)
    assert C.get("/api/netlog/alerts/count").json()["needs_you"] == len(ids)


def test_expected_rule_hides_a_new_device(world):
    aid = newdev_alerts()[0]["id"]
    r = C.post("/api/netlog/rules", json={"from_alert": aid, "scope": "device_kind", "note": "my guest"})
    assert r.status_code == 200, r.text
    rule = r.json()
    assert rule["kind"] == "newdev" and rule["device"] == f"mac:{MAC['F']}"
    inc = [i for i in C.get("/api/netlog/incidents", params={"limit": 0}).json() if i["rule"] == "new_device"]
    assert inc[0]["state"] == "expected"
    C.delete(f"/api/netlog/rules/{rule['id']}")
    inc = [i for i in C.get("/api/netlog/incidents", params={"limit": 0}).json() if i["rule"] == "new_device"]
    assert inc[0]["state"] == "new"


def _guest(who: str, name: str, minutes: int) -> None:
    t = NOW + dt.timedelta(minutes=minutes)
    load(f"{name}.log", [dhcp(t, who, name), conn(t + dt.timedelta(seconds=30), f"C{who}{minutes}", who, "198.51.100.204")])


MAC.update({"I": "02:00:5e:10:00:21", "J": "02:00:5e:10:00:22", "K": "02:00:5e:10:00:23"})
IP.update({"I": "192.0.2.40", "J": "192.0.2.41", "K": "192.0.2.42"})


def test_off_switch_records_devices_without_incidents(world):
    assert C.put("/api/netlog/newdev", json={"enabled": "no"}).status_code == 400
    assert C.put("/api/netlog/newdev", json={"enabled": False}).json()["enabled"] is False
    _guest("I", "printer", 10)
    assert len(newdev_alerts()) == 1 and known_how("I") == "off"
    C.put("/api/netlog/newdev", json={"enabled": True})
    devices.rebuild()
    assert len(newdev_alerts()) == 1                  # turning it back on does not announce what it saw while off


def test_older_than_what_was_seen_is_recognized(world):
    t = util.now() - dt.timedelta(hours=30)        # recent, but well before the logs already seen
    load("backfill.log", [dhcp(t, "J", "old-nas"), conn(t + dt.timedelta(minutes=1), "Cj1", "J", "198.51.100.206")])
    assert f"mac:{MAC['J']}" not in {a["device"] for a in newdev_alerts()}
    assert known_how("J") == "recognized"


def test_privacy_address_fragments_are_not_announced(world):
    t = NOW + dt.timedelta(minutes=20)
    row = {"ts": t.timestamp(), "uid": "V1", "id.orig_h": "2001:db8::77:1", "id.orig_p": 50000, "id.resp_h": "2001:db8:ffff::1",
           "id.resp_p": 443, "proto": "tcp", "conn_state": "SF", "orig_bytes": 10, "resp_bytes": 10, "_path": "conn"}
    load("v6.log", [row])
    assert "ip:2001:db8::77:1" not in {a["device"] for a in newdev_alerts()}
    assert db.query("SELECT how FROM netlog_known_devices WHERE id = 'ip:2001:db8::77:1'")[0]["how"] == "fragment"


def test_merging_a_new_device_into_a_known_one_dismisses_it(world):
    _guest("K", "office-laptop-wifi", 30)
    fa = [a for a in newdev_alerts() if a["device"] == f"mac:{MAC['K']}"]
    assert len(fa) == 1 and fa[0]["status"] == "new"
    r = C.post("/api/netlog/devices/merge", json={"src": f"mac:{MAC['K']}", "dst": f"mac:{MAC['A']}"})
    assert r.status_code == 200, r.text
    fa = [a for a in newdev_alerts() if a["device"] == f"mac:{MAC['K']}"]
    assert fa[0]["status"] == "dismissed" and json.loads(fa[0]["evidence"])["merged_into"] == f"mac:{MAC['A']}"
    C.post("/api/netlog/devices/unmerge", json={"src": f"mac:{MAC['K']}"})   # undoing it never re-announces it
    assert len([a for a in newdev_alerts() if a["device"] == f"mac:{MAC['K']}"]) == 1


# ------------------------------------------------------------------ own lists
LIST = """# my lab's blocklist
198.51.100.7
hxxp://bad[.]example[.]org/payload.bin
203.0.113.0/24
0.0.0.0/0
not a thing
127.0.0.1
"""


def own_alerts(src: str | None = None) -> list[dict]:
    q = "SELECT id, indicator, title, severity, source, evidence, rule FROM alerts WHERE source LIKE 'own:%'"
    return db.query(q + (" AND source = ?" if src else "") + " ORDER BY indicator", [src] if src else [])


def test_parse_handles_comments_hosts_csv_and_junk():
    p = ownlists.parse("ip,comment\n198.51.100.9,seen in a scan\n2001:db8:dead::/48,range\n")
    assert set(p["values"]) == {("ip", "198.51.100.9"), ("cidr", "2001:db8:dead::/48")} and p["skipped"]["count"] == 0
    p = ownlists.parse("0.0.0.0 tracker.example.net\n198.51.100.10:8080 # c2\n[2001:db8::5]:443\nevil[.]example\n*.ads.example.com\n")
    assert set(p["values"]) == {("domain", "tracker.example.net"), ("ip", "198.51.100.10"), ("ip", "2001:db8::5"),
                                ("domain", "evil.example"), ("domain", "ads.example.com")}
    p = ownlists.parse(LIST)
    assert len(p["values"]) == 3 and p["skipped"]["count"] == 3
    assert any("too wide" in s["why"] for s in p["skipped"]["sample"])


@pytest.fixture
def lab_list(world):
    """The list test_upload_a_list_matches_older_logs makes (made here when that test did not run first)."""
    if not C.get("/api/netlog/lists").json():
        assert C.post("/api/netlog/lists", data={"name": "Lab blocklist", "note": "from the router", "text": LIST}).status_code == 200
    return C.get("/api/netlog/lists").json()[0]


def test_upload_a_list_matches_older_logs(world):
    r = C.post("/api/netlog/lists", data={"name": "Lab blocklist", "note": "from the router", "text": LIST})
    assert r.status_code == 200, r.text
    lst = r.json()
    assert lst["entries"] == 3 and lst["kinds"] == {"ip": 1, "domain": 1, "cidr": 1} and lst["skipped"]["count"] == 3
    src = lst["source"]
    al = own_alerts(src)
    inds = {a["indicator"] for a in al}
    assert {BAD_IP, BAD_NAME, "203.0.113.0/24"} <= inds, inds
    for a in al:
        ev = json.loads(a["evidence"])
        assert a["severity"] == "medium", a
        assert "on your list 'Lab blocklist'" in a["title"], a["title"]
        assert ev["source_tier"] == "U" and ev["indicator"]["meta"]["list_name"] == "Lab blocklist"
        assert ev.get("found_later")      # the list arrived after the logs: found by the re-check
    kinds = {i["kind"] for i in C.get("/api/netlog/incidents", params={"limit": 0}).json() if i["source"] == src}
    assert kinds == {"own:out"}
    assert C.get("/api/netlog/alerts/count").json()["needs_you"] >= 3
    got = C.get("/api/netlog/lists").json()
    assert got[0]["name"] == "Lab blocklist" and got[0]["hits"]["incidents"] >= 3
    assert C.post("/api/netlog/lists", data={"name": "lab BLOCKLIST", "text": "198.51.100.1"}).status_code == 400
    assert C.post("/api/netlog/lists", data={"name": "Empty", "text": "nothing here\n"}).status_code == 400


def test_rename_and_note_retitle_alerts(lab_list):
    lst = lab_list
    r = C.patch(f"/api/netlog/lists/{lst['id']}", json={"name": "Router blocks", "note": "edited"})
    assert r.status_code == 200 and r.json()["name"] == "Router blocks"
    assert all("on your list 'Router blocks'" in a["title"] for a in own_alerts(lst["source"]))


def test_expiry_before_the_contacts_makes_them_outside_the_listing(lab_list):
    lst = lab_list
    cut = (T0 - dt.timedelta(days=1)).isoformat()
    assert C.patch(f"/api/netlog/lists/{lst['id']}", json={"expires_at": cut}).status_code == 200
    al = own_alerts(lst["source"])
    assert al and all(a["rule"] == "historical" and a["severity"] == "info" for a in al), al
    assert C.patch(f"/api/netlog/lists/{lst['id']}", json={"expires_days": 30}).status_code == 200
    assert {a["severity"] for a in own_alerts(lst["source"])} == {"medium"}
    assert C.patch(f"/api/netlog/lists/{lst['id']}", json={"expires_days": -3}).status_code == 400


def test_replace_keeps_added_times_and_moves_alerts(lab_list):
    lst = lab_list
    first_added = db.query("""SELECT "start" FROM indicator_intervals WHERE source = ? AND value = ?""", [lst["source"], BAD_IP])[0]["start"]
    r = C.put(f"/api/netlog/lists/{lst['id']}/file",
              files={"file": ("new.txt", f"{BAD_IP}\n198.51.100.200\n".encode(), "text/plain")})
    assert r.status_code == 200, r.text
    assert r.json()["added"] == 1 and r.json()["removed"] == 2 and r.json()["file_name"] == "new.txt"
    inds = {a["indicator"] for a in own_alerts(lst["source"])}
    assert inds == {BAD_IP, "198.51.100.200"}, inds
    again = db.query("""SELECT "start" FROM indicator_intervals WHERE source = ? AND value = ?""", [lst["source"], BAD_IP])[0]["start"]
    assert again == first_added


def test_lists_show_on_entity_lookups(world):
    from osinthub.netlog import intervals
    got = intervals.listed([("ip", BAD_IP)])[("ip", BAD_IP)]
    own = [x for x in got if x["source"].startswith("own:")]
    assert own and own[0]["tier"] == "U" and own[0]["name"] == "your list 'Router blocks'"


def test_delete_removes_its_alerts(world):
    lst = C.get("/api/netlog/lists").json()[0]
    assert C.delete(f"/api/netlog/lists/{lst['id']}").status_code == 200
    assert not own_alerts()
    assert not db.query("SELECT 1 FROM indicator_intervals WHERE source = ?", [lst["source"]])
    assert C.delete(f"/api/netlog/lists/{lst['id']}").status_code == 404
    assert C.get("/api/netlog/lists").json() == []


def test_the_two_expiry_readers_differ_on_purpose():
    """Owner decision 2026-11-18: own lists read form fields, so "30" is 30 days; "expected" rules read JSON numbers, so
    "30" as text is an error and 30 is 30 days. Both take an ISO time, both mean "never" for 0/empty/null, both cap at
    3650 days. Pinned here so neither is merged into the other by accident."""
    from osinthub.netlog import incidents

    def days(t):
        return (t - util.now()).total_seconds() / 86400

    assert 29.99 < days(ownlists._expiry("30")) <= 30 and 29.99 < days(ownlists._expiry(30)) <= 30
    assert ownlists._expiry("0") is None and ownlists._expiry("") is None and ownlists._expiry(None) is None
    assert 29.99 < days(incidents._expiry(30)) <= 30 and 0.49 < days(incidents._expiry(0.5)) <= 0.5
    for text in ("30", "0"):
        with pytest.raises(ValueError, match="bad expiry"):
            incidents._expiry(text)
    assert incidents._expiry(0) is None and incidents._expiry("") is None and incidents._expiry(None) is None
    iso = dt.datetime(2030, 1, 2, 3, 4, tzinfo=dt.UTC)
    for read in (ownlists._expiry, incidents._expiry):
        assert read("2030-01-02T03:04:00Z") == read("2030-01-02T03:04:00") == iso
        for bad in (3651, -1, "4000" if read is ownlists._expiry else 4000):
            with pytest.raises(ValueError, match="from 1 to 3650"):
                read(bad)
        with pytest.raises(ValueError, match="bad expiry"):
            read("next tuesday")
