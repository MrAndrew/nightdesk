"""v1.1 global search (GET /api/search): every group, why each hit matched, and ranking basics.
Offline, temporary lake, no AI helper (keyword mode), documentation-range addresses only.

    uv run --with pytest pytest tests/app/test_search.py -q
"""
from __future__ import annotations

import datetime as dt
import io
import json
import sys
import time
from pathlib import Path

from _lake import make_lake
LAKE = make_lake("v11-search")
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, Query  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db, search, search_all  # noqa: E402
from osinthub.entities import overrides, searcher as esearch, store  # noqa: E402
from osinthub.netlog import devices, importer, incidents, util  # noqa: E402
from osinthub.netlog.devices import AGG_SQL  # noqa: E402
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402
from osinthub.news import search as news_search  # noqa: E402
from osinthub.news.common import ensure_schema as news_schema  # noqa: E402

db.connect()
db.cursor().execute(SCHEMA_SQL + AGG_SQL)
store.ensure_schema()
news_schema()
esearch.register()
search.register_searcher("article", news_search.searcher)

# the same route the app serves (osinthub/api.py), without booting the whole app
_app = FastAPI()


@_app.get("/api/search")
def _route(q: str = "", per: int = Query(5, ge=1, le=50), groups: str | None = None):
    return search_all.everything(q, per, [g for g in (groups or "").split(",") if g] or None)


C = TestClient(_app)

TV_MAC, NAS_MAC = "02:00:5e:00:53:30", "02:00:5e:00:53:50"
TV, NAS = "192.0.2.30", "192.0.2.50"
C2 = "198.51.100.7"
T0 = time.time() - 86400


def ndjson(rows):
    return io.BytesIO("".join(json.dumps(r) + "\n" for r in rows).encode())


def conn(ts, src, dst, uid, mac):
    return {"ts": ts, "uid": uid, "id.orig_h": src, "id.orig_p": 50000, "id.resp_h": dst, "id.resp_p": 443, "proto": "tcp",
            "service": "ssl", "duration": 1.0, "orig_bytes": 500, "resp_bytes": 5000, "conn_state": "SF", "_path": "conn",
            "orig_l2_addr": mac}


def dhcp(ts, mac, ip, name):
    return {"ts": ts, "uids": [f"D{mac[-2:]}"], "client_addr": ip, "server_addr": "192.0.2.1", "mac": mac,
            "host_name": name, "assigned_addr": ip, "lease_time": 86400.0, "msg_types": ["REQUEST", "ACK"], "_path": "dhcp"}


def _world():
    s = util.settings()
    s["home_prefixes"] = ["192.0.2.0/24"]
    util.save_settings(s)
    rows = [dhcp(T0, TV_MAC, TV, "living-room-tv"), dhcp(T0, NAS_MAC, NAS, "storage-box")]
    rows += [conn(T0 + 60 + i, TV, C2, f"CT{i}", TV_MAC) for i in range(3)]
    rows += [conn(T0 + 90, NAS, "203.0.113.80", "CN0", NAS_MAC)]
    assert importer.import_fileobj(ndjson(rows), "v11-search.log", origin="upload").get("inserted")
    devices.rebuild()
    devices.set_label(f"mac:{NAS_MAC}", {"name": "Basement NAS", "owner": "Robin"})
    incidents.ensure()
    now = util.now()

    def alert(aid, ind, sev, device, title, meta=None, status="new"):
        ev = {"indicator": {"value": ind, "kind": "ip", "category": "c2", "observed": [ind], "meta": meta or {}},
              "device": {"ip": TV}}
        db.execute("""INSERT INTO alerts (id, ts, last_ts, severity, device, indicator, source, rule, direction, title, count,
                      evidence, status, created_at, updated_at, demo) VALUES (?, ?, ?, ?, ?, ?, 'feodo_c2', 'c2_outbound',
                      'outbound', ?, 3, ?, ?, ?, ?, false)""",
                   [aid, now, now, sev, device, ind, title, json.dumps(ev), status, now, now])
    alert("nl-search-c2", C2, "high", f"mac:{TV_MAC}", f"living-room-tv contacted {C2}, a botnet controller (QakBot)",
          {"malware": "QakBot"})
    alert("nl-search-nas", "203.0.113.80", "medium", f"mac:{NAS_MAC}", "storage-box contacted 203.0.113.80, a compromised host")
    with db._write_lock:
        incidents.regroup(db.cursor())

    # entities: QakBot, a look-alike that only mentions it, the C2 address, and a duplicate merged into QakBot
    store.upsert_entities([
        {"id": "malware:qakbot", "type": "malware", "name": "QakBot", "aliases": ["QBot"], "attrs": {"description": "Banking trojan."}},
        {"id": "actor:loader-crew", "type": "actor", "name": "Loader Crew", "aliases": [], "attrs": {"description": "Spreads QakBot by email."}},
        {"id": "malware:pinkslip-dup", "type": "malware", "name": "Pinkslipbot", "aliases": [], "attrs": {}},
        {"id": f"ip:{C2}", "type": "ip", "name": C2, "aliases": [], "attrs": {}},
        {"id": "cve:cve-2024-3400", "type": "cve", "name": "CVE-2024-3400", "aliases": [], "attrs": {}},
    ])
    overrides.merge("malware:pinkslip-dup", "malware:qakbot")
    # Log4j: the product, the CVE (an entity and a feed CVE record) and a vendor whose text only mentions it
    store.upsert_entities([
        {"id": "product:apache-log4j2", "type": "product", "name": "Apache Log4j2", "aliases": [], "attrs": {}},
        {"id": "cve:cve-2021-44228", "type": "cve", "name": "CVE-2021-44228", "aliases": ["Log4Shell"], "attrs": {}},
        {"id": "vendor:apache", "type": "vendor", "name": "Apache", "aliases": [],
         "attrs": {"description": "Maintains httpd, Struts and log4j."}},
    ])
    db.execute("""INSERT INTO events (id, source, kind, ts, title, summary, tags, value)
                  VALUES ('nvd:44228', 'nvd_recent', 'cve', now(), 'CVE-2021-44228',
                          'Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP endpoints.',
                          ['Apache Log4j2'], 10.0)""")

    # news: one story and its article
    ts = dt.datetime.now(dt.UTC)
    db.execute("""INSERT INTO articles (id, url, source, title, published, fetched_at, text, story_id, status, tier, dek)
                  VALUES ('art1', 'https://news.example/a1', 'Example Wire', 'Botnet takedown hits QakBot servers', ?, ?,
                          'Police took QakBot servers offline in a joint operation.', 'story:art1', 'ok', 'B', 'QakBot down')""", [ts, ts])
    db.execute("""INSERT INTO stories (id, title, summary, lead_article, first_seen, last_seen, article_count, source_count, sources, updated_at)
                  VALUES ('story:art1', 'Botnet takedown hits QakBot servers', 'Police took the botnet offline.', 'art1', ?, ?, 1, 1,
                          ['Example Wire'], ?)""", [ts, ts, ts])
    # notes (the notes package's table)
    db.execute("""CREATE TABLE IF NOT EXISTS notes (id VARCHAR PRIMARY KEY, kind VARCHAR NOT NULL, item VARCHAR NOT NULL,
                  title VARCHAR, body VARCHAR NOT NULL, created_at TIMESTAMPTZ, updated_at TIMESTAMPTZ)""")
    db.execute("INSERT INTO notes VALUES ('n1', 'incident', 'nl-search-c2', 'The TV beacon', 'Factory reset the TV on Sunday', now(), now())")
    db.execute("""INSERT INTO stories (id, title, summary, lead_article, first_seen, last_seen, article_count, source_count, sources, updated_at)
                  VALUES ('story:rw1', 'Hospital hit by ransomware', 'Systems encrypted overnight.', 'rw1', ?, ?, 1, 1, ['Example Wire'], ?)""",
               [ts, ts, ts])


_world()


def find(q, **kw):
    r = C.get("/api/search", params={"q": q, **kw})
    assert r.status_code == 200, r.text
    return r.json()


def group(res, gid):
    return next((g for g in res["groups"] if g["id"] == gid), None)


def ids(res, gid):
    g = group(res, gid)
    return [i["id"] for i in g["items"]] if g else []


# ---------------------------------------------------------------- incidents
def test_malware_name_finds_the_c2_incident_first():
    res = find("qakbot")
    assert res["groups"][0]["id"] == "incident"          # the network incident leads
    it = group(res, "incident")["items"][0]
    assert it["id"] == "nl-search-c2" and it["href"] == "#network/alerts/nl-search-c2"
    assert it["why"] == {"field": "Malware", "text": "QakBot"} and it["exact"] is True
    assert it["severity"] == "high" and it["state"] == "new" and it["evidence"]["indicator"]["meta"]["malware"] == "QakBot"
    assert res["mode"] == "keyword"                      # the AI helper is down: keyword ranking, labelled


def test_ip_finds_incident_device_and_entity():
    res = find(C2)
    assert ids(res, "incident") == ["nl-search-c2"] and group(res, "incident")["items"][0]["why"]["field"] == "Indicator"
    assert ids(res, "entity") == [f"ip:{C2}"]
    home = find(TV)
    assert ids(home, "device") == [f"mac:{TV_MAC}"]
    assert group(home, "device")["items"][0]["why"] == {"field": "IP address", "text": TV}
    assert "nl-search-c2" in ids(home, "incident")        # the device's incident, matched through the device
    assert group(home, "incident")["items"][0]["why"]["field"] == "Device"


# ---------------------------------------------------------------- devices
def test_device_label_owner_mac_and_hostname():
    res = find("basement nas")
    assert ids(res, "device") == [f"mac:{NAS_MAC}"]
    d = group(res, "device")["items"][0]
    assert d["title"] == "Basement NAS" and d["why"]["field"] == "Your name" and d["href"].startswith("#network/devices/mac:")
    assert "nl-search-nas" in ids(res, "incident")        # a device's label finds its incidents too
    assert group(find("robin"), "device")["items"][0]["why"] == {"field": "Owner", "text": "Robin"}
    assert ids(find(TV_MAC.upper().replace(":", "-")), "device") == [f"mac:{TV_MAC}"]   # any MAC spelling
    assert group(find("storage-box"), "device")["items"][0]["why"]["field"] == "Hostname"


# ---------------------------------------------------------------- news, entities, CVEs
def test_stories_and_articles():
    res = find("botnet takedown")
    st = group(res, "story")["items"][0]
    assert st["id"] == "story:art1" and st["href"] == "#news/story/story%3Aart1" and st["why"]["field"] == "Headline"
    assert ids(res, "article") == ["art1"]
    assert not group(find("takedown zebra"), "story")    # a multi-word query needs every word


def test_entities_resolve_merges():
    res = find("pinkslipbot")                             # the merged-away name answers as the entity it joined
    assert ids(res, "entity")[0] == "malware:qakbot"
    assert "malware:pinkslip-dup" not in ids(res, "entity")
    old = find("malware:pinkslip-dup")                    # an old id typed in full
    assert ids(old, "entity") == ["malware:qakbot"]
    q = group(find("qakbot"), "entity")["items"]
    assert q[0]["id"] == "malware:qakbot" and q[0]["why"]["field"] == "Name" and q[0]["exact"]
    assert any(i["id"] == "actor:loader-crew" and i["why"]["field"] == "Description" for i in q)
    assert group(find("qbot"), "entity")["items"][0]["why"] == {"field": "Also known as", "text": "QBot"}


def test_cve_id_is_exact():
    res = find("CVE-2024-3400")
    ent = group(res, "entity")
    assert ent and ent["items"][0]["id"] == "cve:cve-2024-3400"
    assert ent["items"][0]["href"] == "#entities/cve:cve-2024-3400"


# ---------------------------------------------------------------- sources, settings, notes
def test_sources_and_settings_pages():
    ab = group(find("abuse.ch"), "source")["items"]
    assert {"threatfox", "urlhaus"} <= {i["id"] for i in ab}
    assert all(i["why"]["field"] == "Provider" for i in ab if i["type"] == "source")
    ret = group(find("retention"), "source")["items"][0]
    assert ret["type"] == "setting" and ret["href"] == "#settings/data" and ret["anchor"] == "Retention"
    hp = group(find("home prefixes"), "source")["items"]
    assert hp[0]["href"] == "#settings/home" and hp[0]["anchor"] == "Home prefixes" and hp[0]["exact"]
    assert group(find("subnet"), "source")["items"][0]["anchor"] == "Home prefixes"   # a word people use for it


def test_notes_group_and_its_link():
    n = group(find("factory reset"), "note")
    assert n and n["items"][0]["href"] == "#network/alerts/nl-search-c2"
    assert n["items"][0]["why"]["field"] == "Your note"


def test_notes_group_is_pluggable():
    old = search_all.GROUPS["note"]
    try:
        search_all.register_group("note", "Notes", lambda q, c: ([{"type": "note", "id": "x", "title": "Plugged", "href": "#notes",
                                                                   "why": {"field": "Your note", "text": q}}], 1), 70)
        assert ids(find("anything at all"), "note") == ["x"]
    finally:
        search_all.GROUPS["note"] = old


# ---------------------------------------------------------------- shape and ranking basics
def test_groups_order_caps_and_see_all():
    res = find("qakbot", per=1)
    order = [g["id"] for g in res["groups"]]
    assert order.index("incident") < order.index("entity")
    ent = group(res, "entity")
    assert len(ent["items"]) == 1 and ent["total"] >= 2 and ent["more"] is True      # capped, with "see all"
    full = find("qakbot", per=50, groups="entity")
    assert [g["id"] for g in full["groups"]] == ["entity"] and len(full["groups"][0]["items"]) == ent["total"]


def test_exact_group_moves_ahead():
    # "loader crew" names an entity exactly and nothing on the network: entities lead
    res = find("loader crew")
    assert res["groups"][0]["id"] == "entity" and res["groups"][0]["items"][0]["exact"]


def test_every_item_says_why_and_how_to_open():
    res = find("qakbot", per=50)
    for g in res["groups"]:
        for i in g["items"]:
            assert i["why"]["field"] and i["why"]["text"], (g["id"], i)
            assert i.get("href") or i["type"] in ("event",), (g["id"], i)


def test_short_and_empty_queries():
    assert find("")["groups"] == [] and find("q")["groups"] == []
    assert find("zzqx nothing matches this")["groups"] == []


def test_a_failing_group_does_not_break_search():
    old = search_all.GROUPS["story"]
    try:
        def boom(q, c):
            raise RuntimeError("index gone")
        search_all.register_group("story", "Stories", boom, 30)
        res = find("qakbot")
        assert group(res, "incident") and group(res, "story")["error"] == "unavailable"
    finally:
        search_all.GROUPS["story"] = old


# ---------------------------------------------------------------- word starts and typos
def test_word_start_finds_longer_names_first():
    res = find("log4j")
    ent = ids(res, "entity")
    assert ent and ent[0] == "product:apache-log4j2", ent           # the name that starts with it, before text mentions
    assert ent.index("product:apache-log4j2") < ent.index("vendor:apache") if "vendor:apache" in ent else True
    cve = ids(res, "cve")
    assert "CVE-2021-44228" in cve, res["groups"]


def test_one_letter_typos_find_the_right_thing():
    q = find("qakbto")
    assert q.get("corrected") == "qakbot"
    assert "nl-search-c2" in ids(q, "incident") and "malware:qakbot" in ids(q, "entity")
    assert all(i.get("fuzzy") for g in q["groups"] for i in g["items"])   # marked as close matches, never exact
    assert not any(i.get("exact") for g in q["groups"] for i in g["items"])
    r = find("retenton")
    assert group(r, "source")["items"][0]["anchor"] == "Retention"
    assert "story:rw1" in ids(find("ranswomware"), "story")
    assert find("qackbot").get("corrected") == "qakbot"


def test_exact_hits_rank_before_close_ones():
    res = find("qakbot")
    assert "corrected" not in res                                        # a known word is never "corrected"
    assert not any(i.get("fuzzy") for g in res["groups"] for i in g["items"])


def test_mac_spellings_match_the_same_incidents():
    forms = [TV_MAC, TV_MAC.replace(":", "-"), TV_MAC.replace(":", ""), TV_MAC.upper()]
    seen = {f: (ids(find(f), "incident"), ids(find(f), "device")) for f in forms}
    assert len(set(map(str, seen.values()))) == 1, seen
    assert seen[TV_MAC] == (["nl-search-c2"], [f"mac:{TV_MAC}"])


def test_warming_groups_answer_without_waiting():
    old = dict(search_all._warm, ready=set(search_all._warm["ready"]))
    try:
        search_all._warm.update(state="running", ready={"device", "incident", "source", "note"})
        res = find("qakbot")
        assert res.get("warming") is True
        assert group(res, "incident")["items"]                           # the ready groups answer
        assert group(res, "entity")["warming"] is True and group(res, "entity")["items"] == []
    finally:
        search_all._warm.update(old)


def test_entity_changes_rebuild_in_the_background():
    search_all._entity_snapshot()
    before = search_all._ent["good"]
    store.upsert_entities([{"id": "malware:zz-new-family", "type": "malware", "name": "Zebrafinch", "aliases": [], "attrs": {}}])
    overrides.invalidate()
    search_all._ent["checked"] = 0
    find("qakbot")                                                       # answers from the last index, starts a rebuild
    for _ in range(100):
        if search_all._ent["good"] is not before and not search_all._ent["busy"]:
            break
        time.sleep(0.05)
    assert search_all._ent["good"] is not before
    assert ids(find("zebrafinch"), "entity") == ["malware:zz-new-family"]
