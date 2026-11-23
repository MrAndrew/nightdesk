"""My stack (osinthub/stack.py): one followed list matched across the app. Vendor/product normalisation and its
false-positive guards, the two verified bugs (following SonicWall surfaces its KEV entry; following QakBot surfaces
the QakBot C2 alert), the old News watchlist endpoints, and merged entity ids. Temporary lake, no network.

    uv run --with pytest pytest tests/app/test_stack.py -q
"""
from __future__ import annotations

import datetime as dt
import json

from _lake import make_lake
LAKE = make_lake("stack")

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db, stack  # noqa: E402
from osinthub.news.api import router as news_router  # noqa: E402
from osinthub.news.common import ensure_schema  # noqa: E402
from osinthub.watch.api import router as watch_router  # noqa: E402

db.connect()
ensure_schema()
from osinthub.entities import api as ent_api, overrides, store as ent_store  # noqa: E402

ent_store.ensure_schema()
try:
    from osinthub.netlog.schema import SCHEMA_SQL
    from osinthub.netlog.devices import AGG_SQL
    db.cursor().execute(SCHEMA_SQL + AGG_SQL)
except Exception:   # pragma: no cover
    pass

app = FastAPI()
for r in (watch_router, news_router, stack.router) + (ent_api.router,):
    app.include_router(r)
c = TestClient(app)

NOW = dt.datetime.now(dt.UTC)
ago = lambda **kw: NOW - dt.timedelta(**kw)   # noqa: E731


@pytest.fixture(autouse=True)
def clean():
    for t in ("events", "source_state", "epss", "stories", "articles", "mentions", "entities", "settings"):
        db.execute(f"DELETE FROM {t}")
    for t in ("alerts", "netlog_files", "entity_overrides"):
        try:
            db.execute(f"DELETE FROM {t}")
        except Exception:
            pass
    overrides.invalidate()
    c.put("/api/marker", json={"last_seen": ago(days=1).isoformat()})
    yield


def kev(cve, vendor, product, ts=None, name="Flaw"):
    ts = ts or ago(hours=3)
    db.execute("""INSERT INTO events (id, source, kind, ts, title, summary, tags, stored_at)
                  VALUES (?, 'cisa_kev', 'kev', ?, ?, ?, ?, ?)""",
               [f"cisa_kev:{cve}", ts, f"{cve} · {vendor} {product}", f"{vendor} {product} {name}. Details.",
                [vendor, product], ts])


def sec(d, sid):
    return next(s for s in d["sections"] if s["id"] == sid)


def follow(**body):
    return c.post("/api/stack/follow", json=body).json()


# ------------------------------------------------------------------ normalisation
def test_names_normalise():
    assert stack.tokens("D-Link") == ["d", "link"]
    assert stack.vtokens("Cisco Systems, Inc.") == ["cisco"]
    assert stack.vendor_eq("Palo Alto Networks", "Palo Alto")
    assert stack.vendor_eq("Ubiquiti Networks", "ubiquiti")
    assert stack.vendor_eq("Sonic Wall", "SonicWall")
    assert stack.seq_in(["sma"], stack.tokens("SMA1000 Appliances")), "a model number follows the product"
    assert stack.seq_in(["sonicos"], stack.tokens("Sonic OS SSLVPN")) and stack.seq_in(["sonic", "os"], ["sonicos"])
    assert not stack.seq_in(["sma"], stack.tokens("Smart Home Hub")), "a prefix that is not a model number does not count"
    assert stack.split_label("Synology DSM") == {"vendor": "Synology", "product": "DSM"}
    assert stack.split_label("Ubiquiti UniFi") == {"vendor": "Ubiquiti", "product": "UniFi"}
    assert stack.split_label("Frobnicator 9") == {"vendor": "Frobnicator 9", "product": ""}


def T(*items, **kw):
    return stack.Terms({"entities": kw.get("entities", []), "keywords": kw.get("keywords", []),
                        "stack": [stack.split_label(i) if isinstance(i, str) else i for i in items]})


def test_vendor_and_product_matching():
    t = T("SonicWall SMA", "Synology DSM", "UniFi", "OpenSSH")
    assert t.record("SonicWall", "SMA1000 Appliances") == ["stack:SonicWall SMA"]
    assert t.record("SonicWall", "SonicOS SSLVPN") == [], "SMA is not SonicOS"
    assert t.record("Synology", "DiskStation Manager (DSM)") == ["stack:Synology DSM"]
    assert t.record("Acme", "DSM Server") == [], "a short product needs its vendor"
    assert t.record("Ubiquiti", "UniFi Network Application") == ["stack:UniFi"], "a distinctive product stands alone"
    assert t.record("OpenBSD", "OpenSSH") == ["stack:OpenSSH"]
    # CPE strings where present
    assert T("Synology").record(text="affects cpe:2.3:o:synology:diskstation_manager:7.1:*:*:*:*:*:*:*") == ["stack:Synology"]


def test_false_positive_guards():
    hp, arm = T("HP"), T("Arm")
    assert hp.record("HP", "LaserJet") == ["stack:HP"], "a short vendor matches the vendor field exactly"
    assert hp.record("HPE", "OneView") == [] and hp.record("Acme", "HP-UX tools") == []
    assert hp.text("Attackers chp the network", "HP printers hit") == [], "short names never match a body"
    assert hp.text("HP patches printers") == ["stack:HP"] and hp.text("hp patches printers") == []
    assert arm.record("Arm", "Mali GPU Kernel Driver") == ["stack:Arm"]
    assert arm.text("Police arm themselves", "the arm of the law") == [], "a common word only as written in a headline"
    assert T("SonicWall").text("SonicWallet scam") == [], "whole words only"
    assert T("Synology DSM").text("Synology patches", "the DSM update") == ["stack:Synology DSM"]
    assert T("Synology DSM").text("New DSM rules for doctors") == [], "a short product needs its vendor in free text"
    # a ransomware group named like a vendor is not a victim
    assert T("Barracuda").victim("ADG Blatt", "Barracuda") == []
    assert T("Barracuda").victim("Barracuda Networks", "Akira") == ["stack:Barracuda"]


def test_generic_products_need_their_vendor():
    asus = T({"vendor": "ASUS", "product": "routers"})
    for v, p in (("TP-Link", "Multiple Routers"), ("NETGEAR", "Multiple Routers"), ("D-Link", "Multiple Routers")):
        assert asus.record(v, p) == [], f"{v} {p}"
    assert asus.record("ASUS", "RT-AX88U Router") == ["stack:ASUS routers"], "plural and vendor"
    assert T("ASUS").record("ASUS", "Routers") == ["stack:ASUS"]
    assert T("UniFi").record("Multiple Vendors", "UniFi and others") == [], "no product-only match in a multi-vendor row"
    assert T("OpenSSH").record("OpenBSD", "OpenSSH") == ["stack:OpenSSH"]


def test_aliases_for_common_products():
    assert T("Synology DSM").record("Synology", "DiskStation Manager") == ["stack:Synology DSM"]
    assert T("Synology DSM").record("Synology", "DiskStation Manager (DSM)") == ["stack:Synology DSM"]
    for f in ("Chrome", "Google Chrome"):
        t = T({"vendor": f, "product": ""} if f == "Chrome" else "Google Chrome")
        assert t.record("Google", "Chromium V8") and t.record("Google", "Chromium Mojo"), f
        assert not t.record("Google", "Android"), f
    w = T({"vendor": "Windows", "product": ""})
    assert w.record("Microsoft", "Windows") == ["stack:Windows"] and w.record("Microsoft", "Exchange Server") == []
    assert w.text("Microsoft patches Windows zero-day") == ["stack:Windows"]
    assert T("Synology DSM").text("Synology DiskStation Manager flaw") == ["stack:Synology DSM"]
    ex = T("Microsoft Exchange Server")
    assert ex.record("Microsoft", "Exchange") and not ex.record("Microsoft", "Internet Key Exchange (IKE) Service Extensions")
    assert T("Apache HTTP Server").record("Oracle", "HTTP Server and Oracle Weblogic Server Proxy Plug-in") == []


def test_news_guards_for_everyday_words_and_broad_vendors():
    assert T("Progress").text("Progress report: ransomware down") == [], "a sentence's first word"
    assert T("Progress").text("Attackers hit Progress MOVEit again") == ["stack:Progress"]
    assert T("Arm").text("Patch now. Arm yourself against phishing") == []
    ms = T("Microsoft")
    assert ms.text("Ransomware gang hits hospital", "the attackers used a Microsoft account") == [], "broad vendor: body alone"
    assert ms.text("Microsoft fixes exploited flaw") == ["stack:Microsoft"]
    assert ms.record("Microsoft", "Windows") == ["stack:Microsoft"], "KEV still matches the vendor field"


def test_numbered_group_names():
    db.execute("INSERT INTO entities VALUES ('actor:lockbit', 'actor', 'LockBit', [], '{}', now(), now())")
    t = stack.Terms({"entities": ["actor:lockbit"], "keywords": [], "stack": []})
    assert t.victim("Example Bakery", "lockbit5") == ["actor:lockbit"] and t.victim("Example Bakery", "lockbitx") == []


# ------------------------------------------------------------------ the two verified bugs
def test_following_sonicwall_surfaces_its_kev_entry():
    kev("CVE-2026-19868", "SonicWall", "SonicOS SSLVPN")
    kev("CVE-2026-19999", "Sonicwallet", "Wallet")
    r = follow(text="SonicWall")
    assert r["added"] and r["stack"] == [{"vendor": "SonicWall", "product": ""}] and r["kev"] == 1
    t = sec(c.get("/api/watch").json(), "touches")
    hit = [i for i in t["items"] if i["type"] == "kev"]
    assert [i["cve"] for i in hit] == ["CVE-2026-19868"]
    assert hit[0]["why"] == "follow" and hit[0]["matched"] == ["stack:SonicWall"]
    assert hit[0]["matched_names"] == {"stack:SonicWall": "SonicWall"}
    m = c.post("/api/stack/match", json={"items": [{"key": "a", "vendor": "SonicWall", "product": "SMA100"},
                                                   {"key": "b", "vendor": "Acme", "product": "Router"}]}).json()["matches"]
    assert m == {"a": [{"key": "stack:SonicWall", "name": "SonicWall"}]}
    assert c.get("/api/stack/kev").json()["matches"] == {"CVE-2026-19868": [{"key": "stack:SonicWall", "name": "SonicWall"}]}


def test_a_new_follow_shows_its_recent_exploited_bugs_once():
    kev("CVE-2026-19868", "SonicWall", "SonicOS SSLVPN", ts=ago(days=4))    # older than the marker
    kev("CVE-2020-0001", "SonicWall", "SMA100", ts=ago(days=400))
    t = lambda: [i["cve"] for i in sec(c.get("/api/watch").json(), "touches")["items"] if i["type"] == "kev"]   # noqa: E731
    follow(vendor="SonicWall")
    assert t() == ["CVE-2026-19868"], "just followed: the last 30 days count once"
    c.put("/api/marker", json={})
    assert t() == [], "after Caught up only new entries"


def qakbot_alert(aid="nl-q1", created=None):
    ts = created or ago(hours=2)
    ev = {"indicator": {"value": "198.51.100.7", "kind": "ip", "category": "c2", "observed": ["198.51.100.7"],
                        "meta": {"malware": "QakBot", "port": 443}}}
    db.execute("""INSERT INTO alerts (id, ts, last_ts, severity, device, indicator, source, rule, direction, title, count,
                                      evidence, status, created_at, updated_at, demo)
                  VALUES (?, ?, ?, 'high', 'mac:02:00:00:00:00:01', '198.51.100.7', 'feodo_c2', 'c2_outbound', 'outbound',
                          'device contacted 198.51.100.7, a botnet C2', 1, ?, 'new', ?, ?, false)""",
               [aid, ts, ts, json.dumps(ev), ts, ts])


@pytest.mark.parametrize("how", ["entity", "keyword"])
def test_following_qakbot_surfaces_the_c2_alert(how):
    db.execute("INSERT INTO entities VALUES ('malware:qakbot', 'malware', 'QakBot', ['QBot', 'Pinkslipbot'], '{}', now(), now())")
    qakbot_alert()
    follow(**({"entity": "malware:qakbot"} if how == "entity" else {"keyword": "qakbot"}))
    t = sec(c.get("/api/watch").json(), "touches")
    al = [i for i in t["items"] if i["type"] == "alert"]
    assert [i["id"] for i in al] == ["nl-q1"] and al[0]["why"] == "follow" and al[0]["href"] == "#network/alerts/nl-q1"
    assert al[0]["matched"] == (["malware:qakbot"] if how == "entity" else ["keyword:qakbot"])
    if how == "entity":
        assert al[0]["matched_names"] == {"malware:qakbot": "QakBot"}
    # after Caught up it is no longer new, but still open: listed apart, not counted
    c.put("/api/marker", json={})
    t = sec(c.get("/api/watch").json(), "touches")
    assert not [i for i in t["items"] if i["type"] == "alert"] and [i["id"] for i in t["still_open"]] == ["nl-q1"]
    assert t["still_open_count"] == 1


def test_following_after_caught_up_shows_open_incidents():
    """The normal state: caught up first, then follow QakBot. Its open C2 alert is news to you now."""
    db.execute("INSERT INTO entities VALUES ('malware:qakbot', 'malware', 'QakBot', [], '{}', now(), now())")
    qakbot_alert(created=ago(days=3))
    c.put("/api/marker", json={})
    follow(entity="malware:qakbot")
    t = sec(c.get("/api/watch").json(), "touches")
    al = [i for i in t["items"] if i["type"] == "alert"]
    assert [i["id"] for i in al] == ["nl-q1"] and al[0]["recent_follow"] and t["count"] >= 1
    c.put("/api/marker", json={})
    t = sec(c.get("/api/watch").json(), "touches")
    assert t["count"] == 0 and t["still_open_count"] == 1, "then still open: shown apart, never an all-clear"


def test_alias_and_indicator_and_kev_cve_alerts():
    db.execute("INSERT INTO entities VALUES ('malware:qakbot', 'malware', 'QakBot', ['QBot'], '{}', now(), now())")
    qakbot_alert()
    db.execute("UPDATE alerts SET evidence = replace(evidence, 'QakBot', 'Qbot')")
    follow(entity="malware:qakbot")
    hits = stack.network_hits(stack.Terms(), ago(days=1))
    assert [h["id"] for h in hits] == ["nl-q1"], "an alias of the followed family counts"
    c.put("/api/stack", json={"entities": ["ip:198.51.100.7"], "keywords": [], "stack": []})
    assert [h["matched"] for h in stack.network_hits(stack.Terms(), ago(days=1))] == [["ip:198.51.100.7"]]
    # a KEV-listed CVE on the network of a followed product
    db.execute("DELETE FROM alerts")
    kev("CVE-2026-5555", "Synology", "DiskStation Manager (DSM)")
    db.execute("""INSERT INTO alerts (id, ts, last_ts, severity, device, indicator, source, rule, title, count, evidence,
                                      status, created_at, updated_at) VALUES ('nl-k', now(), now(), 'medium', 'mac:02:00:00:00:00:02',
                  'CVE-2026-5555', 'cisa_kev', 'kev_seen', 'device runs CVE-2026-5555', 1, '{}', 'new', now(), now())""")
    c.put("/api/stack", json={"entities": [], "stack": [{"vendor": "Synology", "product": "DSM"}]})
    assert [h["matched"] for h in stack.network_hits(stack.Terms(), ago(days=1))] == [["stack:Synology DSM"]]


def test_epss_jump_and_ransomware_victims():
    kev("CVE-2026-7001", "Synology", "DSM")
    db.execute("""INSERT INTO epss (cve, epss, percentile, score_date, since, prev_epss) VALUES
                  ('CVE-2026-7001', 0.42, 0.97, now(), now() - INTERVAL 2 HOUR, 0.02),
                  ('CVE-2026-7002', 0.05, 0.80, now(), now() - INTERVAL 2 HOUR, 0.04),
                  ('CVE-2026-7003', 0.60, 0.99, now(), now() - INTERVAL 2 HOUR, 0.01)""")
    db.execute("""INSERT INTO events (id, source, kind, ts, title, tags) VALUES
                  ('ransomware_live:1', 'ransomware_live', 'ransomware', now() - INTERVAL 1 HOUR, 'Akira claims Synology Inc.', ['Akira', 'Technology']),
                  ('ransomware_live:2', 'ransomware_live', 'ransomware', now() - INTERVAL 1 HOUR, 'Synology claims Example Bakery', ['Synology']),
                  ('ransomware_live:3', 'ransomware_live', 'ransomware', now() - INTERVAL 1 HOUR, 'Akira claims Example Dairy', ['Akira'])""")
    db.execute("INSERT INTO entities VALUES ('actor:akira', 'actor', 'Akira', [], '{}', now(), now())")
    c.put("/api/stack", json={"entities": ["cve:cve-2026-7002", "actor:akira"], "stack": [{"vendor": "Synology", "product": "DSM"}]})
    t = sec(c.get("/api/watch").json(), "touches")
    ep = {i["cve"]: i for i in t["items"] if i["type"] == "epss"}
    assert list(ep) == ["CVE-2026-7001"], "a followed CVE's small move is not a jump; an unfollowed CVE is not listed"
    assert ep["CVE-2026-7001"]["matched"] == ["stack:Synology DSM"] and ep["CVE-2026-7001"]["prev_epss"] == 0.02
    vic = {i["id"]: i["matched"] for i in t["items"] if i["type"] == "victim"}
    assert vic == {"ransomware_live:1": ["stack:Synology DSM", "actor:akira"], "ransomware_live:3": ["actor:akira"]}


def test_story_naming_a_followed_product_is_news_you_follow():
    db.execute("""INSERT INTO stories (id, title, first_seen, last_seen, article_count, source_count) VALUES
                  ('story:s', 'Exploited SMA flaw', ?, ?, 1, 1), ('story:n', 'Smart homes', ?, ?, 1, 1)""",
               [ago(hours=2)] * 4)
    db.execute("""INSERT INTO articles (id, url, source, title, text, story_id, status, published) VALUES
                  ('a1', 'https://example.org/1', 'Example', 'Exploited SMA flaw', 'SonicWall warns SMA100 owners', 'story:s', 'ok', ?),
                  ('a2', 'https://example.org/2', 'Example', 'Smart homes', 'Smart SMA-like gear from Sonicwallet', 'story:n', 'ok', ?)""",
               [ago(hours=2), ago(hours=2)])
    follow(vendor="SonicWall", product="SMA")
    f = sec(c.get("/api/watch").json(), "follow")
    assert [i["id"] for i in f["items"]] == ["story:s"] and f["items"][0]["matched"] == ["stack:SonicWall SMA"]
    assert f["items"][0]["matched_names"] == {"stack:SonicWall SMA": "SonicWall SMA"}


# ------------------------------------------------------------------ the old endpoints and the one list
def test_old_watchlist_endpoints_edit_the_same_list():
    follow(vendor="Synology", product="DSM")
    r = c.put("/api/news/watchlist", json={"entities": ["cve:cve-2026-1"], "keywords": ["ExampleGate", "examplegate"]})
    assert r.status_code == 200
    w = c.get("/api/news/watchlist").json()
    assert w["entities"] == ["cve:cve-2026-1"] and w["keywords"] == ["ExampleGate"], "same shape as v1.0, case-folded keywords"
    assert w["stack"] == [{"vendor": "Synology", "product": "DSM"}], "an old client never drops the stack"
    assert c.get("/api/stack").json()["count"] == 3
    assert c.get("/api/news/watchlist/digest").status_code == 200
    # unfollow by the key the UI shows
    c.post("/api/stack/unfollow", json={"key": "stack:Synology DSM"})
    c.post("/api/stack/unfollow", json={"key": "keyword:examplegate"})
    w = c.get("/api/stack").json()
    assert w["stack"] == [] and w["keywords"] == [] and w["entities"] == ["cve:cve-2026-1"]
    assert c.put("/api/news/watchlist", json={"keywords": ["x"] * 2 + [f"k{i}" for i in range(501)]}).status_code == 400


def test_follow_dedupes_and_suggests():
    assert follow(text="Synology DSM")["added"]
    again = follow(vendor="synology", product="dsm")
    assert not again["added"] and again["already"] == "Synology DSM"
    kev("CVE-2026-9001", "Synology", "DSM")
    kev("CVE-2026-9002", "Zyxel", "Firewall")
    s = c.get("/api/stack/suggest", params={"q": "zyx"}).json()["items"]
    assert s[0]["label"] == "Zyxel" and s[0]["kev"] == 1
    assert not [x for x in c.get("/api/stack/suggest", params={"q": "syn"}).json()["items"] if x["label"] == "Synology DSM"], "already followed"
    q = c.get("/api/stack/quick").json()["items"]
    assert q and all(x["label"] != "Synology DSM" for x in q) and {"vendor", "product", "label", "kev"} <= set(q[0])
    st = c.get("/api/setup/status").json()
    item = next(i for i in st["items"] if i["id"] == "watchlist")
    assert item["done"] and item["quick"] and item["action"]["href"] == "#settings/follow"


def test_follow_state_resolves_merged_ids():
    for eid, name in (("malware:exqilin", "ExQilin"), ("malware:exagenda", "ExAgenda")):
        db.execute("INSERT INTO entities VALUES (?, 'malware', ?, [], '{}', now(), now())", [eid, name])
    follow(entity="malware:exagenda")
    assert c.post("/api/entities/merge", json={"src": "malware:exagenda", "dst": "malware:exqilin"}).status_code == 200
    w = c.get("/api/stack").json()
    assert set(w["equivalents"]["malware:exagenda"]) >= {"malware:exagenda", "malware:exqilin"}, "the kept id reads as followed"
    r = follow(entity="malware:exqilin")
    assert not r["added"] and r["already"] == "malware:exagenda" and r["entities"] == ["malware:exagenda"], "no duplicate"
    assert c.put("/api/news/watchlist", json={"entities": ["malware:exagenda", "malware:exqilin"]}).json()["entities"] == ["malware:exagenda"]
    m = c.post("/api/stack/match", json={"items": [{"key": "s", "entities": ["malware:exqilin"]}]}).json()["matches"]
    assert m == {"s": [{"key": "malware:exagenda", "name": "ExQilin"}]}
    # unfollowing the kept id removes the merged one
    assert c.post("/api/stack/unfollow", json={"entity": "malware:exqilin"}).json()["entities"] == []
