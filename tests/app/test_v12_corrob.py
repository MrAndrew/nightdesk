"""v1.2 lane corrob: each address counts once on every dashboard count (Activity timeline, kind totals, map, Threat
Origins, Top Offenders), and how many feeds listed an address is shown beside it (corroboration, not a score).

    uv run --with pytest pytest tests/app/test_v12_corrob.py -q
"""
from __future__ import annotations

from _lake import make_lake

LAKE = make_lake("corrob", disable="news,netlog,ai,entities")

from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db  # noqa: E402

db.connect()
from osinthub.api import app  # noqa: E402

C = TestClient(app, base_url="http://127.0.0.1")

MULTI = "198.51.100.7"     # Feodo, blocklist.de and ThreatFox list it in the last day
SOLO = "203.0.113.9"       # blocklist.de only
OLD = "192.0.2.5"          # CINS ten days ago, Tor exits today
# (id, source, kind, category, hours ago, severity, ip, country, lat, lon)
ROWS = [
    ("e-feodo", "feodo_c2", "c2", "threat", 2, 0.9, MULTI, "NL", 52.1, 5.1),
    ("e-bl", "blocklist_de", "attacker", "threat", 5, 0.5, MULTI, "NL", 52.1, 5.1),
    ("e-tf1", "threatfox", "malware_ioc", "threat", 1, 0.95, MULTI, "NL", 52.1, 5.1),
    ("e-tf2", "threatfox", "malware_ioc", "threat", 3, 0.8, MULTI, "NL", 52.1, 5.1),   # a second IOC (other port)
    ("e-solo", "blocklist_de", "attacker", "threat", 4, 0.5, SOLO, "DE", 50.1, 8.6),
    ("e-cins", "cins_army", "attacker", "threat", 240, 0.6, OLD, "US", 40.7, -74.0),
    ("e-tor", "tor_exits", "tor_exit", "threat", 6, 0.3, OLD, "US", 40.7, -74.0),
    ("e-cve1", "nvd_recent", "cve", "vuln", 3, 0.7, None, None, None, None),
    ("e-cve2", "nvd_recent", "cve", "vuln", 7, 0.7, None, None, None, None),
    ("e-blank", "upload", "indicator", "custom", 2, 0.5, "", None, None, None),   # an empty address is no address
]
for r in ROWS:
    db.execute("INSERT INTO events (id, source, kind, category, ts, title, severity, ip, country, lat, lon) "
               "VALUES (?, ?, ?, ?, now() - to_microseconds(?), ?, ?, ?, ?, ?, ?)",
               [r[0], r[1], r[2], r[3], int(r[4] * 3_600_000_000), f"event {r[0]}", *r[5:]])


def tl(**p):
    out: dict[str, int] = {}
    for r in C.get("/api/stats/timeline", params={"hours": 24, "bucket": "hour", **p}).json():
        out[r["kind"]] = out.get(r["kind"], 0) + r["n"]
    return out


def test_timeline_counts_each_address_once():
    k = tl()
    # MULTI is four events from three feeds: one count, under Feodo's c2 (the original listing beats ThreatFox's
    # copy, then the most severe); OLD counts once under tor_exit (CINS is outside the window); events without an
    # address (and the empty one) count one each
    assert k == {"c2": 1, "attacker": 1, "tor_exit": 1, "cve": 2, "indicator": 1}
    assert sum(k.values()) == 6
    # `a`: how many of the counted are addresses (the panel says "3 addresses + 3 events")
    rows = C.get("/api/stats/timeline", params={"hours": 24, "bucket": "hour"}).json()
    assert sum(r["a"] for r in rows) == 3 and all(r["a"] == 0 for r in rows if r["kind"] in ("cve", "indicator"))
    top = C.get("/api/stats/top", params={"field": "kind", "since_hours": 24, "limit": 100}).json()
    assert sum(r["a"] for r in top) == 3 and sum(r["n"] for r in top) == 6
    # every bucket row is one representative: MULTI sits in the bucket of the Feodo event (2 h ago)
    assert sum(r["n"] for r in C.get("/api/stats/timeline", params={"hours": 24, "bucket": "minute"}).json()) == 6


def test_filters_still_work():
    # a kind filter applies first, so every address that kind lists counts (MULTI is also a blocklist.de attacker)
    assert tl(kinds="attacker") == {"attacker": 2}
    assert tl(kinds="malware_ioc") == {"malware_ioc": 1}            # two ThreatFox IOCs, one address
    assert tl(categories="vuln") == {"cve": 2}                      # no address: unaffected
    assert tl(categories="threat") == {"c2": 1, "attacker": 1, "tor_exit": 1}
    assert tl(q=MULTI) == {"c2": 1}
    assert C.get("/api/stats/timeline", params={"hours": 24, "bucket": "week"}).status_code == 400


def test_kind_totals_count_each_address_once():
    s = C.get("/api/stats/summary", params={"since_hours": 24}).json()
    kinds = {k["kind"]: (k["total"], k["recent"]) for k in s["kinds"]}
    # OLD has an event in the window (Tor), so that one stands for it in the all-history total as well: a kind's
    # recent is never above its total (the older, more severe CINS listing would otherwise be the all-history one)
    assert kinds == {"c2": (1, 1), "attacker": (1, 1), "tor_exit": (1, 1), "cve": (2, 2), "indicator": (1, 1)}
    assert s["totals"]["events"] == len(ROWS) and s["totals"]["recent"] == len(ROWS) - 1   # stored records, every row
    assert s["totals"]["ips"] == 3
    assert all(k["recent"] <= k["total"] for k in s["kinds"])
    # the window's kind totals are the timeline's
    assert {k: v[1] for k, v in kinds.items() if v[1]} == tl()
    # all history: every recent equals its total
    a = C.get("/api/stats/summary", params={"since_hours": 10 ** 9}).json()["kinds"]
    assert all(k["recent"] == k["total"] for k in a) and sum(k["total"] for k in a) == 6


def test_every_panel_agrees_for_the_same_window_and_filters():
    for kinds in (None, "c2,attacker,malware_ioc,tor_exit", "attacker"):
        p = {"since_hours": 24, **({"kinds": kinds} if kinds else {})}
        timeline = sum(tl(**({"kinds": kinds} if kinds else {})).values())
        by_kind = sum(r["n"] for r in C.get("/api/stats/top", params={**p, "field": "kind", "limit": 100}).json())
        assert timeline == by_kind, kinds
        # map, Threat Origins and the country tab count the located events: each address once there too
        located = C.get("/api/geo/points", params={**p, "limit": 1000}).json()["rows"]
        countries = sum(r["n"] for r in C.get("/api/stats/countries", params=p).json())
        cc = sum(r["n"] for r in C.get("/api/stats/top", params={**p, "field": "country", "limit": 100}).json())
        assert len(located) == countries == cc, kinds
        assert len({r[4] for r in located}) == len(located)
        ips = C.get("/api/stats/top", params={**p, "field": "ip", "limit": 100}).json()
        assert all(r["n"] == 1 for r in ips) and len({r["key"] for r in ips}) == len(ips)
    # the event list still shows every event
    assert len(C.get("/api/events", params={"q": MULTI}).json()) == 4


def test_top_ip_shows_how_many_feeds_list_each_address():
    p = {"field": "ip", "since_hours": 24, "limit": 10}
    rows = C.get("/api/stats/top", params=p).json()
    by = {r["key"]: r for r in rows}
    assert set(by) == {MULTI, SOLO, OLD}                              # the empty address is not a row
    m = by[MULTI]
    assert m["feeds"] == 3 and m["n"] == 1 and m["country"] == "NL"
    assert [x["source"] for x in m["sources"]] == ["threatfox", "feodo_c2", "blocklist_de"]   # newest listing first
    assert {x["name"] for x in m["sources"]} == {"Feodo Tracker botnet C2", "ThreatFox malware IOCs", "blocklist.de attackers"}
    assert next(x for x in m["sources"] if x["source"] == "threatfox")["events"] == 2
    assert by[OLD]["feeds"] == 1 and by[SOLO]["feeds"] == 1           # CINS listed OLD outside the window
    # default ranking: most severe first (each address counts once, so n ties); sort=feeds ranks by feeds
    assert [r["key"] for r in rows] == [MULTI, SOLO, OLD]
    assert m["sev"] == 0.95 and m["country"] == "NL"                  # the highest severity any feed gives it
    assert [r["key"] for r in C.get("/api/stats/top", params={**p, "sort": "feeds"}).json()][0] == MULTI
    allh = {r["key"]: r["feeds"] for r in C.get("/api/stats/top", params={"field": "ip", "sort": "feeds"}).json()}
    assert allh[OLD] == 2
    # filters narrow the feeds counted too
    k = {r["key"]: r["feeds"] for r in C.get("/api/stats/top", params={**p, "kinds": "attacker"}).json()}
    assert k == {MULTI: 1, SOLO: 1}
    assert C.get("/api/stats/top", params={**p, "limit": 0}).json() == []
    assert C.get("/api/stats/top", params={"field": "asn", "sort": "feeds"}).status_code == 400
    assert C.get("/api/stats/top", params={**p, "sort": "bogus"}).status_code == 400


def test_feeds_endpoint_and_event_drawer():
    r = C.get("/api/stats/feeds", params={"ips": f"{MULTI},{OLD},{MULTI},192.0.2.200", "since_hours": 24}).json()
    assert [(x["ip"], x["feeds"]) for x in r] == [(MULTI, 3), (OLD, 1), ("192.0.2.200", 0)]
    r = C.get("/api/stats/feeds", params={"ips": OLD}).json()           # all history
    assert r[0]["feeds"] == 2 and [x["source"] for x in r[0]["sources"]] == ["tor_exits", "cins_army"]
    assert C.get("/api/stats/feeds", params={"ips": ",".join(f"192.0.2.{i}" for i in range(250)) + "," +
                                             ",".join(f"198.51.100.{i}" for i in range(251))}).status_code == 400
    e = C.get("/api/events/e-bl").json()
    assert [x["source"] for x in e["reported_by"]] == ["threatfox", "feodo_c2", "blocklist_de"]
    assert all(x["last"] and x["name"] for x in e["reported_by"])
    assert C.get("/api/events/e-cve1").json()["reported_by"] == []
    assert C.get("/api/events/e-blank").json()["reported_by"] == []


def test_feeds_endpoint_normalises_addresses():
    import datetime as dt

    from osinthub.sources.base import Event
    # two feeds spell one address two ways; the event stores it once, in the standard form
    for i, (src, ip) in enumerate((("feodo_c2", "2001:db8::5"), ("blocklist_de", "2001:DB8:0:0::5"))):
        e = Event(source=src, kind="c2", key=("v6", i), ts=dt.datetime.now(dt.UTC), title="v6", ip=ip)
        db.execute("INSERT INTO events (id, source, kind, category, ts, title, severity, ip) "
                   "VALUES (?, ?, 'c2', 'threat', now(), 'v6', 0.9, ?)", [f"e-v6-{i}", src, e.ip])
    r = C.get("/api/stats/feeds", params={"ips": "2001:DB8::5,2001:db8:0:0:0:0:0:5, 198.51.100.7 "}).json()
    assert [(x["ip"], x["feeds"]) for x in r] == [("2001:db8::5", 2), (MULTI, 3)]
    for bad in ("not-an-ip", "198.51.100.300", "198.51.100.7,x' OR 1=1 --"):
        assert C.get("/api/stats/feeds", params={"ips": bad}).status_code == 400, bad
