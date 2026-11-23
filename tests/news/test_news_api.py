"""News API on a temporary lake with synthetic articles, entities and CVE events (no network), and the EPSS bulk
lookup: a GET (Ops calls it on every load, so read-only clients never see a POST) that returns exactly what POST did,
reads the lake only, and keeps its limits.

    uv run --with pytest pytest tests/news/test_news_api.py -q
"""

from _lake import make_lake
LAKE = make_lake("news")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db  # noqa: E402
from osinthub.news import stories  # noqa: E402
from osinthub.news.api import router  # noqa: E402
from osinthub.news.common import ensure_schema  # noqa: E402

ensure_schema()
db.connect()
TEXT1 = ("Attackers exploited CVE-2026-1111 in ExampleGate appliances, Talos said. The Volt Example group used "
         "the server 203.0.113.7 for command and control and the domain evil-c2[.]example. ") * 8 + \
        "The researchers shared their notes on github.com. The script reads container.id first. Fixed in 9.16.4.104 and later."
TEXT2 = ("Unit 42 also saw exploitation of CVE-2026-1111 in ExampleGate devices by the Volt Example group, "
         "with traffic to 203.0.113.7. ") * 8
def test_news_api():
    for i, (src, title, text, day) in enumerate([("Talos", "ExampleGate zero-day CVE-2026-1111 exploited", TEXT1, 1),
                                                 ("Unit 42", "Volt Example exploits ExampleGate flaw", TEXT2, 3)]):
        db.execute("""INSERT INTO articles (id, url, source, title, text, published, status, tier, role)
                      VALUES (?, ?, ?, ?, ?, ?, 'ok', 'B', 'research')""", [f"a{i}", f"https://x{i}.example/a", src, title, text, f"2026-11-0{day}T10:00:00Z"])
        db.execute("INSERT INTO article_chunks VALUES (?, 0, ?)", [f"a{i}", f"{title}\n{text}"])
    for eid, typ, name, aliases in [("cve:cve-2026-1111", "cve", "CVE-2026-1111", []), ("actor:volt-example", "actor", "Volt Example", ["VoltEx"]),
                                    ("ip:203.0.113.7", "ip", "203.0.113.7", []), ("domain:evil-c2.example", "domain", "evil-c2.example", []),
                                    ("domain:github.com", "domain", "github.com", []), ("domain:container.id", "domain", "container.id", []),
                                    ("cve:cve-2026-111", "cve", "CVE-2026-111", []), ("ip:9.16.4.104", "ip", "9.16.4.104", []),
                                    ("domain:not-in-text.example", "domain", "not-in-text.example", [])]:
        db.execute("INSERT INTO entities VALUES (?, ?, ?, ?, '{}', '2026-10-01', '2026-11-03')", [eid, typ, name, aliases])
        for a in ("a0", "a1"):
            db.execute("INSERT INTO mentions VALUES (?, 'article', ?, 'mentioned', 'regex', 0.9, now())", [eid, a])
    db.execute("""INSERT INTO claims VALUES ('c1', 'actor:volt-example', 'uses', 'ip:203.0.113.7', 'reported', ['Talos'], 0.8,
                  '2026-11-01', '2026-11-03', '[]')""")
    db.execute("""INSERT INTO events (id, source, kind, ts, title, summary, value, tags) VALUES
                  ('n1', 'nvd_recent', 'cve', '2026-10-30', 'CVE-2026-1111 · CVSS 9.8', 'ExampleGate RCE', 9.8, ['critical']),
                  ('k1', 'cisa_kev', 'kev', '2026-11-02', 'CVE-2026-1111 · Example ExampleGate', 'x', NULL, ['ransomware'])""")
    stories.cluster_pending()

    app = FastAPI()
    app.include_router(router)
    c = TestClient(app)
    fails = []


    def check(name, cond, detail=""):
        print(("PASS " if cond else "FAIL ") + name + (f"  {detail}" if not cond else ""))
        if not cond:
            fails.append(name)


    st = c.get("/api/news/stories").json()["stories"]
    check("two research reports on one CVE form one story", len(st) == 1 and st[0]["article_count"] == 2, st)
    sd = c.get(f"/api/news/stories/{st[0]['id']}").json()
    check("story timeline", [t["kind"] for t in sd["timeline"]] == ["first_report", "corroboration"], sd["timeline"])
    ioc = {i["value"]: i for i in sd["iocs"]}
    check("story IoC table", "203.0.113.7" in ioc and ioc["203.0.113.7"]["sources"] == ["Talos", "Unit 42"]
          and ioc["203.0.113.7"]["relationships"][0]["predicate"] == "uses", sd["iocs"])
    cv = sd["cves"][0]
    check("IoC table drops field names, truncated CVEs and benign domains",
          "container.id" not in ioc and "github.com" not in ioc and "CVE-2026-111" not in ioc and "evil-c2.example" in ioc
          and "9.16.4.104" not in ioc and "not-in-text.example" not in ioc, sorted(ioc))
    check("CVE enrichment", cv["id"] == "CVE-2026-1111" and cv["cvss"] == 9.8 and cv["kev"] and cv["ransomware"] and "epss" in cv, cv)
    ad = c.get("/api/news/articles/a0").json()
    ents = {e["id"]: e for e in ad["entities"]}
    off = ents["actor:volt-example"]["offsets"]
    check("mention offsets point at the name", off and ad["text"][off[0][0]:off[0][1]] == "Volt Example", off)
    eo = ents["domain:evil-c2.example"]["offsets"]
    check("offsets cover defanged forms", eo and ad["text"][eo[0][0]:eo[0][1]] == "evil-c2[.]example", eo)
    check("CVE offsets", ad["text"][ents["cve:cve-2026-1111"]["offsets"][0][0]:ents["cve:cve-2026-1111"]["offsets"][0][1]] == "CVE-2026-1111")
    check("similar excludes the article's own story", all(r["story_id"] != ad["story_id"] for r in ad["similar"]["results"]), ad["similar"])
    r = c.get("/api/news/search", params={"q": "ExampleGate exploited", "collapse": "story"}).json()
    check("search collapse=story gives one hit per story", len(r["results"]) == 1 and r["results"][0]["story_hits"] == 2, r)
    r2 = c.get("/api/news/search", params={"q": "ExampleGate exploited"}).json()
    check("search without collapse keeps both articles", len(r2["results"]) == 2)
    rv = c.get("/api/news/search", params={"q": "ExampleGate exploited", "mode": "vector"}).json()
    check("vector search without vectors falls back to real keyword hits, labelled honestly",
          rv["mode"] == "keyword" and rv["requested_mode"] == "vector" and rv["fallback"] and len(rv["results"]) == 2, rv)
    check("unknown search mode is a 400", c.get("/api/news/search", params={"q": "x", "mode": "bogus"}).status_code == 400)
    check("unknown collapse is a 400", c.get("/api/news/search", params={"q": "x", "collapse": "bogus"}).status_code == 400)
    check("cves endpoint", c.get("/api/news/cves", params={"ids": "CVE-2026-1111"}).json()[0]["kev_added"] is not None)
    it = c.get("/api/news/intel", params={"story": st[0]["id"]})
    check("intel endpoint (News UI) still answers", it.status_code == 200 and it.json()["available"], it.text[:200])
    # api-probe-r2-005: an unknown story or article is a 404, as on the detail endpoints
    it = c.get("/api/news/intel", params={"story": "story:doesnotexist"})
    check("intel for an unknown story is a 404", it.status_code == 404 and it.json()["detail"] == "unknown story", it.text)
    it = c.get("/api/news/intel", params={"article": "doesnotexist"})
    check("intel for an unknown article is a 404", it.status_code == 404 and it.json()["detail"] == "unknown article", it.text)
    aid = c.get(f"/api/news/stories/{st[0]['id']}").json()["articles"][0]["id"]
    check("intel for a known article", c.get("/api/news/intel", params={"article": aid}).status_code == 200)
    # api-probe-r2-006: an unknown order is a 400 naming the allowed values
    r = c.get("/api/news/stories", params={"order": "newest"})
    check("stories order=newest is a 400", r.status_code == 400 and "last_seen, first_seen, size" in r.json()["detail"], r.text)
    check("stories valid orders", all(c.get("/api/news/stories", params={"order": o}).status_code == 200 for o in ("last_seen", "first_seen", "size")))
    from osinthub.news.api import _story_iocs
    db.execute("""INSERT INTO articles (id, url, source, title, text, published, status, tier, role) VALUES
                  ('a9', 'https://x9.example/a', 'SANS ISC', 'Scans for Example flaw (CVE-2026-2222)', 'Scans seen in our honeypots.',
                   '2026-11-04T10:00:00Z', 'ok', 'B', 'research')""")
    db.execute("INSERT INTO entities VALUES ('cve:cve-2026-2222', 'cve', 'CVE-2026-2222', [], '{}', '2026-11-04', '2026-11-04')")
    db.execute("INSERT INTO mentions VALUES ('cve:cve-2026-2222', 'article', 'a9', 'mentioned', 'regex', 0.9, now())")
    ti = _story_iocs([{"id": "a9", "published": "2026-11-04T10:00:00Z", "source": "SANS ISC"}])
    check("a CVE named only in the headline is in the IoC table", [i["value"] for i in ti] == ["CVE-2026-2222"], ti)
    sv = c.get("/api/news/sources").json()
    check("news/sources enabled is a boolean for every feed", all(isinstance(f["enabled"], bool) for f in sv["feeds"]), sv["feeds"][:2])
    import time
    from osinthub.ai import client as ai_client
    ai_client._down_until = time.monotonic() + 600   # the helper is marked down
    b = c.get("/api/news/entity-brief/actor:volt-example").json()
    check("entity brief with the AI helper down says the wording is unavailable",
          b["evidence"] and b["llm_unavailable"] is True and b["llm_status"] == "unavailable" and not b["llm_pending"],
          {k: b.get(k) for k in ("llm_status", "llm_unavailable", "llm_pending")})
    check("entity brief llm=false is status off", c.get("/api/news/entity-brief/actor:volt-example", params={"llm": "false"}).json()["llm_status"] == "off")
    check("entity brief for an unknown id is a 404", c.get("/api/news/entity-brief/nope", params={"llm": "false"}).status_code == 404)
    check("entity brief for a known entity", c.get("/api/news/entity-brief/actor:volt-example", params={"llm": "false"}).status_code == 200)
    print("ALL PASS" if not fails else f"{len(fails)} FAILED")
    assert not fails, f"{len(fails)} failed: {fails}"


# ---------------------------------------------------------------- EPSS lookup
import socket  # noqa: E402

import pytest  # noqa: E402

from osinthub.news.api import EPSS_GET_MAX  # noqa: E402

E = TestClient(FastAPI())
E.app.include_router(router)


@pytest.fixture()
def rows():
    db.execute("DELETE FROM epss")
    db.execute("""INSERT INTO epss (cve, epss, percentile, score_date, model_version, since, prev_epss) VALUES
                  ('CVE-2026-1111', 0.42, 0.97, '2026-11-12 00:00:00+00', 'v2025.03.14', '2026-11-10 00:00:00+00', 0.05),
                  ('CVE-2026-2222', 0.001, 0.12, '2026-11-12 00:00:00+00', 'v2025.03.14', NULL, NULL)""")
    yield


def test_get_returns_same_payload_as_post(rows):
    ids = ["CVE-2026-1111", "cve-2026-2222", "CVE-2026-9999", "not-a-cve"]
    g = E.get("/api/news/epss", params={"ids": ",".join(ids)})
    p = E.post("/api/news/epss", json={"ids": ids})
    assert g.status_code == 200 and p.status_code == 200
    assert g.json() == p.json()
    body = g.json()
    assert body["score_date"].startswith("2026-11-12") and body["model_version"] == "v2025.03.14"
    assert set(body["scores"]) == {"CVE-2026-1111", "CVE-2026-2222"}
    s = body["scores"]["CVE-2026-1111"]
    assert s["epss"] == 0.42 and s["percentile"] == 0.97 and s["prev_epss"] == 0.05 and s["since"].startswith("2026-11-10")


def test_get_empty_and_limits(rows):
    assert E.get("/api/news/epss").json()["scores"] == {}
    ok = ",".join(f"CVE-2026-{1000 + i}" for i in range(EPSS_GET_MAX))
    assert E.get("/api/news/epss", params={"ids": ok}).status_code == 200
    too_many = ok + ",CVE-2026-99999"
    assert E.get("/api/news/epss", params={"ids": too_many}).status_code == 400
    assert E.post("/api/news/epss", json={"ids": "CVE-2026-1111"}).status_code == 400   # POST keeps its checks


def test_lookup_makes_no_outbound_connection(rows, monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("EPSS lookup tried to open a network connection")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    assert "CVE-2026-1111" in E.get("/api/news/epss", params={"ids": "CVE-2026-1111"}).json()["scores"]
