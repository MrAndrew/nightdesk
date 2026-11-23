"""ATT&CK techniques read from article text, as GET /api/news/intel lists them for the News UI: each one labelled
named (the article prints the id), likely (confirmed tier: mention role `technique`) or possible (suggested tier only),
with the sentence it came from when one is stored, and none of another story's quotes. Read-only; no extraction.
Docs: okf/data/entities.md#technique-labels

    uv run --with pytest pytest tests/news/test_v12_ttpwording.py -q
"""

from _lake import make_lake
LAKE = make_lake("ttpwording")

import json  # noqa: E402

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db  # noqa: E402
from osinthub.entities import store  # noqa: E402
from osinthub.news.api import router  # noqa: E402
from osinthub.news.common import ensure_schema  # noqa: E402

ensure_schema()
store.ensure_schema()
db.connect()

Q_WS = "Once opened, ExampleRAT dropped a web shell on the mail server so the operators could come back later."
Q_PW = "The operators then searched shared folders for text files that held saved passwords."
Q_OTHER = "Another outlet wrote a different sentence about web shells."
TEXT = ("Harbor Threat Notes tracked a new ExampleRAT phishing wave. The emails carried a booby-trapped invoice, "
        f"the delivery method MITRE ATT&CK lists as T1566.001. {Q_WS} {Q_PW} ExampleRAT talks to its operators over web traffic.")


def _ev(ref, quote, suggested=False):
    e = {"source": "Harbor Threat Notes", "tier": "B", "ref_type": "article", "ref_id": ref, "method": "llm", "quote": quote}
    return {**e, "suggested": True} if suggested else e


def setup_module():
    for aid, story, text in (("t1", "story:t1", TEXT), ("t2", "story:t2", "An unrelated report about routers.")):
        db.execute("""INSERT INTO articles (id, url, source, title, text, published, status, tier, role, story_id)
                      VALUES (?, ?, 'Harbor Threat Notes', 'ExampleRAT phishing', ?, '2026-11-10T10:00:00Z', 'ok', 'B', 'research', ?)""",
                   [aid, f"https://{aid}.example/a", text, story])
        db.execute("INSERT INTO stories (id, title, lead_article, first_seen, last_seen) VALUES (?, 'x', ?, now(), now())", [story, aid])
    for eid, name in (("technique:T1566.001", "T1566.001 Spearphishing Attachment"), ("technique:T1505.003", "Web Shell"),
                      ("technique:T1071.001", "Web Protocols"), ("technique:T1552.001", "Credentials In Files"),
                      ("malware:examplerat", "ExampleRAT")):
        db.execute("INSERT INTO entities VALUES (?, ?, ?, [], '{}', '2026-11-01', '2026-11-10')", [eid, eid.split(":")[0], name])
    for eid, role, conf in (("technique:T1566.001", "technique", 0.7), ("technique:T1505.003", "technique", 0.7),
                            ("technique:T1071.001", "technique", 0.7), ("technique:T1552.001", "technique-suggested", 0.3)):
        db.execute("INSERT INTO mentions VALUES (?, 'article', 't1', ?, 'llm', ?, now())", [eid, role, conf])
    # T1505.003 is also in the other story's article, with its own sentence: each story shows only its own quote
    db.execute("INSERT INTO mentions VALUES ('technique:T1505.003', 'article', 't2', 'technique', 'llm', 0.7, now())")
    for cid, obj, ev in (("k1", "technique:T1505.003", [_ev("t1", Q_WS), _ev("t2", Q_OTHER)]),
                         ("k2", "technique:T1552.001", [_ev("t1", Q_PW, suggested=True)])):
        db.execute("INSERT INTO claims VALUES (?, 'malware:examplerat', 'uses', ?, 'reported', ['Harbor Threat Notes'], 0.2, now(), now(), ?)",
                   [cid, obj, json.dumps(ev)])


def _client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_intel_labels_each_technique_with_its_sentence():
    r = _client().get("/api/news/intel", params={"story": "story:t1"})
    assert r.status_code == 200
    ts = {t["id"]: t for t in r.json()["techniques"]}
    assert [t["kind"] for t in r.json()["techniques"]] == ["named", "likely", "likely", "possible"], "named, then likely, then possible"
    assert ts["T1566.001"]["kind"] == "named"
    assert ts["T1566.001"]["quote"] == "The emails carried a booby-trapped invoice, the delivery method MITRE ATT&CK lists as T1566.001."
    assert ts["T1566.001"]["source"] == "Harbor Threat Notes" and ts["T1566.001"]["ref_id"] == "t1"
    assert ts["T1505.003"] == {"id": "T1505.003", "entity": "technique:T1505.003", "name": "Web Shell", "kind": "likely",
                               "quote": Q_WS, "ref_id": "t1", "source": "Harbor Threat Notes"}
    assert ts["T1071.001"]["kind"] == "likely" and ts["T1071.001"]["quote"] is None, "no actor named: no sentence stored"
    assert ts["T1552.001"]["kind"] == "possible" and ts["T1552.001"]["quote"] == Q_PW


def test_intel_quotes_stay_inside_the_story():
    ts = {t["id"]: t for t in _client().get("/api/news/intel", params={"story": "story:t2"}).json()["techniques"]}
    assert set(ts) == {"T1505.003"}
    assert ts["T1505.003"]["quote"] == Q_OTHER and ts["T1505.003"]["ref_id"] == "t2"


def test_intel_for_one_article_and_an_article_without_techniques():
    c = _client()
    ts = c.get("/api/news/intel", params={"article": "t1"}).json()["techniques"]
    assert len(ts) == 4
    db.execute("INSERT INTO articles (id, url, source, title, text, status, tier) VALUES ('t3', 'https://t3.example/', 'X', 'y', 'z', 'ok', 'C')")
    assert c.get("/api/news/intel", params={"article": "t3"}).json()["techniques"] == []


def test_a_long_sentence_is_cut_around_the_printed_id():
    from osinthub.news.api import QUOTE_MAX, _sentence_with
    long = "Intro. The operators " + "moved slowly through the network and " * 14 + "the report maps this to T1059.003 in its appendix. Next one."
    i = long.index("T1059.003")
    s = _sentence_with(long, i, i + 9)
    assert len(s) <= QUOTE_MAX and "T1059.003" in s, s
    assert s.startswith("…") and s.endswith("appendix."), "cut on the left only: the sentence end is near the id"
    early = "Intro. Uses T1059.003 " + "and more words " * 40 + "until the end. Next."
    i = early.index("T1059.003")
    s = _sentence_with(early, i, i + 9)
    assert s.startswith("Uses T1059.003") and s.endswith("…") and len(s) <= QUOTE_MAX
    mid = "A " + "very " * 60 + "long lead to T1059.003 and " + "more " * 60 + "words."
    i = mid.index("T1059.003")
    s = _sentence_with(mid, i, i + 9)
    assert s.startswith("…") and s.endswith("…") and "T1059.003" in s and len(s) <= QUOTE_MAX
    t = "First one. Uses T1059.001 to run scripts! Last."
    i = t.index("T1059.001")
    assert _sentence_with(t, i, i + 9) == "Uses T1059.001 to run scripts!"


def test_intel_marks_a_link_the_catalogue_also_states():
    """A claim row that holds both ATT&CK reference evidence and this story's article evidence keeps `catalogue: true`
    (the reference item itself is not returned), so the News UI never gives it an article label."""
    db.execute("""INSERT INTO claims VALUES ('k3', 'malware:examplerat', 'uses', 'technique:T1566.001', 'reported',
                  ['MITRE ATT&CK', 'Harbor Threat Notes'], 0.9, now(), now(), ?)""",
               [json.dumps([_ev("t1", Q_WS), {"source": "MITRE ATT&CK", "ref_type": "reference", "ref_id": "attack"}])])
    try:
        cl = {c["id"]: c for c in _client().get("/api/news/intel", params={"story": "story:t1"}).json()["claims"]}
        assert cl["k3"]["catalogue"] is True and [e["ref_id"] for e in cl["k3"]["evidence"]] == ["t1"]
        assert cl["k1"]["catalogue"] is False and cl["k2"]["catalogue"] is False
    finally:
        db.execute("DELETE FROM claims WHERE id = 'k3'")


def test_entity_brief_words_article_technique_links_honestly():
    from osinthub.news import brief
    why = lambda eid: " ".join(w["text"] for w in brief.facts(eid)["why"])  # noqa: E731
    assert "Used by" not in why("technique:T1552.001"), "a possible link is left out of the brief"
    assert "Used by ExampleRAT (read automatically from articles; it can be wrong)." in why("technique:T1505.003")
    assert brief._tech_link({"subj": "actor:x", "obj": "technique:T1566.001", "origin": "reported",
                             "evidence": [{"ref_type": "article", "suggested": True}, {"ref_type": "reference"}]}) == "catalogue"


def test_brief_never_states_an_article_link_as_fact_next_to_a_catalogue_link():
    """MITRE links one actor to T1505.003, an article links ExampleRAT: two sentences, each worded by its own evidence."""
    from osinthub.news import brief
    db.execute("INSERT INTO entities VALUES ('actor:ttpw-apt', 'actor', 'TTPW Group', [], '{}', '2026-11-01', '2026-11-10')")
    db.execute("""INSERT INTO claims VALUES ('k4', 'actor:ttpw-apt', 'uses', 'technique:T1505.003', 'reported', ['MITRE ATT&CK'], 0.9,
                  now(), now(), ?)""", [json.dumps([{"source": "MITRE ATT&CK", "ref_type": "reference", "ref_id": "attack"}])])
    try:
        texts = [w["text"] for w in brief.facts("technique:T1505.003")["why"]]
        assert "Used by TTPW Group." in texts, texts
        assert "Used by ExampleRAT (read automatically from articles; it can be wrong)." in texts, texts
        assert not any("TTPW Group" in t and "ExampleRAT" in t for t in texts), "never one sentence mixing the two"
    finally:
        db.execute("DELETE FROM claims WHERE id = 'k4'")
