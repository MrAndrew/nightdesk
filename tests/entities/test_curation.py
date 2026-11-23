"""Curating entities: "Same as…" merges and "Wrong type…" retypes survive re-extraction and can be undone,
likely duplicates are suggested (and "Not the same" dismisses them), "Disagree…" stores a reason and keeps the
trust lane's reject semantics, and the review queue lists what is left to judge. Verdicts annotate claims (reject
hides, also from a story's intel; confirm never double-counts), computed links are hypotheses capped below sourced
claims, reference rows are authoritative, /activity takes no ids. Temporary lake, no network.

    uv run --with pytest pytest tests/entities/test_curation.py -q
"""
import json

from _lake import make_lake
LAKE = make_lake("entities-intelx")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db  # noqa: E402
from osinthub.entities import api, overrides, scoring, store  # noqa: E402
from osinthub.news import api as news_api  # noqa: E402
from osinthub.news.common import ensure_schema as news_schema  # noqa: E402

db.connect()
store.ensure_schema()
news_schema()
_app = FastAPI()
_app.include_router(api.router)
_app.include_router(news_api.router)
C = TestClient(_app)

# One ransomware operation split three ways, as on the test lake (made-up names, so other tests never collide).
ACT, MAL, ALT = "actor:ixqilin", "malware:ixqilin", "malware:ixagendacrypt"
CVE, VIC, TOOL = "cve:cve-2099-0001", "org:ix-victim", "tool:ixtool"
TS = "2026-10-01T00:00:00+00:00"


def _m(eid, ref, ts=TS):
    return {"entity_id": eid, "ref_type": "article", "ref_id": ref, "role": "mentioned", "method": "llm", "confidence": 0.9, "ts": ts}


def _claim(subj, pred, obj, src="vendor.example", tier="B", ref="r1", quote=None):
    return {"subj": subj, "predicate": pred, "obj": obj, "origin": "reported", "sources": [src], "first_seen": TS, "last_seen": TS,
            "evidence": [{"source": src, "tier": tier, "quote": quote or f"{subj} {pred} {obj}", "ref_type": "article", "ref_id": ref}]}


def _reset():
    """Fresh copies of the three entities with their mentions and claims (undoing any earlier override)."""
    for o in db.query("SELECT id FROM entity_overrides WHERE src LIKE '%ix%' OR dst LIKE '%ix%' ORDER BY created_at DESC"):
        try:
            overrides.undo(o["id"])
        except overrides.OverrideError:
            store.execute("DELETE FROM entity_overrides WHERE id = ?", [o["id"]])
    overrides.invalidate()
    ids = [ACT, MAL, ALT, CVE, VIC, TOOL, "actor:ixother", "malware:ixother", "campaign:ixqilin"]
    with store._tx() as cur:
        cur.execute("DELETE FROM claims WHERE subj IN (SELECT unnest(?)) OR obj IN (SELECT unnest(?))", [ids, ids])
        cur.execute("DELETE FROM mentions WHERE entity_id IN (SELECT unnest(?))", [ids])
        cur.execute("DELETE FROM entities WHERE id IN (SELECT unnest(?))", [ids])
    store.upsert_entities([
        {"id": ACT, "type": "actor", "name": "IxQilin"},
        {"id": MAL, "type": "malware", "name": "IxQilin", "aliases": ["IxAgenda"], "attrs": {"description": "Ransomware family."}},
        {"id": ALT, "type": "malware", "name": "IxAgendaCrypt", "aliases": ["IxAgenda", "IxQilin"], "attrs": {"description": "Old name."}},
        {"id": CVE, "type": "cve", "name": "CVE-2099-0001"}, {"id": VIC, "type": "org", "name": "Ix Victim"},
        {"id": TOOL, "type": "tool", "name": "IxTool"},
    ])
    store.add_mentions([_m(ACT, "a1"), _m(MAL, "a1"), _m(MAL, "a2"), _m(ALT, "a3"), _m(ALT, "a1")])
    store.upsert_claims([
        _claim(ACT, "exploits", CVE, ref="a1"),
        _claim(MAL, "exploits", CVE, src="other.example", ref="a2"),     # the same link from another outlet
        _claim(ACT, "targets", VIC, ref="a1"),
        _claim(ALT, "uses", TOOL, ref="a3"),
        _claim(ACT, "uses", MAL, ref="a1"),                               # a link between two names of one thing
    ])
    scoring.rescore_claims()


def _detail(eid):
    r = C.get(f"/api/entities/{eid}", params={"evidence": 8})
    assert r.status_code == 200, r.text
    return r.json()


def _rows(d):
    return [c for v in d["claims"].values() for c in v]


def _list(eid):
    r = C.get("/api/entities", params={"type": eid.split(":", 1)[0], "q": eid.split(":", 1)[1], "limit": 5}).json()
    return next((x for x in r["items"] if x["id"] == eid), None)


# ------------------------------------------------------------------------------------------------ merge
def test_merge_unifies_names_moves_mentions_and_claims_and_counts_follow():
    _reset()
    before = _list(MAL)
    r = C.post("/api/entities/merge", json={"src": ACT, "dst": MAL})
    assert r.status_code == 200, r.text
    oid = r.json()["id"]
    assert not db.query("SELECT 1 FROM entities WHERE id = ?", [ACT]), "the merged entity is gone"
    d = _detail(MAL)
    assert d["name"] == "IxQilin" and d["type"] == "malware"
    assert d["mentions"]["refs"] == 2, "a1 is one reference, not two: the duplicate mention is not double-counted"
    rows = _rows(d)
    ex = [c for c in rows if c["other"] == CVE]
    assert len(ex) == 1, "the actor's and the malware's 'exploits' link became one claim"
    assert set(ex[0]["sources"]) == {"vendor.example", "other.example"}, "with both sources"
    assert any(c["other"] == VIC for c in rows), "the actor's other claims moved"
    assert not any(c["other"] in (ACT, MAL) for c in rows), "a link between the two names is dropped, not a self-loop"
    assert {r["id"] for r in d["related"]} >= {CVE, VIC}
    # before: exploits CVE, and the actor's "uses" link to it; after: exploits CVE (one claim) and targets the victim
    assert before["claims"] == 2 and _list(MAL)["claims"] == 2
    assert {x["id"] for x in _detail(MAL)["related"]} == {CVE, VIC}
    assert any(o["id"] == oid for o in d["merged_here"])
    # the graph follows
    g = C.get("/api/entities/graph", params={"id": MAL}).json()
    assert {n["id"] for n in g["nodes"]} >= {MAL, CVE, VIC} and ACT not in {n["id"] for n in g["nodes"]}
    # an old link to the merged id opens the kept one
    old = _detail(ACT)
    assert old["id"] == MAL and old["redirected_from"]["id"] == ACT


def test_merge_survives_re_extraction():
    _reset()
    assert C.post("/api/entities/merge", json={"src": ALT, "dst": MAL}).status_code == 200
    # the reference import and the article extractor produce the old id again
    store.upsert_entities([{"id": ALT, "type": "malware", "name": "IxAgendaCrypt", "aliases": ["IxAgenda 2"],
                            "attrs": {"description": "Old name."}}])
    store.rename_entities({ALT: "IxAgendaCrypt"})
    store.add_mentions([_m(ALT, "a9")])
    store.upsert_claims([_claim(ALT, "targets", VIC, src="new.example", ref="a9"), _claim(ALT, "uses", MAL, ref="a9")])
    assert not db.query("SELECT 1 FROM entities WHERE id = ?", [ALT]), "re-extraction must not bring the duplicate back"
    assert not db.query("SELECT 1 FROM mentions WHERE entity_id = ?", [ALT])
    assert not db.query("SELECT 1 FROM claims WHERE subj = ? OR obj = ?", [ALT, ALT])
    e = db.query("SELECT name, aliases, json_extract_string(attrs, '$.description') AS d FROM entities WHERE id = ?", [MAL])[0]
    assert e["name"] == "IxQilin", "a reference rename of the merged id must not rename the kept entity"
    assert e["d"] == "Ransomware family.", "the merged entity's facts never overwrite the kept one's"
    assert {"IxAgendaCrypt", "IxAgenda 2"} <= set(e["aliases"]) and "IxQilin" not in e["aliases"]
    assert db.query("SELECT 1 FROM mentions WHERE entity_id = ? AND ref_id = 'a9'", [MAL])
    assert db.query("SELECT 1 FROM claims WHERE subj = ? AND obj = ? AND predicate = 'targets'", [MAL, VIC])
    assert not db.query("SELECT 1 FROM claims WHERE subj = ? AND obj = ?", [MAL, MAL]), "no self-loop from re-extraction"
    # lookups by the old name find the kept entity
    hit = C.get("/api/entities/lookup", params={"values": "ixagendacrypt"}).json()["results"][0]
    assert hit["found"] and hit["entity"]["id"] == MAL


def test_undo_merge_restores_both_sides():
    _reset()
    d0 = _detail(MAL)
    a0 = _detail(ACT)
    oid = C.post("/api/entities/merge", json={"src": ACT, "dst": MAL}).json()["id"]
    r = C.post(f"/api/entities/overrides/{oid}/undo")
    assert r.status_code == 200, r.text
    a1, d1 = _detail(ACT), _detail(MAL)
    assert a1["id"] == ACT and "redirected_from" not in a1
    assert sorted(c["other"] for c in _rows(a1)) == sorted(c["other"] for c in _rows(a0))
    assert sorted(c["other"] for c in _rows(d1)) == sorted(c["other"] for c in _rows(d0))
    assert d1["aliases"] == d0["aliases"] and d1["mentions"] == d0["mentions"] and a1["mentions"] == a0["mentions"]
    ex = next(c for c in _rows(d1) if c["other"] == CVE)
    assert ex["sources"] == ["other.example"], "the kept side's claim is back to its own sources"
    assert not d1["merged_here"]
    # and the redirect is gone: new writes for the actor stay on the actor
    store.add_mentions([_m(ACT, "a7")])
    assert db.query("SELECT 1 FROM mentions WHERE entity_id = ? AND ref_id = 'a7'", [ACT])


def test_undo_out_of_order_is_refused():
    _reset()
    o1 = C.post("/api/entities/merge", json={"src": ALT, "dst": MAL}).json()["id"]
    o2 = C.post("/api/entities/merge", json={"src": ACT, "dst": MAL}).json()["id"]
    r = C.post(f"/api/entities/overrides/{o1}/undo")
    assert r.status_code == 409 and "first" in r.json()["detail"]
    assert C.post(f"/api/entities/overrides/{o2}/undo").status_code == 200
    assert C.post(f"/api/entities/overrides/{o1}/undo").status_code == 200
    assert db.query("SELECT 1 FROM entities WHERE id = ?", [ALT]) and db.query("SELECT 1 FROM entities WHERE id = ?", [ACT])


def test_merge_rejects_bad_requests():
    _reset()
    assert C.post("/api/entities/merge", json={"src": ACT, "dst": ACT}).status_code == 400
    assert C.post("/api/entities/merge", json={"src": CVE, "dst": MAL}).status_code == 400, "indicators are not merged"
    assert C.post("/api/entities/merge", json={"src": ACT, "dst": "malware:ix-nothing"}).status_code == 404
    assert C.post("/api/entities/overrides/nope/undo").status_code == 404


# ------------------------------------------------------------------------------------------------ retype
def test_retype_into_an_existing_type_merges_and_survives_re_extraction():
    _reset()
    r = C.post("/api/entities/retype", json={"id": ACT, "type": "malware"})
    assert r.status_code == 200, r.text
    assert r.json()["dst"] == MAL and not r.json()["dst_created"]
    store.upsert_entities([{"id": ACT, "type": "actor", "name": "IxQilin"}])
    store.upsert_claims([_claim(ACT, "targets", "org:ix-victim", ref="a8")])
    assert not db.query("SELECT 1 FROM entities WHERE id = ?", [ACT])
    assert any(c["other"] == VIC for c in _rows(_detail(MAL)))


def test_retype_to_a_new_type_creates_it_and_undo_removes_it():
    _reset()
    r = C.post("/api/entities/retype", json={"id": ALT, "type": "campaign"})
    assert r.status_code == 200, r.text
    new = r.json()["dst"]
    assert new == "campaign:ixagendacrypt" and r.json()["dst_created"]
    d = _detail(new)
    assert d["type"] == "campaign" and d["name"] == "IxAgendaCrypt" and d["attrs"]["description"] == "Old name."
    assert any(c["other"] == TOOL for c in _rows(d))
    # something reaches the new entity after the retype; undo hands it back to the original
    store.add_mentions([_m(ALT, "a6")])
    assert db.query("SELECT 1 FROM mentions WHERE entity_id = ? AND ref_id = 'a6'", [new])
    assert C.post(f"/api/entities/overrides/{r.json()['id']}/undo").status_code == 200
    assert not db.query("SELECT 1 FROM entities WHERE id = ?", [new])
    a = _detail(ALT)
    assert a["type"] == "malware" and any(c["other"] == TOOL for c in _rows(a))
    assert db.query("SELECT 1 FROM mentions WHERE entity_id = ? AND ref_id = 'a6'", [ALT])
    assert C.post("/api/entities/retype", json={"id": CVE, "type": "malware"}).status_code == 400
    assert C.post("/api/entities/retype", json={"id": ALT, "type": "spaceship"}).status_code == 400


# ------------------------------------------------------------------------------------------------ duplicates
def _pairs(items):
    return {frozenset((s["a"]["id"], s["b"]["id"])): s for s in items}


def test_duplicate_suggestions_same_name_and_alias():
    _reset()
    p = _pairs(C.get("/api/entities/duplicates", params={"limit": 500}).json()["items"])
    s = p.get(frozenset((ACT, MAL)))
    assert s and "same name under two types" in s["reasons"]
    s2 = p.get(frozenset((ALT, MAL)))
    assert s2 and any("another name" in x for x in s2["reasons"]), "AgendaCrypt lists Qilin as an alias"
    assert s2["a"]["id"] == MAL, "the better-documented entity is the suggested keeper"
    # per entity, and on its page
    mine = _pairs(C.get("/api/entities/duplicates", params={"id": ACT}).json()["items"])
    assert frozenset((ACT, MAL)) in mine and all(ACT in k for k in mine)
    assert any({x["a"]["id"], x["b"]["id"]} == {ACT, MAL} for x in _detail(ACT)["possible_duplicates"])


def test_not_the_same_dismisses_a_suggestion_and_undo_brings_it_back():
    _reset()
    r = C.post("/api/entities/not-same", json={"a": MAL, "b": ACT})
    assert r.status_code == 200, r.text
    p = _pairs(C.get("/api/entities/duplicates", params={"limit": 500}).json()["items"])
    assert frozenset((ACT, MAL)) not in p and frozenset((ALT, MAL)) in p
    assert C.post("/api/entities/not-same", json={"a": ACT, "b": MAL}).json()["id"] == r.json()["id"], "idempotent"
    assert C.post(f"/api/entities/overrides/{r.json()['id']}/undo").status_code == 200
    assert frozenset((ACT, MAL)) in _pairs(C.get("/api/entities/duplicates", params={"limit": 500}).json()["items"])


def test_a_merged_pair_is_no_longer_suggested():
    _reset()
    C.post("/api/entities/merge", json={"src": ALT, "dst": MAL})
    p = _pairs(C.get("/api/entities/duplicates", params={"limit": 500}).json()["items"])
    assert not any(ALT in k for k in p)
    assert frozenset((ACT, MAL)) in p


# ------------------------------------------------------------------------------------------------ disagree
def test_disagree_with_a_reason_hides_the_link_and_lists_it_for_review():
    _reset()
    cid = store.claim_id(ACT, "targets", VIC, "reported")
    n0 = _list(ACT)["claims"]
    r = C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "reject", "reason": "wrong-link", "note": "it was the victim"})
    assert r.status_code == 200, r.text
    d = _detail(ACT)
    assert not any(x["id"] == VIC for x in d["related"]), "the trust lane's reject: the link leaves Related"
    assert _list(ACT)["claims"] == n0 - 1, "and the counts"
    rej = d["rejected"][0]
    assert rej["other"] == VIC and rej["verdict_reason"] == "wrong-link" and rej["verdict_note"] == "it was the victim"
    q = C.get("/api/entities/review").json()
    mine = [x for x in q["disagreed"] if x["subj"] == ACT and x["obj"] == VIC]
    assert mine and mine[0]["reason"] == "wrong-link" and mine[0]["obj_name"] == "Ix Victim"
    assert q["counts"]["disagreed"] >= 1
    # Undo from the review queue (the queue row's id is the verdict row)
    assert C.post(f"/api/entities/claims/{mine[0]['id']}/feedback", json={"verdict": "clear"}).status_code == 200
    assert any(x["id"] == VIC for x in _detail(ACT)["related"])
    assert not [x for x in C.get("/api/entities/review").json()["disagreed"] if x["subj"] == ACT and x["obj"] == VIC]


def test_disagree_reasons_are_checked():
    _reset()
    cid = store.claim_id(ACT, "targets", VIC, "reported")
    for reason in ("wrong-type", "outdated", "other"):
        assert C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "reject", "reason": reason}).status_code == 200
    ev = json.loads(db.query("SELECT evidence FROM claims WHERE id = ?", [store.claim_id(ACT, "targets", VIC, "user")])[0]["evidence"])
    assert [e.get("reason") for e in ev][-3:] == ["wrong-type", "outdated", "other"]
    assert C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "reject", "reason": "because"}).status_code == 400
    assert C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "confirm", "reason": "outdated"}).status_code == 400
    C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "clear"})


def test_a_verdict_moves_with_a_merge():
    _reset()
    cid = store.claim_id(ACT, "targets", VIC, "reported")
    C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "reject", "reason": "outdated"})
    oid = C.post("/api/entities/merge", json={"src": ACT, "dst": MAL}).json()["id"]
    d = _detail(MAL)
    assert [c["other"] for c in d["rejected"]] == [VIC] and not any(x["id"] == VIC for x in d["related"])
    C.post(f"/api/entities/overrides/{oid}/undo")
    assert [c["other"] for c in _detail(ACT)["rejected"]] == [VIC]


def test_review_lists_contested_attributions_until_one_is_confirmed():
    _reset()
    store.upsert_entities([{"id": "actor:ixother", "type": "actor", "name": "IxOther"}, {"id": "campaign:ixqilin", "type": "campaign", "name": "Ix Op"}])
    store.upsert_claims([_claim("campaign:ixqilin", "attributed-to", ACT, ref="a1"),
                         _claim("campaign:ixqilin", "attributed-to", "actor:ixother", src="blog.example", tier="D", ref="a4")])
    scoring.rescore_claims()
    q = C.get("/api/entities/review").json()
    g = next(x for x in q["contested"] if x["subj"] == "campaign:ixqilin")
    assert {c["obj"] for c in g["candidates"]} == {ACT, "actor:ixother"} and g["subj_name"] == "Ix Op"
    assert q["counts"]["contested"] >= 1
    best = next(c for c in g["candidates"] if c["obj"] == ACT)
    assert C.post(f"/api/entities/claims/{best['id']}/feedback", json={"verdict": "confirm"}).status_code == 200
    assert not any(x["subj"] == "campaign:ixqilin" for x in C.get("/api/entities/review").json()["contested"])
    C.post(f"/api/entities/claims/{best['id']}/feedback", json={"verdict": "clear"})


def test_review_lists_identity_changes_with_undo():
    _reset()
    oid = C.post("/api/entities/merge", json={"src": ALT, "dst": MAL, "note": "same family"}).json()["id"]
    ch = next(x for x in C.get("/api/entities/review").json()["changes"] if x["id"] == oid)
    assert ch["action"] == "merge" and ch["src_name"] == "IxAgendaCrypt" and ch["dst_name"] == "IxQilin" and ch["note"] == "same family"
    assert C.get("/api/entities/overrides").json()["items"][0]["id"] == oid


# ------------------------------------------------------------------------------------------------ cross-feature
def _story():
    db.execute("DELETE FROM articles WHERE id = 'ix-art'")
    db.execute("DELETE FROM stories WHERE id = 'ix-story'")
    db.execute("""INSERT INTO stories (id, title, first_seen, last_seen, article_count, source_count, top_entities)
                  VALUES ('ix-story', 'IxQilin hits a hospital', now() - INTERVAL 1 HOUR, now(), 1, 1, ?)""",
               [json.dumps([{"id": MAL, "name": "IxQilin"}])])
    db.execute("""INSERT INTO articles (id, url, source, title, story_id, status, published)
                  VALUES ('ix-art', 'https://news.example/ix', 'news.example', 'IxQilin hits a hospital', 'ix-story', 'done', now())""")
    store.add_mentions([_m(ALT, "ix-art", ts=None)])


def _digest():
    return {s["id"]: s["matched"] for s in C.get("/api/news/watchlist/digest", params={"since": "3650d"}).json()["stories"]}


def test_a_followed_entity_survives_a_merge_either_way():
    _reset()
    _story()
    prev = db.get_setting("news.watchlist", None)
    try:
        C.put("/api/news/watchlist", json={"entities": [ALT]})
        assert _digest().get("ix-story") == [ALT]
        oid = C.post("/api/entities/merge", json={"src": ALT, "dst": MAL}).json()["id"]
        assert _digest().get("ix-story") == [ALT], "following the merged name still finds its stories"
        assert C.get("/api/news/watchlist").json()["entities"] == [ALT], "the stored list is not rewritten"
        C.post(f"/api/entities/overrides/{oid}/undo")
        assert _digest().get("ix-story") == [ALT], "and Undo needs no clean-up"
        # following the kept entity also finds stories that only carry the merged id
        C.put("/api/news/watchlist", json={"entities": [MAL]})
        db.execute("UPDATE stories SET top_entities = ? WHERE id = 'ix-story'", [json.dumps([{"id": ALT}])])
        db.execute("DELETE FROM mentions WHERE ref_id = 'ix-art'")
        assert "ix-story" not in _digest()
        C.post("/api/entities/merge", json={"src": ALT, "dst": MAL})
        assert _digest().get("ix-story") == [MAL]
        r = C.get("/api/news/stories", params={"entity": MAL, "since": "3650d"})
        assert r.status_code == 200 and "ix-story" in {x["id"] for x in r.json()["stories"]}, "the News entity filter too"
    finally:
        db.set_setting("news.watchlist", prev or {"entities": [], "keywords": []})


def test_endpoints_taking_an_entity_id_follow_the_redirect():
    _reset()
    C.post("/api/entities/merge", json={"src": ACT, "dst": MAL})
    g = C.get("/api/entities/graph", params={"id": ACT})
    assert g.status_code == 200 and g.json()["root"] == MAL
    tl = C.get("/api/entities/timeline", params={"ids": ACT}).json()
    assert [l["id"] for l in tl["lanes"]] == [MAL]
    act = C.get("/api/entities/activity", params={"ids": ACT}).json()["items"]
    assert ACT in act and act[ACT] == act[MAL]
    hit = C.get("/api/entities/lookup", params={"values": ACT}).json()["results"][0]
    assert hit["found"] and hit["entity"]["id"] == MAL


def test_a_stale_merged_id_is_refused_as_the_merge_source():
    _reset()
    C.post("/api/entities/merge", json={"src": ACT, "dst": MAL})
    r = C.post("/api/entities/merge", json={"src": ACT, "dst": ALT})
    assert r.status_code == 409, r.text
    assert db.query("SELECT 1 FROM entities WHERE id = ?", [MAL]), "the kept entity was not merged away"


def test_undo_returns_later_verdicts_and_evidence_to_the_merged_entity():
    _reset()
    store.upsert_claims([_claim(MAL, "uses", "tool:ixtool", src="b.example", ref="b1")])   # MAL's own link, shared with ALT
    scoring.rescore_claims()
    oid = C.post("/api/entities/merge", json={"src": ACT, "dst": MAL}).json()["id"]
    # after the merge: a Disagree on the actor's link, new evidence on it, and new evidence on a link both had
    cid = store.claim_id(MAL, "targets", VIC, "reported")
    assert C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "reject", "reason": "outdated"}).status_code == 200
    store.upsert_claims([_claim(MAL, "targets", VIC, src="late.example", ref="l1"), _claim(MAL, "exploits", CVE, src="late2.example", ref="l2")])
    pv = C.get(f"/api/entities/overrides/{oid}/undo-preview").json()
    assert pv["moved_back"] >= 2
    assert len(pv["stays"]) == 1 and "both had" in pv["stays"][0] and "CVE-2099-0001" in pv["stays"][0]
    assert pv["dst_name"] == "the malware IxQilin" and pv["src_name"] == "the threat actor IxQilin", "same names say the type"
    r = C.post(f"/api/entities/overrides/{oid}/undo").json()
    assert r["stays"] == pv["stays"]
    a = _detail(ACT)
    assert [c["other"] for c in a["rejected"]] == [VIC] and a["rejected"][0]["verdict_reason"] == "outdated", \
        "the Disagree made after the merge went back to the actor"
    assert "late.example" in a["rejected"][0]["sources"], "so did the evidence that arrived on its link"
    m = _detail(MAL)
    assert not m["rejected"] and not any(c["other"] == VIC for c in _rows(m))
    ex = next(c for c in _rows(m) if c["other"] == CVE)
    assert "late2.example" in ex["sources"], "a later source on a link both had stays on the kept entity"
    assert not db.query("SELECT 1 FROM claims WHERE origin = 'user' AND (subj = ? OR obj = ?)", [MAL, MAL])


# ---------------------------------------------------------------- verdicts and hypotheses (trust)
A, M, T, CAMP, H = "actor:trust-a", "malware:trust-loader", "tool:trust-net", "campaign:trust-op", "hash:" + "ab" * 32
QUOTE = "The Trust A group used the Trust Loader against regional banks."


def _t_ent(eid, name=None):
    if not db.query("SELECT 1 FROM entities WHERE id = ?", [eid]):
        t = eid.split(":", 1)[0]
        db.execute("INSERT INTO entities (id, type, name) VALUES (?, ?, ?)", [eid, t, name or eid.split(":", 1)[1]])


def _t_seed():
    if db.query("SELECT 1 FROM entities WHERE id = ?", [A]):
        return
    for e in (A, M, T, CAMP, H, "org:trust-victim"):
        _t_ent(e)
    store.upsert_claims([
        # a quoted claim from one low-tier outlet: the weakest kind of sourced claim
        {"subj": A, "predicate": "uses", "obj": M, "origin": "reported", "sources": ["blog.example"],
         "evidence": [{"source": "blog.example", "tier": "D", "quote": QUOTE, "method": "llm", "ref_type": "article", "ref_id": "a1"}]},
        # a reference listing (ATT&CK): authoritative, nothing to vote on
        {"subj": A, "predicate": "uses", "obj": T, "origin": "reported", "sources": ["MITRE ATT&CK"],
         "evidence": [{"source": "MITRE ATT&CK", "tier": "B", "ref_type": "reference", "note": "MITRE ATT&CK lists this relation"}]},
        # the campaign and the actor share a specific hash: inference will link them
        {"subj": CAMP, "predicate": "uses", "obj": H, "origin": "reported", "sources": ["vendor.example"],
         "evidence": [{"source": "vendor.example", "tier": "B", "quote": "Op used the hash", "ref_type": "article", "ref_id": "a2"}]},
        {"subj": A, "predicate": "uses", "obj": H, "origin": "reported", "sources": ["vendor.example"],
         "evidence": [{"source": "vendor.example", "tier": "B", "quote": "A used the hash", "ref_type": "article", "ref_id": "a3"}]},
        # and one outlet says it outright, in a quote
        {"subj": CAMP, "predicate": "attributed-to", "obj": A, "origin": "reported", "sources": ["blog.example"],
         "evidence": [{"source": "blog.example", "tier": "D", "quote": "Trust A was behind the operation", "method": "llm",
                       "ref_type": "article", "ref_id": "a4"}]},
    ])
    # the actor and a victim named in the same article: a co-mention, no claim
    store.add_mentions([{"entity_id": A, "ref_type": "article", "ref_id": "a9", "role": "mentioned", "method": "llm", "confidence": 0.9, "ts": None},
                        {"entity_id": "org:trust-victim", "ref_type": "article", "ref_id": "a9", "role": "mentioned", "method": "llm", "confidence": 0.9, "ts": None}])
    scoring.rescore_claims()
    scoring.infer_links()


def _t_cid(subj, pred, obj, origin):
    return store.claim_id(subj, pred, obj, origin)


def _t_detail():
    r = C.get(f"/api/entities/{A}", params={"evidence": 8})
    assert r.status_code == 200, r.text
    return r.json()


def _t_rows(d):
    return [c for v in d["claims"].values() for c in v]


def _t_graph_edges(eid=A):
    return C.get("/api/entities/graph", params={"id": eid}).json()["edges"]


def _t_list_claims(eid=A):
    t = eid.split(":", 1)[0]
    r = C.get("/api/entities", params={"type": t, "q": eid.split(":", 1)[1], "limit": 5}).json()
    return next(x["claims"] for x in r["items"] if x["id"] == eid)


# ------------------------------------------------------------------------------------------------ verdicts
def test_reject_hides_the_link_everywhere_and_undo_restores_it():
    _t_seed()
    cid = _t_cid(A, "uses", M, "reported")
    d0 = _t_detail()
    assert any(r["id"] == M for r in d0["related"])
    n_claims, n_list = sum(d0["claim_counts"].values()), _t_list_claims()
    assert any({e["source"], e["target"]} == {A, M} for e in _t_graph_edges())

    r = C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "reject"})
    assert r.status_code == 200, r.text
    d = _t_detail()
    assert not any(r["id"] == M for r in d["related"]), "a rejected link must leave Related"
    assert not any(r["id"] == M for r in d["related_hypotheses"])
    assert sum(d["claim_counts"].values()) == n_claims - 1, "a rejected link must leave the claim counts"
    assert d["claim_counts"]["user"] == 0, "a verdict is never a claim of its own"
    assert not any(c["other"] == M for c in _t_rows(d))
    assert [c["other"] for c in d["rejected"]] == [M] and d["rejected"][0]["verdict"] == "reject"
    assert not any({e["source"], e["target"]} == {A, M} for e in _t_graph_edges()), "a rejected link must leave the graph"
    assert _t_list_claims() == n_list - 1
    act = C.get("/api/entities/activity", params={"ids": A}).json()["items"][A]
    assert "user" not in act["origins"]

    # Undo
    r = C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "clear"})
    assert r.status_code == 200, r.text
    d = _t_detail()
    assert any(r["id"] == M for r in d["related"]) and not d["rejected"]
    assert sum(d["claim_counts"].values()) == n_claims and _t_list_claims() == n_list
    row = next(c for c in _t_rows(d) if c["other"] == M)
    assert row["verdict"] is None and row["confidence"] >= scoring.BANDS["low"][0]


def test_confirm_marks_the_row_and_does_not_double_count():
    _t_seed()
    cid = _t_cid(A, "uses", M, "reported")
    d0 = _t_detail()
    n_claims, n_list = sum(d0["claim_counts"].values()), _t_list_claims()
    rel0 = next(r for r in d0["related"] if r["id"] == M)
    r = C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "confirm", "note": "seen it myself"})
    assert r.status_code == 200, r.text
    d = _t_detail()
    rows = [c for c in _t_rows(d) if c["other"] == M]
    assert len(rows) == 1 and rows[0]["origin"] == "reported", rows
    assert rows[0]["verdict"] == "confirm" and rows[0]["verdict_note"] == "seen it myself"
    assert rows[0]["confidence"] >= 0.95
    assert sum(d["claim_counts"].values()) == n_claims and d["claim_counts"]["user"] == 0
    assert next(r for r in d["related"] if r["id"] == M)["n"] == rel0["n"], "confirming must not add a second link"
    assert _t_list_claims() == n_list
    edges = [e for e in _t_graph_edges() if {e["source"], e["target"]} == {A, M}]
    assert len(edges) == 1 and edges[0]["origin"] == "reported" and edges[0]["verdict"] == "confirm"
    C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "clear"})


def test_latest_verdict_wins_and_history_is_kept():
    _t_seed()
    cid = _t_cid(A, "uses", M, "reported")
    for v in ("reject", "confirm", "reject", "confirm"):
        assert C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": v}).status_code == 200
    row = next(c for c in _t_rows(_t_detail()) if c["other"] == M)
    assert row["verdict"] == "confirm"
    ev = json.loads(db.query("SELECT evidence FROM claims WHERE id = ?", [_t_cid(A, "uses", M, "user")])[0]["evidence"])
    assert [e["verdict"] for e in ev] == ["reject", "confirm", "reject", "confirm"]
    C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "clear"})
    assert not db.query("SELECT 1 FROM claims WHERE origin = 'user' AND subj = ? AND obj = ?", [A, M])


def test_stored_verdicts_from_before_are_read_the_new_way():
    """Verdict rows written by the old feedback code (one origin:user claim per triple) are annotations too."""
    _t_seed()
    now = "2026-11-01T00:00:00+00:00"
    store.upsert_claims([{"subj": A, "predicate": "uses", "obj": M, "origin": "user", "sources": ["user"],
                          "evidence": [{"verdict": "reject", "note": "", "ts": now, "claim": "x", "source": "user", "ref_id": now}]}])
    scoring.rescore_claims()
    d = _t_detail()
    assert not any(r["id"] == M for r in d["related"])
    assert [c["other"] for c in d["rejected"]] == [M]
    assert d["claim_counts"]["user"] == 0
    store.execute("DELETE FROM claims WHERE origin = 'user' AND subj = ? AND obj = ?", [A, M])
    # an old confirm whose original claim no longer exists stays visible once, as the analyst's own link
    store.upsert_claims([{"subj": A, "predicate": "targets", "obj": "org:trust-victim", "origin": "user", "sources": ["user"],
                          "evidence": [{"verdict": "confirm", "note": "", "ts": now, "claim": "y", "source": "user", "ref_id": now}]}])
    scoring.rescore_claims()
    d = _t_detail()
    mine = d["claims"]["user"]
    assert len(mine) == 1 and mine[0]["verdict"] == "confirm"
    assert next(r for r in d["related"] if r["id"] == "org:trust-victim")["n"] == 1
    store.execute("DELETE FROM claims WHERE origin = 'user' AND subj = ? AND predicate = 'targets'", [A])


# ------------------------------------------------------------------------------------------------ hypotheses
def test_a_quoted_attributed_claim_outranks_any_computed_link():
    _t_seed()
    weakest, band_, _ = scoring.assess([{"source": "x.social", "tier": "D", "quote": "q", "method": "llm", "ref_type": "article"}], [])
    assert band_ == "low" and weakest > scoring.HYPOTHESIS_CAP
    inf = db.query("SELECT confidence FROM claims WHERE origin = 'inferred' AND subj = ? AND obj = ?", [CAMP, A])
    rep = db.query("SELECT confidence FROM claims WHERE origin = 'reported' AND subj = ? AND predicate = 'attributed-to' AND obj = ?", [CAMP, A])
    assert inf and rep, "the seed must produce both an inferred and a reported link for the pair"
    assert inf[0]["confidence"] <= scoring.HYPOTHESIS_CAP < rep[0]["confidence"]
    # the campaign page: the reported claim is listed, the hypothesis is labelled as one and ranks below
    d = C.get(f"/api/entities/{CAMP}").json()
    hyp = [c for c in d["claims"]["inferred"] if c["other"] == A]
    assert hyp and hyp[0]["hypothesis"] and hyp[0]["band"] == "hypothesis"
    assert hyp[0]["why"].startswith("Computed by the hub")
    srt = sorted(_t_rows(d), key=lambda c: -(c["confidence"] or 0))
    assert [c["origin"] for c in srt if c["other"] == A] == ["reported", "inferred"]
    # graph: one edge for the pair, the sourced one
    edges = [e for e in _t_graph_edges(CAMP) if {e["source"], e["target"]} == {CAMP, A}]
    assert len(edges) == 1 and edges[0]["origin"] == "reported" and not edges[0]["hypothesis"]


def test_hypotheses_are_kept_out_of_related():
    _t_seed()
    # drop the reported attribution: only the computed link remains between campaign and actor
    store.execute("DELETE FROM claims WHERE subj = ? AND predicate = 'attributed-to' AND origin = 'reported'", [CAMP])
    try:
        d = C.get(f"/api/entities/{A}").json()
        assert not any(r["id"] == CAMP for r in d["related"])
        h = next(r for r in d["related_hypotheses"] if r["id"] == CAMP)
        assert h["how"] == "inferred"
        co = next(r for r in d["related_hypotheses"] if r["id"] == "org:trust-victim")
        assert co["how"] == "mentioned-with"
        edges = [e for e in _t_graph_edges() if {e["source"], e["target"]} == {CAMP, A}]
        assert len(edges) == 1 and edges[0]["hypothesis"] and edges[0]["band"] == "hypothesis"
        assert edges[0]["confidence"] <= scoring.HYPOTHESIS_CAP
    finally:
        store.upsert_claims([{"subj": CAMP, "predicate": "attributed-to", "obj": A, "origin": "reported", "sources": ["blog.example"],
                              "evidence": [{"source": "blog.example", "tier": "D", "quote": "Trust A was behind the operation",
                                            "method": "llm", "ref_type": "article", "ref_id": "a4"}]}])
        scoring.rescore_claims()


def test_co_mentions_are_labelled_as_such_in_the_graph():
    _t_seed()
    g = C.get("/api/entities/graph", params={"id": "org:trust-victim"}).json()
    co = [e for e in g["edges"] if e["predicate"] == "mentioned-with"]
    assert co and all(e["origin"] == "co-mention" and e["hypothesis"] for e in co)


def test_reference_listings_are_authoritative():
    _t_seed()
    rows = {c["other"]: c for c in _t_rows(_t_detail())}
    assert rows[T]["authoritative"] is True
    assert rows[M]["authoritative"] is False and rows[H]["authoritative"] is False


# ------------------------------------------------------------------------------------------------ activity
def test_activity_without_ids_is_empty_not_422():
    for p in ({"weeks": 26}, {"ids": "", "weeks": 26}, {"ids": " , ", "weeks": 26}):
        r = C.get("/api/entities/activity", params=p)
        assert r.status_code == 200, (p, r.status_code, r.text)
        assert r.json() == {"weeks": 26, "items": {}}


# ------------------------------------------------------------------------------------------------ evaluator nits (r1)
def test_a_rejected_pair_does_not_return_as_a_hypothesis():
    _t_seed()
    store.upsert_claims([{"subj": A, "predicate": "targets", "obj": "org:trust-victim", "origin": "reported", "sources": ["blog.example"],
                          "evidence": [{"source": "blog.example", "tier": "D", "quote": "Trust A hit the victim", "method": "llm",
                                        "ref_type": "article", "ref_id": "a9"}]}])
    scoring.rescore_claims()
    cid = _t_cid(A, "targets", "org:trust-victim", "reported")
    try:
        assert C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "reject"}).status_code == 200
        d = _t_detail()
        ids = {r["id"] for r in d["related"]} | {r["id"] for r in d["related_hypotheses"]}
        assert "org:trust-victim" not in ids, "the co-mention of a rejected pair must not come back"
        g = C.get("/api/entities/graph", params={"id": "org:trust-victim"}).json()
        assert not any(A in (e["source"], e["target"]) for e in g["edges"])
    finally:
        C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "clear"})
        store.execute("DELETE FROM claims WHERE subj = ? AND predicate = 'targets'", [A])


def test_a_confirmed_hypothesis_counts_as_the_users_link():
    _t_seed()
    cid = _t_cid(CAMP, "attributed-to", A, "inferred")
    assert db.query("SELECT 1 FROM claims WHERE id = ?", [cid])
    try:
        assert C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "confirm"}).status_code == 200
        d = C.get(f"/api/entities/{CAMP}").json()
        # a source also states this pair: the reported row stands for it, once, marked confirmed
        rows = [c for v in d["claims"].values() for c in v if c["other"] == A and c["predicate"] == "attributed-to"]
        assert len(rows) == 1 and rows[0]["origin"] == "reported" and rows[0]["verdict"] == "confirm"
        assert d["claim_counts"]["inferred"] == 0
        # without the reported claim the confirmed hypothesis is the analyst's own link
        store.execute("DELETE FROM claims WHERE subj = ? AND predicate = 'attributed-to' AND origin = 'reported'", [CAMP])
        d = C.get(f"/api/entities/{CAMP}").json()
        assert d["claim_counts"]["user"] == 1 and d["claim_counts"]["inferred"] == 0
        row = d["claims"]["user"][0]
        assert row["origin"] == "inferred" and row["verdict"] == "confirm" and not row["hypothesis"] and row["band"] != "hypothesis"
        assert any(r["id"] == A for r in d["related"])
    finally:
        C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "clear"})
        store.upsert_claims([{"subj": CAMP, "predicate": "attributed-to", "obj": A, "origin": "reported", "sources": ["blog.example"],
                              "evidence": [{"source": "blog.example", "tier": "D", "quote": "Trust A was behind the operation",
                                            "method": "llm", "ref_type": "article", "ref_id": "a4"}]}])
        scoring.rescore_claims()


# ---------------------------------------------------------------- a rejected claim leaves the story's intel
RW_A, RW_V, RW_ART = "actor:rw1-group", "country:rw1-land", "rw1-article"


def _rw_seed():
    for e in (RW_A, RW_V):
        if not db.query("SELECT 1 FROM entities WHERE id = ?", [e]):
            db.execute("INSERT INTO entities (id, type, name) VALUES (?, ?, ?)", [e, e.split(":")[0], e.split(":")[1]])
    if not db.query("SELECT 1 FROM articles WHERE id = ?", [RW_ART]):
        db.execute("INSERT INTO articles (id, url) VALUES (?, ?)", [RW_ART, "https://blog.example/rw1"])
    store.upsert_claims([{"subj": RW_A, "predicate": "targets", "obj": RW_V, "origin": "reported", "sources": ["blog.example"],
                          "evidence": [{"source": "blog.example", "tier": "C", "quote": "The group targets the land.",
                                        "ref_type": "article", "ref_id": RW_ART}]}])


def test_a_rejected_claim_leaves_the_story_intel():
    _rw_seed()
    before = news_api.intel(article=RW_ART)["claims"]
    assert [(c["subj"], c["obj"]) for c in before] == [(RW_A, RW_V)]
    cid = store.claim_id(RW_A, "targets", RW_V, "reported")
    assert C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "reject"}).status_code == 200
    after = news_api.intel(article=RW_ART)["claims"]
    assert after == [], after                       # neither the claim nor the verdict row is listed
    assert C.post(f"/api/entities/claims/{cid}/feedback", json={"verdict": "clear"}).status_code == 200
    assert [(c["subj"], c["obj"]) for c in news_api.intel(article=RW_ART)["claims"]] == [(RW_A, RW_V)]


def test_merging_aliases_keeps_their_order():
    """A second upsert adds new aliases after the known ones, in order and once each: the page shows the first few
    and folds the rest behind "+N more", so a hash-ordered union could hide the best-known names (seen on Linux)."""
    eid = "actor:ixorder"
    store.upsert_entities([{"id": eid, "type": "actor", "name": "IxOrder", "aliases": ["Best Known", "G9999", "Third"]}])
    store.upsert_entities([{"id": eid, "type": "actor", "name": "IxOrder",
                            "aliases": ["Third", "IxOrder", "Fourth", "Best Known", "Fifth"]}])
    got = db.query("SELECT aliases FROM entities WHERE id = ?", [eid])[0]["aliases"]
    assert got == ["Best Known", "G9999", "Third", "Fourth", "Fifth"]
