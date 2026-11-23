"""A technique link MITRE's catalogue states keeps that standing when articles report it too: the entity API marks
the merged claim `catalogue: true` (its evidence mixes the reference item with article items, so `authoritative` is
false), and the UI keeps it "confirmed" instead of an article label (okf/data/entities.md#technique-labels).

    uv run --with pytest pytest tests/entities/test_v12_ttpwording.py -q
"""
from _lake import make_lake
LAKE = make_lake("entities-ttpwording")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db  # noqa: E402
from osinthub.entities import api, store  # noqa: E402

db.connect()
store.ensure_schema()
_app = FastAPI()
_app.include_router(api.router)
C = TestClient(_app)

A, T1, T2 = "actor:ttpw-actor", "technique:T1566.001", "technique:T1505.003"
REF = {"source": "MITRE ATT&CK", "tier": "B", "ref_type": "reference", "note": "MITRE ATT&CK lists this relation"}


def _art(ref, quote, suggested=False):
    e = {"source": "news.example", "tier": "B", "quote": quote, "method": "llm", "ref_type": "article", "ref_id": ref}
    return {**e, "suggested": True} if suggested else e


def setup_module():
    for eid in (A, T1, T2):
        db.execute("INSERT INTO entities (id, type, name) VALUES (?, ?, ?)", [eid, eid.split(":")[0], eid.split(":", 1)[1]])
    store.upsert_claims([
        {"subj": A, "predicate": "uses", "obj": T1, "origin": "reported", "sources": ["MITRE ATT&CK"], "evidence": [REF]},
        {"subj": A, "predicate": "uses", "obj": T2, "origin": "reported", "sources": ["news.example"],
         "evidence": [_art("a1", "They dropped a web shell.", suggested=True)]},
    ])
    # an article reports the catalogue link too: same (subj, predicate, obj, origin), so it joins the reference row
    store.upsert_claims([{"subj": A, "predicate": "uses", "obj": T1, "origin": "reported", "sources": ["news.example"],
                          "evidence": [_art("a2", "The emails carried a booby-trapped attachment.")]}])


def _rows():
    d = C.get(f"/api/entities/{A}", params={"evidence": 8}).json()
    return {c["other"]: c for v in d["claims"].values() for c in v}


def test_catalogue_link_reported_by_an_article_stays_a_catalogue_link():
    r = _rows()[T1]
    assert sorted(e.get("ref_type") for e in r["evidence"]) == ["article", "reference"], "one merged row"
    assert r["authoritative"] is False, "mixed evidence is not a pure reference listing (unchanged)"
    assert r["catalogue"] is True


def test_article_only_link_is_not_a_catalogue_link():
    r = _rows()[T2]
    assert r["catalogue"] is False and r["suggested"] is True


def test_catalogue_flag_survives_a_short_evidence_list():
    # many article items before the reference one: the flag is computed on all evidence, not the truncated list
    store.upsert_claims([{"subj": A, "predicate": "uses", "obj": T1, "origin": "reported", "sources": ["news.example"],
                          "evidence": [_art(f"b{i}", f"Sentence {i} about attachments.") for i in range(6)]}])
    d = C.get(f"/api/entities/{A}", params={"evidence": 1}).json()
    r = {c["other"]: c for v in d["claims"].values() for c in v}[T1]
    assert len(r["evidence"]) == 1 and r["catalogue"] is True
    assert r["article_count"] == 7, "every article reporting the link (a2, b0-b5), not only the returned evidence"
    assert _rows()[T2]["article_count"] == 1
