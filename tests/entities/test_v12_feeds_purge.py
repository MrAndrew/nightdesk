"""Once per lake, AI output derived from feeds that are now AI-excluded (Feodo Tracker joined the abuse.ch sources on
2026-11-19) is removed: a malware family known only from those feeds gets `ai_excluded` and loses its vector; a cached
entity-brief text that no longer matches its facts is dropped. Catalogue families, families also named elsewhere and
up-to-date briefs are left alone. Offline, temporary lake, local DuckDB vectors, no AI helper.

    uv run --with pytest pytest tests/entities/test_v12_feeds_purge.py -q
"""
from __future__ import annotations

import json

from _lake import make_lake
LAKE = make_lake("feeds-purge", OSINTHUB_VECTORS="duckdb")

from osinthub import db, vectors  # noqa: E402
from osinthub.entities import searcher, store  # noqa: E402
from osinthub.news import brief  # noqa: E402

db.connect()
store.ensure_schema()
db.execute(searcher.VEC_SCHEMA)

FEODO_ONLY = "malware:feodo-only-family"
MIXED = "malware:also-in-the-news"
ALLOWED_STALE = "actor:allowed-but-stale"     # no AI-excluded evidence; its brief is stale only because a claim was seen again
FEODO_CLAIMED = "actor:named-in-a-feodo-claim"  # a claim from Feodo: its stale brief may hold Feodo-derived text


def _ent(eid, attrs=None):
    db.execute("INSERT INTO entities (id, type, name, aliases, attrs) VALUES (?, 'malware', ?, [], ?)",
               [eid, eid.split(":", 1)[1], json.dumps(attrs or {})])


def _mention(eid, ref_type, ref_id):
    db.execute("INSERT INTO mentions (entity_id, ref_type, ref_id, role, method, confidence) VALUES (?, ?, ?, 'malware', 'field', 1.0)",
               [eid, ref_type, ref_id])


def _setup():
    _ent(FEODO_ONLY)    # made by an earlier version: no ai_excluded mark, embedded
    _mention(FEODO_ONLY, "event", "feodo_c2:aaa")
    _mention(FEODO_ONLY, "event", "threatfox:bbb")
    _ent(MIXED)
    _mention(MIXED, "event", "feodo_c2:ccc")
    _mention(MIXED, "article", "art-1")
    for eid in (FEODO_ONLY, MIXED):
        db.execute("INSERT INTO entity_vec VALUES (?, 'h', now())", [eid])
    vectors.upsert("entities", [{"id": e, "vector": [0.1] * vectors.DIM, "payload": {"type": "malware", "name": e}}
                                for e in (FEODO_ONLY, MIXED)])
    for eid, src in ((ALLOWED_STALE, "otx"), (FEODO_CLAIMED, "feodo_c2")):
        db.execute("INSERT INTO entities (id, type, name, aliases, attrs) VALUES (?, 'actor', ?, [], '{}')",
                   [eid, eid.split(":", 1)[1]])
        db.execute("""INSERT INTO claims (id, subj, predicate, obj, origin, sources, confidence, first_seen, last_seen, evidence)
                      VALUES (?, ?, 'uses', 'malware:x', 'observed', [?], 0.5, '2026-11-01', '2026-11-15', '[]')""",
                   [f"c-{eid}", eid, src])
        db.set_setting(brief.CACHE_KEY + eid, {"hash": "older-than-the-claims", "why_now": [{"text": "x", "cites": [1]}]})
    db.set_setting(brief.CACHE_KEY + FEODO_ONLY, {"hash": "made-from-feodo", "why_now": [{"text": "x", "cites": [1]}]})
    db.set_setting(brief.CACHE_KEY + MIXED, {"hash": brief.facts(MIXED)["claims_hash"], "why_now": []})


def _vec_ids() -> set:
    return {r[0] for r in vectors.backend().conn.cursor().execute(
        "SELECT id FROM vectors WHERE collection = 'entities'").fetchall()}


def test_purge_runs_once_and_removes_only_excluded_derivatives():
    _setup()
    assert {FEODO_ONLY, MIXED} <= _vec_ids()
    out = searcher.purge_ai_excluded_once()
    assert out["marked"] == 1 and out["briefs_dropped"] == 2
    assert db.get_setting(brief.CACHE_KEY + ALLOWED_STALE) is not None      # stale, but no excluded evidence: kept
    assert db.get_setting(brief.CACHE_KEY + FEODO_CLAIMED) is None          # stale and Feodo-derived: dropped
    attrs = json.loads(db.query("SELECT attrs FROM entities WHERE id = ?", [FEODO_ONLY])[0]["attrs"])
    assert attrs["ai_excluded"]
    assert FEODO_ONLY not in _vec_ids() and MIXED in _vec_ids()
    assert not db.query("SELECT 1 FROM entity_vec WHERE id = ?", [FEODO_ONLY])
    assert db.get_setting(brief.CACHE_KEY + FEODO_ONLY) is None
    assert db.get_setting(brief.CACHE_KEY + MIXED) is not None             # still matches its facts: kept
    assert json.loads(db.query("SELECT attrs FROM entities WHERE id = ?", [MIXED])[0]["attrs"]).get("ai_excluded") is None
    # never re-embedded, and the purge does not run twice
    assert searcher.purge_ai_excluded_once() == {}
    pending = db.query("""SELECT e.id FROM entities e LEFT JOIN entity_vec v ON v.id = e.id
                          WHERE json_extract_string(e.attrs, '$.ai_excluded') IS NULL AND v.id IS NULL""")
    assert FEODO_ONLY not in {r["id"] for r in pending}
