"""Entity, mention and claim tables, and batch writes. Model: okf/data/entities.md#tables"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import threading
import uuid
from pathlib import Path

from .. import config, db

# No PRIMARY KEY and no ART indexes on purpose. DuckDB ART indexes on tables that also get
# UPDATEs and DELETEs can end up out of step with the rows ("Failed to delete all rows from
# index. Only deleted 34 out of 57 rows"), which is FATAL and invalidates the whole database.
# Uniqueness is kept by the writers below (one lock, anti-joins), and these tables are small
# enough (10^4-10^6 rows) that zone maps and scans are fast. Docs: okf/data/entities.md#tables
SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
    id         VARCHAR NOT NULL,
    type       VARCHAR NOT NULL,
    name       VARCHAR,
    aliases    VARCHAR[],
    attrs      JSON,
    first_seen TIMESTAMPTZ,
    last_seen  TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS mentions (
    entity_id  VARCHAR NOT NULL,
    ref_type   VARCHAR NOT NULL,
    ref_id     VARCHAR NOT NULL,
    role       VARCHAR NOT NULL,
    method     VARCHAR,
    confidence DOUBLE,
    ts         TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS claims (
    id         VARCHAR NOT NULL,
    subj       VARCHAR NOT NULL,
    predicate  VARCHAR NOT NULL,
    obj        VARCHAR NOT NULL,
    origin     VARCHAR NOT NULL,
    sources    VARCHAR[],
    confidence DOUBLE,
    first_seen TIMESTAMPTZ,
    last_seen  TIMESTAMPTZ,
    evidence   JSON
);
CREATE TABLE IF NOT EXISTS entity_linked (ref_type VARCHAR, ref_id VARCHAR, hash VARCHAR, linked_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS entity_dirty (id VARCHAR, since TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS entity_overrides (
    id         VARCHAR NOT NULL,
    action     VARCHAR NOT NULL,   -- merge | retype | distinct (see overrides.py)
    src        VARCHAR NOT NULL,
    dst        VARCHAR NOT NULL,
    note       VARCHAR,
    created_at TIMESTAMPTZ,
    snapshot   JSON                -- what a merge moved, for Undo
);
"""
TABLE_KEYS = {"entities": ["id"], "mentions": ["entity_id", "ref_type", "ref_id", "role"], "claims": ["id"],
              "entity_linked": ["ref_type", "ref_id"], "entity_dirty": ["id"], "entity_vec": ["id"], "entity_overrides": ["id"]}

EVIDENCE_CAP = 25

# Every writer of the entity tables (ingest, linking, scoring, inference, feedback, cleanup)
# holds this re-entrant lock for its whole read-merge-write, and each write is one transaction.
_CLAIMS_LOCK = threading.RLock()


def claims_lock() -> threading.RLock:
    return _CLAIMS_LOCK


def ensure_schema() -> None:
    with db._write_lock:
        db.cursor().execute(SCHEMA)
    drop_indexes()


def drop_indexes() -> list[str]:
    """One-time migration: rebuild entity tables created with a PRIMARY KEY or ART indexes as
    plain tables, keeping one row per key. Also repairs a table whose index is out of step."""
    cur = db.cursor()
    names = list(TABLE_KEYS)
    idx = cur.execute("SELECT table_name, index_name FROM duckdb_indexes() WHERE table_name IN (SELECT unnest(?))", [names]).fetchall()
    con = cur.execute("""SELECT DISTINCT table_name FROM duckdb_constraints()
                         WHERE table_name IN (SELECT unnest(?)) AND constraint_type IN ('PRIMARY KEY', 'UNIQUE')""", [names]).fetchall()
    todo = sorted({t for t, _ in idx} | {t for (t,) in con})
    if not todo:
        return []
    with _CLAIMS_LOCK, db._write_lock:
        cur = db.cursor()
        for t in todo:
            keys = ", ".join(TABLE_KEYS[t])
            cur.execute("BEGIN")
            try:
                for tt, i in idx:
                    if tt == t:
                        cur.execute(f'DROP INDEX IF EXISTS "{i}"')
                cur.execute(f"CREATE TABLE {t}__plain AS SELECT * FROM {t} QUALIFY row_number() OVER (PARTITION BY {keys}) = 1")
                cur.execute(f"DROP TABLE {t}")
                cur.execute(f"ALTER TABLE {t}__plain RENAME TO {t}")
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise
    import logging
    logging.getLogger("osinthub.entities").info("rebuilt %s without indexes", ", ".join(todo))
    return todo


class _tx:
    """Entity-table lock + DuckDB write lock + one transaction on this thread's cursor."""

    def __enter__(self):
        _CLAIMS_LOCK.acquire()
        db._write_lock.acquire()
        self.cur = db.cursor()
        self.cur.execute("BEGIN")
        return self.cur

    def __exit__(self, et, ev, tb):
        try:
            self.cur.execute("COMMIT" if et is None else "ROLLBACK")
        finally:
            db._write_lock.release()
            _CLAIMS_LOCK.release()
        return False


def _redirects() -> dict[str, str]:
    """User merges and retypes (overrides.py): an old id is written under the id it now lives under, so
    re-extraction and reference imports never bring a merged duplicate back."""
    from . import overrides
    return overrides.redirects()


def mark_dirty(ids) -> None:
    rd = _redirects()
    ids = sorted({rd.get(i, i) for i in ids if i})
    if not ids:
        return
    with _tx() as cur:
        cur.execute("""INSERT INTO entity_dirty SELECT x, now() FROM (SELECT unnest(?) AS x)
                       WHERE x NOT IN (SELECT id FROM entity_dirty)""", [ids])


def clear_dirty(ids) -> None:
    ids = sorted(set(ids))
    if ids:
        with _tx() as cur:
            cur.execute("DELETE FROM entity_dirty WHERE id IN (SELECT unnest(?))", [ids])


def execute(sql: str, params=()) -> None:
    """One write statement on an entity table, under the lock and in a transaction."""
    with _tx() as cur:
        cur.execute(sql, params)


def claim_id(subj: str, predicate: str, obj: str, origin: str) -> str:
    return hashlib.sha1(f"{subj}|{predicate}|{obj}|{origin}".encode()).hexdigest()[:16]


def _iso(v):
    if v is None:
        return None
    if isinstance(v, dt.datetime):
        return (v if v.tzinfo else v.replace(tzinfo=dt.UTC)).isoformat()
    return str(v)


def _q(p: Path) -> str:
    return str(p).replace("'", "''")


def _ndjson(rows: list[dict], name: str) -> Path:
    p = Path(config.TMP_DIR) / f"ent-{name}-{uuid.uuid4().hex[:8]}.ndjson"
    with p.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r, default=_iso) + "\n")
    return p


def upsert_entities(rows: list[dict]) -> int:
    """Insert or merge entities: aliases are unioned, attrs merged (new keys win), seen times widened."""
    if not rows:
        return 0
    rd = _redirects()
    if rd:
        # a merged id's row joins the entity it was merged into: its name becomes an alias, and its facts
        # never overwrite the kept entity's (they were folded in, kept entity first, at merge time)
        rows = [r if r["id"] not in rd else {"id": rd[r["id"]], "type": rd[r["id"]].split(":", 1)[0], "name": None,
                                             "aliases": [x for x in [r.get("name"), *(r.get("aliases") or [])] if x],
                                             "first_seen": r.get("first_seen"), "last_seen": r.get("last_seen")}
                for r in rows]
    merged: dict[str, dict] = {}
    for r in rows:
        m = merged.get(r["id"])
        if m is None:
            merged[r["id"]] = m = {"id": r["id"], "type": r["type"], "name": r.get("name") or r["id"].split(":", 1)[1],
                                   "aliases": [], "attrs": {}, "first_seen": None, "last_seen": None}
        for a in r.get("aliases") or []:
            if a and a not in m["aliases"] and a != m["name"]:
                m["aliases"].append(a)
        m["attrs"].update({k: v for k, v in (r.get("attrs") or {}).items() if v not in (None, "", [])})
        for k, f in (("first_seen", min), ("last_seen", max)):
            v = r.get(k)
            if v is not None:
                v = _iso(v)
                m[k] = v if m[k] is None else f(m[k], v)
    rows = list(merged.values())
    for r in rows:
        r["attrs"] = json.dumps(r["attrs"])
    p = _ndjson(rows, "e")
    try:
        with _tx() as cur:
            cur.execute(f"""CREATE OR REPLACE TEMP TABLE _ne AS SELECT * FROM read_json('{_q(p)}', format='newline_delimited',
                columns={{'id':'VARCHAR','type':'VARCHAR','name':'VARCHAR','aliases':'VARCHAR[]','attrs':'VARCHAR',
                          'first_seen':'TIMESTAMPTZ','last_seen':'TIMESTAMPTZ'}})""")
            cur.execute("""
                UPDATE entities SET
                  name = coalesce(entities.name, n.name),
                  -- union in order (list_distinct hashes and reorders, so the well-known names the page shows
                  -- first could land behind "+N more"): keep each alias at its first position only
                  aliases = list_filter(list_concat(coalesce(entities.aliases, []), coalesce(n.aliases, [])),
                                        lambda x, i: x IS DISTINCT FROM coalesce(entities.name, n.name)
                                          AND list_position(list_concat(coalesce(entities.aliases, []), coalesce(n.aliases, [])), x) = i),
                  attrs = json_merge_patch(coalesce(entities.attrs, '{}'::JSON), coalesce(n.attrs::JSON, '{}'::JSON)),
                  first_seen = CASE WHEN entities.first_seen IS NULL THEN n.first_seen WHEN n.first_seen IS NULL THEN entities.first_seen
                                    ELSE least(entities.first_seen, n.first_seen) END,
                  last_seen = CASE WHEN entities.last_seen IS NULL THEN n.last_seen WHEN n.last_seen IS NULL THEN entities.last_seen
                                   ELSE greatest(entities.last_seen, n.last_seen) END
                FROM _ne n WHERE entities.id = n.id""")
            cur.execute("""INSERT INTO entities SELECT id, type, name, aliases, attrs::JSON, first_seen, last_seen FROM _ne n
                           WHERE n.id NOT IN (SELECT id FROM entities)""")
            cur.execute("DROP TABLE _ne")
    finally:
        p.unlink(missing_ok=True)
    return len(rows)


def rename_entities(names: dict[str, str]) -> None:
    """Set canonical names (reference import overrides names created from raw text)."""
    rd = _redirects()
    names = {k: v for k, v in names.items() if k not in rd}   # a merged entity's name is an alias of the kept one
    if not names:
        return
    p = _ndjson([{"id": k, "name": v} for k, v in names.items()], "n")
    try:
        with _tx() as cur:
            cur.execute(f"CREATE OR REPLACE TEMP TABLE _nn AS SELECT * FROM read_json('{_q(p)}', format='newline_delimited', columns={{'id':'VARCHAR','name':'VARCHAR'}})")
            cur.execute("UPDATE entities SET name = _nn.name FROM _nn WHERE entities.id = _nn.id AND entities.name IS DISTINCT FROM _nn.name")
            cur.execute("DROP TABLE _nn")
    finally:
        p.unlink(missing_ok=True)


def add_mentions(rows: list[dict]) -> int:
    """rows: {entity_id, ref_type, ref_id, role, method, confidence, ts}. Duplicates are ignored;
    the referenced entities' seen times are widened and they are marked dirty for scoring."""
    if not rows:
        return 0
    rd = _redirects()
    if rd:
        rows = [r if r["entity_id"] not in rd else dict(r, entity_id=rd[r["entity_id"]]) for r in rows]
    uniq = {}
    for r in rows:
        uniq[(r["entity_id"], r["ref_type"], r["ref_id"], r["role"])] = r
    p = _ndjson(list(uniq.values()), "m")
    try:
        with _tx() as cur:
            cur.execute(f"""CREATE OR REPLACE TEMP TABLE _nm AS SELECT * FROM read_json('{_q(p)}', format='newline_delimited',
                columns={{'entity_id':'VARCHAR','ref_type':'VARCHAR','ref_id':'VARCHAR','role':'VARCHAR','method':'VARCHAR',
                          'confidence':'DOUBLE','ts':'TIMESTAMPTZ'}})""")
            cur.execute("""INSERT INTO mentions SELECT n.entity_id, n.ref_type, n.ref_id, n.role, n.method, n.confidence, n.ts
                           FROM _nm n ANTI JOIN mentions m USING (entity_id, ref_type, ref_id, role)""")
            cur.execute("""CREATE OR REPLACE TEMP TABLE _ms AS SELECT entity_id AS id, min(ts) AS f, max(ts) AS l FROM _nm GROUP BY 1""")
            cur.execute("""UPDATE entities SET
                             first_seen = CASE WHEN first_seen IS NULL OR _ms.f < first_seen THEN _ms.f ELSE first_seen END,
                             last_seen = CASE WHEN last_seen IS NULL OR _ms.l > last_seen THEN _ms.l ELSE last_seen END
                           FROM _ms WHERE entities.id = _ms.id AND (entities.first_seen IS NULL OR _ms.f < entities.first_seen
                                 OR entities.last_seen IS NULL OR _ms.l > entities.last_seen)""")
            cur.execute("""INSERT INTO entity_dirty SELECT DISTINCT entity_id, now() FROM _nm
                           WHERE split_part(entity_id, ':', 1) IN ('actor','campaign','malware','tool')
                             AND entity_id NOT IN (SELECT id FROM entity_dirty)""")
            cur.execute("DROP TABLE _nm")
            cur.execute("DROP TABLE _ms")
    finally:
        p.unlink(missing_ok=True)
    return len(uniq)


def upsert_claims(rows: list[dict], replace_evidence: bool = False) -> int:
    """rows: {subj, predicate, obj, origin, sources[], first_seen, last_seen, evidence[]}.
    Same (subj, predicate, obj, origin) merges: sources unioned, evidence appended (capped,
    de-duplicated by source+quote), seen times widened. Confidence is set by scoring.
    The whole read-merge-write runs under the claims lock."""
    if not rows:
        return 0
    rd = _redirects()
    if rd:
        out = []
        for r in rows:
            s, o = rd.get(r["subj"], r["subj"]), rd.get(r["obj"], r["obj"])
            if s == o:
                continue                      # a link between two names of one thing
            if s != r["subj"] or o != r["obj"]:
                r = {k: v for k, v in r.items() if k != "id"} | {"subj": s, "obj": o}
            out.append(r)
        rows = out
        if not rows:
            return 0
    with _CLAIMS_LOCK:
        return _upsert_claims(rows, replace_evidence)


def _upsert_claims(rows: list[dict], replace_evidence: bool) -> int:
    merged: dict[str, dict] = {}
    for r in rows:
        cid = r.get("id") or claim_id(r["subj"], r["predicate"], r["obj"], r["origin"])
        m = merged.get(cid)
        if m is None:
            merged[cid] = m = {"id": cid, "subj": r["subj"], "predicate": r["predicate"], "obj": r["obj"],
                               "origin": r["origin"], "sources": [], "confidence": r.get("confidence"),
                               "first_seen": None, "last_seen": None, "evidence": []}
        for s in r.get("sources") or []:
            if s not in m["sources"]:
                m["sources"].append(s)
        m["evidence"].extend(r.get("evidence") or [])
        for k, f in (("first_seen", min), ("last_seen", max)):
            v = r.get(k)
            if v is not None:
                v = _iso(v)
                m[k] = v if m[k] is None else f(m[k], v)
    rows = list(merged.values())
    existing = {}
    ids = [r["id"] for r in rows]
    for i in range(0, len(ids), 5000):
        for cid, ev in db.cursor().execute("SELECT id, evidence FROM claims WHERE id IN (SELECT unnest(?))", [ids[i:i + 5000]]).fetchall():
            existing[cid] = json.loads(ev) if isinstance(ev, str) else (ev or [])
    for r in rows:
        prior = [] if replace_evidence else existing.get(r["id"], [])
        r["evidence"] = json.dumps(_dedupe_evidence(prior + r["evidence"])[:EVIDENCE_CAP])
    p = _ndjson(rows, "c")
    try:
        with _tx() as cur:
            cur.execute(f"""CREATE OR REPLACE TEMP TABLE _nc AS SELECT * FROM read_json('{_q(p)}', format='newline_delimited',
                columns={{'id':'VARCHAR','subj':'VARCHAR','predicate':'VARCHAR','obj':'VARCHAR','origin':'VARCHAR',
                          'sources':'VARCHAR[]','confidence':'DOUBLE','first_seen':'TIMESTAMPTZ','last_seen':'TIMESTAMPTZ',
                          'evidence':'VARCHAR'}})""")
            cur.execute("""
                UPDATE claims SET
                  sources = list_distinct(list_concat(coalesce(claims.sources, []), coalesce(n.sources, []))),
                  confidence = n.confidence,
                  first_seen = CASE WHEN claims.first_seen IS NULL THEN n.first_seen WHEN n.first_seen IS NULL THEN claims.first_seen
                                    ELSE least(claims.first_seen, n.first_seen) END,
                  last_seen = CASE WHEN claims.last_seen IS NULL THEN n.last_seen WHEN n.last_seen IS NULL THEN claims.last_seen
                                   ELSE greatest(claims.last_seen, n.last_seen) END,
                  evidence = n.evidence::JSON
                FROM _nc n WHERE claims.id = n.id""")
            cur.execute("""INSERT INTO claims SELECT id, subj, predicate, obj, origin, sources, confidence, first_seen, last_seen,
                                                  evidence::JSON FROM _nc n WHERE n.id NOT IN (SELECT id FROM claims)""")
            cur.execute("""INSERT INTO entity_dirty SELECT DISTINCT x, now() FROM
                             (SELECT subj AS x FROM _nc WHERE origin <> 'inferred' UNION SELECT obj FROM _nc WHERE origin <> 'inferred')
                           WHERE split_part(x, ':', 1) IN ('actor','campaign','malware','tool') AND x NOT IN (SELECT id FROM entity_dirty)""")
            cur.execute("DROP TABLE _nc")
    finally:
        p.unlink(missing_ok=True)
    return len(rows)


def _dedupe_evidence(ev: list[dict]) -> list[dict]:
    out, seen = [], set()
    for e in ev:
        k = (e.get("source"), e.get("ref_id"), e.get("quote"))
        if k in seen:
            continue
        seen.add(k)
        out.append(e)
    return out


def mark_linked(ref_type: str, items: list[tuple[str, str]]) -> None:
    if not items:
        return
    p = _ndjson([{"ref_type": ref_type, "ref_id": i, "hash": h} for i, h in items], "l")
    try:
        with _tx() as cur:
            cur.execute(f"""CREATE OR REPLACE TEMP TABLE _nl AS SELECT DISTINCT * FROM read_json('{_q(p)}', format='newline_delimited',
                columns={{'ref_type':'VARCHAR','ref_id':'VARCHAR','hash':'VARCHAR'}})""")
            cur.execute("DELETE FROM entity_linked WHERE (ref_type, ref_id) IN (SELECT ref_type, ref_id FROM _nl)")
            cur.execute("INSERT INTO entity_linked SELECT ref_type, ref_id, hash, now() FROM _nl")
            cur.execute("DROP TABLE _nl")
    finally:
        p.unlink(missing_ok=True)
