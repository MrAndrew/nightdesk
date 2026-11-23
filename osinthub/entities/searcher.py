"""`entity` searcher for osinthub.search, and the `entities` vector collection.

Keyword: BM25 over name + aliases (+ description for named types), with exact hits first, in
tiers: the id, a whole name, a whole alias, a name or alias without generic words ("lazarus" for
"Lazarus Group"), then names and aliases that start with the query's words; most-mentioned first
within a tier. A query of only generic words ("the", "group", "apt") gets no tiers. Vector: embeddings of "name; aliases; description" for named entity types.
Docs: okf/data/entities.md#search
"""
from __future__ import annotations

import hashlib
import logging
import threading
import time

from .. import db
from ..keyword import STOP as _KW_STOP
from .normalize import STRIP_EDGES, key, stripped_key, tokens

# Words that name nothing on their own ("the", "group", "operation", "apt", ...): a query made only of these
# gets no name/alias tiers, and a name reduced to one of them is not a stripped key.
GENERIC = set(STRIP_EDGES) | _KW_STOP | {"new", "apt", "says", "said", "report", "attack", "attacks", "hackers", "hacker"}
PREFIX_MIN = 4   # the first query word must be this long for the word-prefix tier ("volt" yes, "win"/"apt" no)

log = logging.getLogger("osinthub.entities.search")

NAMED = ("actor", "malware", "tool", "campaign", "technique", "vendor", "product", "sector", "country", "org")
_corpus: dict = {"t": 0, "n": -1, "docs": {}, "alias": {}, "names": {}, "stripped": {}, "prefix": {}}
_lock = threading.Lock()


def _doc_text(name, aliases, desc, typ) -> str:
    parts = [name or ""]
    if aliases:
        parts.append("aka " + ", ".join(aliases[:40]))
    if desc and typ in NAMED:
        parts.append(desc[:800])
    return f"{typ}: " + ". ".join(p for p in parts if p)


def corpus() -> dict:
    with _lock:
        if time.time() - _corpus["t"] < 120 and _corpus["docs"]:
            return _corpus
    n = db.query("SELECT count(*) AS n FROM entities")[0]["n"]
    if n == _corpus["n"] and _corpus["docs"]:
        _corpus["t"] = time.time()
        return _corpus
    docs, alias, names, stripped, prefix = {}, {}, {}, {}, {}
    rows = db.cursor().execute("""
        SELECT e.id, e.type, e.name, e.aliases, json_extract_string(e.attrs, '$.description'), coalesce(m.n, 0)
        FROM entities e LEFT JOIN (SELECT entity_id, count(*) n FROM mentions GROUP BY 1) m ON m.entity_id = e.id""").fetchall()
    for eid, typ, name, aliases, desc, nm in rows:
        docs[eid] = {"text": _doc_text(name, aliases or [], desc, typ), "title": name, "type": typ,
                     "snippet": (desc or ", ".join((aliases or [])[:8]) or eid)[:240], "mentions": nm}
        for j, a in enumerate([name, *(aliases or [])]):
            k = key(a or "")
            if len(k) < 3:
                continue
            alias.setdefault(k, []).append(eid)
            if j == 0:
                names.setdefault(k, []).append(eid)
            if typ in NAMED:   # name-like matches only for named types, not for IOCs such as lazarus.example
                sk = stripped_key(a)
                if len(sk) >= 3 and sk != k and sk not in GENERIC:   # "The Group" must not become "the"
                    stripped.setdefault(sk, []).append(eid)
                tk = tuple(tokens(a))
                if len(tk) > 1:
                    prefix.setdefault(tk[0], []).append((tk, eid))
    with _lock:
        _corpus.update(t=time.time(), n=n, docs=docs, alias=alias, names=names, stripped=stripped, prefix=prefix)
    return _corpus


def exact_ids(c: dict, qs: str) -> list[str]:
    """Entities a query names, best first: the id, then a whole name, a whole alias, a name or alias
    without its generic words, a name or alias starting with the query's words, then aliases equal to a
    single word of a longer query. Most-mentioned first within each tier."""
    docs = c["docs"]
    ment = lambda i: -(docs.get(i, {}).get("mentions") or 0)  # noqa: E731
    qk, qt = key(qs), tuple(tokens(qs))
    tiers: list[list[str]] = [[qs] if qs in docs else []]
    if all(t in GENERIC for t in qt):   # only generic words: leave ranking to BM25 / vectors
        return tiers[0]
    if len(qk) >= 3:
        tiers.append(sorted(c["names"].get(qk, []), key=ment))
        tiers.append(sorted(c["alias"].get(qk, []), key=ment))
        sk = stripped_key(qs)
        tiers.append(sorted({*c["stripped"].get(qk, []), *c["stripped"].get(sk, [])}, key=ment))
        if qt and len(qt[0]) >= PREFIX_MIN and qt[0] not in GENERIC:
            n = len(qt)
            hits = {eid for tk, eid in c["prefix"].get(qt[0], ()) if len(tk) > n and tk[:n] == qt}
            tiers.append(sorted(hits, key=ment)[:5])
    words = []
    for tok in qs.split():
        if len(tok) >= 4 and key(tok) != qk and tok.lower() not in GENERIC:
            words += c["alias"].get(key(tok), [])[:3]
    tiers.append(words)
    return list(dict.fromkeys(i for t in tiers for i in t))[:10]


def search_entities(q: str, qvec, k: int) -> list[dict]:
    from .. import search
    c = corpus()
    docs = c["docs"]

    out = []
    for i, s, cos, kw in search.hybrid("entity", docs, "entities", q, qvec, k, lambda qs: exact_ids(c, qs)):
        d = docs[i]
        out.append({"type": "entity", "id": i, "title": d["title"], "score": round(s, 4), "snippet": d["snippet"],
                    "url": f"#/entities/{i}", "entity_type": d["type"], "mentions": d["mentions"],
                    "match": {"vector": cos, "keyword": round(kw, 3)}})
    return out


def register() -> None:
    try:
        from .. import search
        search.register_searcher("entity", search_entities)
    except Exception as e:
        log.warning("entity searcher not registered: %s", e)


# ---------------------------------------------------------------- vectors
VEC_SCHEMA = "CREATE TABLE IF NOT EXISTS entity_vec (id VARCHAR, h VARCHAR, embedded_at TIMESTAMPTZ);"   # no index: see store.SCHEMA


def embed_pending(batch: int = 64, max_batches: int = 20) -> int:
    """Embed named entities whose text changed. Returns how many were embedded."""
    try:
        from .. import vectors
        from ..ai import client
    except Exception:
        return 0
    done = 0
    for _ in range(max_batches):
        rows = db.cursor().execute(f"""
            SELECT e.id, e.type, e.name, e.aliases, json_extract_string(e.attrs, '$.description') FROM entities e
            LEFT JOIN entity_vec v ON v.id = e.id
            WHERE e.type IN ({','.join('?' * len(NAMED))})
              -- families known only from abuse.ch feeds: their terms forbid using the data with AI models
              AND json_extract_string(e.attrs, '$.ai_excluded') IS NULL
              AND (v.id IS NULL OR v.h <> md5(coalesce(e.name,'') || array_to_string(coalesce(e.aliases, []), ',') ||
                                              coalesce(json_extract_string(e.attrs, '$.description'), '')))
            LIMIT {int(batch)}""", list(NAMED)).fetchall()
        if not rows:
            break
        texts = [_doc_text(n, a or [], d, t) for _, t, n, a, d in rows]
        vecs = client.embed(texts, kind="document")
        if not vecs:
            break
        items = [{"id": r[0], "vector": v, "payload": {"type": r[1], "name": r[2]}} for r, v in zip(rows, vecs)]
        try:
            vectors.upsert("entities", items)
        except Exception as e:
            log.warning("entity vectors upsert failed: %s", e)
            break
        hs = [hashlib.md5(((r[2] or "") + ",".join(r[3] or []) + (r[4] or "")).encode()).hexdigest() for r in rows]
        from . import store
        with store._tx() as cur:
            cur.execute("DELETE FROM entity_vec WHERE id IN (SELECT unnest(?))", [[r[0] for r in rows]])
            cur.executemany("INSERT INTO entity_vec VALUES (?, ?, now())", [[r[0], h] for r, h in zip(rows, hs)])
        done += len(rows)
    return done


# ---------------------------------------------------------------- one-off: AI-excluded data out of stored AI output
PURGE_KEY = "entities.ai_excluded_purge"
PURGE_TAG = "2026-11-feodo"   # Feodo Tracker became ai_ok = False (pre-alpha terms review, 2026-11-19)


def purge_ai_excluded_once() -> dict:
    """Once per lake: what earlier versions derived with AI from data that is now AI-excluded (Feodo Tracker joined the
    abuse.ch sources). Malware families known only from those feeds (every mention is one of their events, and the
    name is not in the reference catalogue) get `ai_excluded`, and their vectors are deleted; a cached entity-brief
    text that no longer matches its facts is dropped only when its entity has evidence from such a feed (it is
    written again from the allowed evidence when the AI helper is up); briefs stale for other reasons are kept."""
    if db.get_setting(PURGE_KEY) == PURGE_TAG:
        return {}
    from ..news import brief
    ex = sorted(brief.ai_excluded_sources())
    out = {"marked": 0, "vectors_deleted": 0, "briefs_dropped": 0}
    ids: list[str] = []
    if ex:
        marks = ",".join("?" * len(ex))
        rows = db.query(f"""
            SELECT e.id FROM entities e
            WHERE e.type = 'malware' AND json_extract_string(e.attrs, '$.ai_excluded') IS NULL
              AND EXISTS (SELECT 1 FROM mentions m WHERE m.entity_id = e.id)
              AND NOT EXISTS (SELECT 1 FROM mentions m WHERE m.entity_id = e.id
                              AND NOT (m.ref_type = 'event' AND split_part(m.ref_id, ':', 1) IN ({marks})))""", ex)
        try:
            from .refdata import catalog
            known = catalog().entities
        except Exception:
            known = {}
        ids = [r["id"] for r in rows if r["id"] not in known]
        if ids:
            try:   # vectors first: if this fails nothing is marked, so the next start finds the same ids again
                from .. import vectors
                vectors.delete("entities", ids)
                out["vectors_deleted"] = len(ids)
            except Exception as e:
                log.warning("deleting AI-excluded entity vectors failed: %s", e)
                return out
            db.execute("DELETE FROM entity_vec WHERE id IN (SELECT unnest(?))", [ids])
            db.execute("""UPDATE entities SET attrs = json_merge_patch(coalesce(attrs, '{}'::JSON), ?::JSON)
                          WHERE id IN (SELECT unnest(?))""", ['{"ai_excluded": "abuse.ch terms of use"}', ids])
            out["marked"] = len(ids)
    # A cached brief is dropped only when it is stale AND the entity has AI-excluded evidence (a claim from one of
    # those feeds, or the entity was just marked above). A brief that is stale for any other reason (a claim seen
    # again) is left alone: it is still shown, marked stale, and rewritten when the AI helper is up.
    tainted = set(ids)
    if ex:
        marks = ",".join("?" * len(ex))
        tainted |= {r["e"] for r in db.query(f"""
            SELECT subj AS e FROM claims WHERE list_has_any(sources, [{marks}]::VARCHAR[])
            UNION SELECT obj FROM claims WHERE list_has_any(sources, [{marks}]::VARCHAR[])""", ex + ex)}
    for r in db.query("SELECT key FROM settings WHERE key LIKE ?", [brief.CACHE_KEY + "%"]):
        eid = r["key"][len(brief.CACHE_KEY):]
        if eid not in tainted:
            continue
        cached = db.get_setting(r["key"]) or {}
        try:
            now_hash = brief.facts(eid)["claims_hash"]
        except Exception:
            now_hash = None
        if cached.get("hash") != now_hash:
            db.execute("DELETE FROM settings WHERE key = ?", [r["key"]])
            out["briefs_dropped"] += 1
    db.set_setting(PURGE_KEY, PURGE_TAG)
    if out["marked"] or out["briefs_dropped"]:
        log.info("AI-excluded data purge: %s", out)
    return out
