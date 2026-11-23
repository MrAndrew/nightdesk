"""After an article is fetched: chunks, MinHash signature, entity hook, embeddings.

All steps are incremental (driven by NULL marker columns on `articles`) and safe to re-run.
Embeddings catch up on their own when the AI helper comes back.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import re
import uuid

import numpy as np

from .. import db
from .common import ai_client, embed, ensure_schema, entities, log, vectors

UTC = dt.UTC
CHUNK_WORDS = 300        # ~400 tokens for English prose (about 1.3 tokens per word)
CHUNK_OVERLAP = 60       # ~80 tokens of overlap between neighbouring chunks
MINHASH_PERMS = 96
COLLECTION = "articles"
_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9'\-\.]*[A-Za-z0-9]|[A-Za-z0-9]")
_P = (1 << 61) - 1
_rng = np.random.default_rng(20261104)
_A = _rng.integers(1, _P, MINHASH_PERMS, dtype=np.uint64)
_B = _rng.integers(0, _P, MINHASH_PERMS, dtype=np.uint64)

state = {"embed_pending": 0, "embed_last_error": None, "embedded": 0, "entities_module": False}


# ------------------------------------------------------------------ chunks
def chunk_text(title: str | None, text: str) -> list[str]:
    """Paragraph-aware chunks of about CHUNK_WORDS words with CHUNK_OVERLAP words of overlap.

    Each chunk is prefixed with the title so a chunk stands on its own in search.
    """
    words: list[str] = []
    for para in re.split(r"\n\s*\n|\n", text or ""):
        w = para.split()
        if w:
            words.extend(w)
            words.append("\n")
    words = words[:-1] if words and words[-1] == "\n" else words
    chunks = []
    step = CHUNK_WORDS - CHUNK_OVERLAP
    i = 0
    while i < len(words):
        part = words[i:i + CHUNK_WORDS]
        body = " ".join(part).replace(" \n ", "\n").replace("\n ", "\n").strip()
        if body:
            chunks.append(f"{title}\n{body}" if title else body)
        if i + CHUNK_WORDS >= len(words):
            break
        i += step
    return chunks


# ------------------------------------------------------------------ minhash
def shingles(text: str, k: int = 5) -> set[int]:
    toks = [t.lower() for t in _WORD.findall(text or "")]
    if len(toks) < k:
        toks = toks + [""] * (k - len(toks))
    return {int.from_bytes(hashlib.blake2b(" ".join(toks[i:i + k]).encode(), digest_size=8).digest(), "little") & _P
            for i in range(len(toks) - k + 1)}


def minhash(text: str) -> list[int]:
    sh = np.fromiter(shingles(text), dtype=np.uint64)
    if not len(sh):
        return [0] * MINHASH_PERMS
    # (a*x + b) mod p with 61-bit arithmetic done in Python ints would be slow; use float-free
    # 64-bit wraparound hashing instead, which is a valid universal-ish family for this purpose.
    h = (np.outer(sh, _A) + _B)           # uint64 wraparound
    h ^= h >> np.uint64(29)
    return [int(x) for x in h.min(axis=0)]


def jaccard_est(a, b) -> float:
    if a is None or b is None:
        return 0.0
    a, b = np.asarray(a, dtype=np.uint64), np.asarray(b, dtype=np.uint64)
    return float((a == b).mean())


# ------------------------------------------------------------------ steps
def prepare_pending(limit: int = 500) -> int:
    """Chunks + MinHash for fetched articles that don't have them yet."""
    ensure_schema()
    rows = db.query("SELECT id, title, text FROM articles WHERE status = 'ok' AND chunks IS NULL LIMIT ?", [limit])
    for r in rows:
        ch = chunk_text(r["title"], r["text"])
        sig = minhash(r["text"])
        db.execute("DELETE FROM article_chunks WHERE article_id = ?", [r["id"]])
        for i, c in enumerate(ch):
            db.execute("INSERT INTO article_chunks VALUES (?, ?, ?)", [r["id"], i, c])
        db.execute("UPDATE articles SET chunks = ?, minhash = ?, embedded_at = NULL WHERE id = ?", [len(ch), sig, r["id"]])
    return len(rows)


LLM_RETRY_MIN = 10       # minutes before an article the LLM missed (or whose ingest failed) is tried again
RETRY_MAX_MIN = 24 * 60  # each further miss in a row doubles the wait, up to once a day


def _backoff(count_col: str, at_col: str) -> str:
    """SQL: true when the article's last failure (at_col) is older than its backoff wait. The wait is
    LLM_RETRY_MIN minutes, doubled for each earlier failure in a row (count_col), at most RETRY_MAX_MIN."""
    return (f"({at_col} IS NULL OR {at_col} < now() - to_minutes(CAST(least({LLM_RETRY_MIN} * "
            f"pow(2, least(greatest(coalesce({count_col}, 0) - 1, 0), 20)), {RETRY_MAX_MIN}) AS BIGINT)))")


LLM_MAX_TRIES = 6        # misses while the helper is up (waits 10, 20, 40, 80, 160 min) before giving up


def _llm_missed(stats: dict) -> bool:
    """The LLM pass got no answer for at least one chunk it sent: helper down, timed out, an HTTP error or an
    unusable reply (extract() keeps the regex and alias results and whatever chunks did answer). Answered
    chunks are cached, so a retry only asks again for the missing ones. Empty texts and IOC-appendix chunks
    (never sent) are not misses."""
    chunks = stats.get("chunks", 0)
    if chunks <= 0:
        return False
    if not stats.get("llm"):
        return True
    return stats.get("ok", 0) < chunks - stats.get("skipped_appendix", 0)


def _helper_down() -> bool:
    c = ai_client()
    try:
        return bool(c and c.is_down())
    except Exception:
        return False


def _ingest_one(ent, r) -> bool | None:
    """Ingest one article; True when the LLM pass ran, False when it got no answer (deterministic
    results only; the article is revisited later), None on failure (retried later, with backoff)."""
    try:
        ent.ingest_text("article", r["id"], f"{r['title'] or ''}\n\n{r['text'] or ''}", r["url"], r["tier"])
    except Exception as e:
        log.warning("entities.ingest_text failed for %s: %s", r["id"], e)
        db.execute("UPDATE articles SET entities_fails = coalesce(entities_fails, 0) + 1, entities_failed_at = now() "
                   "WHERE id = ?", [r["id"]])
        return None
    from ..entities.extract import LAST_STATS
    missed = _llm_missed(LAST_STATS)
    # An outage (helper down) is not the article's fault: it waits the plain delay. A timeout, HTTP error
    # or unusable reply while the helper is up counts as a try, so the wait doubles; after LLM_MAX_TRIES
    # the article is given up (entities_llm_missed cleared, entities_llm_tries kept as the record), so a
    # text the helper always times out on cannot hold it for 15 minutes once a day forever.
    if not missed:
        tries = "NULL"
    elif _helper_down():
        tries = "entities_llm_tries"
    else:
        tries = "coalesce(entities_llm_tries, 0) + 1"
    db.execute(f"""UPDATE articles SET entities_at = now(), entities_llm_tries = {tries},
                   entities_llm_missed = CASE WHEN ? AND coalesce({tries}, 0) < {LLM_MAX_TRIES} THEN now() END,
                   entities_fails = NULL, entities_failed_at = NULL WHERE id = ?""", [missed, r["id"]])
    if missed and db.query("SELECT entities_llm_missed IS NULL AS gave_up FROM articles WHERE id = ?",
                           [r["id"]])[0]["gave_up"]:
        log.info("entities: giving up the LLM pass for article %s after %d tries", r["id"], LLM_MAX_TRIES)
    return not missed


def ingest_entities_pending(limit: int = 200) -> int:
    """Hand article text to the entities layer once it exists (guarded: it may not be built yet).

    New articles first; one whose ingest raised waits with backoff and then comes after fresh ones.
    Then, while the AI helper is up, articles whose LLM pass got no answer (entities_llm_missed:
    helper down, timed out or errored) are ingested again so they get actors, victims, sectors and
    reported claims; re-ingesting only adds what is new."""
    ent = entities()
    state["entities_module"] = ent is not None
    if ent is None:
        return 0
    rows = db.query(f"""SELECT id, url, title, text, tier FROM articles WHERE status = 'ok' AND entities_at IS NULL
                          AND {_backoff('entities_fails', 'entities_failed_at')}
                        ORDER BY coalesce(entities_fails, 0) > 0, published DESC NULLS LAST LIMIT ?""", [limit])
    n = sum(1 for r in rows if _ingest_one(ent, r) is not None)
    left = limit - len(rows)
    if left <= 0 or _helper_down():
        return n
    rows = db.query(f"""SELECT id, url, title, text, tier FROM articles
                        WHERE status = 'ok' AND entities_at IS NOT NULL AND entities_llm_missed IS NOT NULL
                          AND {_backoff('entities_llm_tries', 'entities_llm_missed')}
                          AND {_backoff('entities_fails', 'entities_failed_at')}
                        ORDER BY coalesce(entities_llm_tries, 0), published DESC NULLS LAST LIMIT ?""", [left])
    for r in rows:
        ok = _ingest_one(ent, r)
        if ok:
            n += 1
        elif ok is False:
            break  # no answer again: leave the rest for a later cycle
    return n


def chunk_point_id(aid: str, idx: int) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"article:{aid}:{idx}"))


def embed_pending(limit: int = 40, batch: int = 16) -> int:
    """Embed chunks of articles not embedded yet. Returns articles embedded (0 when the helper is down)."""
    rows = db.query("""SELECT id, source, published, title, tier FROM articles
                       WHERE status = 'ok' AND chunks > 0 AND embedded_at IS NULL
                       ORDER BY published DESC NULLS LAST LIMIT ?""", [limit])
    state["embed_pending"] = db.query("SELECT count(*) n FROM articles WHERE status='ok' AND chunks > 0 AND embedded_at IS NULL")[0]["n"]
    if not rows:
        return 0
    vec = vectors()
    done = 0
    for r in rows:
        chunks = db.query("SELECT idx, text FROM article_chunks WHERE article_id = ? ORDER BY idx", [r["id"]])
        vecs: list[list[float]] = []
        for i in range(0, len(chunks), batch):
            out = embed([c["text"] for c in chunks[i:i + batch]], kind="document")
            if not out:
                state["embed_last_error"] = "AI helper unavailable"
                return done
            vecs.extend(out)
        if vec is not None:
            pub = r["published"].isoformat() if r["published"] else None
            items = [{"id": chunk_point_id(r["id"], c["idx"]), "vector": v,
                      "payload": {"article_id": r["id"], "source": r["source"], "published": pub,
                                  "title": r["title"], "chunk": c["idx"], "tier": r["tier"],
                                  "ts": r["published"].timestamp() if r["published"] else None}}
                     for c, v in zip(chunks, vecs)]
            try:
                vec.upsert(COLLECTION, items)
            except Exception as e:
                state["embed_last_error"] = f"vectors.upsert: {e}"
                log.warning("vectors.upsert failed: %s", e)
                return done
        m = np.asarray(vecs, dtype=np.float32).mean(axis=0)
        m /= (np.linalg.norm(m) or 1.0)
        db.execute("INSERT OR REPLACE INTO article_vecs VALUES (?, ?)", [r["id"], m.tolist()])
        db.execute("UPDATE articles SET embedded_at = now() WHERE id = ?", [r["id"]])
        done += 1
    state["embedded"] += done
    state["embed_last_error"] = None
    return done


async def entity_loop() -> None:
    """Entity extraction can call the local LLM and is slow, so it runs on its own, a few articles at a time."""
    while True:
        try:
            n = await asyncio.to_thread(ingest_entities_pending, 5)
        except Exception as e:
            log.warning("news entity hook failed: %s", e)
            n = 0
        await asyncio.sleep(2 if n else 60)


async def summary_loop() -> None:
    """LLM story summaries run on their own: a busy helper must not hold up embeddings and clustering."""
    from . import stories
    while True:
        try:
            n = await asyncio.to_thread(stories.summarise_pending, 3)
        except Exception as e:
            log.warning("news summaries failed: %s", e)
            n = 0
        await asyncio.sleep(5 if n else 60)


async def process_loop() -> None:
    """Chunks, embeddings, stories: every 30 s, each step incremental."""
    from . import stories
    while True:
        try:
            await asyncio.to_thread(prepare_pending)
            while await asyncio.to_thread(embed_pending) > 0:
                pass
            await asyncio.to_thread(stories.cluster_pending)
        except Exception as e:
            log.warning("news processing failed: %s", e)
        await asyncio.sleep(30)
