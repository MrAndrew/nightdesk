"""Background embedding pipeline: keeps the ``cves`` and ``events`` vector collections in step
with the warehouse.

Each pass builds the documents (osinthub/ai/docs.py), compares their hashes with what the
active vector backend holds (``vectors.indexed``), and embeds only new or changed ones. When
the AI helper is down the pass stops early and the next one (every ``INTERVAL`` seconds)
catches up, so nothing is lost. Other packages can add collections with ``register_corpus``.
"""
from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Callable

from .. import vectors
from . import client, docs

log = logging.getLogger("osinthub.ai.indexer")

INTERVAL = 60
BATCH = 128

# collection -> function returning {id: {"text", "hash", "payload"}}
CORPORA: dict[str, Callable[[], dict[str, dict]]] = {"cves": docs.cve_docs, "events": docs.event_docs}
_state: dict[str, dict] = {}
_run_lock = threading.Lock()


def register_corpus(collection: str, fn: Callable[[], dict[str, dict]]) -> None:
    CORPORA[collection] = fn


def sync_collection(collection: str, fn: Callable[[], dict[str, dict]]) -> dict:
    t0 = time.time()
    st = _state.setdefault(collection, {})
    backend = vectors.backend_name()
    corpus = fn()
    done = vectors.indexed(collection, backend)
    if done and vectors.count(collection) == 0:
        # The index was wiped (Qdrant storage removed, vectors.duckdb deleted): rebuild it.
        log.info("%s: %s index is empty; re-embedding all %d documents", collection, backend, len(corpus))
        vectors.reset_indexed(collection, backend)
        done = {}
    todo = [d for i, d in corpus.items() if done.get(i) != d["hash"]]
    gone = [i for i in done if i not in corpus]
    if gone:
        # Documents that left the warehouse (retention, removed records) leave the index too.
        for j in range(0, len(gone), 500):
            vectors.delete(collection, gone[j:j + 500])
        vectors.unmark_indexed(collection, gone, backend)
        log.info("%s: removed %d vectors for documents that are gone", collection, len(gone))
    embedded = 0
    for i in range(0, len(todo), BATCH):
        part = todo[i:i + BATCH]
        vecs = client.embed([d["text"] for d in part], kind="document")
        if vecs is None:
            st["waiting"] = "AI helper unavailable; will catch up"
            break
        vectors.upsert(collection, [{"id": d["id"], "vector": v, "payload": d["payload"]} for d, v in zip(part, vecs)])
        vectors.mark_indexed(collection, {d["id"]: d["hash"] for d in part}, backend)
        embedded += len(part)
    else:
        st.pop("waiting", None)
    st.update(backend=backend, documents=len(corpus), embedded_now=embedded,
              pending=len(todo) - embedded, removed_now=len(gone), last_pass=time.time(),
              seconds=round(time.time() - t0, 1))
    if embedded:
        log.info("%s: embedded %d documents into %s in %.1fs (%d pending)", collection, embedded, backend,
                 time.time() - t0, len(todo) - embedded)
    return dict(st)


def sync_all() -> dict:
    with _run_lock:  # one pass at a time (the loop and POST /api/ai/reindex)
        out = {}
        for c, fn in list(CORPORA.items()):
            try:
                out[c] = sync_collection(c, fn)
            except Exception as e:
                log.warning("indexing %s failed: %s", c, e)
                _state.setdefault(c, {})["error"] = f"{type(e).__name__}: {e}"[:300]
                out[c] = dict(_state[c])
        return out


def status() -> dict:
    return {c: dict(_state.get(c, {})) for c in CORPORA}


async def index_loop() -> None:
    await asyncio.sleep(3)  # let startup finish first
    while True:
        await asyncio.to_thread(sync_all)
        await asyncio.sleep(INTERVAL)
