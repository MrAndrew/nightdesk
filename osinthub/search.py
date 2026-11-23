"""Hybrid semantic search: vector similarity plus keyword (BM25) scoring, fused per type.

    semantic(q, types=None, k=10) -> [{"type", "id", "title", "score", "snippet", "url", ...}]

Types are pluggable. Foundation registers ``cve`` and ``event``; other packages call
``register_searcher("article", fn)`` from their ext module, where ``fn(q, qvec, k)`` returns
result dicts with a ``score`` in roughly 0..1 (``qvec`` is None when no embedding is
available, and the searcher must then fall back to keywords).

Without the AI helper (offline from it, or down) every type still answers from keywords.
Architecture: okf/architecture/local-ai.md#search
"""
from __future__ import annotations

import logging
import re
import threading
from collections.abc import Callable

from . import keyword, vectors

log = logging.getLogger("osinthub.search")

Searcher = Callable[[str, "list[float] | None", int], list[dict]]
SEARCHERS: dict[str, Searcher] = {}
DEFAULT_TYPES: list[str] = []

# Fusion weights: final = W_VEC * cosine + W_KW * keyword score (absolute 0..1, see keyword.py).
W_VEC = 1.0
W_KW = 0.5
CANDIDATES = 60


def register_searcher(type_: str, fn: Searcher, default: bool = True) -> None:
    SEARCHERS[type_] = fn
    if default and type_ not in DEFAULT_TYPES:
        DEFAULT_TYPES.append(type_)


# ------------------------------------------------------------------ keyword index
_bm25: dict[str, tuple[int, int, keyword.BM25F]] = {}
_bm_lock = threading.Lock()


def keyword_index(name: str, corpus: dict[str, dict]) -> keyword.BM25F:
    """A BM25F index over a corpus dict ({id: {"text"} or {"fields": {...}}}), rebuilt when the
    corpus object changes."""
    with _bm_lock:
        cur = _bm25.get(name)
        if cur and cur[0] == id(corpus) and cur[1] == len(corpus):
            return cur[2]
    idx = keyword.BM25F(corpus)
    with _bm_lock:
        _bm25[name] = (id(corpus), len(corpus), idx)
    return idx


def hybrid(name: str, corpus: dict[str, dict], collection: str, q: str, qvec, k: int,
           exact: Callable[[str], list[str]] | None = None) -> list[tuple[str, float, float | None, float]]:
    """Fuse vector and keyword hits over one corpus. Returns [(id, score, cosine, keyword)].

    keyword is on an absolute 0..1 scale (osinthub/keyword.py), so scores from different
    corpora and types can be merged: hybrid = cosine + W_KW * keyword, keyword-only = keyword.
    """
    kws = dict(keyword_index(name, corpus).search(q, CANDIDATES))
    vec: dict[str, float] = {}
    if qvec is not None:
        for h in vectors.search(collection, qvec, CANDIDATES):
            if h["id"] in corpus:
                vec[h["id"]] = h["score"]
    floor = (min(vec.values()) - 0.02) if vec else None
    out = []
    for i in set(kws) | set(vec):
        kw = kws.get(i, 0.0)
        if floor is not None:
            # Keyword-only candidates (not embedded yet, or below the vector cut) get the weakest
            # cosine seen, so a strong lexical match can still surface.
            c = vec.get(i, floor)
            s = W_VEC * c + W_KW * kw
        else:
            c = None
            s = kw
        out.append((i, s, c, kw))
    if exact:
        ids = list(dict.fromkeys(x for x in exact(q) if x in corpus))[:10]
        if ids:  # a query naming an id gets that id first; several keep the order exact() ranks them in
            top = max((s for _, s, _, _ in out), default=0.0)
            bump = (top + 1.0) if floor is not None else 1.0
            pos = {x: n for n, x in enumerate(ids)}   # at most 10, so bump - 0.001 * n stays above 0.99
            seen = {i for i, *_ in out}
            out = [(i, (bump - 0.001 * pos[i] if i in pos else (s if floor is not None else min(s, 0.99))), c, kw_)
                   for i, s, c, kw_ in out]
            out += [(i, bump - 0.001 * pos[i], None, 0.0) for i in ids if i not in seen]
    out.sort(key=lambda x: -x[1])
    return out[:k]


# ------------------------------------------------------------------ built-in searchers
def _cve_exact(q: str) -> list[str]:
    return [m.upper() for m in re.findall(r"CVE-\d{4}-\d{4,}", q, re.I)]


def search_cves(q: str, qvec, k: int) -> list[dict]:
    from .ai import docs
    corpus = docs.cve_docs()
    out = []
    for i, s, c, kw in hybrid("cve", corpus, "cves", q, qvec, k, _cve_exact):
        d = corpus[i]
        out.append({"type": "cve", "id": i, "title": d["title"], "score": round(s, 4), "snippet": d["snippet"],
                    "url": d["url"], "kev": d["payload"]["kev"], "cvss": d["payload"]["cvss"],
                    "events": d["payload"]["events"], "match": {"vector": c, "keyword": round(kw, 3)}})
    try:   # latest FIRST EPSS, read live (it changes daily; the search corpus does not)
        from .sources.vulns import epss_lookup
        sc = epss_lookup([r["id"] for r in out])
        for r in out:
            s = sc.get(str(r["id"]).upper())
            r["epss"], r["epss_percentile"] = (s["epss"], s["percentile"]) if s else (None, None)
    except Exception:
        pass
    return out


def search_events(q: str, qvec, k: int) -> list[dict]:
    from .ai import docs
    corpus = docs.event_docs()
    out = []
    for i, s, c, kw in hybrid("event", corpus, "events", q, qvec, k):
        d = corpus[i]
        p = d["payload"]
        out.append({"type": "event", "id": i, "title": d["title"], "score": round(s, 4), "snippet": d["snippet"],
                    "url": d["url"], "source": p["source"], "kind": p["kind"], "ts": p["ts"],
                    "match": {"vector": c, "keyword": round(kw, 3)}})
    return out


register_searcher("cve", search_cves)
register_searcher("event", search_events)


# ------------------------------------------------------------------ entry point
def query_vector(q: str) -> list[float] | None:
    from .ai import client
    v = client.embed([q], kind="query")  # short read timeout; a hung helper is marked down
    return v[0] if v else None


def semantic(q: str, types: list[str] | None = None, k: int = 10) -> list[dict]:
    q = (q or "").strip()
    if not q:
        return []
    from . import ext
    ext.load_all()  # other packages register their searchers from their ext modules
    wanted = [t for t in (types or DEFAULT_TYPES) if t in SEARCHERS]
    qvec = query_vector(q)
    results: list[dict] = []
    for t in wanted:
        try:
            results += SEARCHERS[t](q, qvec, k)
        except Exception as e:
            log.warning("searcher %s failed: %s", t, e)
    results.sort(key=lambda r: -float(r.get("score") or 0))
    mode = "hybrid" if qvec is not None else "keyword"
    for r in results:
        r.setdefault("mode", mode)
    return results[:k]
