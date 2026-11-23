"""Article search: hybrid vector + keyword, grouped per article. Method: okf/data/news.md#search

* Keyword: BM25 over article chunks (plus title + feed summary for articles not fetched yet),
  built in memory from DuckDB and rebuilt when articles change. Works offline with no AI helper.
* Vector: the query embedding against the `articles` chunk collection in osinthub.vectors.
* Fusion: cosine of the best chunk + 0.25 x normalised BM25 (as osinthub/search.py), with
  the best chunk as the snippet. Keyword-only when no embeddings are available.
* Filters: since / until (published), sources (outlet label or source id), tiers.
"""
from __future__ import annotations

import datetime as dt
import math
import re
import threading
from collections import Counter, defaultdict

from .. import db
from .common import embed, ensure_schema, log, vectors
from .pipeline import COLLECTION

_TOK = re.compile(r"[a-z0-9][a-z0-9\-\.]*[a-z0-9]|[a-z0-9]")
STOP = set("a an the and or of to in on for with by at from as is are was were be been it its this that which who what "
           "when where how not but if than so into over about after before new says said has have had will can may".split())
K1, B = 1.4, 0.72

_lock = threading.Lock()
_index: dict | None = None
_index_key = None


def toks(text: str) -> list[str]:
    out = []
    for t in _TOK.findall((text or "").lower()):
        t = t.strip(".-")
        if t and t not in STOP:
            out.append(t)
            if "-" in t and not t.startswith("cve-"):
                out.extend(p for p in t.split("-") if p and p not in STOP)
    return out


def _key():
    r = db.query("SELECT count(*) n, max(fetched_at) f, max(queued_at) q, count(chunks) c FROM articles")[0]
    return (r["n"], r["f"], r["q"], r["c"])


def _build() -> dict:
    docs: list[tuple[str, int, str]] = []
    for r in db.query("SELECT article_id, idx, text FROM article_chunks"):
        docs.append((r["article_id"], r["idx"], r["text"]))
    have = {d[0] for d in docs}
    for r in db.query("SELECT id, title, dek FROM articles WHERE status IS DISTINCT FROM 'skipped'"):
        if r["id"] not in have and (r["title"] or r["dek"]):
            docs.append((r["id"], -1, f"{r['title'] or ''}\n{r['dek'] or ''}"))
    titles = {r["id"]: r["title"] or "" for r in db.query("SELECT id, title FROM articles")}
    tfs, lens, df = [], [], Counter()
    for aid, _idx, text in docs:
        # The title is repeated in every chunk; count it once more so headline matches weigh more.
        c = Counter(toks(text) + toks(titles.get(aid, "")))
        tfs.append(c)
        lens.append(sum(c.values()))
        df.update(c.keys())
    n = max(1, len(docs))
    postings: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for i, c in enumerate(tfs):
        for t, f in c.items():
            postings[t].append((i, f))
    return {"docs": docs, "lens": lens, "avg": (sum(lens) / n) if lens else 1.0, "n": n,
            "idf": {t: math.log(1 + (n - d + 0.5) / (d + 0.5)) for t, d in df.items()}, "post": postings}


def index() -> dict:
    global _index, _index_key
    k = _key()
    with _lock:
        if _index is None or k != _index_key:
            _index = _build()
            _index_key = k
        return _index


def keyword(q: str, k: int = 100) -> list[tuple[str, int, float]]:
    """BM25 per chunk -> best chunk per article. Returns [(article_id, chunk_idx, score)]."""
    ix = index()
    qt = toks(q)
    if not qt:
        return []
    scores: dict[int, float] = defaultdict(float)
    for t in set(qt):
        idf = ix["idf"].get(t)
        if idf is None:
            continue
        for i, f in ix["post"][t]:
            dl = ix["lens"][i]
            scores[i] += idf * f * (K1 + 1) / (f + K1 * (1 - B + B * dl / ix["avg"]))
    # exact phrase bonus (e.g. "Salt Typhoon", CVE ids)
    phrase = " ".join(qt)
    best: dict[str, tuple[int, float]] = {}
    for i, s in scores.items():
        aid, idx, text = ix["docs"][i]
        if len(qt) > 1 and phrase in " ".join(toks(text)):
            s *= 1.25
        if aid not in best or s > best[aid][1]:
            best[aid] = (idx, s)
    ranked = sorted(best.items(), key=lambda x: -x[1][1])[:k]
    return [(aid, idx, s) for aid, (idx, s) in ranked]


def vector(q: str, k: int = 100, qvec: list[float] | None = None) -> list[tuple[str, int, float]] | None:
    vec = vectors()
    if vec is None:
        return None
    if qvec is None:
        qv = embed([q], kind="query")
        if not qv:
            return None
        qvec = qv[0]
    try:
        hits = vec.search(COLLECTION, qvec, k * 3)
    except Exception as e:
        log.debug("vector search failed: %s", e)
        return None
    best: dict[str, tuple[int, float]] = {}
    for h in hits or []:
        p = h.get("payload") or {}
        aid = p.get("article_id")
        if not aid:
            continue
        s = float(h.get("score") or 0)
        if aid not in best or s > best[aid][1]:
            best[aid] = (int(p.get("chunk") or 0), s)
    ranked = sorted(best.items(), key=lambda x: -x[1][1])[:k]
    return [(aid, idx, s) for aid, (idx, s) in ranked]


def _snippet(text: str, q: str, n: int = 320) -> str:
    body = text.split("\n", 1)[1] if "\n" in text else text  # drop the title prefix
    body = " ".join(body.split())
    qt = [t for t in toks(q) if len(t) > 2]
    low = body.lower()
    pos = min((low.find(t) for t in qt if low.find(t) >= 0), default=0)
    start = max(0, pos - n // 3)
    s = body[start:start + n]
    return ("…" if start else "") + s + ("…" if start + n < len(body) else "")


def _filters(rows: dict[str, dict], since=None, until=None, sources=None, tiers=None) -> set[str]:
    keep = set()
    srcs = {s.lower() for s in sources or []}
    tiers_u = {t.upper() for t in tiers or []}
    for aid, r in rows.items():
        p = r["published"] or r["queued_at"]
        if since and p and p < since:
            continue
        if until and p and p > until:
            continue
        if srcs and (r["source"] or "").lower() not in srcs and (r["source_id"] or "").lower() not in srcs:
            continue
        if tiers_u and (r["tier"] or "") not in tiers_u:
            continue
        keep.add(aid)
    return keep


def _ts(v) -> dt.datetime | None:
    if v is None or v == "":
        return None
    if isinstance(v, dt.datetime):
        return v if v.tzinfo else v.replace(tzinfo=dt.UTC)
    s = str(v).strip()
    if re.fullmatch(r"\d+(\.\d+)?[hd]", s):
        n = float(s[:-1])
        try:
            return dt.datetime.now(dt.UTC) - (dt.timedelta(hours=n) if s.endswith("h") else dt.timedelta(days=n))
        except OverflowError:  # before year 1: a ValueError, so the API answers 400 "bad time"
            raise ValueError(f"relative time too large: {s}") from None
    d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=dt.UTC)


from ..search import W_KW, W_VEC  # noqa: E402  same fusion as osinthub/search.py, so article scores compare with cve/event ones

MODES = ("hybrid", "keyword", "vector")


def search(q: str, k: int = 10, since=None, until=None, sources=None, tiers=None, mode: str = "hybrid",
           qvec: list[float] | None = None, collapse: str | None = None) -> dict:
    """Hybrid article search. Returns {"mode", "requested_mode", "fallback", "collapse", "results"}.

    `mode` is the search that actually ran. When vectors are unavailable (AI helper down, no vector
    store) a `vector` or `hybrid` request runs as `keyword` and `fallback` says why; an unknown mode
    raises ValueError.

    Score = W_VEC * cosine of the best chunk + W_KW * keyword (keyword-only hits get the weakest
    cosine seen minus 0.02). Without embeddings the score is the keyword score. keyword is on the
    absolute 0..1 scale of osinthub/keyword.py: BM25 / the BM25 of an ideal chunk holding every
    query term once, squashed as x / (x + 0.5), so it compares across types.
    """
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}: use one of {', '.join(MODES)}")
    if collapse not in (None, "", "story"):
        raise ValueError(f"unknown collapse {collapse!r}: use 'story' or leave it out")
    collapse = collapse or None
    ensure_schema()
    since, until = _ts(since), _ts(until)
    vh = vector(q, 200, qvec) if mode in ("hybrid", "vector") else None
    fallback = None
    if mode != "keyword" and vh is None:
        # No embeddings to search with: answer from keywords and say so, rather than return nothing.
        used, fallback = "keyword", "vector search unavailable (AI helper or vector store down); keyword results"
    else:
        used = mode
    kw = keyword(q, 200) if used in ("hybrid", "keyword") else []
    head = {"mode": used, "requested_mode": mode, "fallback": fallback, "collapse": collapse}
    ids = {a for a, _, _ in kw} | {a for a, _, _ in (vh or [])}
    if not ids:
        return {**head, "results": []}
    rows = {r["id"]: r for r in db.query(f"""SELECT id, url, source, source_id, tier, title, published, queued_at, story_id, status, dek
                                             FROM articles WHERE id IN ({','.join('?' * len(ids))})""", list(ids))}
    keep = _filters(rows, since, until, sources, tiers)
    vec_s = {aid: (idx, sc) for aid, idx, sc in (vh or []) if aid in keep}
    kw_kept = [x for x in kw if x[0] in keep]
    ix = index()
    ideal = sum(ix["idf"].get(t, math.log(1 + (ix["n"] + 0.5) / 0.5)) for t in set(toks(q))) or 1.0
    kw_s = {aid: (idx, (sc / ideal) / (sc / ideal + 0.5)) for aid, idx, sc in kw_kept}
    floor = (min(v[1] for v in vec_s.values()) - 0.02) if vec_s else 0.0
    fused: dict[str, float] = {}
    best_chunk: dict[str, int] = {}
    for aid in set(vec_s) | set(kw_s):
        kn = kw_s.get(aid, (None, 0.0))[1]
        if vec_s:
            fused[aid] = W_VEC * vec_s.get(aid, (None, floor))[1] + W_KW * kn
        else:
            fused[aid] = kn
        best_chunk[aid] = vec_s[aid][0] if aid in vec_s else kw_s[aid][0]
    ranked = sorted(fused.items(), key=lambda x: -x[1])
    hits_per_story: dict[str, int] = {}
    if collapse == "story":
        kept, seen = [], set()
        for aid, sc_ in ranked:
            sk = rows[aid]["story_id"] or aid
            hits_per_story[sk] = hits_per_story.get(sk, 0) + 1
            if sk not in seen:
                seen.add(sk)
                kept.append((aid, sc_))
        ranked = kept
    ranked = ranked[:k]
    chunks = {}
    if ranked:
        want = {(a, best_chunk[a]) for a, _ in ranked}
        for r in db.query(f"""SELECT article_id, idx, text FROM article_chunks WHERE article_id IN
                              ({','.join('?' * len(ranked))})""", [a for a, _ in ranked]):
            if (r["article_id"], r["idx"]) in want:
                chunks[(r["article_id"], r["idx"])] = r["text"]
    out = []
    for aid, s in ranked:
        r = rows[aid]
        idx = best_chunk[aid]
        text = chunks.get((aid, idx)) or f"{r['title']}\n{r['dek'] or ''}"
        out.append({"type": "article", "id": aid, "title": r["title"], "score": round(s, 4), "snippet": _snippet(text, q),
                    "url": r["url"], "source": r["source"], "tier": r["tier"], "story_id": r["story_id"],
                    "published": r["published"].isoformat() if r["published"] else None, "chunk": idx, "status": r["status"],
                    **({"story_hits": hits_per_story.get(r["story_id"] or aid, 1)} if collapse == "story" else {})})
    return {**head, "results": out}


def searcher(q: str, qvec: list[float] | None = None, k: int = 10) -> list[dict]:
    """osinthub.search searcher contract: fn(q, qvec, k) -> [{type, id, title, score, snippet, url, ...}]."""
    return search(q, k=k, mode="hybrid" if qvec is not None else "keyword", qvec=qvec)["results"]
