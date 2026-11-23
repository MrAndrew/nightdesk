"""Score the news pipeline against a running Night Desk. Method: okf/data/news.md#measurement

    OSINTHUB_LAKE=<scratch lake> OSINTHUB_PORT=8802 OSINTHUB_OFFLINE=1 uv run python -m osinthub &
    uv run python tests/eval/score_news.py --base http://127.0.0.1:8802

Uses only the HTTP API, so it runs offline against already-fetched data. Measures:

1. Fetch success rate per source (ok / attempted; queued articles are not counted).
2. Extraction quality on 20 sampled articles: headline equals the feed headline, published date
   matches the date in the page (JSON-LD / meta, within 1 day), no boilerplate phrases in the
   text. The sample is written to tests/eval/out/news_extraction_sample.json for a critic.
3. Story clustering pair accuracy on tests/eval/news_pairs.json (labelled same / different event).
   Target >= 0.9.
4. Search recall@5 on tests/eval/news_queries.json (15 queries with expected article URLs).
   Target >= 0.85.
"""
from __future__ import annotations

import argparse
import html as _h
import datetime as dt
import gzip
import json
import os
import random
import re
import sys
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"

BOILERPLATE = [
    r"\bsubscribe to (our|the) newsletter\b", r"\bsign up for (our|the)\b.*newsletter", r"\ball rights reserved\b",
    r"\bcookie (policy|settings|preferences)\b", r"\bshare (this|on) (article|facebook|twitter|linkedin)\b",
    r"\brelated (articles|posts|stories)\s*:?\s*$", r"\bread more:?\s*$", r"\bfollow us on\b", r"\bprivacy policy\b",
    r"\bterms of (use|service)\b", r"\badvertisement\b", r"\bskip to (main )?content\b", r"\bleave a (reply|comment)\b",
    r"\bthe post .* appeared first on\b", r"\bnewsletter\b.*\bemail address\b", r"\btrending\s*:?\s*$",
]


def norm(s: str) -> str:
    s = re.sub(r"[‘’“”]", "'", s or "")
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def page_date(lake: Path | None, html_path: str | None) -> str | None:
    """Published date stated in the stored page (JSON-LD datePublished or article:published_time)."""
    if not lake or not html_path:
        return None
    p = lake / html_path
    if not p.exists():
        return None
    html = gzip.decompress(p.read_bytes()).decode("utf-8", "replace")
    for rx in (r'"datePublished"\s*:\s*"([^"]+)"', r'property=["\']article:published_time["\'][^>]*content=["\']([^"\']+)',
               r'content=["\']([^"\']+)["\'][^>]*property=["\']article:published_time', r'<time[^>]+datetime=["\']([^"\']+)'):
        m = re.search(rx, html)
        if m:
            return m.group(1)
    return None


def to_date(s: str | None) -> dt.date | None:
    if not s:
        return None
    try:
        d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return (d.astimezone(dt.UTC) if d.tzinfo else d).date()
    except ValueError:
        m = re.match(r"(\d{4}-\d{2}-\d{2})", s)
        return dt.date.fromisoformat(m.group(1)) if m else None


def fetch_rates(c: httpx.Client) -> dict:
    st = c.get("/api/news/sources").json()
    rates = {}
    for o in st["outlets"]:
        attempted = o["ok"] + o["blocked"] + o["failed"] + o["skipped"]
        rates[o["source"] or "?"] = {"ok": o["ok"], "attempted": attempted, "blocked": o["blocked"], "failed": o["failed"],
                                     "queued": o["queued"], "rate": round(o["ok"] / attempted, 3) if attempted else None}
    tot_ok = sum(r["ok"] for r in rates.values())
    tot = sum(r["attempted"] for r in rates.values())
    return {"per_source": rates, "overall": round(tot_ok / tot, 3) if tot else None, "reasons": st["reasons"][:15]}


def extraction(c: httpx.Client, lake: Path | None, n: int = 20, seed: int = 7) -> dict:
    arts = c.get("/api/news/articles", params={"status": "ok", "limit": 1000}).json()
    by_src: dict[str, list] = {}
    for a in arts:
        by_src.setdefault(a["source"], []).append(a)
    rng = random.Random(seed)
    sample, srcs = [], sorted(by_src)
    for lst in by_src.values():
        rng.shuffle(lst)
    while len(sample) < n and any(by_src.values()):   # round-robin across outlets
        for s in srcs:
            if by_src[s] and len(sample) < n:
                sample.append(by_src[s].pop())
    rows, ok_title, ok_date, ok_clean = [], 0, 0, 0
    for a in sample:
        d = c.get(f"/api/news/articles/{a['id']}", params={"similar": 0}).json()
        text = d["text"] or ""
        feed_title = d["title"]
        # The title the pipeline stores is the feed's; check the page itself states the same headline.
        page_t = None
        if lake and d.get("html_path"):
            html = gzip.decompress((lake / d["html_path"]).read_bytes()).decode("utf-8", "replace")
            cands = [m.group(1) for rx in (r'property=["\']og:title["\'][^>]*content="([^"]+)"', r"property=['\"]og:title['\"][^>]*content='([^']+)'",
                                           r"<title[^>]*>(.*?)</title>", r"<h1[^>]*>(.*?)</h1>") for m in [re.search(rx, html, re.S | re.I)] if m]
            page_ts = [_h.unescape(re.sub(r"<[^>]+>", "", re.sub(r"\s+", " ", c))).strip() for c in cands]
            page_t = " || ".join(page_ts)
        else:
            page_ts = []
        # The stored headline must be the page's own headline (og:title, <title> or the <h1>).
        title_ok = bool(feed_title) and (not page_ts or any(norm(feed_title) == norm(t) or (len(norm(t)) > 20 and norm(t) in norm(feed_title))
                                                            or norm(feed_title) in norm(t) for t in page_ts))
        pd = page_date(lake, d.get("html_path"))
        date_ok = (pd is None and d.get("published") is not None) or (
            to_date(pd) is not None and to_date(d.get("published")) is not None and abs((to_date(pd) - to_date(d["published"])).days) <= 1)
        # Boilerplate shows up as short standalone lines ("Privacy Policy", "Follow us on X"); the same
        # words inside a sentence of the story are not boilerplate.
        short = "\n".join(l for l in text.splitlines() if len(l) < 100)
        hits = [rx for rx in BOILERPLATE if re.search(rx, short, re.I | re.M)]
        clean = not hits and len(text) >= 400
        ok_title += title_ok; ok_date += date_ok; ok_clean += clean
        rows.append({"id": d["id"], "source": d["source"], "url": d["url"], "title": feed_title, "page_title": page_t,
                     "published": d.get("published"), "page_date": pd, "author": d.get("author"), "lang": d.get("lang"),
                     "chars": len(text), "links": len(d.get("links") or []), "boilerplate_hits": hits,
                     "title_ok": title_ok, "date_ok": date_ok, "clean": clean,
                     "text_head": text[:400], "text_tail": text[-400:]})
    OUT.mkdir(exist_ok=True)
    (OUT / "news_extraction_sample.json").write_text(json.dumps(rows, indent=1, ensure_ascii=False))
    k = max(1, len(rows))
    return {"n": len(rows), "title_ok": round(ok_title / k, 3), "date_ok": round(ok_date / k, 3), "no_boilerplate": round(ok_clean / k, 3),
            "failures": [{"url": r["url"], "title_ok": r["title_ok"], "date_ok": r["date_ok"], "boilerplate": r["boilerplate_hits"],
                          "chars": r["chars"]} for r in rows if not (r["title_ok"] and r["date_ok"] and r["clean"])]}


def _by_url(c: httpx.Client) -> dict[str, dict]:
    arts = c.get("/api/news/articles", params={"limit": 1000}).json()
    out = {}
    from urllib.parse import urlsplit
    for a in arts:
        u = urlsplit(a["url"])
        out[(u.netloc.removeprefix("www.") + u.path.rstrip("/")).lower()] = a
    return out


def _key(url: str) -> str:
    from urllib.parse import urlsplit
    u = urlsplit(url)
    return (u.netloc.removeprefix("www.") + u.path.rstrip("/")).lower()


def clustering(c: httpx.Client) -> dict:
    pairs = json.loads((HERE / "news_pairs.json").read_text())["pairs"]
    idx = _by_url(c)
    right, missing, wrong = 0, [], []
    for p in pairs:
        a, b = idx.get(_key(p["a"])), idx.get(_key(p["b"]))
        if not a or not b:
            missing.append(p)
            continue
        # Sponsored posts and press releases have no story: they are their own event.
        pred = a["story_id"] is not None and a["story_id"] == b["story_id"]
        if pred == p["same"]:
            right += 1
        else:
            wrong.append({"a": a["title"], "b": b["title"], "label_same": p["same"], "pred_same": pred})
    scored = len(pairs) - len(missing)
    return {"pairs": len(pairs), "scored": scored, "accuracy": round(right / scored, 3) if scored else None,
            "same_pairs": sum(p["same"] for p in pairs), "wrong": wrong, "missing": [m["a"] for m in missing]}


def search(c: httpx.Client, k: int = 5) -> dict:
    qs = json.loads((HERE / "news_queries.json").read_text())["queries"]
    recalls, misses, modes = [], [], set()
    for q in qs:
        res = c.get("/api/news/search", params={"q": q["q"], "k": k}).json()
        modes.add(res["mode"])
        got = {_key(r["url"]) for r in res["results"]}
        exp = {_key(u) for u in q["expected"]}
        r = len(exp & got) / len(exp)
        recalls.append(r)
        if r < 1:
            misses.append({"q": q["q"], "recall": round(r, 2), "top": [x["title"] for x in res["results"][:k]]})
    return {"queries": len(qs), "recall_at_5": round(sum(recalls) / len(recalls), 3), "modes": sorted(modes), "misses": misses}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=f"http://127.0.0.1:{os.environ.get('OSINTHUB_PORT', '8802')}")
    ap.add_argument("--lake", default=os.environ.get("OSINTHUB_LAKE"), help="lake dir, to read stored HTML for date/title checks")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    lake = Path(a.lake) if a.lake else None
    with httpx.Client(base_url=a.base, timeout=120, trust_env=False) as c:
        res = {"fetch": fetch_rates(c), "extraction": extraction(c, lake), "clustering": clustering(c), "search": search(c)}
    res["pass"] = {"clustering_ge_0.9": (res["clustering"]["accuracy"] or 0) >= 0.9,
                   "search_recall5_ge_0.85": res["search"]["recall_at_5"] >= 0.85}
    if a.json:
        print(json.dumps(res, indent=1, default=str))
    else:
        f = res["fetch"]
        print(f"fetch success overall {f['overall']}")
        for s, r in sorted(f["per_source"].items()):
            print(f"  {s:32} {r['ok']:>4}/{r['attempted']:<4} rate {r['rate']}  blocked {r['blocked']} failed {r['failed']} queued {r['queued']}")
        e = res["extraction"]
        print(f"extraction n={e['n']} title_ok={e['title_ok']} date_ok={e['date_ok']} no_boilerplate={e['no_boilerplate']}")
        for x in e["failures"]:
            print("   ", x)
        cl = res["clustering"]
        print(f"clustering pair accuracy {cl['accuracy']} on {cl['scored']}/{cl['pairs']} pairs ({cl['same_pairs']} same)")
        for x in cl["wrong"]:
            print("   ", x)
        s = res["search"]
        print(f"search recall@5 {s['recall_at_5']} over {s['queries']} queries (mode {', '.join(s['modes'])})")
        for x in s["misses"]:
            print("   ", x)
        print("pass:", res["pass"])
    return 0 if all(res["pass"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
