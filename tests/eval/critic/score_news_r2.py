"""Round-2 critic scorer for osinthub/news, HTTP API only (works offline).

usage: python tests/eval/critic/score_news_r2.py [base_url]   (default http://127.0.0.1:8815)
Writes tests/eval/critic/out_news_r2.json.
"""
from __future__ import annotations

import json
import pathlib
import sys
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).parent
BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8815").rstrip("/")
C_OUTLETS = {"The Hacker News", "Help Net Security"}


def get(path, **params):
    q = ("?" + urllib.parse.urlencode(params)) if params else ""
    with urllib.request.urlopen(BASE + path + q, timeout=120) as r:
        return json.load(r)


def pairs():
    arts = {a["id"]: a for a in get("/api/news/articles", limit=1000)}
    P = json.load(open(HERE / "news_pairs_r2.json"))["pairs"]
    rows, ok = [], 0
    for p in P:
        sa, sb = arts[p["a_id"]]["story_id"], arts[p["b_id"]]["story_id"]
        got = sa is not None and sa == sb
        ok += got == p["same"]
        rows.append({"category": p["category"], "label_same": p["same"], "got_same": got, "correct": got == p["same"],
                     "a": p["a_title"][:70], "b": p["b_title"][:70], "story_a": sa, "story_b": sb})
    return {"accuracy": round(ok / len(P), 3), "n": len(P), "misses": [r for r in rows if not r["correct"]]}


def queries():
    Q = json.load(open(HERE / "news_queries_r2.json"))["queries"]
    out = {}
    for mode in ("hybrid", "keyword"):
        tot, miss = 0.0, []
        for q in Q:
            res = get("/api/news/search", q=q["q"], k=5, mode=mode)["results"][:5]
            ids = [r.get("id") for r in res]
            exp = q["expected_ids"]
            r5 = sum(e in ids for e in exp) / min(len(exp), 5)
            tot += r5
            if r5 < 1:
                miss.append({"q": q["q"], "recall": r5, "top5": [r.get("title", "")[:60] for r in res]})
        out[mode] = {"recall@5": round(tot / len(Q), 3), "misses": miss}
    # collapse=story: one result per story
    bad = []
    for q in Q:
        res = get("/api/news/search", q=q["q"], k=10, collapse="story")["results"]
        sids = [r.get("story_id") for r in res if r.get("story_id")]
        if len(sids) != len(set(sids)) or any("story_hits" not in r for r in res):
            bad.append(q["q"])
    out["collapse_story_violations"] = bad
    return out


def corroboration():
    stories = get("/api/news/stories", limit=500, min_articles=2)["stories"]
    issues, checked = [], 0
    for s in stories:
        d = get("/api/news/stories/" + urllib.parse.quote(s["id"], safe=":"))
        arts = d["articles"]
        orig = [a for a in arts if not a["dup_of"]]
        outlets = {a["source"]: a["tier"] for a in orig}
        exp_tc: dict[str, int] = {}
        for t in outlets.values():
            exp_tc[t] = exp_tc.get(t, 0) + 1
        checked += 1
        tc = d.get("tier_counts") or {}
        if d["source_count"] != len(outlets) or {k: v for k, v in tc.items() if v} != exp_tc:
            issues.append({"story": s["id"], "title": d["title"][:60], "source_count": d["source_count"],
                           "expected_sources": len(outlets), "tier_counts": tc, "expected_tier_counts": exp_tc})
        # copies across outlets: a dup from another outlet must not add an outlet
        for a in arts:
            if a["dup_of"] and a["source"] not in outlets and a["source"] in (d.get("sources") or []):
                issues.append({"story": s["id"], "copy_counted": a["id"], "source": a["source"]})
    arts = get("/api/news/articles", limit=1000)
    tier_bad = [{"id": a["id"], "source": a["source"], "tier": a["tier"], "title": a["title"][:60]} for a in arts
                if (a["source"] in C_OUTLETS) != (a["tier"] == "C")]
    a_tier = [{"id": a["id"], "source": a["source"], "title": a["title"][:80]} for a in arts if a["tier"] == "A"]
    return {"stories_checked": checked, "count_issues": issues, "tier_vs_outlet_mismatch": tier_bad, "tier_A": a_tier}


def api_readiness(sample_articles, sample_stories):
    rep = {"offsets": [], "timeline": [], "iocs": [], "cves": [], "similar": []}
    for aid in sample_articles:
        a = get(f"/api/news/articles/{aid}", similar=8)
        text = a.get("text") or ""
        n_ent, n_off, bad = len(a["entities"]), 0, []
        for e in a["entities"]:
            names = {x.lower() for x in [e.get("name"), e["id"].split(":", 1)[-1], *(e.get("aliases") or [])] if x}
            for s, t in e.get("offsets") or []:
                n_off += 1
                if text[s:t].lower() not in names:
                    bad.append((e["id"], text[s:t]))
            if not e.get("offsets"):
                bad.append((e["id"], "NO OFFSETS"))
        rep["offsets"].append({"article": aid, "entities": n_ent, "offsets": n_off, "bad": bad[:8], "n_bad": len(bad)})
        sim = a.get("similar") or {}
        own = a.get("story_id")
        leak = [r["id"] for r in sim.get("results", []) if r.get("story_id") == own]
        rep["similar"].append({"article": aid, "method": sim.get("method"), "n": len(sim.get("results", [])), "same_story_leaks": leak,
                               "top": [r["title"][:50] for r in sim.get("results", [])[:3]]})
        for c in a.get("cves") or []:
            rep["cves"].append({k: c.get(k) for k in ("id", "cvss", "severity", "kev", "kev_added", "epss", "published")})
    for sid in sample_stories:
        d = get("/api/news/stories/" + urllib.parse.quote(sid, safe=":"))
        tl = d.get("timeline") or []
        ts = [x["ts"] for x in tl]
        rep["timeline"].append({"story": sid, "n": len(tl), "sorted": ts == sorted(ts), "kinds": [x["kind"] for x in tl],
                                "articles": d["article_count"]})
        rep["iocs"].append({"story": sid, "n": len(d.get("iocs") or []),
                            "types": sorted({i["type"] for i in d.get("iocs") or []}),
                            "sample": [i["value"] for i in (d.get("iocs") or [])[:6]]})
    return rep


if __name__ == "__main__":
    res = {"pairs": pairs(), "search": queries(), "corroboration": corroboration()}
    sa = sys.argv[2].split(",") if len(sys.argv) > 2 else []
    ss = sys.argv[3].split(",") if len(sys.argv) > 3 else []
    if sa or ss:
        res["api"] = api_readiness(sa, ss)
    (HERE / "out_news_r2.json").write_text(json.dumps(res, indent=1, default=str))
    print(json.dumps({"pair_accuracy": res["pairs"]["accuracy"], "hybrid": res["search"]["hybrid"]["recall@5"],
                      "keyword": res["search"]["keyword"]["recall@5"],
                      "count_issues": len(res["corroboration"]["count_issues"]),
                      "tier_mismatch": len(res["corroboration"]["tier_vs_outlet_mismatch"])}))
