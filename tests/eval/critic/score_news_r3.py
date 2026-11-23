"""Round-3 critic scorer for osinthub/news, HTTP API only (works offline).

usage: python tests/eval/critic/score_news_r3.py [base_url]   (default http://127.0.0.1:8817)
Writes tests/eval/critic/out_news_r3.json.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).parent
BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8817").rstrip("/")


def get(path, **params):
    q = ("?" + urllib.parse.urlencode(params)) if params else ""
    with urllib.request.urlopen(BASE + path + q, timeout=180) as r:
        return json.load(r)


def pairs():
    arts = {a["id"]: a for a in get("/api/news/articles", limit=1000)}
    P = json.load(open(HERE / "news_pairs_r3.json"))["pairs"]
    rows, ok = [], 0
    by_cat: dict[str, list[int]] = {}
    for p in P:
        sa, sb = arts[p["a_id"]]["story_id"], arts[p["b_id"]]["story_id"]
        got = sa is not None and sa == sb
        ok += got == p["same"]
        by_cat.setdefault(p["category"].split("/")[0], []).append(int(got == p["same"]))
        rows.append({"category": p["category"], "label_same": p["same"], "got_same": got, "correct": got == p["same"],
                     "a": p["a_title"][:70], "b": p["b_title"][:70], "story_a": sa, "story_b": sb})
    pos = [r for r in rows if r["label_same"]]
    neg = [r for r in rows if not r["label_same"]]
    return {"accuracy": round(ok / len(P), 3), "n": len(P),
            "same_recall": round(sum(r["correct"] for r in pos) / len(pos), 3),
            "diff_specificity": round(sum(r["correct"] for r in neg) / len(neg), 3),
            "by_category": {k: f"{sum(v)}/{len(v)}" for k, v in by_cat.items()},
            "misses": [r for r in rows if not r["correct"]]}


def queries():
    Q = json.load(open(HERE / "news_queries_r3.json"))["queries"]
    out = {}
    for mode in ("hybrid", "keyword"):
        tot, hit, miss = 0.0, 0, []
        for q in Q:
            res = get("/api/news/search", q=q["q"], k=5, mode=mode)["results"][:5]
            ids = [r.get("id") for r in res]
            exp = q["expected_ids"]
            r5 = sum(e in ids for e in exp) / min(len(exp), 5)
            tot += r5
            hit += any(e in ids for e in exp)
            if r5 < 1:
                rank = None
                full = get("/api/news/search", q=q["q"], k=50, mode=mode)["results"]
                fids = [r.get("id") for r in full]
                rank = [fids.index(e) + 1 if e in fids else None for e in exp]
                miss.append({"q": q["q"], "recall": r5, "rank_of_expected": rank,
                             "top5": [r.get("title", "")[:60] for r in res]})
        out[mode] = {"recall@5": round(tot / len(Q), 3), "hit@5": round(hit / len(Q), 3), "misses": miss}
    return out


def ioc_and_offsets(story_ids):
    """IoC table per story, and offset check for every IOC entity on every article: the span must
    refang to the value."""
    def refang(s):
        s = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\s\[?dot\]?\s", ".", s, flags=re.I)
        return re.sub(r"^h(xx|XX)p", "http", s.replace("[:]", ":"))
    stories, off_bad, off_n, defanged_spans, missed_defanged = [], [], 0, 0, []
    for sid in story_ids:
        d = get("/api/news/stories/" + urllib.parse.quote(sid, safe=":"))
        stories.append({"story": sid, "title": d["title"][:70], "n_iocs": len(d["iocs"]),
                        "iocs": [(i["type"], i["value"], i["articles"]) for i in d["iocs"]],
                        "cves": [{k: c[k] for k in ("id", "cvss", "cvss_status", "kev", "kev_added", "epss_status")} for c in d["cves"]]})
        for a in d["articles"]:
            ad = get("/api/news/articles/" + a["id"], similar=0)
            text = ad.get("text") or ""
            for e in ad["entities"]:
                if e["type"] not in ("ip", "domain", "url", "sha256", "sha1", "md5", "cve", "email"):
                    continue
                val = e["id"].split(":", 1)[-1]
                for s, t in e.get("offsets") or []:
                    off_n += 1
                    span = text[s:t]
                    if span != refang(span):
                        defanged_spans += 1
                    if refang(span).lower() != val.lower() and not any(refang(span).lower() == (x or "").lower()
                                                                       for x in [e.get("name"), *(e.get("aliases") or [])]):
                        off_bad.append({"article": a["id"], "entity": e["id"], "span": span})
                if not e.get("offsets"):
                    missed_defanged.append({"article": a["id"], "entity": e["id"]})
    return {"stories": stories, "offsets_checked": off_n, "defanged_spans": defanged_spans,
            "offset_mismatches": off_bad[:30], "entities_without_offsets": missed_defanged[:30],
            "n_entities_without_offsets": len(missed_defanged)}


if __name__ == "__main__":
    out = {"pairs": pairs(), "queries": queries()}
    ids = sys.argv[2].split(",") if len(sys.argv) > 2 else []
    if ids:
        out["ioc"] = ioc_and_offsets(ids)
    (HERE / "out_news_r3.json").write_text(json.dumps(out, indent=1, default=str))
    print(json.dumps({"pairs": {k: out["pairs"][k] for k in ("accuracy", "same_recall", "diff_specificity", "by_category")},
                      "hybrid": out["queries"]["hybrid"]["recall@5"], "keyword": out["queries"]["keyword"]["recall@5"]}, indent=1))
