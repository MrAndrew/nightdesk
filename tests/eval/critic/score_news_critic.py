"""Critic scoring of the news backend on independent labels (news_pairs_critic.json, news_queries_critic.json).

    uv run python tests/eval/critic/score_news_critic.py --base http://127.0.0.1:8813
Uses only the HTTP API.
"""
import argparse, json
from pathlib import Path
import httpx

HERE = Path(__file__).resolve().parent

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--base", default="http://127.0.0.1:8813")
    args = ap.parse_args()
    c = httpx.Client(base_url=args.base, timeout=120)
    arts = c.get("/api/news/articles", params={"limit": 1000}).json()
    by_url = {a["url"]: a for a in arts}
    pairs = json.loads((HERE / "news_pairs_critic.json").read_text())["pairs"]
    ok, misses = 0, []
    for p in pairs:
        a, b = by_url[p["a"]], by_url[p["b"]]
        pred = a["story_id"] == b["story_id"]
        if pred == p["same"]:
            ok += 1
        else:
            misses.append({"label_same": p["same"], "why": p["why"], "a": a["title"], "b": b["title"]})
    same = [p for p in pairs if p["same"]]
    print(f"pair accuracy {ok}/{len(pairs)} = {ok/len(pairs):.3f}")
    for m in misses: print("  MISS", json.dumps(m))
    qs = json.loads((HERE / "news_queries_critic.json").read_text())["queries"]
    res = {}
    for mode in ("hybrid", "keyword"):
        tot, rows = 0.0, []
        for q in qs:
            r = c.get("/api/news/search", params={"q": q["q"], "k": 5, "mode": mode}).json()
            top = [x["url"] for x in r["results"][:5]]
            exp = set(q["expected"])
            rec = len(exp & set(top)) / min(len(exp), 5)
            tot += rec
            rows.append((round(rec, 2), r["mode"], q["q"], [x["title"][:60] for x in r["results"][:5]] if rec < 1 else []))
        res[mode] = tot / len(qs)
        print(f"recall@5 {mode}: {tot/len(qs):.3f}")
        for row in rows:
            if row[0] < 1: print("  ", row)
    (HERE / "out_news_critic.json").write_text(json.dumps({"pair_acc": ok/len(pairs), "misses": misses, "recall5": res}, indent=1))

main()
