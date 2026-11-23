#!/usr/bin/env python3
"""Score CVE semantic search against tests/eval/cve_queries.jsonl.

Calls GET {base}/api/search/semantic?q=...&types=cve&k=5 for each question and
computes recall@5 and top-1 accuracy.  Pass: recall@5 >= 0.90 and top1 >= 0.70.

    uv run python tests/eval/score_cve_search.py --base http://127.0.0.1:8801

Stdlib only.  Gold data is owned by the eval author; builders must not edit it.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
RECALL_BAR = 0.90
TOP1_BAR = 0.70


def result_cve(item: dict) -> str | None:
    """CVE id of one search hit. Look at id, then title, then url (never the
    snippet, which may cite other CVEs)."""
    for key in ("id", "title", "url"):
        v = item.get(key)
        if isinstance(v, str):
            m = CVE_RE.search(v)
            if m:
                return m.group(0).upper()
    return None


def query(base: str, q: str, k: int, timeout: float) -> list[dict]:
    url = f"{base.rstrip('/')}/api/search/semantic?" + urllib.parse.urlencode(
        {"q": q, "types": "cve", "k": k})
    with urllib.request.urlopen(url, timeout=timeout) as r:
        data = json.loads(r.read().decode("utf-8"))
    if isinstance(data, dict):  # tolerate {"results": [...]} wrappers
        data = data.get("results") or data.get("items") or []
    return data if isinstance(data, list) else []


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://127.0.0.1:8787", help="server base URL")
    ap.add_argument("--queries", default=str(HERE / "cve_queries.jsonl"))
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("-v", "--verbose", action="store_true", help="print every query")
    args = ap.parse_args()

    qs = [json.loads(l) for l in Path(args.queries).read_text().splitlines() if l.strip()]
    n = len(qs)
    hit5 = top1 = errors = 0
    by_diff: dict[str, list[int]] = {}
    lat: list[float] = []
    misses = []
    for item in qs:
        ok = {item["answer"].upper(), *(a.upper() for a in item.get("also_accept", []))}
        t0 = time.perf_counter()
        try:
            res = query(args.base, item["q"], args.k, args.timeout)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
            errors += 1
            res = []
            print(f"  ERROR {item['id']}: {e}", file=sys.stderr)
        lat.append(time.perf_counter() - t0)
        got = [result_cve(r) for r in res[: args.k]]
        h5 = any(g in ok for g in got)
        h1 = bool(got) and got[0] in ok
        hit5 += h5
        top1 += h1
        d = by_diff.setdefault(item.get("difficulty", "?"), [0, 0, 0])
        d[0] += 1; d[1] += h5; d[2] += h1
        if not h5:
            misses.append((item, got))
        if args.verbose:
            print(f"{'OK ' if h1 else ('@5 ' if h5 else 'MISS')} {item['id']} want={item['answer']} got={got}")

    if errors == n:
        print(f"FAIL: no query succeeded against {args.base} (is the server running?)")
        return 2
    r5, t1 = hit5 / n, top1 / n
    print(f"\nCVE semantic search: {n} queries, {errors} errors, median latency {sorted(lat)[n // 2]:.2f}s")
    for d, (c, a, b) in sorted(by_diff.items()):
        print(f"  {d:8s} n={c:2d}  recall@{args.k}={a / c:.2f}  top1={b / c:.2f}")
    if misses:
        print("Misses (not in top-%d):" % args.k)
        for item, got in misses:
            print(f"  {item['id']} want {item['answer']}: {item['q'][:80]!r} -> {got}")
    ok = r5 >= RECALL_BAR and t1 >= TOP1_BAR
    print(f"\nrecall@{args.k} = {r5:.3f} (bar {RECALL_BAR})   top1 = {t1:.3f} (bar {TOP1_BAR})")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
