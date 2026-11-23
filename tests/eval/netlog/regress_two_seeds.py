"""Regression: two planted sets (different seeds) imported into one lake. Every planted positive uid of
BOTH sets must be in a high or medium alert, merged alerts must union their uids, and evidence counts must
agree with the full uid list. Uses tests/eval/zeek_planted.py --out-dir to write the files (no scoring).

    uv run python tests/eval/netlog/regress_two_seeds.py --base http://127.0.0.1:8804 --seeds 1 2
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[3]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--seeds", nargs=2, type=int, default=[1, 2])
    a = ap.parse_args()
    c = httpx.Client(base_url=a.base.rstrip("/"), timeout=900)
    sets = []
    with tempfile.TemporaryDirectory() as tmp:
        for seed in a.seeds:
            d = Path(tmp) / f"seed{seed}"
            subprocess.run([sys.executable, str(ROOT / "tests/eval/zeek_planted.py"), "--out-dir", str(d), "--seed", str(seed)],
                           check=True, capture_output=True)
            m = json.loads((d / "manifest.json").read_text())
            c.put("/api/netlog/settings", json={"home_prefixes": m["home_prefixes"]}).raise_for_status()
            files = [("files", (p.name, p.read_bytes())) for p in sorted(d.iterdir()) if p.is_file() and p.name != "manifest.json"]
            c.post("/api/netlog/import", files=files).raise_for_status()
            sets.append(m)
    alerts = c.get("/api/netlog/alerts", params={"limit": 0}).json()
    hm: set = set()
    fails = []
    merged = 0
    for al in alerts:
        ev = al["evidence"]
        full = c.get(f"/api/netlog/alerts/{al['id']}/uids").json()
        allu = {u["uid"] for u in full["uids"]}
        if full["total"] != ev["uid_count"] or not set(ev["uids"]) <= allu:
            fails.append(f"{al['id']}: evidence uid_count {ev['uid_count']} vs {full['total']}")
        if al["severity"] in ("high", "medium"):
            hm |= allu
        seeds_in = sum(1 for m in sets if allu & {t["uid"] for t in m["truth"]})
        merged += seeds_in == 2
    for i, m in enumerate(sets):
        pos = [t for t in m["truth"] if t["kind"] == "positive"]
        miss = [t["uid"] for t in pos if t["uid"] not in hm]
        print(f"seed {a.seeds[i]}: {len(pos) - len(miss)}/{len(pos)} planted positive uids in high/medium alerts")
        if miss:
            fails.append(f"seed {a.seeds[i]} missing {miss[:5]}")
    print(f"alerts holding uids from both seeds (merged): {merged}")
    if not merged:
        fails.append("no alert merged rows from both imports")
    for f in fails:
        print("FAIL", f)
    print("PASS" if not fails else "FAIL")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
