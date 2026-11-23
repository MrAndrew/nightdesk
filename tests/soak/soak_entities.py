"""Soak test for the entities writers: link_loop passes alongside text ingest and claim feedback.

Runs on a scratch lake only. Three threads hammer the claims tables the way a live server does:
  * the link pass (event linking, IP-in-prefix, rescoring, re-inference of every campaign)
  * text ingest (ingest_text on cached report texts, deterministic + cached LLM answers)
  * analyst feedback (confirm / reject on random claims, which rescores and re-infers)
Exit code 0 when no write raised and every table is still readable at the end.

    OSINTHUB_LAKE=<scratch lake> OSINTHUB_OFFLINE=1 uv run python tests/soak/soak_entities.py --minutes 30
"""
from __future__ import annotations

import argparse
import glob
import os
import random
import sys
import threading
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
assert os.environ.get("OSINTHUB_LAKE"), "set OSINTHUB_LAKE to a scratch lake"

from osinthub import db  # noqa: E402
from osinthub.entities import ext as E  # noqa: E402
from osinthub.entities import ingest, link, scoring, store  # noqa: E402

errors: list[str] = []
counts = {"passes": 0, "ingests": 0, "feedback": 0}
stop = threading.Event()


def guard(name, fn):
    def run():
        while not stop.is_set():
            try:
                fn()
            except Exception as e:
                errors.append(f"{name}: {type(e).__name__}: {e}")
                traceback.print_exc()
                if "FATAL" in str(e) or "invalidated" in str(e):
                    stop.set()
    return threading.Thread(target=run, name=name, daemon=True)


def link_pass():
    # mark every campaign dirty so each pass re-infers (the path that deletes inferred claims)
    store.mark_dirty([r["id"] for r in db.query("SELECT id FROM entities WHERE type IN ('campaign','actor')")])
    E._pass()
    counts["passes"] += 1


TEXTS = sorted(glob.glob(str(ROOT / "tests/eval/cache/*.txt")))
CACHED = [t for t in TEXTS if Path(t).stem.split("-")[0] in ("dfir", "eset", "msft", "rf")]   # LLM answers cached


def ingest_once():
    llm = bool(CACHED) and random.random() < 0.5
    f = random.choice(CACHED if llm else TEXTS)
    ingest.ingest_text("article", f"soak-{random.randrange(10**6)}", Path(f).read_text(encoding="utf-8"),
                       f"https://outlet{random.randrange(5)}.example/soak", random.choice("ABCD"), use_llm=llm)
    counts["ingests"] += 1


def feedback_once():
    rows = db.query("SELECT id, subj, predicate, obj FROM claims USING SAMPLE 1 ROWS")
    if not rows:
        time.sleep(0.5)
        return
    c = rows[0]
    import datetime as dt
    now = dt.datetime.now(dt.UTC)
    store.upsert_claims([{"subj": c["subj"], "predicate": c["predicate"], "obj": c["obj"], "origin": "user",
                          "sources": ["user"], "first_seen": now, "last_seen": now,
                          "evidence": [{"verdict": random.choice(["confirm", "reject"]), "ts": now.isoformat(),
                                        "source": "user", "ref_id": now.isoformat()}]}])
    if True:
        store.execute("UPDATE claims SET confidence = NULL WHERE subj = ? AND predicate = ? AND obj = ? AND origin <> 'inferred'",
                   [c["subj"], c["predicate"], c["obj"]])
    store.mark_dirty([c["subj"]])
    scoring.drain_dirty()
    counts["feedback"] += 1


def read_once():
    """API-style reads on other cursors while writers run (the server answers requests in a pool)."""
    from osinthub.entities import api
    api.list_entities(type="actor", q=None, limit=50, offset=0, sort="mentions", since_hours=None)
    r = db.query("SELECT id FROM entities WHERE type IN ('actor','campaign','malware') USING SAMPLE 1 ROWS")
    if r:
        api.detail(r[0]["id"], evidence=5, bucket="day")
        api.graph(id=r[0]["id"], depth=2, limit=150, min_confidence=0.0, collapse_over=15)
    api.timeline(ids=None, type="campaign", limit=12, station_types="malware,tool,domain,ip,url,hash,cve,technique")
    counts["reads"] = counts.get("reads", 0) + 1


def checkpoint_once():
    time.sleep(20)                       # the server checkpoints every 10 minutes; do it often here
    try:
        db.execute("CHECKPOINT")
        counts["checkpoints"] = counts.get("checkpoints", 0) + 1
    except Exception as e:
        # the server's checkpoint loop logs this and retries later; it is not a write failure
        if "Cannot CHECKPOINT" not in str(e):
            raise
        counts["checkpoints_skipped"] = counts.get("checkpoints_skipped", 0) + 1


def legacy_infer_once():
    """The pre-fix pattern: delete every inferred row, then re-insert the same ids."""
    rows = db.query("SELECT id, subj, predicate, obj, origin, sources, confidence, evidence FROM claims WHERE origin = 'inferred'")
    store.execute("DELETE FROM claims WHERE id IN (SELECT unnest(?))", [[r["id"] for r in rows]])
    import json
    store.upsert_claims([{**r, "evidence": json.loads(r["evidence"]) if isinstance(r["evidence"], str) else r["evidence"]}
                         for r in rows])
    counts["legacy"] = counts.get("legacy", 0) + 1


def uniqueness() -> dict:
    """Rows sharing a key, per table (the tables have no PRIMARY KEY; writers must keep keys unique)."""
    out = {}
    for t, keys in store.TABLE_KEYS.items():
        k = ", ".join(keys)
        try:
            out[t] = db.query(f"SELECT count(*) AS n FROM (SELECT {k} FROM {t} GROUP BY {k} HAVING count(*) > 1)")[0]["n"]
        except Exception:
            out[t] = None
    return {t: v for t, v in out.items() if v is not None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=30)
    ap.add_argument("--legacy", action="store_true", help="also run the pre-fix delete-and-reinsert pattern (to reproduce)")
    a = ap.parse_args()
    db.connect()
    store.ensure_schema()
    if db.query("SELECT count(*) n FROM claims")[0]["n"] < 1000:
        link.link_reference()
    threads = [guard("link", link_pass), guard("ingest", ingest_once), guard("feedback", feedback_once),
               guard("checkpoint", checkpoint_once), guard("read1", read_once), guard("read2", read_once)]
    if a.legacy:
        threads.append(guard("legacy", legacy_infer_once))
    for t in threads:
        t.start()
    end = time.time() + a.minutes * 60
    while time.time() < end and not stop.is_set():
        time.sleep(10)
        print(f"{time.strftime('%H:%M:%S')} {counts} errors={len(errors)}", flush=True)
    stop.set()
    for t in threads:
        t.join(timeout=120)
    try:
        n = db.query("SELECT (SELECT count(*) FROM claims) c, (SELECT count(*) FROM mentions) m, (SELECT count(*) FROM entities) e")[0]
        print("final", n, counts)
        dups = uniqueness()
        print("duplicate keys:", dups)
        if any(dups.values()):
            errors.append(f"duplicate keys: {dups}")
    except Exception as e:
        errors.append(f"final read: {e}")
    print(f"errors: {len(errors)}")
    for e in errors[:10]:
        print("  ", e)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
