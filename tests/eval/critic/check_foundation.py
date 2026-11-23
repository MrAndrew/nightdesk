#!/usr/bin/env python3
"""Critic checks of the HLTA foundation (ext registry, AI client, vectors, indexer, search fusion).

    uv run python tests/eval/critic/check_foundation.py

Runs against a throwaway lake in a temp dir (never the real lake) and the shared AI helper
at AI_URL (default 127.0.0.1:8790); never loads a model. Prints PASS/FAIL per check.
"""
from __future__ import annotations

import asyncio
import math
import os
import sys
import tempfile
import time
import types
from pathlib import Path

TMP = Path(tempfile.mkdtemp(prefix="hlta-critic-"))
os.environ["OSINTHUB_LAKE"] = str(TMP)
os.environ["OSINTHUB_VECTORS"] = "duckdb"
os.environ["OSINTHUB_OFFLINE"] = "1"
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from osinthub import config, ext, search, vectors
from osinthub.ai import client, indexer

assert str(config.LAKE).startswith(str(TMP)), "refusing to run outside a temp lake"
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, info: str = "") -> None:
    results.append((name, ok, info))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {info}")


def cos(a, b):
    return sum(x * y for x, y in zip(a, b)) / (math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b)))


def unit(seed: int):
    v = [math.sin(seed * 7.1 + i * 0.37) for i in range(config.EMBED_DIM)]
    n = math.sqrt(sum(x * x for x in v))
    return [x / n for x in v]


# ---------------------------------------------------------------- embeddings (shared helper)
text = "Fortinet FortiWeb SQL injection lets an unauthenticated attacker run SQL commands"
doc = client.embed([text], kind="document")
qry = client.embed([text], kind="query")
if doc is None or qry is None:
    check("helper reachable", False, f"AI helper at {config.AI_URL} down")
else:
    norms = [math.sqrt(sum(x * x for x in v)) for v in doc + qry]
    check("embedding dim 1024", all(len(v) == 1024 for v in doc + qry), str({len(v) for v in doc + qry}))
    check("embeddings L2-normalised", all(abs(n - 1) < 1e-3 for n in norms), str([round(n, 5) for n in norms]))
    c = cos(doc[0], qry[0])
    check("query/document asymmetry (same text differs)", c < 0.995, f"cos={c:.4f}")
    q2 = client.embed(["Can someone without a login run database queries on Fortinet's web firewall?"], kind="query")[0]
    other = client.embed(["Use after free in WebGPU in Google Chrome allows code execution via a crafted page"],
                         kind="document")[0]
    check("query closer to its doc than to an unrelated doc", cos(q2, doc[0]) > cos(q2, other),
          f"{cos(q2, doc[0]):.3f} vs {cos(q2, other):.3f}")
    d2 = client.embed([text], kind="document")[0]
    check("document embedding deterministic", cos(d2, doc[0]) > 0.9999, f"cos={cos(d2, doc[0]):.6f}")

# ---------------------------------------------------------------- vectors: dimension checks
try:
    vectors.upsert("cves", [{"id": "bad", "vector": [0.1, 0.2, 0.3], "payload": {}}])
    check("upsert rejects wrong dimension", False, "accepted a 3-d vector")
except ValueError:
    check("upsert rejects wrong dimension with ValueError", True)
except Exception as e:
    check("upsert rejects wrong dimension with ValueError", False, f"raw backend error {type(e).__name__}")
try:
    hits = vectors.search("cves", [0.1] * 512, 5)
except ValueError as e:  # raising is the reported error the check asks for
    hits = [f"raised ValueError: {e}"]
check("search with wrong-dimension query is reported, not silently []", False if hits == [] else True,
      "vectors.search swallowed the error and returned []")
try:
    vectors.upsert("cves", [{"id": "nan", "vector": [float("nan")] * 1024, "payload": {}}])
    h = vectors.search("cves", unit(1), 5)
    check("NaN vector rejected", False, f"NaN stored; search -> {[(x['id'], x['score']) for x in h]}")
except Exception as e:
    check("NaN vector rejected", True, type(e).__name__)
vectors.drop("cves")

# ---------------------------------------------------------------- upsert idempotency
items = [{"id": f"CVE-0000-{i:04d}", "vector": unit(i), "payload": {"n": i, "kev": i % 2 == 0}} for i in range(10)]
vectors.upsert("cves", items)
vectors.upsert("cves", items)
vectors.upsert("cves", [{"id": "CVE-0000-0003", "vector": unit(3), "payload": {"n": 33, "kev": False}}])
check("upsert idempotent (count stays 10)", vectors.count("cves") == 10, f"count={vectors.count('cves')}")
h = vectors.search("cves", unit(3), 1)
check("re-upsert replaces payload", h and h[0]["payload"].get("n") == 33, str(h[:1]))
check("top hit cosine ~1 for identical vector", h and abs(h[0]["score"] - 1) < 1e-4, str(h[0]["score"] if h else None))
hf = vectors.search("cves", unit(4), 10, filter={"kev": True})
check("bool payload filter works", hf and all(x["payload"]["kev"] is True for x in hf) and len(hf) == 5, f"n={len(hf)}")

# ---------------------------------------------------------------- retention deletes
corpus = {it["id"]: {"id": it["id"], "text": f"doc {it['id']}", "hash": "h1", "payload": {}} for it in items}
vectors.drop("cves")
vectors.reset_indexed("cves")
orig_embed = client.embed
client.embed = lambda texts, kind="document", **k: [unit(abs(hash(t)) % 1000) for t in texts]
try:
    indexer.sync_collection("cves", lambda: corpus)
    n0 = vectors.count("cves")
    for gone in list(corpus)[:4]:
        corpus.pop(gone)  # these events aged out under retention
    st = indexer.sync_collection("cves", lambda: corpus)
    n1 = vectors.count("cves")
    tracked = len(vectors.indexed("cves"))
    check("retention: vanished docs deleted from vectors", n1 == 6,
          f"count {n0} -> {n1}, tracking rows {tracked}, stale_in_index={st.get('stale_in_index')}")
finally:
    client.embed = orig_embed

# ---------------------------------------------------------------- fusion sanity
corp = {"A": {"text": "zyxel firewall command injection cgi"}, "B": {"text": "apache superset default secret key"},
        "C": {"text": "zyxel nas"}}
vectors.drop("t")
out = search.hybrid("t-critic", corp, "t", "zyxel firewall", None, 3)
check("keyword-only scores in 0..1", all(0 <= s <= 1.0001 for _, s, _, _ in out), str(out))
# Cross-type: in keyword mode the best hit of every type is normalised to 1.0, so a weak event
# match ties a strong CVE match.
weak = search.hybrid("t-weak", {"E": {"text": "zyxel"}}, "t", "zyxel firewall command injection cgi", None, 1)
strong = search.hybrid("t-strong", corp, "t", "zyxel firewall command injection cgi", None, 1)
check("keyword mode: cross-type scores comparable (weak 1-term match < full match)",
      weak[0][1] < strong[0][1], f"weak={weak[0][1]:.3f} strong={strong[0][1]:.3f}")
# Partial index: vectors for only some docs; mode is still reported as 'hybrid'.
vectors.upsert("t", [{"id": "C", "vector": unit(9), "payload": {}}])
part = search.hybrid("t-part", corp, "t", "zyxel firewall command injection", unit(9), 3)
check("partial index: unembedded best keyword match not buried", part[0][0] == "A",
      f"ranking {[(i, round(s, 3)) for i, s, _, _ in part]}")

# ---------------------------------------------------------------- ext registry isolation
mod = types.ModuleType("osinthub.critic_half.ext")
saved_discover = ext.discover
ext._loaded = False
src = ("from osinthub import ext\nfrom fastapi import APIRouter\nr=APIRouter(prefix='/api/half')\n"
       "@r.get('/x')\ndef x(): return 1\next.register('half', router=r)\nraise RuntimeError('boom after register')\n")
pkg = TMP / "critic_half_pkg"
pkg.mkdir()
(pkg / "critic_half_ext.py").write_text(src)
sys.path.insert(0, str(pkg))
ext.discover = lambda: ["critic_half_ext"]
try:
    ext.load_all()
    check("import failure recorded", "critic_half_ext" in ext.FAILED, str(ext.FAILED))
    check("half-imported extension NOT left registered", "half" not in ext.EXTENSIONS,
          f"EXTENSIONS={list(ext.EXTENSIONS)} (router of a failed module would still be mounted)")
finally:
    ext.discover = saved_discover
    ext.EXTENSIONS.pop("half", None)


async def _hooks():
    calls = {"n": 0}

    async def flaky():
        calls["n"] += 1
        raise RuntimeError("task boom")

    def slow_start():
        time.sleep(3)

    ext.EXTENSIONS.clear()
    ext.register("flaky", tasks=(flaky,))
    ext.register("slow", on_start=slow_start)
    beat = []

    async def heartbeat():
        for _ in range(30):
            beat.append(time.monotonic())
            await asyncio.sleep(0.1)

    hb = asyncio.create_task(heartbeat())
    t0 = time.monotonic()
    await ext.start()
    took = time.monotonic() - t0
    await asyncio.sleep(0.2)
    pts = [t0] + beat
    gaps = max(b - a for a, b in zip(pts, pts[1:])) if beat else took
    check("raising task is supervised (ran, error recorded)", calls["n"] >= 1 and ext.EXTENSIONS["flaky"].errors,
          str(ext.EXTENSIONS["flaky"].errors[:1]))
    check("slow sync on_start does not block the event loop", gaps < 1.0,
          f"loop stalled {gaps:.1f}s during on_start (startup {took:.1f}s)")
    await ext.stop()
    hb.cancel()


asyncio.run(_hooks())

# ---------------------------------------------------------------- client fail-fast
config.AI_URL = "http://127.0.0.1:9"
client._http = None
client._down_until = 0
t0 = time.monotonic()
r1 = client.embed(["x"], kind="query", timeout=10)
t1 = time.monotonic() - t0
t0 = time.monotonic()
r2 = client.embed(["x"], kind="query", timeout=10)
t2 = time.monotonic() - t0
check("dead port: None fast", r1 is None and r2 is None and t1 < 0.6 and t2 < 0.01, f"first {t1*1000:.0f}ms, cached {t2*1000:.1f}ms")

failed = [r for r in results if not r[1]]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
