"""Technique verifier built on ATT&CK procedure examples.

ATT&CK's `uses` relationships to techniques carry procedure examples: real report sentences
("APT28 has used ... to ...") labelled with a technique id. They are embedded once
(osinthub.ai.client.embed) into the `techniques` vector collection and a local matrix
(`<lake>/cache/procedures.npz`) used for fast batch nearest-neighbour search.

* verify: a proposed technique is accepted when the evidence sentence's top-k nearest
  procedure examples include that technique (or its parent, or a sub-technique of it) with
  cosine >= TAU.
* propose: a sentence whose nearest examples agree on one technique family with high
  similarity proposes it.

K, TAU and the proposal thresholds are calibrated only on held-out procedure examples
(calibrate_procvec.py, a lab script kept in the development repo), never on the extraction eval. Docs: okf/data/entities.md#extraction
"""
from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path

from .. import config
from . import refdata

log = logging.getLogger("osinthub.entities.procvec")

# Calibrated on 1,764 held-out ATT&CK procedure examples (calibrate_procvec.py, a lab script kept in the development repo):
# verify TPR 0.60 at 0.17 FPR on hard negatives (0.002 on random); propose precision 0.905
# at 29% coverage. Never fitted on tests/eval.
K = 20
TAU = 0.55
VOTES = 4
PROPOSE_K = 10
PROPOSE_TAU = 0.725
PROPOSE_VOTES = 5

_lock = threading.Lock()
_index: dict | None = None


def index_path() -> Path:
    return Path(config.LAKE) / "cache" / "procedures.npz"


def _clean(s: str) -> str:
    s = re.sub(r"\(Citation:[^)]*\)", "", s or "")
    s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
    s = re.sub(r"<code>|</code>", "", s)
    return re.sub(r"\s+", " ", s).strip()


def procedure_examples() -> list[dict]:
    """[{id, tid, text}] from the cached ATT&CK bundle."""
    p = refdata.path("attack")
    if not p.exists():
        return []
    bundle = json.loads(p.read_bytes())
    objs = bundle.get("objects", [])
    tech = {}
    for o in objs:
        if o.get("type") == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            for r in o.get("external_references", []):
                if r.get("source_name") == "mitre-attack":
                    tech[o["id"]] = r.get("external_id")
    out = []
    for o in objs:
        if o.get("type") != "relationship" or o.get("relationship_type") != "uses" or o.get("revoked"):
            continue
        tid = tech.get(o.get("target_ref"))
        text = _clean(o.get("description") or "")
        if tid and len(text) >= 20:
            out.append({"id": o["id"], "tid": tid, "text": text[:600], "src": o.get("source_ref")})
    return out


def build(examples: list[dict] | None = None, path: Path | None = None, batch: int = 128,
          upsert: bool = True) -> int:
    """Embed procedure examples and save the matrix. Returns the count, 0 if the helper is down."""
    import numpy as np
    from ..ai import client
    ex = examples if examples is not None else procedure_examples()
    if not ex:
        return 0
    vecs = []
    for i in range(0, len(ex), batch):
        v = client.embed([e["text"] for e in ex[i:i + batch]], kind="document", timeout=300)
        if v is None:
            log.warning("procedure embedding stopped at %d of %d: helper unavailable", i, len(ex))
            return 0
        vecs.extend(v)
    m = np.asarray(vecs, dtype=np.float32)
    m /= np.linalg.norm(m, axis=1, keepdims=True) + 1e-9
    path = path or index_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(path, m=m.astype(np.float16), tid=np.asarray([e["tid"] for e in ex]),
                        id=np.asarray([e["id"] for e in ex]))
    if upsert:
        try:
            from .. import vectors
            for i in range(0, len(ex), 512):
                vectors.upsert("techniques", [{"id": e["id"], "vector": m[j].tolist(),
                                               "payload": {"tid": e["tid"], "text": e["text"][:300]}}
                                              for j, e in enumerate(ex[i:i + 512], start=i)])
        except Exception as e:
            log.warning("techniques collection not updated: %s", e)
    global _index
    with _lock:
        _index = None
    return len(ex)


def load(path: Path | None = None) -> dict | None:
    global _index
    with _lock:
        if _index is not None and path is None:
            return _index
    import numpy as np
    p = path or index_path()
    if not p.exists():
        return None
    z = np.load(p)
    idx = {"m": z["m"].astype(np.float32), "tid": z["tid"]}
    if path is None:
        with _lock:
            _index = idx
    return idx


def neighbours(texts: list[str], k: int = K, index: dict | None = None, qvecs=None) -> list[list[tuple[str, float]]] | None:
    """Top-k (technique id, cosine) for each text, or None without an index or embeddings."""
    import numpy as np
    idx = index or load()
    if idx is None or not texts:
        return None if idx is None else []
    if qvecs is None:
        from ..ai import client
        qvecs = client.embed(texts, kind="document", timeout=120)
        if qvecs is None:
            return None
    q = np.asarray(qvecs, dtype=np.float32)
    q /= np.linalg.norm(q, axis=1, keepdims=True) + 1e-9
    sims = q @ idx["m"].T
    top = np.argpartition(-sims, kth=min(k, sims.shape[1] - 1), axis=1)[:, :k]
    out = []
    for r in range(len(texts)):
        cols = top[r][np.argsort(-sims[r, top[r]])]
        out.append([(str(idx["tid"][c]), float(sims[r, c])) for c in cols])
    return out


def family_match(cand: str, nb: str) -> bool:
    """Same technique, its parent, or a sub-technique of it (siblings don't match)."""
    return nb == cand or nb == cand.split(".")[0] or nb.split(".")[0] == cand


def supports(cand: str, nbs: list[tuple[str, float]], k: int = K, tau: float = TAU, votes: int | None = None) -> bool:
    """At least `votes` of the top-k neighbours with cosine >= tau are the candidate's family."""
    v = VOTES if votes is None else votes
    return sum(1 for t, s in nbs[:k] if s >= tau and family_match(cand, t)) >= v


def propose(nbs: list[tuple[str, float]], tau: float = PROPOSE_TAU, votes: int = PROPOSE_VOTES) -> str | None:
    """The technique family most of the close neighbours agree on, if enough do."""
    from collections import Counter
    close = [t for t, s in nbs[:PROPOSE_K] if s >= tau]
    if len(close) < votes:
        return None
    fam = Counter(t.split(".")[0] for t in close)
    f, n = fam.most_common(1)[0]
    if n < votes:
        return None
    subs = Counter(t for t in close if t.split(".")[0] == f)
    best, bn = subs.most_common(1)[0]
    return best if bn >= votes else f
