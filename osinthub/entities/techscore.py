"""Technique score fusion: one calibrated score per (text, technique).

Signals, all general:
  llm     the model proposed it with a verified quote
  frac    best neighbour agreement: the largest share of one sentence's 20 nearest ATT&CK
          procedure examples that are this technique's family
  maxsim  the highest cosine between any sentence and a procedure example of the family
  support how many sentences have at least 3 of 20 neighbours in the family (log1p)
  lex     a keyword for the technique appears in the text; keywords come from ATT&CK only:
          technique names, and words or commands that almost always mean one technique
          across the procedure examples (e.g. rundll32, lsass, schtasks)
  cue     an artefact cue from techcues.py matched

A logistic model over these is fitted on held-out ATT&CK procedure examples arranged as
pseudo-reports (calibrate_techscore.py, a lab script kept in the development repo), never on tests/eval. The threshold is the one
with the most recall at precision >= 0.75 on that held-out set.
Docs: okf/data/entities.md#extraction
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path

from .. import config

FEATURES = ("llm", "frac", "maxsim", "support", "lex", "cue")
# Fitted by calibrate_techscore.py (a lab script kept in the development repo) (see the docs for the curve).
WEIGHTS = {"bias": -2.612, "llm": 0.837, "frac": 2.107, "maxsim": 0.517, "support": 0.89, "lex": 0.752, "cue": 0.788}
# held-out pseudo-reports: precision 0.793, recall 0.639 at this threshold
THRESHOLD = 0.40
FAMILY_K = 20

_WORD = re.compile(r"[a-z][a-z0-9_.\-]{2,}[a-z0-9]")
_STOP = set("""the and for with from that this was were has have had used using use uses also into which their they them
its can been has malware adversary attackers attacker threat actors actor group victim victims system systems file files
data information command commands such other more than via the able capable capability collected collect including
access network user users process processes windows code execute executed execution run runs running payload payloads""".split())


def keywords_path() -> Path:
    return Path(config.LAKE) / "cache" / "technique-keywords.json"


def build_keywords(examples: list[dict], tech_names: dict[str, str], min_count: int = 5, purity: float = 0.6) -> dict[str, list[str]]:
    """{family id: [keywords]} from ATT&CK only: words or commands that occur in at least
    `min_count` procedure examples and belong to one technique family at least `purity` of the time,
    plus multi-word technique names."""
    by_word: dict[str, Counter] = defaultdict(Counter)
    for e in examples:
        fam = e["tid"].split(".")[0]
        for w in set(_WORD.findall(e["text"].lower())):
            if w not in _STOP:
                by_word[w][fam] += 1
    out: dict[str, set] = defaultdict(set)
    for w, c in by_word.items():
        n = sum(c.values())
        fam, k = c.most_common(1)[0]
        if n >= min_count and k / n >= purity:
            out[fam].add(w)
    for tid, name in tech_names.items():
        n = name.lower()
        if " " in n or len(n) >= 6:
            out[tid.split(".")[0]].add(n)
    return {k: sorted(v) for k, v in out.items()}


_KW: dict | None = None


def keywords() -> dict[str, list[str]]:
    global _KW
    if _KW is None:
        p = keywords_path()
        _KW = json.loads(p.read_text()) if p.exists() else {}
    return _KW


def lexical_hits(text: str, kw: dict[str, list[str]]) -> dict[str, int]:
    t = text.lower()
    words = set(_WORD.findall(t))
    out = {}
    for fam, ks in kw.items():
        n = sum(1 for k in ks if (k in words) if " " not in k) + sum(1 for k in ks if " " in k and k in t)
        if n:
            out[fam] = n
    return out


def family(a: str) -> str:
    return a.split(".")[0]


def candidate_features(sentences: list[str], nbs: list[list[tuple[str, float]]], llm: dict[str, set],
                       cues: dict[str, str], text: str, kw: dict[str, list[str]] | None = None) -> dict[str, dict]:
    """{technique id: feature dict} for every candidate: the model's techniques, cue
    techniques, keyword families and every family with neighbour support."""
    kw = keywords() if kw is None else kw
    fam_frac: dict[str, float] = defaultdict(float)
    fam_sim: dict[str, float] = defaultdict(float)
    fam_sup: dict[str, int] = defaultdict(int)
    best_sub: dict[str, Counter] = defaultdict(Counter)
    best_sent: dict[str, int] = {}
    for i, nb in enumerate(nbs):
        c = Counter(family(t) for t, _ in nb[:FAMILY_K])
        for f, n in c.items():
            if n / FAMILY_K > fam_frac[f]:
                best_sent[f] = i
            fam_frac[f] = max(fam_frac[f], n / FAMILY_K)
            if n >= 3:
                fam_sup[f] += 1
        for t, s in nb[:FAMILY_K]:
            f = family(t)
            fam_sim[f] = max(fam_sim[f], s)
            best_sub[f][t] += 1
    lex = lexical_hits(text, kw)
    cands = set(llm) | set(cues)
    for f, n in fam_sup.items():
        if n >= 1:
            cands.add(best_sub[f].most_common(1)[0][0])
    for f in lex:
        if fam_frac.get(f, 0) >= 0.1:
            cands.add(best_sub[f].most_common(1)[0][0] if best_sub.get(f) else f)
    feats = {}
    for t in cands:
        f = family(t)
        feats[t] = {"llm": 1.0 if t in llm or any(family(x) == f and x == t for x in llm) else 0.0,
                    "frac": fam_frac.get(f, 0.0), "maxsim": fam_sim.get(f, 0.0),
                    "support": math.log1p(fam_sup.get(f, 0)), "lex": 1.0 if f in lex else 0.0,
                    "cue": 1.0 if t in cues else 0.0,
                    "_sentence": sentences[best_sent[f]] if f in best_sent and best_sent[f] < len(sentences) else None}
    # a parent and its sub-technique both proposed: keep the more specific one
    for t in list(feats):
        if "." not in t and any(x != t and family(x) == t for x in feats):
            sub = max((x for x in feats if family(x) == t and x != t), key=lambda x: (feats[x]["llm"], feats[x]["cue"]))
            for k in ("llm", "cue"):
                feats[sub][k] = max(feats[sub][k], feats[t][k])
            del feats[t]
    return feats


def score(f: dict, w: dict | None = None) -> float:
    w = WEIGHTS if w is None else w
    z = w["bias"] + sum(w[k] * f[k] for k in FEATURES)
    return 1 / (1 + math.exp(-z))
