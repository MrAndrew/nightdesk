"""Claim confidence and inferred campaign-actor links. Method: okf/data/entities.md#scoring

* Observed and reported claims: independent sources, weighted by tier (A=3, B=2, C=1, D=0.5),
  combined with a noisy-OR so each extra source adds less. Copies of one text (same quote, same
  story, same publisher) count once, at the best tier among them.
* User verdicts (origin "user" on the same triple) override: confirm lifts to at least 0.95,
  reject cuts to a tenth and marks the claim rejected. Rejected claims don't feed inference.
  A verdict annotates the claims of its triple; it is never a claim of its own in any count
  (entities/api.py hides rejected triples and folds the verdict into the original row).
* Inferred campaign -> actor links: shared features weighted by specificity (IDF over how many
  actors and campaigns share the feature), by type, by a commodity discount (cloud, CDN and
  Tor addresses, common tools) and by a type-specific time decay between the two sightings.
  Conflicting attributions are separate claims; nothing is averaged.
* Inferred links are hypotheses: their confidence is capped at HYPOTHESIS_CAP, below the floor of
  the lowest band any sourced claim can get, so a claim a named source reported (even one quoted
  sentence from a tier-D outlet) always outranks a link the hub computed for the same pair.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import math
import re
from collections import defaultdict

from .. import db
from . import store

log = logging.getLogger("osinthub.entities.scoring")

TIER_WEIGHT = {"A": 3.0, "B": 2.0, "C": 1.0, "D": 0.5}
SOURCE_TIER = {
    "cisa_kev": "A", "nvd_recent": "A", "cisa_advisories": "A", "ris_live": "A", "spamhaus_drop": "A", "tor_exits": "A",
    "dshield_top": "B", "et_compromised": "B", "feodo_c2": "B", "ioda_outages": "B", "security_news": "B",
    "blocklist_de": "C", "cins_army": "C", "ransomware_live": "C", "bluesky_cyber": "D",
    "threatfox": "B", "urlhaus": "B", "sslbl": "B",
    "MITRE ATT&CK": "B", "MISP galaxy": "C", "dbip": "C", "upload": "D",
}


def tier_of(source: str | None, default: str = "C") -> str:
    return SOURCE_TIER.get(source or "", default)


def p_of(weight: float) -> float:
    """Probability-like contribution of one independent source: A 0.5, B 0.4, C 0.25, D 0.14."""
    return weight / (weight + 3.0)


def band(conf: float | None) -> str:
    if conf is None:
        return "unscored"
    return "high" if conf >= BANDS["high"][0] else "moderate" if conf >= BANDS["moderate"][0] else "low"


def _qkey(q: str | None) -> str | None:
    if not q:
        return None
    return hashlib.sha1(re.sub(r"\W+", "", q.lower()).encode()).hexdigest()[:12]


def _model_extracted(e: dict) -> bool:
    """Evidence from text extraction (articles, reports) rather than a curated source (reference
    data) or a feed record (events). Older rows carry no `method`, so the reference type decides."""
    if e.get("method"):
        return e["method"] == "llm"
    return e.get("ref_type") not in (None, "reference", "event")


def independent_groups(evidence: list[dict], sources: list[str]) -> list[dict]:
    """Union evidence items that are not independent (same publisher, or the same quote, which
    marks a syndicated copy). Outlets in one news story cluster stay independent;
    return [{src, w, tier, llm}] per group: best tier among its items; llm only when every item
    of the group was extracted by the model."""
    items = []
    for e in evidence or []:
        if not isinstance(e, dict) or e.get("verdict"):
            continue
        src = e.get("source") or "?"
        tier = e.get("tier") or tier_of(src)
        items.append({"src": src, "w": TIER_WEIGHT.get(tier, 1.0), "tier": tier, "llm": _model_extracted(e),
                      "keys": {f"s:{src}", *([f"q:{_qkey(e.get('quote'))}"] if e.get("quote") else [])}})
    covered = {i["src"] for i in items}
    for s in sources or []:
        if s not in covered:
            items.append({"src": s, "w": TIER_WEIGHT[tier_of(s)], "tier": tier_of(s), "llm": False, "keys": {f"s:{s}"}})
    parent = list(range(len(items)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    owner: dict[str, int] = {}
    for i, it in enumerate(items):
        for k in it["keys"]:
            if k in owner:
                parent[find(i)] = find(owner[k])
            else:
                owner[k] = i
    groups: dict[int, dict] = {}
    for i, it in enumerate(items):
        r = find(i)
        g = groups.get(r)
        if g is None:
            groups[r] = {"src": it["src"], "w": it["w"], "tier": it["tier"], "llm": it["llm"]}
        else:
            if it["w"] > g["w"]:
                g.update(src=it["src"], w=it["w"], tier=it["tier"])
            g["llm"] = g["llm"] and it["llm"]
    return list(groups.values())


SCORING_VERSION = "2026-11-10-hypothesis-cap"
BANDS = {"low": (0.10, 0.34), "moderate": (0.35, 0.64), "high": (0.65, 0.97)}
# Every sourced claim scores at least BANDS["low"][0]; a computed link stays strictly below it.
HYPOTHESIS_CAP = 0.09


def assess(evidence, sources, observed: bool = False) -> tuple[float, str, str]:
    """(confidence, band, why) for a claim from its independent sources.

    * high: two or more independent tier-A/B sources, or corroboration by an observed claim
    * moderate: one curated (not model-extracted) tier-A/B source, two or more tier-C sources,
      or one model-extracted tier-A/B source plus any other independent source
    * low: anything else (one tier-C/D source, or one model-extracted article)
    Within the band the value grows with the noisy-OR of the tier weights, so more and better
    sources still rank higher.
    """
    groups = independent_groups(evidence, sources)
    ab = [g for g in groups if g["tier"] in ("A", "B")]
    curated_ab = [g for g in ab if not g["llm"]]
    c = [g for g in groups if g["tier"] == "C"]
    if len(ab) >= 2 or observed:
        b = "high"
    elif curated_ab or len(c) >= 2 or (ab and len(groups) >= 2):
        b = "moderate"
    else:
        b = "low"
    miss = 1.0
    for g in groups:
        miss *= 1 - p_of(g["w"])
    raw = 1 - miss
    lo, hi = BANDS[b]
    conf = round(lo + (hi - lo) * min(raw / 0.9, 1.0), 4)
    tiers = ", ".join(sorted((g["tier"] for g in groups), key="ABCD".index)) or "none"
    why = f"{len(groups)} source{'s' if len(groups) != 1 else ''}: {tiers}"
    if groups and all(g["llm"] for g in groups):
        why += " (model-extracted)"
    if observed:
        why += "; corroborated by an observed claim"
    return conf, b, why


def source_confidence(evidence, sources, observed: bool = False) -> tuple[float, int]:
    conf, _, _ = assess(evidence, sources, observed)
    return conf, len(independent_groups(evidence, sources))


def _verdicts() -> dict[tuple[str, str, str], str]:
    out = {}
    for subj, pred, obj, ev in db.cursor().execute(
            "SELECT subj, predicate, obj, evidence FROM claims WHERE origin = 'user'").fetchall():
        ev = json.loads(ev) if isinstance(ev, str) else (ev or [])
        last = sorted((e for e in ev if isinstance(e, dict) and e.get("verdict")), key=lambda e: e.get("ts") or "")
        if last:
            out[(subj, pred, obj)] = last[-1]["verdict"]
    return out


def apply_verdict(conf: float, verdict: str | None) -> float:
    if verdict == "confirm":
        return max(conf, 0.95)
    if verdict == "reject":
        return round(conf * 0.1, 4)
    return conf


SUGGESTED_CAP = 0.15


def is_suggested(evidence) -> bool:
    """A claim whose every evidence item is a suggested (unconfirmed) model technique."""
    items = [e for e in (evidence or []) if isinstance(e, dict) and not e.get("verdict")]
    return bool(items) and all(e.get("suggested") for e in items)


def observed_triples() -> set[tuple[str, str, str]]:
    return {tuple(r) for r in db.cursor().execute("SELECT subj, predicate, obj FROM claims WHERE origin = 'observed'").fetchall()}


def rescore_claims(limit: int = 200_000) -> int:
    """Score observed and reported claims whose confidence is unset (new or changed)."""
    rows = db.cursor().execute(
        "SELECT id, subj, predicate, obj, origin, sources, evidence FROM claims "
        "WHERE confidence IS NULL AND origin IN ('observed','reported','local') LIMIT ?", [limit]).fetchall()
    if not rows:
        return 0
    verdicts = _verdicts()
    observed = observed_triples()
    out = []
    for cid, subj, pred, obj, origin, sources, ev in rows:
        ev = json.loads(ev) if isinstance(ev, str) else (ev or [])
        conf, _ = source_confidence(ev, sources or [], origin != "observed" and (subj, pred, obj) in observed)
        if is_suggested(ev):
            conf = min(conf, SUGGESTED_CAP)
        out.append({"id": cid, "confidence": apply_verdict(conf, verdicts.get((subj, pred, obj)))})
    _set_conf(out)
    # user rows: confidence is the verdict itself
    store.execute("""UPDATE claims SET confidence = CASE WHEN json_extract_string(evidence, '$[-1].verdict') = 'confirm' THEN 1.0 ELSE 0.0 END
                  WHERE origin = 'user' AND confidence IS DISTINCT FROM
                        (CASE WHEN json_extract_string(evidence, '$[-1].verdict') = 'confirm' THEN 1.0 ELSE 0.0 END)""")
    return len(out)


def _set_conf(rows: list[dict]) -> None:
    if not rows:
        return
    p = store._ndjson(rows, "s")
    try:
        with store._tx() as cur:
            cur.execute(f"CREATE OR REPLACE TEMP TABLE _sc AS SELECT * FROM read_json('{store._q(p)}', format='newline_delimited', columns={{'id':'VARCHAR','confidence':'DOUBLE'}})")
            cur.execute("UPDATE claims SET confidence = _sc.confidence FROM _sc WHERE claims.id = _sc.id")
            cur.execute("DROP TABLE _sc")
    finally:
        p.unlink(missing_ok=True)


# ---------------------------------------------------------------- inference
TYPE_WEIGHT = {"ip": 1.0, "domain": 1.3, "url": 1.3, "hash": 1.6, "malware": 1.0, "tool": 0.35, "technique": 0.12,
               "cve": 0.5, "prefix": 0.6, "asn": 0.1, "country": 0.05, "sector": 0.05}
HALF_LIFE_DAYS = {"ip": 30, "url": 60, "domain": 120, "prefix": 90, "asn": 180, "hash": 365, "cve": 365,
                  "tool": 540, "malware": 730, "technique": 1095, "country": 1095, "sector": 1095}
COMMODITY_TOOLS = {"tool:cobalt-strike", "malware:cobalt-strike", "tool:mimikatz", "tool:psexec", "tool:adfind",
                   "tool:rclone", "tool:anydesk", "tool:ngrok", "tool:plink", "tool:impacket", "tool:metasploit",
                   "tool:net", "tool:cmd", "tool:powershell", "tool:systeminfo", "tool:ipconfig", "tool:tasklist",
                   "tool:whoami", "tool:netstat", "tool:wmic", "tool:reg", "tool:at", "tool:schtasks", "tool:7-zip",
                   "tool:winrar", "tool:certutil", "tool:bitsadmin", "tool:sliver", "tool:advanced-ip-scanner",
                   "tool:netscan", "tool:teamviewer", "tool:screenconnect", "tool:atera", "tool:splashtop"}
CLOUD_CDN_ASNS = {"13335", "16509", "14618", "15169", "396982", "8075", "20940", "16625", "54113", "14061", "16276",
                  "24940", "63949", "20473", "31898", "45102", "37963", "132203", "8068", "8987", "19551", "209242",
                  "13238", "60068", "202422", "212238", "9009", "51167"}
FEATURE_TYPES = tuple(TYPE_WEIGHT)
TYPE_CAP = {"technique": 1.2, "tool": 1.0, "country": 0.3, "sector": 0.3, "asn": 0.5}
MIN_SCORE = 1.0
ACTORISH = ("actor", "campaign")


def _features() -> dict[str, dict[str, dt.datetime | None]]:
    """entity (actor or campaign) -> {feature entity id: latest time it was tied to the entity}."""
    cur = db.cursor()
    feats: dict[str, dict] = defaultdict(dict)
    verdicts = _verdicts()

    def put(e, f, ts):
        if e == f:
            return
        old = feats[e].get(f)
        if old is None or (ts is not None and ts > old):
            feats[e][f] = ts

    for subj, pred, obj, ts, origin, ev in cur.execute(
            "SELECT subj, predicate, obj, coalesce(last_seen, first_seen), origin, evidence FROM claims "
            "WHERE origin IN ('observed','reported','user','local') AND predicate <> 'attributed-to' "
            "AND (split_part(subj, ':', 1) IN ('actor','campaign') OR split_part(obj, ':', 1) IN ('actor','campaign'))").fetchall():
        if verdicts.get((subj, pred, obj)) == "reject" or origin == "user":
            continue
        if pred == "uses" and is_suggested(json.loads(ev) if isinstance(ev, str) else ev):
            continue                              # suggested techniques never feed attribution
        st, ot = subj.split(":", 1)[0], obj.split(":", 1)[0]
        if st in ACTORISH and ot in FEATURE_TYPES:
            put(subj, obj, ts)
        elif ot in ACTORISH and st in FEATURE_TYPES:
            put(obj, subj, ts)
    # co-mention in one text: weaker, only for specific feature types
    for e, f, ts in cur.execute("""
            SELECT a.entity_id, b.entity_id, max(coalesce(b.ts, a.ts))
            FROM mentions a JOIN mentions b ON a.ref_type = b.ref_type AND a.ref_id = b.ref_id AND a.entity_id <> b.entity_id
            WHERE split_part(a.entity_id, ':', 1) IN ('actor','campaign') AND a.ref_type NOT IN ('event','reference')
              AND split_part(b.entity_id, ':', 1) IN ('ip','domain','url','hash','malware','tool','cve')
            GROUP BY 1, 2""").fetchall():
        if f not in feats[e]:
            feats[e][f] = ts
            feats[e].setdefault("__co__", set()).add(f)
    return feats


def _commodity(fid: str, attrs: dict) -> float:
    if fid in COMMODITY_TOOLS:
        return 0.2
    t = fid.split(":", 1)[0]
    if t == "ip":
        if attrs.get("tor"):
            return 0.05
        if str(attrs.get("asn", "")).lstrip("ASas") in CLOUD_CDN_ASNS:
            return 0.15
    if t in ("domain", "url") and attrs.get("shared_hosting"):
        return 0.2
    return 1.0


_SPEC: dict = {"t": 0.0, "v": {}}


def specificity(ids: list[str]) -> dict[str, float]:
    """0..1 per feature entity: how specific it is to one actor or campaign. It is the IDF over
    how many actors and campaigns share it, normalised, times the commodity discount (cloud, CDN
    and Tor addresses, common tools). It is the same weight inference uses, so a UI can mute
    commodity features from data. Cached for 5 minutes."""
    import time
    if time.time() - _SPEC["t"] > 300:
        feats = _features()
        ents = [e for e in feats if not e.startswith("__")]
        df: dict[str, int] = defaultdict(int)
        for e in ents:
            for f in feats[e]:
                if not f.startswith("__"):
                    df[f] += 1
        n = max(len(ents), 2)
        _SPEC.update(t=time.time(), v={"df": dict(df), "n": n})
    df, n = _SPEC["v"]["df"], _SPEC["v"]["n"]
    out = {}
    attrs = {}
    if ids:
        for fid, a in db.cursor().execute("SELECT id, attrs FROM entities WHERE id IN (SELECT unnest(?))", [list(ids)]).fetchall():
            attrs[fid] = json.loads(a) if isinstance(a, str) else (a or {})
    for i in ids:
        d = df.get(i, 1)
        idf = math.log(1 + n / d) / math.log(1 + n)
        out[i] = round(idf * _commodity(i, attrs.get(i, {})), 3)
    return out


def infer_links(campaigns: list[str] | None = None) -> int:
    """Recompute inferred campaign -> actor links (all campaigns, or the given ones)."""
    feats = _features()
    cur = db.cursor()
    entities = [e for e in feats if not e.startswith("__")]
    if not entities:
        return 0
    df: dict[str, int] = defaultdict(int)
    for e in entities:
        for f in feats[e]:
            if not f.startswith("__"):
                df[f] += 1
    n = len(entities)
    fids = list(df)
    attrs = {}
    for i in range(0, len(fids), 5000):
        for fid, a, name in cur.execute("SELECT id, attrs, name FROM entities WHERE id IN (SELECT unnest(?))", [fids[i:i + 5000]]).fetchall():
            a = json.loads(a) if isinstance(a, str) else (a or {})
            a["_name"] = name
            attrs[fid] = a
    by_feature: dict[str, list[str]] = defaultdict(list)
    for e in entities:
        if e.startswith("actor:"):
            for f in feats[e]:
                if not f.startswith("__"):
                    by_feature[f].append(e)
    verdicts = _verdicts()
    targets = [c for c in entities if c.startswith("campaign:") and (campaigns is None or c in campaigns)]
    rows, keep = [], set()
    now = dt.datetime.now(dt.UTC)
    for c in targets:
        cf = feats[c]
        co = cf.get("__co__", set())
        scores: dict[str, list] = defaultdict(list)
        for f, ts_c in cf.items():
            if f.startswith("__"):
                continue
            t = f.split(":", 1)[0]
            idf = math.log(1 + n / df[f])
            base = TYPE_WEIGHT.get(t, 0.2) * _commodity(f, attrs.get(f, {})) * (0.5 if f in co else 1.0)
            for a in by_feature.get(f, ()):
                ts_a = feats[a].get(f)
                gap = abs((ts_c - ts_a).total_seconds()) / 86400 if ts_c and ts_a else 0.0
                decay = 0.5 ** (gap / HALF_LIFE_DAYS.get(t, 365))
                w = base * idf * decay
                scores[a].append((w, f, idf, gap, df[f]))
        for a, parts in scores.items():
            parts.sort(reverse=True)
            # diminishing returns within one feature type: 1, 1/2, 1/3 ...
            per_type: dict[str, int] = defaultdict(int)
            by_type: dict[str, float] = defaultdict(float)
            for w, f, *_ in parts:
                t = f.split(":", 1)[0]
                per_type[t] += 1
                by_type[t] += w / per_type[t]
            # behaviour alone (techniques, commodity tools) can never make a strong link
            s = sum(min(v, TYPE_CAP.get(t, 99.0)) for t, v in by_type.items())
            if s < MIN_SCORE:
                continue
            conf = round(HYPOTHESIS_CAP * (1 - math.exp(-s / 4)), 4)
            verdict = verdicts.get((c, "attributed-to", a))
            conf = apply_verdict(conf, verdict)
            reasons = []
            for w, f, idf, gap, d in parts[:8]:
                nm = attrs.get(f, {}).get("_name") or f.split(":", 1)[1]
                when = f", {gap:.0f} days apart" if gap >= 1 else ""
                how = "co-mentioned" if f in co else "shared"
                reasons.append({"feature": f, "weight": round(w, 3),
                                "text": f"{how} {f.split(':', 1)[0]} {nm} (held by {d} of {n} actors/campaigns, idf {idf:.1f}{when})"})
            ev = [{"score": round(s, 3), "band": "rejected" if verdict == "reject" else "hypothesis",
                   "features": len(parts), "reasons": reasons, "computed_at": now.isoformat()}]
            cid = store.claim_id(c, "attributed-to", a, "inferred")
            keep.add(cid)
            rows.append({"id": cid, "subj": c, "predicate": "attributed-to", "obj": a, "origin": "inferred",
                         "sources": ["inference"], "confidence": conf, "first_seen": now, "last_seen": now, "evidence": ev})
    # Under the claims lock: delete only links that disappeared (never a row about to be
    # rewritten), and rewrite only links whose confidence changed, replacing their evidence.
    with store.claims_lock():
        if targets:
            old = {r[0]: r[1] for r in cur.execute(
                "SELECT id, confidence FROM claims WHERE origin = 'inferred' AND subj IN (SELECT unnest(?))", [targets]).fetchall()}
            stale = sorted(set(old) - keep)
            if stale:
                store.execute("DELETE FROM claims WHERE id IN (SELECT unnest(?))", [stale])
            rows = [r for r in rows if r["id"] not in old or old[r["id"]] is None or abs(old[r["id"]] - r["confidence"]) > 1e-4]
        store.upsert_claims(rows, replace_evidence=True)
    return len(keep)


def drain_dirty() -> dict:
    """Incremental recompute: score new or changed claims, and re-infer links when any actor,
    campaign, malware or tool changed since the last pass."""
    cur = db.cursor()
    dirty = [r[0] for r in cur.execute("SELECT id FROM entity_dirty").fetchall()]
    n_claims = rescore_claims()
    n_inf = 0
    if dirty:
        store.clear_dirty(dirty)
        n_inf = infer_links()
    return {"claims_scored": n_claims, "dirty": len(dirty), "inferred": n_inf}
