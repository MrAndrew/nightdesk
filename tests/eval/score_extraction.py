#!/usr/bin/env python3
"""Score osinthub.entities.extract.extract against the vendor-report gold set.

    uv run python tests/eval/score_extraction.py            # full run (LLM on)
    uv run python tests/eval/score_extraction.py --no-llm   # regex/dictionary only
    uv run python tests/eval/score_extraction.py --fetch    # (re)build tests/eval/cache first
    uv run python tests/eval/score_extraction.py -v --only eset-webworm
    python3 tests/eval/score_extraction.py --from-outputs DIR   # score saved extract() outputs
    uv run python tests/eval/score_extraction.py --save-outputs DIR   # also save every extract() output

What is measured (bars from tests/eval/README.md, "Pass bars"):
  * IOCs on the FULL page text (ip, domain, url, sha256, sha1, md5, cve):
    precision >= 0.95 and recall >= 0.90 (micro-averaged over all reports).
  * ATT&CK techniques on the BODY ONLY (text before body_end_marker, i.e. with
    the IOC/ATT&CK appendix stripped), scored two ways:
      - "described in the body" (gold.techniques_body, the 2026-11-19
        re-adjudication): revoked ids mapped to their ATT&CK v20.1
        replacements (gold.revoked), Mobile ids left out and counted
        separately. THE BARS APPLY TO THIS MEASURE: precision >= 0.70,
        recall >= 0.50. Unsure entries and never-adjudicated predictions are
        counted and printed.
      - "vendor table" (gold.techniques, as before 2026-11-19): printed for
        comparison with older numbers, no bar.
    A predicted ID matches a gold ID if equal, or if one is the parent of the
    other (T1059 <-> T1059.001). Sibling sub-techniques do not match.
  * Actors and malware named by the report, after alias normalisation, all
    found in >= 85% of the reports that name any (names may come back in either
    the actors or the malware list).
  * Zero claims whose evidence quote is not found verbatim (after whitespace,
    case, quote and dash normalisation) in the text that was passed in.

Gold values are refanged and lowercased. Values in a report's "neutral" lists
(legitimate services, loopback addresses, JA3/imphash digests, git commit
hashes inside reference URLs) are neither rewarded nor penalised, nor is a
predicted domain/IP that is the host of a gold URL.

Works offline from tests/eval/cache/ (or $ND_EVAL_CACHE) once built. Stdlib only.
--from-outputs DIR reads DIR/<report id>.json = {"full": {"out": ...}, "body": {"out": ...}}
(as saved by the 2026-11-19 audit wrapper) and needs neither the extractor nor the model;
the claims check then runs only when the cache is present. --save-outputs DIR writes that
format during a live run (one file per report as soon as it is scored, "body" left out when
the report has no body marker), adding each call's seconds, error and extract.LAST_STATS.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import traceback
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import evalfetch

IOC_TYPES = ("ip", "domain", "url", "sha256", "sha1", "md5", "cve")
BARS = dict(ioc_p=0.95, ioc_r=0.90, tech_p=0.70, tech_r=0.50, entity_hit=0.85)


# ------------------------------------------------------------------ normalise

def refang(v: str) -> str:
    v = v.strip().strip("<>\"'`,;")
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."),
                 ("[:]", ":"), ("[://]", "://"), ("[/]", "/")):
        v = v.replace(a, b)
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    v = re.sub(r"^fxp", "ftp", v, flags=re.I)
    return v


def norm_ioc(kind: str, v) -> str | None:
    if not isinstance(v, str):
        return None
    v = refang(v).lower()
    if kind == "ip":
        v = re.sub(r":\d+$", "", v)
    elif kind == "domain":
        v = v.rstrip(".")
    elif kind == "url":
        v = v.rstrip(".,;)]")
    return v or None


def url_host(u: str) -> str:
    try:
        return (urlsplit(u).hostname or "").lower()
    except ValueError:
        return ""


_SUFFIX = re.compile(r"(ransomware|malware|backdoor|loader|stealer|infostealer|downloader|wiper|implant|"
                     r"beacon|rat|group|team|apt|family|framework|trojan)$")


def norm_name(s: str) -> str:
    s = re.sub(r"[^0-9a-z]", "", s.casefold())
    prev = None
    while s != prev and len(s) > 3:
        prev, s = s, _SUFFIX.sub("", s) or s
    return s


_Q = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-",
                    "—": "-", "‑": "-", " ": " ", "\u200b": ""})


def norm_quote(s: str) -> str:
    return re.sub(r"\s+", " ", s.translate(_Q).casefold()).strip()


def tech_match(a: str, b: str) -> bool:
    return a == b or a.split(".")[0] == b or b.split(".")[0] == a


# ------------------------------------------------------------------ helpers

def load_extract():
    sys.path.insert(0, str(ROOT))
    try:
        from osinthub.entities.extract import extract  # type: ignore
    except ImportError as e:
        print("ERROR: cannot import osinthub.entities.extract.extract "
              f"({e}).\nThe entities package must provide extract(text, url=None, use_llm=True) "
              "per the contract in okf/data/entities.md#extraction. Run from the repo with "
              "`uv run python tests/eval/score_extraction.py`.", file=sys.stderr)
        sys.exit(2)
    return extract


def load_reports(path: Path, only: list[str]) -> list[dict]:
    reps = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    return [r for r in reps if not only or r["id"] in only]


def ensure_cache(reps: list[dict], fetch: bool) -> list[dict]:
    ok = []
    for r in reps:
        _, tp = evalfetch.cache_paths(r["id"])
        if fetch:
            try:
                evalfetch.fetch_to_cache(r["id"], r["url"], force=True)
                print(f"  fetched {r['id']}")
            except evalfetch.Refused as e:
                print(f"  SKIP {r['id']}: site refused automated client ({e})", file=sys.stderr)
            except Exception as e:  # network down etc.: keep any older cache
                print(f"  fetch failed for {r['id']}: {e}", file=sys.stderr)
        if tp.exists():
            ok.append(r)
        else:
            print(f"  MISSING cache for {r['id']} (run with --fetch)", file=sys.stderr)
    return ok


def as_list(x) -> list:
    return x if isinstance(x, list) else []


def last_stats() -> dict:
    """extract.LAST_STATS right after a call (LLM seconds, chunks, gate counts), if loaded."""
    m = sys.modules.get("osinthub.entities.extract")
    return dict(getattr(m, "LAST_STATS", {}) or {})


def _jsonable(o):
    return sorted(o) if isinstance(o, (set, frozenset)) else list(o) if isinstance(o, tuple) else str(o)


def save_output(d: Path, rid: str, full: dict, body: dict | None) -> None:
    """DIR/<id>.json in the format load_output() and --from-outputs read."""
    rec = {"id": rid, "full": full}
    if body is not None:
        rec["body"] = body
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{rid}.json").write_text(json.dumps(rec, indent=1, ensure_ascii=False, default=_jsonable),
                                   encoding="utf-8")


def call(extract, text: str, url: str, use_llm: bool) -> tuple[dict, float, str | None]:
    t0 = time.perf_counter()
    try:
        out = extract(text, url=url, use_llm=use_llm)
        err = None if isinstance(out, dict) else f"extract returned {type(out).__name__}"
    except Exception:
        out, err = {}, traceback.format_exc(limit=3)
    return (out if isinstance(out, dict) else {}), time.perf_counter() - t0, err


# ------------------------------------------------------------------ scoring

def score_iocs(pred: dict, gold: dict, neutral: dict, acc: dict, detail: dict) -> None:
    piocs = pred.get("iocs") if isinstance(pred.get("iocs"), dict) else {}
    gold_hosts = {url_host(u) for u in gold.get("url", [])} - {""}
    for k in IOC_TYPES:
        g = {norm_ioc(k, v) for v in gold.get(k, [])} - {None}
        neu = {norm_ioc(k, v) for v in neutral.get(k, [])} - {None}
        p = {norm_ioc(k, v) for v in as_list(piocs.get(k))} - {None}
        if k in ("domain", "ip"):
            neu |= gold_hosts
        p_scored = {v for v in p if v in g or v not in neu}
        tp, fp, fn = p_scored & g, p_scored - g, g - p
        a = acc.setdefault(k, [0, 0, 0])
        a[0] += len(tp); a[1] += len(fp); a[2] += len(fn)
        if fp or fn:
            detail[k] = {"fp": sorted(fp), "fn": sorted(fn)}


def score_techs(pred: dict, gold: list[str], acc: list[int], detail: dict) -> None:
    p = _techs(pred)
    g = {t.upper() for t in gold}
    tp_p = {x for x in p if any(tech_match(x, y) for y in g)}
    tp_g = {y for y in g if any(tech_match(x, y) for x in p)}
    acc[0] += len(tp_p); acc[1] += len(p); acc[2] += len(tp_g); acc[3] += len(g)
    detail["tech_fp"] = sorted(p - tp_p)
    detail["tech_fn"] = sorted(g - tp_g)


def _techs(pred: dict, key: str = "techniques") -> set[str]:
    p = {str(t).strip().upper() for t in as_list(pred.get(key))}
    return {t for t in p if re.fullmatch(r"T\d{4}(\.\d{3})?", t)} | ({"<malformed>"} if any(
        not re.fullmatch(r"T\d{4}(\.\d{3})?", t) for t in p) else set())


def score_techs_body(pred: dict, gold: dict, acc: dict, detail: dict) -> None:
    """Score against gold.techniques_body: revoked ids mapped, Mobile ids counted apart."""
    rev = {k.upper(): v.upper() for k, v in (gold.get("revoked") or {}).items()}
    mp = lambda t: rev.get(t, t)  # noqa: E731
    p = {mp(t) for t in _techs(pred)}
    ent = [e for e in as_list(gold.get("techniques_body")) if isinstance(e, dict) and e.get("id")]
    body = [(mp(e["id"].upper()), e) for e in ent if not e.get("mobile")]
    mobile = [mp(e["id"].upper()) for e in ent if e.get("mobile")]
    rejected = {mp(str(e.get("id", "")).upper()) for e in as_list(gold.get("techniques_rejected"))}
    g_ids = {i for i, _ in body}
    tp_p = {x for x in p if any(tech_match(x, y) for y in g_ids)}
    fp = p - tp_p
    tp_g = {y for y in g_ids if any(tech_match(x, y) for x in p)}
    fn = g_ids - tp_g
    unsure_ids = {i for i, e in body if e.get("unsure")}
    sure_ids = g_ids - unsure_ids
    c = acc
    c["tp_p"] += len(tp_p); c["pred"] += len(p); c["tp_g"] += len(tp_g); c["gold"] += len(g_ids)
    c["tp_unsure"] += sum(1 for x in tp_p if not any(tech_match(x, y) for y in sure_ids))
    c["fn_unsure"] += len(fn & unsure_ids)
    c["unjudged"] += sum(1 for x in fp if x not in rejected and x != "<malformed>")
    c["mobile"] += len(set(mobile))
    c["mobile_found"] += sum(1 for y in set(mobile) if any(tech_match(x, y) for x in p))
    c["not_in_body_unsure"] += sum(1 for e in as_list(gold.get("techniques_not_in_body")) if e.get("unsure"))
    c["body_unsure"] += len(unsure_ids)
    table_ids = {i for i, e in body if not e.get("by")}  # vendor-table entries, not audit additions
    c["table_gold"] += len(table_ids)
    c["table_tp"] += len(tp_g & table_ids)
    detail["tech_body_fp"] = sorted(fp)
    detail["tech_body_fn"] = sorted(fn)
    detail["tech_body_unjudged"] = sorted(x for x in fp if x not in rejected and x != "<malformed>")


VENDOR_SHORT = {"The DFIR Report": "DFIR", "ESET": "ESET", "Microsoft Threat Intelligence": "Microsoft",
                "Recorded Future (Insikt Group)": "RF"}


def score_entities(pred: dict, gold_groups: list[list[str]]) -> tuple[int, int, list[str]]:
    names = {norm_name(str(n)) for n in as_list(pred.get("actors")) + as_list(pred.get("malware"))}
    names.discard("")
    found, missing = 0, []
    for grp in gold_groups:
        if any(norm_name(a) in names for a in grp):
            found += 1
        else:
            missing.append(grp[0])
    return found, len(gold_groups), missing


def bad_claims(pred: dict, text: str) -> list[dict]:
    nt = norm_quote(text)
    bad = []
    for c in as_list(pred.get("claims")):
        q = c.get("quote") if isinstance(c, dict) else None
        if not isinstance(q, str) or not q.strip() or norm_quote(q) not in nt:
            bad.append(c if isinstance(c, dict) else {"claim": c})
    return bad


def pr(tp: int, fp: int, fn: int) -> tuple[float, float]:
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return p, r


def load_output(d: Path, rid: str) -> tuple[dict, dict | None, float, list[str]] | None:
    """One saved extract() result pair: {"full": {"out", "seconds", "error"}, "body": {...}}."""
    p = d / f"{rid}.json"
    if not p.exists():
        return None
    o = json.loads(p.read_text(encoding="utf-8"))
    full, body = o.get("full") or {}, o.get("body")
    if body is None:  # the run found no body (marker missing): body metrics are skipped, as in a live run
        return (full.get("out") or {}), None, float(full.get("seconds") or 0), [e for e in [full.get("error")] if e]
    errs = [e for e in (full.get("error"), body.get("error")) if e]
    secs = float(full.get("seconds") or 0) + float(body.get("seconds") or 0)
    return (full.get("out") or {}), (body.get("out") or {}), secs, errs


def vendor_of(r: dict) -> str:
    v = r.get("vendor") or r["id"].split("-")[0]
    return VENDOR_SHORT.get(v, v)


def ratio(a: int, b: int) -> float:
    return a / b if b else 0.0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--no-llm", action="store_true", help="call extract(..., use_llm=False)")
    ap.add_argument("--fetch", action="store_true", help="(re)build tests/eval/cache from the report URLs first")
    ap.add_argument("--from-outputs", metavar="DIR",
                    help="score saved extract() outputs DIR/<id>.json instead of running the extractor")
    ap.add_argument("--save-outputs", metavar="DIR",
                    help="also write every extract() output to DIR/<id>.json (the --from-outputs format)")
    ap.add_argument("--reports", default=str(HERE / "reports.jsonl"))
    ap.add_argument("--only", nargs="*", default=[], help="score only these report ids")
    ap.add_argument("--json", help="write per-report results to this file")
    ap.add_argument("-v", "--verbose", action="store_true", help="print FP/FN per report")
    args = ap.parse_args()

    saved = Path(args.from_outputs) if args.from_outputs else None
    save_dir = Path(args.save_outputs) if args.save_outputs else None
    if saved is not None:
        if args.fetch or save_dir is not None:
            print("--fetch and --save-outputs do not combine with --from-outputs", file=sys.stderr)
            return 2
        reps = []
        for r in load_reports(Path(args.reports), args.only):
            if (saved / f"{r['id']}.json").exists():
                reps.append(r)
            else:
                print(f"  MISSING saved output for {r['id']} in {saved}", file=sys.stderr)
        if not reps:
            print(f"FAIL: no saved outputs to score in {saved}")
            return 2
        extract, use_llm = None, None
    else:
        reps = ensure_cache(load_reports(Path(args.reports), args.only), args.fetch)
        if not reps:
            print("FAIL: no cached reports to score (run with --fetch)")
            return 2
        extract = load_extract()
        use_llm = not args.no_llm

    ioc_acc: dict[str, list[int]] = {}
    tech_acc = [0, 0, 0, 0]  # vendor table: matched-pred, pred, matched-gold, gold
    vt_vendor: dict[str, list[int]] = {}
    body_keys = ("tp_p", "pred", "tp_g", "gold", "tp_unsure", "fn_unsure", "unjudged", "mobile", "mobile_found",
                 "not_in_body_unsure", "body_unsure", "table_gold", "table_tp")
    body_acc = dict.fromkeys(body_keys, 0)
    body_vendor: dict[str, dict] = {}
    ent_reports = ent_hits = ent_found = ent_total = 0
    n_bad_claims = n_claims = errors = 0
    claims_checked = 0
    marker_missing = []
    rows = []
    t_all = time.perf_counter()

    src = f"saved outputs in {saved}" if saved is not None else f"use_llm={use_llm}"
    print(f"Scoring {len(reps)} reports ({src})\n")
    print(f"{'report':32s} {'iocP':>5s} {'iocR':>5s} {'bP':>5s} {'bR':>5s} {'tP':>5s} {'tR':>5s} {'ent':>5s} "
          f"{'badQ':>4s} {'sec':>6s}")
    for r in reps:
        tpath = evalfetch.cache_paths(r["id"])[1]
        text = tpath.read_text(encoding="utf-8") if tpath.exists() else None
        gold = r["gold"]
        det: dict = {"id": r["id"]}
        if saved is not None:
            full_out, body_out, secs, errs = load_output(saved, r["id"])
            has_body = body_out is not None
            body_out = body_out or {}
            body = None
            if text is not None:
                cut = text.find(r["body_end_marker"])
                if cut < 0:
                    marker_missing.append(r["id"])
                body = text[:cut] if cut > 0 else None
        else:
            cut = text.find(r["body_end_marker"])
            if cut < 0:
                marker_missing.append(r["id"])
            body = text[:cut] if cut > 0 else None
            has_body = body is not None
            full_out, t1, e1 = call(extract, text, r["url"], use_llm)
            s1 = last_stats()
            body_out, t2, e2 = call(extract, body, r["url"], use_llm) if body else ({}, 0.0, None)
            s2 = last_stats() if body else {}
            secs, errs = t1 + t2, [e for e in (e1, e2) if e]
            if save_dir is not None:
                save_output(save_dir, r["id"], {"out": full_out, "seconds": round(t1, 3), "error": e1, "stats": s1},
                            {"out": body_out, "seconds": round(t2, 3), "error": e2, "stats": s2} if body else None)
        for e in errs:
            errors += 1
            det.setdefault("errors", []).append(e)

        rep_acc: dict[str, list[int]] = {}
        score_iocs(full_out, gold["iocs"], r.get("neutral", {}), rep_acc, det)
        for k, v in rep_acc.items():
            a = ioc_acc.setdefault(k, [0, 0, 0])
            for i in range(3):
                a[i] += v[i]
        rp, rr = pr(*(sum(v[i] for v in rep_acc.values()) for i in range(3)))

        vend = vendor_of(r)
        trow = [0, 0, 0, 0]
        brow = dict.fromkeys(body_keys, 0)
        if has_body:
            score_techs(body_out, gold["techniques"], trow, det)
            score_techs_body(body_out, gold, brow, det)
            vv = vt_vendor.setdefault(vend, [0, 0, 0, 0])
            bv = body_vendor.setdefault(vend, dict.fromkeys(body_keys, 0))
            for i in range(4):
                tech_acc[i] += trow[i]
                vv[i] += trow[i]
            for k in body_keys:
                body_acc[k] += brow[k]
                bv[k] += brow[k]
        nan = float("nan")
        tp_ = trow[0] / trow[1] if trow[1] else nan
        tr_ = trow[2] / trow[3] if trow[3] else nan
        bp_ = brow["tp_p"] / brow["pred"] if brow["pred"] else nan
        br_ = brow["tp_g"] / brow["gold"] if brow["gold"] else nan

        groups = gold.get("actors", []) + gold.get("malware", [])
        ent_s = "  -  "
        if groups and has_body:
            f, n, miss = score_entities(body_out, groups)
            ent_reports += 1; ent_found += f; ent_total += n
            ent_hits += f == n
            ent_s = f"{f}/{n}"
            if miss:
                det["entities_missing"] = miss
            det["pred_actors"] = as_list(body_out.get("actors"))
            det["pred_malware"] = as_list(body_out.get("malware"))

        n_claims += len(as_list(full_out.get("claims"))) + len(as_list(body_out.get("claims")))
        bad = []
        if text is not None:
            claims_checked += 1
            bad = bad_claims(full_out, text) + (bad_claims(body_out, body) if body else [])
        n_bad_claims += len(bad)
        if bad:
            det["bad_claims"] = bad[:5]
        det["seconds"] = round(secs, 1)
        rows.append(det)
        bq = f"{len(bad):4d}" if text is not None else "   -"
        print(f"{r['id'][:32]:32s} {rp:5.2f} {rr:5.2f} {bp_:5.2f} {br_:5.2f} {tp_:5.2f} {tr_:5.2f} {ent_s:>5s} "
              f"{bq} {secs:6.1f}")
        if args.verbose:
            for k in IOC_TYPES:
                if k in det:
                    print(f"    {k}: FP {det[k]['fp'][:8]}  FN {det[k]['fn'][:8]}")
            if has_body:
                print(f"    techniques (body) FP {det.get('tech_body_fp', [])}  FN {det.get('tech_body_fn', [])}"
                      f"  never adjudicated {det.get('tech_body_unjudged', [])}")
                print(f"    techniques (vendor table) FP {det.get('tech_fp', [])}  FN {det.get('tech_fn', [])}")
            if det.get("entities_missing"):
                print(f"    entities missing {det['entities_missing']}  got actors={det.get('pred_actors')} "
                      f"malware={det.get('pred_malware')}")
            for c in det.get("bad_claims", []):
                print(f"    claim quote not in text: {json.dumps(c, ensure_ascii=False)[:200]}")
            for e in det.get("errors", []):
                print(f"    ERROR: {e.strip().splitlines()[-1]}")

    # ---------------------------------------------------------------- summary
    print("\nIOCs (full page)            TP    FP    FN  precision  recall")
    tot = [0, 0, 0]
    for k in IOC_TYPES:
        a = ioc_acc.get(k, [0, 0, 0])
        for i in range(3):
            tot[i] += a[i]
        p, rc = pr(*a)
        print(f"  {k:24s} {a[0]:5d} {a[1]:5d} {a[2]:5d}   {p:7.3f}  {rc:6.3f}")
    ioc_p, ioc_r = pr(*tot)
    print(f"  {'overall':24s} {tot[0]:5d} {tot[1]:5d} {tot[2]:5d}   {ioc_p:7.3f}  {ioc_r:6.3f}")

    b = body_acc
    tech_p, tech_r = ratio(b["tp_p"], b["pred"]), ratio(b["tp_g"], b["gold"])
    vt_p, vt_r = ratio(tech_acc[0], tech_acc[1]), ratio(tech_acc[2], tech_acc[3])
    print("\nATT&CK techniques (body, appendix stripped)")
    print("  described in the body (bars apply; revoked ids mapped, Mobile ids apart):")
    print(f"    precision {tech_p:.3f} ({b['tp_p']}/{b['pred']}), recall {tech_r:.3f} ({b['tp_g']}/{b['gold']})")
    print(f"    recall over the vendor-table entries alone (no audit additions, so no bias from the extractor's "
          f"own proposals): {ratio(b['table_tp'], b['table_gold']):.3f} ({b['table_tp']}/{b['table_gold']})")
    print(f"    unsure: {b['tp_unsure']} matched predictions rest only on unsure entries, {b['fn_unsure']} of "
          f"{b['gold'] - b['tp_g']} misses are unsure ({b['body_unsure']} unsure body entries; "
          f"{b['not_in_body_unsure']} unsure 'not in body' exclusions)")
    print(f"    never adjudicated: {b['unjudged']} predictions that are neither in the body gold nor judged "
          "wrong (counted wrong)")
    print(f"    Mobile ids (scored apart; the extractor emits Enterprise ids only): {b['mobile_found']}/{b['mobile']}")
    print(f"  vendor table (gold.techniques, no bar): precision {vt_p:.3f} ({tech_acc[0]}/{tech_acc[1]}), "
          f"recall {vt_r:.3f} ({tech_acc[2]}/{tech_acc[3]})")
    print(f"\n  {'vendor':10s} {'n':>3s}  {'body P':>14s} {'body R':>14s} {'unjudged':>8s}  {'table P':>14s} "
          f"{'table R':>14s}")
    n_by_v: dict[str, int] = {}
    for r in reps:
        n_by_v[vendor_of(r)] = n_by_v.get(vendor_of(r), 0) + 1
    for v in sorted(body_vendor):
        bv, vv = body_vendor[v], vt_vendor[v]
        print(f"  {v:10s} {n_by_v[v]:3d}  {ratio(bv['tp_p'], bv['pred']):5.3f} {bv['tp_p']:3d}/{bv['pred']:<4d}"
              f" {ratio(bv['tp_g'], bv['gold']):5.3f} {bv['tp_g']:3d}/{bv['gold']:<4d} {bv['unjudged']:8d}  "
              f"{ratio(vv[0], vv[1]):5.3f} {vv[0]:3d}/{vv[1]:<4d} {ratio(vv[2], vv[3]):5.3f} {vv[2]:3d}/{vv[3]:<4d}")
    hit = ent_hits / ent_reports if ent_reports else 0.0
    print(f"\nActors+malware: all named entities found in {ent_hits}/{ent_reports} reports = {hit:.3f}; "
          f"entity recall {ent_found}/{ent_total}")
    if claims_checked == len(reps):
        print(f"Claims: {n_claims} total, {n_bad_claims} with quote not found in text")
    else:
        print(f"Claims: {n_claims} total; quotes checked for {claims_checked}/{len(reps)} reports only "
              "(no cached text for the rest)")
    if errors:
        print(f"Extractor errors: {errors} (counted as empty output)")
    if marker_missing:
        print(f"WARNING: body_end_marker not found (body metrics skipped): {marker_missing}")
    print(f"Elapsed {time.perf_counter() - t_all:.0f}s")

    checks = [
        ("IOC precision", ioc_p, BARS["ioc_p"]), ("IOC recall", ioc_r, BARS["ioc_r"]),
        ("technique precision", tech_p, BARS["tech_p"]), ("technique recall", tech_r, BARS["tech_r"]),
        ("actor/malware hit rate", hit, BARS["entity_hit"]),
    ]
    ok = True
    print("\n  (technique bars are applied to the 'described in the body' measure)")
    for name, v, bar in checks:
        good = v >= bar
        ok &= good
        print(f"  {'ok  ' if good else 'FAIL'} {name:24s} {v:.3f} (bar {bar})")
    if claims_checked:
        good = n_bad_claims == 0
        ok &= good
        print(f"  {'ok  ' if good else 'FAIL'} {'claims w/o quote in text':24s} {n_bad_claims} (bar 0)"
              + ("" if claims_checked == len(reps) else f" ({claims_checked}/{len(reps)} reports checked)"))
    else:
        print("  skip claims w/o quote in text (no cached text to check against)")
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=1, ensure_ascii=False))
    print("\nPASS" if ok else "\nFAIL", "(--no-llm)" if args.no_llm else "")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
