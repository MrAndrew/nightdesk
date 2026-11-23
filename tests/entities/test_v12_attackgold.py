"""The 2026-11-19 ATT&CK re-adjudication: the "described in the body" scoring in tests/eval/score_extraction.py,
--from-outputs, and the shape of the added gold in tests/eval/reports.jsonl (built by private/tools/attack_gold.py).

No network, no extractor, no model: the scorer runs on synthetic saved outputs.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EVAL = ROOT / "tests" / "eval"
sys.path.insert(0, str(EVAL))
import score_extraction as se  # noqa: E402

REPORTS = [json.loads(l) for l in (EVAL / "reports.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
TID = re.compile(r"T\d{4}(\.\d{3})?")


def _acc():
    return dict.fromkeys(("tp_p", "pred", "tp_g", "gold", "tp_unsure", "fn_unsure", "unjudged", "mobile",
                          "mobile_found", "not_in_body_unsure", "body_unsure", "table_gold", "table_tp"), 0)


GOLD = {
    "techniques": ["T1574.002", "T1059.001", "T1406", "T1518"],
    "techniques_body": [
        {"id": "T1574.002"}, {"id": "T1059.001", "unsure": True}, {"id": "T1406", "mobile": True},
        {"id": "T1082", "by": "audit-2026-11-19", "tier": "confirmed", "quote": "systeminfo"},
    ],
    "techniques_not_in_body": [{"id": "T1518", "unsure": True}],
    "techniques_rejected": [{"id": "T1055", "cat": "A"}],
    "revoked": {"T1574.002": "T1574.001"},
}


def test_body_measure_maps_revoked_and_sets_mobile_apart():
    acc, det = _acc(), {}
    # T1574.001 is the v20 replacement of the table's revoked T1574.002; T1059 is the parent of an unsure entry;
    # T1055 was judged wrong; T1046 was never adjudicated.
    se.score_techs_body({"techniques": ["T1574.001", "T1059", "T1082", "T1055", "T1046"]}, GOLD, acc, det)
    assert (acc["tp_p"], acc["pred"], acc["tp_g"], acc["gold"]) == (3, 5, 3, 3)
    assert acc["mobile"] == 1 and acc["mobile_found"] == 0
    assert acc["unjudged"] == 1 and det["tech_body_unjudged"] == ["T1046"]
    assert acc["tp_unsure"] == 1  # T1059 matches only the unsure T1059.001
    assert acc["body_unsure"] == 1 and acc["not_in_body_unsure"] == 1
    assert (acc["table_tp"], acc["table_gold"]) == (2, 2)  # the B addition is not a table entry
    # the vendor-table measure is unchanged: no revoked mapping, Mobile and G ids count
    t = [0, 0, 0, 0]
    se.score_techs({"techniques": ["T1574.001", "T1059", "T1082", "T1055", "T1046"]}, GOLD["techniques"], t, {})
    assert t == [1, 5, 1, 4]


def test_misses_count_unsure():
    acc, det = _acc(), {}
    se.score_techs_body({"techniques": []}, GOLD, acc, det)
    assert acc["tp_g"] == 0 and acc["gold"] == 3 and acc["fn_unsure"] == 1
    assert det["tech_body_fn"] == ["T1059.001", "T1082", "T1574.001"]


def test_from_outputs_scores_saved_results_without_extractor(tmp_path):
    rep = {"id": "x-test", "url": "https://example.com/r", "vendor": "ESET", "title": "t", "published": "2026-01-01",
           "body_end_marker": "\nIoCs\n",
           "gold": {"iocs": {"ip": ["192.0.2.10"], "domain": ["bad.example.net"]}, "actors": [["Example Panda"]],
                    "malware": [], **GOLD}, "neutral": {}}
    (tmp_path / "reports.jsonl").write_text(json.dumps(rep) + "\n")
    out = tmp_path / "out"
    out.mkdir()
    body = {"iocs": {}, "techniques": ["T1574.001", "T1082", "T1046"], "actors": ["Example Panda"], "malware": []}
    full = {"iocs": {"ip": ["192.0.2.10"], "domain": ["bad.example.net"]}, "claims": []}
    (out / "x-test.json").write_text(json.dumps({"id": "x-test", "full": {"out": full, "seconds": 1.0, "error": None},
                                                 "body": {"out": body, "seconds": 2.0, "error": None}}))
    empty = tmp_path / "cache"
    empty.mkdir()
    env = {"ND_EVAL_CACHE": str(empty), "PATH": "/usr/bin:/bin"}
    p = subprocess.run([sys.executable, "-I", str(EVAL / "score_extraction.py"), "--reports",
                        str(tmp_path / "reports.jsonl"), "--from-outputs", str(out), "--json", str(tmp_path / "r.json")],
                       capture_output=True, text=True, env=env, timeout=60)
    assert p.returncode == 1, p.stdout + p.stderr  # body recall 2/3 passes, precision 2/3 fails the 0.70 bar
    assert "described in the body" in p.stdout and "vendor table" in p.stdout
    assert "precision 0.667 (2/3), recall 0.667 (2/3)" in p.stdout
    assert "never adjudicated: 1" in p.stdout
    assert "skip claims" in p.stdout  # no cached text: the claims check is skipped, not passed silently
    rows = json.loads((tmp_path / "r.json").read_text())
    assert rows[0]["tech_body_unjudged"] == ["T1046"]


def test_evalfetch_cache_env(tmp_path):
    code = "import sys; sys.path.insert(0, sys.argv[1]); import evalfetch; print(evalfetch.CACHE)"
    p = subprocess.run([sys.executable, "-I", "-c", code, str(EVAL)], capture_output=True, text=True,
                       env={"ND_EVAL_CACHE": str(tmp_path), "PATH": "/usr/bin:/bin"}, timeout=60)
    assert p.stdout.strip() == str(tmp_path)
    p = subprocess.run([sys.executable, "-I", "-c", code, str(EVAL)], capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin"}, timeout=60)
    assert p.stdout.strip() == str(EVAL / "cache")


def test_reports_gold_shape():
    c = Counter()
    for r in REPORTS:
        g = r["gold"]
        table = [t.upper() for t in g["techniques"]]
        body = g["techniques_body"]
        from_table = [e["id"] for e in body if not e.get("by")]
        added = [e for e in body if e.get("by")]
        not_in = [e["id"] for e in g["techniques_not_in_body"]]
        # every vendor-table id is either described in the body or listed as not in it, never both
        assert sorted(from_table + not_in) == sorted(set(table)), r["id"]
        for e in added:
            assert e["by"] == "audit-2026-11-19" and e["tier"] in ("confirmed", "suggested"), (r["id"], e)
            assert TID.fullmatch(e["id"]) and e["id"] not in table, (r["id"], e)
            assert 0 < len(e["quote"]) <= 250 and "\n" not in e["quote"], (r["id"], e)  # short, one sentence
        assert set(g["revoked"]) <= set(table) and all(TID.fullmatch(v) for v in g["revoked"].values())
        for e in g["techniques_rejected"]:
            assert e["cat"] in "ACDE" and e["id"] not in table, (r["id"], e)
        c["table"] += len(table)
        c["B"] += len(added)
        c["mobile"] += sum(1 for e in body if e.get("mobile"))
        c["G"] += len(not_in)
        c["revoked"] += len(g["revoked"])
    # the audit's counts (REPORT.md): 598 table ids, 63 not in the body, 18 Mobile, 13 revoked, 104 + 60 B
    assert c == Counter(table=598, B=164, mobile=18, G=63, revoked=13)


def test_attack_gold_script_is_stdlib_and_offline():
    script = ROOT / "private" / "tools" / "attack_gold.py"
    if not script.exists():   # a skipif mark would not survive tests/conftest.py's child processes
        pytest.skip("the lab script is in the development repo only")
    src = script.read_text()
    spec = importlib.util.find_spec("evalfetch")
    assert spec is not None
    assert "fetch(" not in src.replace("evalfetch", "")  # it only reads the cache location
    imports = set(re.findall(r"^(?:from|import) ([a-z_]+)", src, re.M))
    assert imports <= {"__future__", "argparse", "json", "re", "sys", "pathlib", "evalfetch"}, imports
