"""Technique extraction ignores defender text (osinthub/entities/defender.py, fix round 3, lane attackdefender).

Defender sections (hunting, detections, mitigations) and their KQL, and analyst procedure ("To deobfuscate ..., it's
necessary to") must not produce techniques, from the cues, the procedure-example proposals or the model's quotes,
while attacker sentences next to them still do and IOCs are unchanged. Also the scorer's --save-outputs.

Short invented texts, documentation addresses only; a tiny ATT&CK bundle written here; no model, no network.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from _lake import make_lake
LAKE = make_lake("attackdefender")

from osinthub.entities import defender as D  # noqa: E402
from osinthub.entities import extract as X  # noqa: E402
from osinthub.entities import procvec, refdata  # noqa: E402
from osinthub.entities.iocs import extract_iocs  # noqa: E402
from osinthub.entities.techcues import cue_techniques  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
TECHS = {"T1566": "Phishing", "T1566.001": "Spearphishing Attachment", "T1053": "Scheduled Task/Job",
         "T1053.005": "Scheduled Task", "T1569": "System Services", "T1569.002": "Service Execution",
         "T1140": "Deobfuscate/Decode Files or Information", "T1083": "File and Directory Discovery",
         "T1571": "Non-Standard Port", "T1518": "Software Discovery", "T1518.001": "Security Software Discovery",
         "T1059": "Command and Scripting Interpreter", "T1059.005": "Visual Basic",
         "T1033": "System Owner/User Discovery", "T1056.001": "Keylogging", "T1113": "Screen Capture",
         "T1218": "System Binary Proxy Execution", "T1218.011": "Rundll32", "T1490": "Inhibit System Recovery",
         "T1057": "Process Discovery", "T1486": "Data Encrypted for Impact", "T1497": "Virtualization/Sandbox Evasion",
         "T1547": "Boot or Logon Autostart Execution", "T1547.001": "Registry Run Keys / Startup Folder",
         "T1003": "OS Credential Dumping", "T1003.001": "LSASS Memory", "T1059.003": "Windows Command Shell"}


def _ref_dir() -> Path:
    d = Path(LAKE) / "fixture-ref"
    d.mkdir(exist_ok=True)
    objs = [{"type": "attack-pattern", "id": f"attack-pattern--{i:08d}-0000-4000-8000-000000000000", "name": n,
             "external_references": [{"source_name": "mitre-attack", "external_id": t,
                                      "url": "https://attack.mitre.org/techniques/" + t.replace(".", "/")}]}
            for i, (t, n) in enumerate(TECHS.items())]
    (d / "enterprise-attack.json").write_text(json.dumps({"type": "bundle", "id": "bundle--1", "objects": objs}))
    return d


refdata.REF = _ref_dir()
refdata.reload()

ATTACKER = "The attackers sent spearphishing emails with a malicious attachment to finance staff."
SHA = SHA256_HEX = "9f2c4be1d03a5e67b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5"
HUNTING = """Advanced hunting

Use this query to find scheduled task creation and PsExec use linked to this activity.

DeviceProcessEvents
| where FileName =~ "schtasks.exe" or ProcessCommandLine has "psexec"
| where SHA256 == "9f2c4be1d03a5e67b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5" or RemotePort in (80, 445, 636, 88)
| project Timestamp, DeviceName, ProcessCommandLine
"""


def techs(text: str) -> list[str]:
    return X.extract(text, use_llm=False)["techniques"]


class HuntingSectionAndQuery(unittest.TestCase):
    def test_hunting_section_with_kql_yields_nothing(self):
        text = f"Attack chain\n\n{ATTACKER}\n\n{HUNTING}"
        got = techs(text)
        self.assertIn("T1566.001", got)
        self.assertNotIn("T1053.005", got)          # schtasks only in the query
        self.assertNotIn("T1569.002", got)          # PsExec only in the hunting text

    def test_bare_query_yields_nothing(self):
        q = HUNTING.split("\n\n", 2)[2]
        self.assertEqual(techs(q), [])
        self.assertTrue(all(why == "code" for _, _, why in D.defender_spans(q)))

    def test_attacker_text_after_a_reset_heading_is_read_again(self):
        text = (f"{HUNTING}\nMITRE ATT&CK techniques\n\n"
                "The operators created a scheduled task with schtasks to relaunch the loader.\n")
        self.assertIn("T1053.005", techs(text))

    def test_menu_entries_do_not_open_a_section(self):
        # a site menu or table of contents lists "Threat Hunting" / "Detections" between other short links
        text = ("Threat Hunting\n\nDetection Pack\n\nAbout us\n\nContact\n\nCase Summary\n\n"
                "The operators created a scheduled task with schtasks to relaunch the loader every hour.\n")
        self.assertIn("T1053.005", techs(text))
        self.assertEqual(D.defender_spans(text), [])

    def test_iocs_are_unchanged(self):
        text = f"{ATTACKER} The loader exploited CVE-2024-21412 on the mail gateway.\n\n{HUNTING}"
        out = X.extract(text, use_llm=False)
        self.assertEqual(out["iocs"], extract_iocs(text))
        self.assertIn(SHA, out["iocs"]["sha256"])     # the hash inside the hunting query is still an IOC
        self.assertIn("CVE-2024-21412", [c.upper() for c in out["iocs"]["cve"]])


class AdviceAndAnalystSentences(unittest.TestCase):
    def test_advice_inside_a_defender_section_yields_nothing(self):
        text = ("Mitigation and protection guidance\n\nVerify that Microsoft Defender Antivirus cloud-delivered "
                "protection is enabled to stop schtasks abuse.\n\nTurn on tamper protection so PsExec cannot stop the "
                "security service.\n")
        self.assertEqual(techs(text), [])

    def test_advice_outside_a_section_is_left_alone(self):
        # Known limit, by design (owner, 2026-11-19: keep the filter simple): only sections, query code and the
        # audit's analyst phrases are masked, so a lone advice sentence in the narrative is still read.
        line = "Organizations should monitor scheduled task creation by schtasks."
        self.assertEqual(D.defender_spans(line), [])

    def test_malware_command_tables_are_kept(self):
        # capability lists describe the malware in the imperative; they are attacker text
        for line, tid in (("Configure the driver to create a scheduled task for the specified service.", "T1053.005"),
                          ("Enable the keylogger and send keystrokes to the C2 server.", "T1056.001"),
                          ("Run whoami and send the output back.", "T1033")):
            if tid in X.catalog().tech_name:
                self.assertIn(tid, techs(line), line)
            self.assertEqual(D.defender_spans(line), [], line)

    def test_narrative_use_of_is_kept(self):
        self.assertIn("T1569.002", techs("Use of PsExec was observed on three hosts in the network."))
        self.assertEqual(D.defender_spans("Use of PsExec was observed on three hosts in the network."), [])

    def test_analyst_procedure_yields_nothing(self):
        for line in ("To deobfuscate the command line, it's necessary to:",
                     "To deobfuscate the command line, it’s necessary to reverse the string first.",
                     "This payload can be deobfuscated using the following CyberChef recipe:",
                     "Once deobfuscated, we can spot the header of the beacon.",
                     "The first-stage script has been deobfuscated and refactored for readability."):
            self.assertEqual(techs(line), [], line)
        self.assertEqual(techs("The loader deobfuscates its payload in memory before it runs it."), ["T1140"])


# The round-1 evaluator's repro texts (evals/attackdefender-r1.md): attacker text that must keep every technique the
# cues find in the unfiltered text. (text, techniques that must be found, spans expected)
EVAL_R1 = [
    # 1. list items never open a section
    ("Overview\n\nThe backdoor supports these features:\n\n- Keylogging\n- Protection\n- Screenshots\n\nThe backdoor "
     "also launches rundll32.exe to load its second stage from the user's temp folder.\n\nLater, the operators used "
     "PsExec to move to the file server and ran vssadmin to delete shadow copies.\n",
     {"T1056.001", "T1113", "T1218.011", "T1490", "T1569.002"}),
    ("Overview\n\nThe backdoor supports these features:\n\n- Keylogging\n- Detections\n- Hunting\n- Recommendations\n"
     "- Remediation\n\nThe backdoor also launches rundll32.exe to load its second stage from the temp folder.\n",
     {"T1056.001", "T1218.011"}),
    # 2. headings an attacker write-up uses
    ("Technical analysis\n\nDetection and anti-analysis\n\nThe loader checks for installed antivirus products and "
     "exits "
     "if any are found in the process list.\n\nThe operators then ran vssadmin delete shadows /all /quiet to remove "
     "backups before encrypting the files.\n", {"T1057", "T1486", "T1490", "T1497", "T1518.001"}),
    ("Security measures\n\nThe implant uses rundll32.exe to load an encrypted DLL and stores its configuration under "
     "the Run key in the registry.\n", {"T1218.011", "T1547.001"}),
    ("Threat hunting\n\nDuring our threat hunting we found that the operators used rundll32.exe and PsExec on the "
     "servers.\n", {"T1218.011", "T1569.002"}),
    ("Recommendations\n\nWe identified the following steps the operators took during the intrusion.\n\nSecond stage"
     "\n\nThe operators used PsExec and created a scheduled task on each host.\n", {"T1053.005", "T1569.002"}),
    # 3. sentence rules
    ("To ensure persistence, it is copied to the Startup folder and registered as a scheduled task.\n",
     {"T1053.005", "T1547.001"}),
    ("To move laterally, we can see that the actor used PsExec against three servers.\n", {"T1569.002"}),
    ("The backdoor accepts these commands. Check for installed antivirus products. Run a command with cmd.exe /c and "
     "return the output.\n", {"T1518.001", "T1059.003"}),
    ("Update your browser to continue, the lure page said, before dropping a VBScript downloader.\n", {"T1059.005"}),
    # 4. attacker JavaScript and a stray Sigma key
    ("The deobfuscated script:\n\nlet c = 'schtasks /create /tn upd /tr payload.exe';\nlet d = c + ' /sc onlogon';\n"
     "// run it\nWScript.Shell.Run(c);\n", {"T1053.005"}),
    ("The operators deployed a scheduled task.\n\ndetection:\n\ndescription: the malware uses rundll32.exe to run its "
     "DLL\n", {"T1053.005", "T1218.011"}),
]


class EvaluatorRound1(unittest.TestCase):
    def test_attacker_texts_keep_every_cue_technique(self):
        for text, must in EVAL_R1:
            unfiltered = {t for t in cue_techniques(text) if t in X.catalog().tech_name}
            got = set(techs(text))
            self.assertEqual(got, unfiltered, text)
            self.assertLessEqual(must, got, text)

    def test_stray_sigma_key_marks_only_its_own_line(self):
        text = EVAL_R1[-1][0]
        spans = D.defender_spans(text)
        self.assertEqual([text[a:b] for a, b, _ in spans], ["detection:"])

    def test_an_analyst_sentence_never_takes_the_next_sentence(self):
        for text, tid, kept in (
                ("Once deobfuscated, we can see the URL. Émotet then used rundll32.exe to load its DLL from the "
                 "temp folder.\n", "T1218.011", "Émotet then used rundll32.exe"),
                ("Once deobfuscated, we can see the URL. rundll32.exe was then used to load the DLL from the temp "
                 "folder.\n", "T1218.011", "rundll32.exe was then used"),
                ("Once deobfuscated, we can see the URL。rundll32.exe was then used to load the DLL from the temp "
                 "folder.\n", "T1218.011", "rundll32.exe was then used")):
            self.assertEqual(techs(text), [tid], text)
            self.assertIn(kept, D.mask(text))
            self.assertNotIn("Once deobfuscated", D.mask(text))


class SectionsOpenAndClose(unittest.TestCase):
    def test_a_weak_section_ends_at_the_next_heading_with_text(self):
        text = ("Protection and Mitigation\n\nUse Microsoft Defender for Endpoint to block PsExec and schtasks on "
                "servers.\n\nRestrict scheduled task creation to administrators.\n\nSecond stage\n\n"
                "The operators then used rundll32.exe to load the DLL from the temp folder.\n")
        self.assertEqual(techs(text), ["T1218.011"])

    def test_detections_with_rule_names_yield_nothing(self):
        rules = ("Detections\n\nNetwork\n\nET POLICY PsExec service created\nET POLICY SMB Executable File Transfer\n"
                 "\nSigma\n\nSuspicious Scheduled Task Creation 5cc90652-4cbd-4241-aa3b-4b462fa5a248\n")
        self.assertEqual(techs(rules), [])

    def test_section_closes_at_a_heading_with_attacker_prose(self):
        text = (f"{HUNTING}\nLateral movement\n\n"
                "The operators then used PsExec to run the payload on three more servers in the network.\n")
        self.assertEqual(techs(text), ["T1569.002"])

    def test_subheadings_with_advice_or_queries_stay_in_the_section(self):
        text = ("Mitigation and protection guidance\n\nMicrosoft recommends the following mitigations.\n\n"
                "Immediate actions\n\nTurn on tamper protection and block PsExec on servers.\n\n"
                "Possible scheduled-task persistence\n\nFind scheduled-task creation events from the last 30 days.\n\n"
                "DeviceEvents\n| where ActionType == \"ScheduledTaskCreated\"\n")
        self.assertEqual(techs(text), [])
        self.assertEqual({w for _, _, w in D.defender_spans(text)}, {"section: Mitigation and protection guidance"})


class EvaluatorRound2(unittest.TestCase):
    def test_attacker_tables_are_not_query_code(self):
        # trafilatura writes HTML tables as Markdown rows; a row may start with a KQL/SPL word
        text = ("| Top | Command |\n| --- | --- |\n| Count | schtasks /create /tn upd /tr payload.exe |\n"
                "| Search | rundll32.exe payload.dll,Start |\n")
        self.assertEqual(D.defender_spans(text), [])
        self.assertIn("T1053.005", techs(text))

    def test_many_sigma_rules_are_fast(self):
        import time
        rule = "title: r\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Image: x\n  condition: sel\n"
        text = rule * 2000
        t0 = time.monotonic()
        D.defender_spans(text)
        self.assertLess(time.monotonic() - t0, 2.0)


R3_PREFIX = ("Recommendations\n\nMonitor for unusual rundll32.exe executions and alert on new services created by "
             "PsExec.\n\n")
R3_NARR = ("The loader then disabled real-time monitoring with Set-MpPreference, launched rundll32.exe to load its DLL, "
           "used PsExec to move to the domain controller and ran vssadmin to delete shadow copies.\n")


class EvaluatorRound3(unittest.TestCase):
    def test_weak_sections_close_at_any_heading_with_text_under_it(self):
        must = {"T1218.011", "T1490", "T1569.002"}
        for mid in ("Second wave\n\n", "macOS variant\n\n", "njRAT payload\n\n", "What happened next?\n\n",
                    "Tampering with Microsoft Defender\n\n", "Network\n\n", "Files\n\n",
                    "Second wave\n\nThe loader hijacks the COM object {3f2504e0-4f89-11d3-9a0c-0305e82c3301} and ",
                    "Persistence mechanism\n\nThe implant creates the mutex 6b29fc40-ca47-1067-b31d-00dd010662da so "
                    "only one copy runs, and ",
                    "Second wave\n\nThe loader ran next.\n\n",
                    "Second wave\n\ncmd.exe /c schtasks /create /tn upd /tr C:\\Users\\Public\\upd.exe /sc onlogon\n\n",
                    "Second wave\n\n- Loader runs\n- DLL loads\n\n"):
            text = R3_PREFIX + mid + R3_NARR
            self.assertLessEqual(must, set(techs(text)), mid)

    def test_one_column_tables_are_not_query_code(self):
        for text in (
                "The operators sent the following commands to the backdoor within minutes of the first callback from "
                "the host.\n| take: Take a screenshot of the desktop |\n| persist: Create a scheduled task named upd "
                "running rundll32.exe |\nAfterwards the operators used PsExec to move to the file server.",
                "Commands:\n| Backdoor commands |\n|---|\n| search - search the disk and exfiltrate documents |\n"
                "| persist - create a scheduled task named upd |\n"):
            self.assertEqual(D.defender_spans(text), [], text)
            self.assertIn("T1053.005", techs(text))

    def test_rule_listings_stay_inside_a_detections_section(self):
        text = ("Detections\n\nSigma\n\nhttps://github.com/SigmaHQ/sigma/blob/master/rules/x.yml\n"
                "Potential Recon Activity Via Nltest.EXE id: 5cc90652-4cbd-4241-aa3b-4b462fa5a248\n\nYara\n\n"
                "/*\nYARA Rule Set\n*/\nrule x_1 {\nmeta:\ndescription = \"files - schtasks loader\"\nstrings:\n"
                "$s1 = \"schtasks /create\" ascii\ncondition:\nall of them\n\nMITRE\n\nScheduled Task – T1053.005\n")
        spans = D.defender_spans(text)
        self.assertTrue(spans, "the Sigma and YARA listings are a defender section")
        cut = text[:text.index("MITRE")]
        masked = D.mask(text)
        self.assertNotIn("schtasks", masked[:len(cut)])
        self.assertIn("MITRE", masked)


class MaskShape(unittest.TestCase):
    def test_mask_keeps_offsets_and_lines(self):
        # a defender section runs to the next reset heading or the end, so the mixed line comes first
        text = f"{ATTACKER}\nOnce deobfuscated, we can see the URL. The actor ran whoami.\n\n{HUNTING}"
        m = D.mask(text)
        self.assertEqual(len(m), len(text))
        self.assertEqual([i for i, c in enumerate(m) if c == "\n"], [i for i, c in enumerate(text) if c == "\n"])
        self.assertIn(ATTACKER, m)
        self.assertIn("The actor ran whoami.", m)
        self.assertNotIn("DeviceProcessEvents", m)
        self.assertNotIn("Once deobfuscated", m)

    def test_norm_flags_align_with_source(self):
        text = f"  {ATTACKER}\n\n\t{HUNTING}  "
        norm, flags = D.norm_flags(text, D.defender_spans(text))
        self.assertEqual(norm, X.Source(text).norm)
        self.assertEqual(len(flags), len(norm))
        i = norm.find("DeviceProcessEvents")
        self.assertTrue(D.mostly_defender(norm, flags, i, i + 40))
        self.assertFalse(D.mostly_defender(norm, flags, 0, len(ATTACKER)))


class ProposalsAndModelQuotes(unittest.TestCase):
    """The procedure-example proposals never see defender sentences; model quotes from them are dropped."""
    TEXT = (f"Attack chain\n\n{ATTACKER} The implant later listed the user's home folder and its documents to "
            f"find files worth stealing.\n\n{HUNTING}\n"
            "Verify that Microsoft Defender Antivirus cloud-delivered protection is enabled on every endpoint.\n")

    def run_extract(self, techniques):
        seen: list[str] = []

        def neighbours(texts, *a, **k):
            seen.extend(texts)
            out = []
            for t in texts:
                if "home folder" in t:
                    out.append([("T1083", 0.9)] * 10)
                elif re.search(r"Defender|DeviceProcessEvents|hunting", t):
                    out.append([("T1518.001", 0.9)] * 10)
                else:
                    out.append([("T1033", 0.1)] * 10)
            return out

        raw = {"actors": [], "malware": [], "tools": [], "campaigns": [], "victims": [], "sectors": [],
               "countries": [], "techniques": techniques, "claims": []}
        with mock.patch.object(X, "llm_extract", return_value=raw), \
                mock.patch.object(procvec, "load", return_value={"m": None, "tid": None}), \
                mock.patch.object(procvec, "neighbours", side_effect=neighbours):
            return X.extract(self.TEXT), seen

    def test_no_proposal_from_defender_sentences(self):
        out, seen = self.run_extract([])
        self.assertIn("T1083", out["techniques"])               # proposed by the attacker sentence
        self.assertNotIn("T1518.001", out["techniques"] + out["suggested_techniques"])
        self.assertTrue(seen)
        self.assertFalse([t for t in seen if re.search(r"Defender|DeviceProcessEvents|Advanced hunting", t)], seen)

    def test_model_quote_in_hunting_query_is_dropped(self):
        out, _ = self.run_extract([
            {"name": "Non-Standard Port", "id": "T1571", "quote": "RemotePort in (80, 445, 636, 88)"},
            {"name": "Spearphishing Attachment", "id": "T1566.001",
             "quote": "sent spearphishing emails with a malicious attachment"}])
        allt = out["techniques"] + out["suggested_techniques"]
        self.assertNotIn("T1571", allt)
        self.assertIn("T1566.001", allt)
        self.assertEqual(X.LAST_STATS["dropped_defender"], 1)


class ScorerSaveOutputs(unittest.TestCase):
    def test_save_outputs_round_trips_through_from_outputs(self):
        tmp = Path(LAKE).parent / "scorer"
        cache, saved = tmp / "cache", tmp / "saved"
        cache.mkdir(parents=True)
        body = (f"{ATTACKER} The operators ran schtasks to create a scheduled task. The loader exploited "
                "CVE-2024-21412.\n\n")
        (cache / "x-test.txt").write_text(body + f"\nIoCs\n{SHA}\n", encoding="utf-8")
        (cache / "y-test.txt").write_text(body, encoding="utf-8")       # no body marker: "body" left out
        gold = {"iocs": {"cve": ["CVE-2024-21412"], "sha256": [SHA]}, "actors": [], "malware": [],
                "techniques": ["T1053.005"], "techniques_body": [{"id": "T1053.005"}],
                "techniques_not_in_body": [], "techniques_rejected": [], "revoked": {}}
        reps = [{"id": i, "url": f"https://example.com/{i}", "vendor": "ESET", "title": "t",
                 "published": "2026-01-01", "body_end_marker": "\nIoCs\n", "gold": gold, "neutral": {}}
                for i in ("x-test", "y-test")]
        (tmp / "reports.jsonl").write_text("".join(json.dumps(r) + "\n" for r in reps))
        env = {"ND_EVAL_CACHE": str(cache), "PATH": "/usr/bin:/bin", "OSINTHUB_OFFLINE": "1",
               "OSINTHUB_LAKE": str(LAKE), "AI_URL": "http://127.0.0.1:9"}
        base = [sys.executable, "-I", str(ROOT / "tests" / "eval" / "score_extraction.py"), "--reports",
                str(tmp / "reports.jsonl")]
        live = subprocess.run(base + ["--no-llm", "--save-outputs", str(saved), "--json", str(tmp / "a.json")],
                              capture_output=True, text=True, env=env, timeout=120)
        self.assertIn(live.returncode, (0, 1), live.stdout + live.stderr)
        rec = json.loads((saved / "x-test.json").read_text())
        self.assertEqual(set(rec), {"id", "full", "body"})
        self.assertEqual(set(rec["body"]), {"out", "seconds", "error", "stats"})
        self.assertIn(SHA, rec["full"]["out"]["iocs"]["sha256"])
        self.assertNotIn("body", json.loads((saved / "y-test.json").read_text()))
        back = subprocess.run(base + ["--from-outputs", str(saved), "--json", str(tmp / "b.json")],
                              capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(back.returncode, live.returncode, back.stdout + back.stderr)

        def summary(s):   # everything after the per-report table, minus timing
            s = s[s.index("IOCs (full page)"):]
            return [l for l in s.splitlines() if not l.startswith(("Elapsed", "PASS", "FAIL"))]
        self.assertEqual(summary(live.stdout), summary(back.stdout))
        def rows(p):
            return [{k: v for k, v in r.items() if k != "seconds"} for r in json.loads(p.read_text())]
        self.assertEqual(rows(tmp / "a.json"), rows(tmp / "b.json"))
        bad = subprocess.run(base + ["--from-outputs", str(saved), "--save-outputs", str(tmp / "x")],
                             capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(bad.returncode, 2)


if __name__ == "__main__":
    unittest.main()
