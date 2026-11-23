"""Unit tests for entity extraction precision rules (stdlib unittest; no LLM, no network).

The ATT&CK / MISP reference data comes from a small checked-in fixture (tests/entities/fixtures/ref/:
APT28 as an ATT&CK intrusion set and a MISP threat actor), not from the lake, so any lake works:

    uv run --with pytest pytest tests/entities/test_extract.py -q
"""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from _lake import make_lake
LAKE = make_lake("entities-extract")

from osinthub.entities import extract as X  # noqa: E402
from osinthub.entities import procvec, refdata  # noqa: E402
from osinthub.entities.iocs import extract_iocs  # noqa: E402

refdata.REF = Path(__file__).resolve().parent / "fixtures" / "ref"
refdata.reload()


class VersionNumbersAreNotIPs(unittest.TestCase):
    def test_version_cues(self):
        for t in ("Update to version 8.0.5.2 now.", "Honeygain SDK 8.0.5.2 was bundled.",
                  "Chrome Remote Desktop 8.0.5.2 and later are affected.", "This was fixed in 8.0.5.2.",
                  "Install KB 10.0.19041.2 first.", "Firmware 1.2.10.4 adds support."):
            self.assertEqual(extract_iocs(t)["ip"], [], t)

    def test_small_octets_without_ioc_context(self):
        self.assertEqual(extract_iocs("Honeygain 8.0.5.2 shipped last week.")["ip"], [])

    def test_real_addresses_kept(self):
        self.assertEqual(extract_iocs("The C2 at 45.9.148.21 was contacted.")["ip"], ["45.9.148.21"])
        self.assertEqual(extract_iocs("The implant beacons to 5.2.3.1 every hour.")["ip"], ["5.2.3.1"])
        self.assertEqual(extract_iocs("Payload hosted on 185.220.101[.]5.")["ip"], ["185.220.101.5"])


class CommercialServicesAreNotActors(unittest.TestCase):
    TEXT = ("Honeygain and Oxylabs sell residential proxy bandwidth to businesses. "
            "Researchers say the GopherWhisper group deployed backdoors against government targets in Mongolia. "
            "APT28 also appears in the report.")

    def run_extract(self, actors):
        raw = {"actors": actors, "malware": [], "tools": [], "campaigns": [], "victims": [], "sectors": [],
               "countries": [], "techniques": [], "claims": []}
        with mock.patch.object(X, "llm_extract", return_value=raw), mock.patch.object(procvec, "load", return_value=None):
            return X.extract(self.TEXT)

    def test_vendor_is_org(self):
        r = self.run_extract(["Honeygain", "Oxylabs", "GopherWhisper", "APT28"])
        self.assertNotIn("Honeygain", r["actors"])
        self.assertNotIn("Oxylabs", r["actors"])
        self.assertIn("Honeygain", r["orgs"])
        self.assertIn("Oxylabs", r["orgs"])

    def test_known_or_malicious_is_actor(self):
        r = self.run_extract(["Honeygain", "Oxylabs", "GopherWhisper", "APT28"])
        self.assertIn("GopherWhisper", r["actors"])   # malicious activity attributed in the text
        self.assertIn("APT28", r["actors"])           # an ATT&CK / MISP threat actor


if __name__ == "__main__":
    unittest.main()
