"""nightdesk-redact (osinthub/redact.py): a log sample made safe to share, consistently.

    uv run --with pytest pytest tests/app/test_redact.py -q
"""
from __future__ import annotations

import ipaddress
import json
import subprocess
import sys
from pathlib import Path

from osinthub.redact import Redactor

ROOT = Path(__file__).resolve().parents[2]

ZEEK = "\t".join(["1700000000.123456", "CHhAvVGS1DHFjwGM9", "192.168.1.23", "51544", "142.250.72.14", "443", "tcp",
                  "ssl", "a4:83:e7:12:34:56", "nas.lan", "mail.google.com"])
DNS = json.dumps({"ts": "2026-11-20T12:30:45.123Z", "client": "fd12:3456:789a::5", "query": "wpad.home.arpa.example-corp.net",
                  "answers": ["2607:f8b0:4005:80b::200e", "203.0.113.200"], "mac": "00-1B-63-84-45-E6",
                  "user": "alice@example-corp.net", "file": "dns.log.gz", "version": "2.6.1"})


def test_nothing_identifying_survives():
    r = Redactor()
    out = r.line(ZEEK) + r.line(DNS)
    for leak in ("192.168.1.23", "142.250.72.14", "a4:83:e7", "nas.lan", "google", "fd12:3456", "2607:f8b0",
                 "00-1B-63", "alice", "example-corp"):
        assert leak not in out, (leak, out)


def test_the_same_value_gets_the_same_placeholder_everywhere():
    r = Redactor()
    a = r.line("10.0.0.5 talked to 8.8.8.8; 10.0.0.5 again; AA:BB:CC:DD:EE:01 and aa:bb:cc:dd:ee:01")
    assert a.count("192.0.2.1") == 2 and "203.0.113.1" in a
    assert a.count("02:00:00:00:00:01") == 2
    assert r.line("later: 10.0.0.5 and printer.local and PRINTER.LOCAL") == "later: 192.0.2.1 and site1.example and site1.example"


def test_replacements_are_documentation_values_and_keep_the_kind():
    r = Redactor()
    out = r.line("192.168.0.2 100.64.1.1 169.254.1.1 1.1.1.1 fe80::1c2b:3cff:fe4d:5e6f 2001:4860::8888").split()
    v4 = [ipaddress.ip_address(x) for x in out[:4]]
    assert all(a in ipaddress.ip_network("192.0.2.0/24") for a in v4[:3]) and v4[3] in ipaddress.ip_network("203.0.113.0/24")
    assert out[4].startswith("fe80::") and ipaddress.ip_address(out[5]) in ipaddress.ip_network("2001:db8::/32")


def test_what_carries_no_identity_stays():
    text = "127.0.0.1 0.0.0.0 255.255.255.255 224.0.0.251 ::1 :: ff02::fb 00:00:00:00:00:00 ff:ff:ff:ff:ff:ff"
    assert Redactor().line(text) == text
    text = "conn.log x.json.gz version 1.2.3 at 12:30:45 uid CHhAvVGS1DHFjwGM9 ts 1700000000.123456 example.com"
    assert Redactor().line(text) == text


def test_many_addresses_never_leave_the_reserved_ranges():
    r = Redactor()
    reserved = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15")]
    for i in range(1200):
        out = r.line(f"10.1.{i // 250}.{i % 250 + 1}")
        assert any(ipaddress.ip_address(out) in n for n in reserved), out
    assert len(set(r.ips.values())) == 1200


def test_the_command_reads_files_and_reports_on_stderr(tmp_path):
    f = tmp_path / "conn.log"
    f.write_text(ZEEK + "\n")
    p = subprocess.run([sys.executable, "-m", "osinthub.redact", str(f)], capture_output=True, text=True, cwd=ROOT)
    assert p.returncode == 0 and "192.168.1.23" not in p.stdout and "192.0.2.1" in p.stdout
    assert "redacted:" in p.stderr and "Read the result" in p.stderr
