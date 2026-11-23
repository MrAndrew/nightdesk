"""Nothing from the owner's machine or network, and no secret, gets into the repo.

The checks live in tools/release_scan.py (also run by hand before a release); this module runs the scan over every
tracked file in the unit suite:

* no tracked file holds this machine's home folder, login name or git identity (read here at run time, so no literal
  enters the repo);
* no key-like string, unlisted `*.lan` / `*.local` host or `/Volumes/<name>` drive, or hardware MAC;
* in every tracked file, each IPv6 literal that could be a real network is documentation (2001:db8::/32), the demo
  (fd4e:6400:d35c::/48) or a listed public service (an allowlist on purpose: a real home prefix is never written
  anywhere, not even as a hash), and each private IPv4 address is the demo home (10.86.24.0/24), documentation or a
  listed textbook example;
* no tracked file is left unscanned (unreadable or unknown binary), and symlinks are checked as their target path.

The owner's own names (drive, LAN hosts, home prefix) are patterns in a private file outside the repo; set
NIGHTDESK_SCAN_PATTERNS to its path to include them. Without it those patterns are skipped and the rest still runs.

    uv run --with pytest pytest tests/web/test_repo_hygiene.py -q
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("release_scan", ROOT / "tools" / "release_scan.py")
rs = importlib.util.module_from_spec(_spec)
sys.modules["release_scan"] = rs
_spec.loader.exec_module(rs)


def _patterns() -> Path | None:
    p = os.environ.get(rs.ENV_PATTERNS)
    return Path(p).expanduser() if p else None


def _report(hits) -> str:
    # file, line and category only: the redacted preview is in the scan's own output (python3 tools/release_scan.py)
    return "release scan: " + "; ".join(f"{h.path}:{h.line} {h.category}" for h in hits[:40])


def test_release_scan_finds_nothing_in_tracked_files():
    assert len(rs.tracked_files(ROOT)) > 400
    hits, _warnings = rs.scan(ROOT, None)
    assert not hits, _report(hits)


def test_the_owners_private_patterns_match_no_tracked_file():
    p = _patterns()
    if p is None or not p.is_file():
        pytest.skip(f"set {rs.ENV_PATTERNS} to the private patterns file to check the owner's own names")
    assert rs.load_patterns(p), "the private patterns file has no patterns"
    hits, _warnings = rs.scan(ROOT, p)
    assert not hits, _report(hits)


def test_the_checker_recognises_what_it_must_refuse():
    ula, public = "fd12" + ":3456:789a::1", "2a00" + ":1450:4001:80b::200e"   # split, so this file passes its own check
    sample = f"doc 2001:db8::1, demo fd4e:6400:d35c::12, ula {ula}, public [{public}]:443, loopback [::1]:8787"
    got = [str(a) for _s, _e, a in rs.v6_literals(sample) if rs.v6_could_be_real(a)]
    assert got == [ula, public]
    home4 = "192.168" + ".7.23"   # split, so this file passes its own check
    v4 = f"doc 192.0.2.7, demo 10.86.24.30, example 192.168.1.0/24, any 0.0.0.0, metadata 169.254.169.254, lan {home4}"
    assert [str(a) for _s, _e, a in rs.private_v4(v4)] == [home4]


# Variables a tool reads from the shell that a regex over Python code cannot see (tools/*.sh, tests/e2e via the gate).
TOOL_VARS = {"ND_LAKES", "ND_LAKE_BASE", "ND_GATE_OUT", "ND_E2E_PORTS", "ND_EVAL_CACHE", "ND_SEED_LAKE", "ND_LIVE_LAKE",
             "NIGHTDESK_SCAN_PATTERNS", "FORWARDED_ALLOW_IPS"}
# Set by the AI helper for its own libraries (setdefault), not settings a user changes.
NOT_SETTINGS = {"HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "TOKENIZERS_PARALLELISM",
                # the operating system's own app-data locations, read to find the default lake (config.default_lake)
                "XDG_DATA_HOME", "LOCALAPPDATA", "XDG_CONFIG_HOME", "APPDATA",
                # set by the app for the AI helper and model download it starts (osinthub/ai/setup.py), not by users
                "OSINTHUB_AI_LIBS",
                # the Hugging Face cache, found the way huggingface_hub finds it (osinthub/ai/setup.py hf_cache)
                "HF_HUB_CACHE", "HF_HOME", "XDG_CACHE_HOME",
                # set for the model download it starts (osinthub/ai/fetch.py), not by users
                "HF_HUB_DISABLE_TELEMETRY"}


def test_env_example_lists_every_variable_the_app_reads():
    import re
    read = set()
    pat = re.compile(r"""(?:environ(?:\.get|\.setdefault)?[\[(]\s*|getenv\(\s*|_flag\(\s*|_ENV\s*=\s*)["']([A-Z][A-Z0-9_]+)["']""")
    for rel in rs.tracked_files(ROOT):
        if rel.startswith(("osinthub/", "tools/")) and rel.endswith(".py"):
            read |= set(pat.findall((ROOT / rel).read_text()))
    assert {"OSINTHUB_LAKE", "ABUSECH_AUTH_KEY", "CLOUDFLARE_RADAR_TOKEN", "OSINTHUB_INBOX"} <= read   # the regex works
    example = (ROOT / ".env.example").read_text()
    listed = set(re.findall(r"^#?\s*([A-Z][A-Z0-9_]+)=", example, re.M))
    missing = sorted((read | TOOL_VARS) - NOT_SETTINGS - listed)
    assert not missing, f".env.example does not list: {missing} (add each with a one-line comment; okf/environment.md too)"
    assert ".env" in (ROOT / ".gitignore").read_text().split()
