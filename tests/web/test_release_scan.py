"""tools/release_scan.py on a throwaway git repo with invented values only.

Every key-like or owner-like value below is built from pieces, so this file passes the scan it tests.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("release_scan_t", ROOT / "tools" / "release_scan.py")
rs = importlib.util.module_from_spec(_spec)
sys.modules["release_scan_t"] = rs
_spec.loader.exec_module(rs)

USER = "zq" + "owner"                       # an invented login name
HOME = "/home/" + USER
NAME, EMAIL = "Zed " + "Quill", "zq" + "@invented-host.example"
DRIVE = "Zq" + "Archive9"                   # an invented drive name, only in the private patterns file
ISP6 = "2a0" + "9:5b1c:77"                  # an invented global IPv6 prefix (not documentation)
REPO_URL = "https://github.com/" + USER + "/night-desk"   # the throwaway repo's own origin


class Repo:
    """A throwaway git repo; add() writes a file, and `root` stages them all, so `git ls-files` lists them."""

    def __init__(self, path: Path):
        self.path = path
        self.dirty = False

    def __str__(self) -> str:
        return str(self.root)

    @property
    def root(self) -> Path:
        """The repo, with everything added so far staged (one `git add` for all files)."""
        if self.dirty:
            subprocess.run(["git", "add", "-A"], cwd=self.path, check=True)
            self.dirty = False
        return self.path

    def add(self, rel: str, content: str | bytes) -> None:
        p = self.path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode())
        self.dirty = True


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", HOME)
    monkeypatch.setenv("GIT_AUTHOR_NAME", NAME)
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", EMAIL)
    monkeypatch.delenv(rs.ENV_PATTERNS, raising=False)
    r = Repo(tmp_path / "repo")
    r.path.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=r.path, check=True)
    subprocess.run(["git", "remote", "add", "origin", REPO_URL + ".git"], cwd=r.path, check=True)
    return r


def _cats(hits) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for h in hits:
        out.setdefault(h.path, set()).add(h.category)
    return out


def test_a_clean_tree_passes(repo, capsys):
    repo.add("README.md", "Night Desk. Clone " + REPO_URL + ".git and run it (issues: " + REPO_URL + "/issues).\n"
             "Lake at /Volumes/ExternalDrive/night-desk, proxy https://nightdesk.lan:8443/, demo 10.86.24.30, "
             "2001:db8::1, fd4e:6400:d35c::12, MAC 02:4e:44:00:00:01, ~/nightdesk-data\n")
    repo.add("okf/x.md", "sha256 " + "ab" * 32 + "\nintegrity sha512-" + "Q" * 20 + "\n")
    repo.add("img.png", b"\x89PNG\x00\x00" + HOME.encode())                # binary: not read
    assert rs.main(["--root", str(repo)]) == 0
    out = capsys.readouterr()
    assert "release scan: clean" in out.out
    assert "no private patterns file" in out.err                             # skipped with a warning


def test_owner_values_from_the_machine_are_found(repo):
    repo.add("okf/a.md", f"data in {HOME}/lake\n")
    repo.add("okf/b.md", f"see ~{USER}/notes\n")
    repo.add("tools/c.py", f"# by {USER.upper()}\n")
    repo.add("okf/d.md", f"mail {EMAIL} or {NAME}\n")
    hits, _ = rs.scan(repo.root, None)
    got = _cats(hits)
    assert got["okf/a.md"] == {"home"} and got["okf/b.md"] == {"home"}
    assert got["tools/c.py"] == {"user"} and got["okf/d.md"] == {"identity"}


def test_private_patterns_file_literal_and_regex(repo, tmp_path, monkeypatch, capsys):
    pats = tmp_path / "private.txt"
    pats.write_text(f"# the owner's drive\n{DRIVE}\n\nre:(?<![0-9a-f:]){ISP6.replace(':', ':')}:\n")
    repo.add("okf/e.md", f"the {DRIVE.lower()} drive\n")
    repo.add("tests/f.py", f'NET = "{ISP6}:0::/48"\n')
    monkeypatch.setenv(rs.ENV_PATTERNS, str(pats))
    assert rs.main(["--root", str(repo)]) == 1
    out = capsys.readouterr().out
    assert "okf/e.md:1: private:" in out and "tests/f.py:1: private:" in out
    assert DRIVE.lower() not in out.lower() and ISP6 not in out          # the report never repeats a value
    assert "[REDACTED]" in out and "by category:" in out and "by folder:" in out


@pytest.mark.parametrize("text", [
    "ghp" + "_" + "a1B2c3D4" * 5,
    "github" + "_pat_" + "11ABCDEFG0" * 3,
    "sk" + "-ant-" + "Zx9" * 9,
    "xox" + "b-" + "1234567890-abcdef",
    "AK" + "IA" + "ABCDEFGHIJ234567",
    "-----BEGIN RSA " + "PRIVATE KEY-----",
    "Authorization: Bearer " + "eyJhbGciOiJIUzI1NiJ9" + "abcDEF12",
    "Authorization: " + "Basic " + "aHVudGVyOmh1bnRlcjI=",
    "api_" + "key = " + "q8Rv2Lm4Zt7Wp1Ys",
    'TOKEN: "' + "9fK3mQ" + "7tL2vX8pR4" + '"',
    "https://alice:" + "s3cr3tpw" + "@db.example/x",
])
def test_key_like_strings_are_found(text):
    assert "key" in _scan_one("osinthub/k.py", text + "\n"), text


def test_high_entropy_strings_but_not_hashes(repo):
    rnd = "Zq8" + "fK2mR9vXc4LpT7" + "wQ1sY6uB3nE5hJ0aGd"
    repo.add("okf/g.md", f"value {rnd}\n")
    repo.add("okf/h.md", f"commit {'0123abcd' * 5} and sha256 {'9e' * 32}\n")
    repo.add("okf/i.md", f"opaque {'7c41d9a2b8e6' * 4}\n")                # 48 hex chars with no hash word
    repo.add("uv.lock", f'hash = "sha256:{"9e" * 32}"\nx = "{rnd}"\n')     # allowlisted file
    repo.add("osinthub/names.py", "def a_very_long_function_name_without_digits_at_all(): pass\n")
    hits, _ = rs.scan(repo.root, None)
    got = _cats(hits)
    assert got.get("okf/g.md") == {"entropy"} and got.get("okf/i.md") == {"entropy"}
    assert "okf/h.md" not in got and "uv.lock" not in got and "osinthub/names.py" not in got


def test_hosts_drives_addresses_and_macs(repo):
    repo.add("okf/j.md", "proxy at https://zq" + "box" + ".lan:8443/ and threading.local() in code\n")
    repo.add("okf/k.md", "lake at /Volumes/" + "ZqBackup/lake, or /Volumes/<name>\n")
    repo.add("okf/l.md", "my router is 192.168" + ".44.1\n")
    repo.add("tests/m.py", 'NET = "192.168.1.0/24"\n')                     # textbook examples pass; tests are not exempt
    repo.add("web/n.js", "const a = '" + ISP6 + "::1';\n")
    repo.add("okf/o.md", "nic 3c:22:fb" + ":12:34:56, invented 02:00:5e:10:00:01, rotated conn.04:00:00-04:03:00\n")
    hits, _ = rs.scan(repo.root, None)
    got = _cats(hits)
    assert got.get("okf/j.md") == {"host"} and got.get("okf/k.md") == {"volume"}
    assert got.get("okf/l.md") == {"ipv4"} and "tests/m.py" not in got
    assert got.get("web/n.js") == {"ipv6"} and got.get("okf/o.md") == {"mac"}


def test_redaction_hides_every_flagged_value_on_the_line(repo):
    tok = "ghp" + "_" + "Q" * 12 + "w" * 12 + "7" * 12
    repo.add("okf/p.md", f"{HOME} and {tok} on one line\n")
    hits, _ = rs.scan(repo.root, None)
    assert {h.category for h in hits} == {"home", "key"}
    for h in hits:
        assert HOME not in h.preview and tok not in h.preview and h.preview.count("[REDACTED]") == 2


def test_a_missing_patterns_file_warns_and_still_scans(repo, tmp_path, capsys):
    repo.add("okf/q.md", f"{HOME}\n")
    assert rs.main(["--root", str(repo), "--patterns", str(tmp_path / "absent.txt"), "--summary"]) == 1
    out = capsys.readouterr()
    assert "private patterns file not found" in out.err and "home 1" in out.out


# ---------------------------------------------------------------- round 2: one test per evaluator failure

IDENT = rs.identity_from(HOME, f"{NAME} <{EMAIL}> 1700000000 +0000", [REPO_URL + ".git"])


def _scan_one(rel: str, text: str, private=None) -> set[str]:
    """Categories found in one file's text (no git repo needed: fast)."""
    return {h.category for h in rs.scan_text(rel, text, IDENT, private)}


HEX32 = "0f1e2d3c" + "4b5a6978" + "8796a5b4" + "c3d2e1f0"
HEX40 = "9f8e7d6c5b4a" + "32100a1b2c3d" + "4e5f6789" + "c0ffee12"   # random-looking, a SHA-1's length
VAL = "q8Rv2Lm4" + "Zt7Wp1Ys9KdE"


@pytest.mark.parametrize("text", [
    '{"api_' + 'key": "' + VAL + '"}',
    '{"api' + 'Key": "' + VAL + '"}',
    '{"pass' + 'word": "' + "Zq8fK2mR" + '9vXc4LpT"}',
    '{"tok' + 'en": "' + HEX32 + '"}',
    "headers = {'Auth-" + "Key': '" + HEX32 + "'}",
    "sec" + "ret = 'Hunter2!" + "Hunter2!Hunter2!'",
    "url = 'https://api.example/v1?api" + "key=" + VAL + "&q=1'",
    "sec" + "ret=" + VAL + "_secret",                                  # a placeholder word inside no longer exempts it
])
def test_failure1_quoted_and_punctuated_key_values_are_found(text):
    cats = _scan_one("tests/fixtures/x.json", text + "\n")
    assert "key" in cats, text


@pytest.mark.parametrize("text", [
    'token = request.headers.get("X-Auth-Token")',
    'KEY = os.environ["ABUSECH_AUTH_' + 'KEY"]',
    "api_" + "key: <your key here>",
    'api_' + 'key = "test-auth-key-6f1d2c9a0b7e"',
    "password_file = /run/secrets/db_password_v2",
    "token_url: https://auth.example/oauth2/v1/token",
])
def test_failure1_code_paths_and_placeholders_are_not_keys(text):
    cats = _scan_one("osinthub/y.py", text + "\n")
    assert "key" not in cats, text


@pytest.mark.parametrize("rel,text,cat", [
    (".env.example", "INGEST_URL=https://192.168" + ".44.7:8788", "ipv4"),
    ("docker-compose.yml", "      - " + ISP6 + "::5:8787", "ipv6"),
    ("deploy/Caddyfile", "reverse_proxy 192.168" + ".44.7:8787", "ipv4"),
    ("deploy/Caddyfile", "bind " + ISP6 + "::1", "ipv6"),
    ("tools/a.py", "HOST = '" + ISP6 + "::9'", "ipv6"),
    ("Dockerfile", "ENV OSINTHUB_HOST=100.6" + "4.12.7", "ipv4"),                # CGNAT counts too
])
def test_failure2_addresses_are_checked_in_every_file(rel, text, cat):
    cats = _scan_one(rel, text + "\n")
    assert cat in cats, (rel, text)


def test_failure2_ranges_named_by_their_base_and_test_data_pass():
    assert not _scan_one("okf/r.md", "private ranges 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, CGNAT 100.64.0.0/10\n")
    assert not _scan_one("tests/t.py", 'HOME_NET = "192.168.1.0/24"; ROUTER = "192.168.1.1"\n')   # textbook examples


def test_failure3_a_stem_pattern_catches_the_name_without_its_number(tmp_path):
    pats = tmp_path / "private.txt"
    pats.write_text(DRIVE[:-1] + "\n")                                  # the stem, without the trailing digit
    text = "fits on a small fraction of one " + DRIVE[:-1] + " drive; or " + DRIVE + "\n"
    hits = rs.scan_text("okf/s.md", text, IDENT, rs.load_patterns(pats))
    assert [(h.path, h.category) for h in hits] == [("okf/s.md", "private")]
    assert DRIVE[:-1].lower() not in hits[0].preview.lower()


def test_failure4_private_macs_match_in_any_notation(tmp_path):
    mac = "ae:12:" + "34:56:78:9a"                                      # invented, locally administered
    pats = tmp_path / "private.txt"
    pats.write_text("# a NIC\n" + mac + "\n")
    private = rs.load_patterns(pats)
    forms = [mac.replace(":", "-"), mac.upper(), "ae12.3456.789a", "AE123456789A", "mac=" + mac.replace(":", "")]
    for f in forms:
        hits = rs.scan_text("okf/m.md", f"nic {f} here\n", IDENT, private)
        assert [h.category for h in hits] == ["private"], f
        assert "ae12" not in hits[0].preview.lower().replace(":", "").replace("-", "").replace(".", "")
    other = "nic ae:12:34:56:78:9b, rotated conn.04:00:00-04:03:00\n"     # another (invented) MAC, a time
    assert not rs.scan_text("okf/other.md", other, IDENT, private)


def test_failure4_hardware_macs_in_cisco_notation():
    cats = _scan_one("okf/c.md", "switch port 3c22" + ".fb12.3456\n")
    assert cats == {"mac"}


@pytest.mark.parametrize("text,flagged", [
    (REPO_URL, False),
    (REPO_URL + "/issues/12", False),
    ("git@github.com:" + USER + "/night-desk.git", False),
    ("https://github.com/" + USER + "/secret-other-repo", True),
    ("https://gist.github.com/" + USER + "/0a1b2c3d", True),
    (REPO_URL + "-fork", True),
])
def test_failure5_only_this_repos_own_url_may_name_the_account(text, flagged):
    cats = _scan_one("okf/u.md", f"see {text} for more\n")
    assert ("user" in cats) is flagged, text


def test_failure6_pgp_private_key_block():
    cats = _scan_one("okf/k.asc", "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----\n")
    assert cats == {"key"}


def test_failure6_file_names_are_scanned_and_redacted(repo, capsys):
    repo.add("okf/notes/" + USER + "-todo.md", "nothing here\n")
    repo.add("okf/notes/zq" + "box" + ".lan-setup.md", "a home folder: " + HOME + "\n")
    assert rs.main(["--root", str(repo)]) == 1
    out = capsys.readouterr().out
    assert "okf/notes/[REDACTED]-todo.md:0: user: (file name)" in out
    assert "okf/notes/[REDACTED]-setup.md:0: host: (file name)" in out
    assert "okf/notes/[REDACTED]-setup.md:1: home:" in out                   # its text hit prints the redacted name too
    assert USER not in out and ("zq" + "box") not in out


def test_failure6_other_text_encodings_are_scanned_with_a_warning(repo):
    repo.add("okf/w16.txt", ("\ufeffdata in " + HOME + "\n").encode("utf-16-le"))   # BOM: decoded silently? no: warned
    repo.add("okf/w16b.txt", ("data in " + HOME + "\n").encode("utf-16-be"))         # no BOM
    repo.add("okf/l1.txt", ("caf\xe9 in " + HOME + "\n").encode("latin-1"))
    repo.add("okf/blob.dat", b"\x00\x01\x02" + HOME.encode())                          # unknown binary: a hit
    repo.add("web/img.png", b"\x89PNG\x00\x00" + HOME.encode())                        # known binary: silent
    hits, warnings = rs.scan(repo.root, None)
    got = _cats(hits)
    assert got.get("okf/w16.txt") == {"home"} and got.get("okf/w16b.txt") == {"home"} and got.get("okf/l1.txt") == {"home"}
    joined = "\n".join(warnings)
    assert got.get("okf/blob.dat") == {"unscanned"}
    for name in ("okf/w16.txt", "okf/w16b.txt", "okf/l1.txt"):
        assert name in joined, name
    assert "web/img.png" not in joined


# ---------------------------------------------------------------- round 2: the evaluator's nits

@pytest.mark.parametrize("text,cat", [
    ("/Users/" + "zqdev/notes", "home"),
    ("/home/" + "zqdev/notes", "home"),
    ("C:\\Users\\" + "zqdev\\notes", "home"),
    ("/vol" + "umes/ZqBackup/lake", "volume"),
    ("https://zqbox" + ".internal/", "host"),
    ("zqbox" + ".localdomain", "host"),
    ("commit to" + "ken " + HEX40, "entropy"),
])
def test_nits_are_caught(text, cat):
    cats = _scan_one("okf/n.md", text + "\n")
    assert cat in cats, text


def test_nits_placeholders_pass():
    text = ("/Users/you/lake, /home/<name>/x, C:\\Users\\me\\x, /Volumes/ExternalDrive/x, "
            "host.docker.internal, commit " + HEX40 + "\n")
    assert not rs.scan_text("okf/n.md", text, IDENT), text


# ---------------------------------------------------------------- round 3 (lead): the round-2 evaluator's failures

@pytest.mark.parametrize("text", [
    "The Pi is at 192.168" + ".44.7.",                                  # sentence end
    "see 192.168" + ".44.7.\n",
    "inet 172.20" + ".9.4/16 brd",                                       # a host with a short mask is still a host
])
def test_r3_failure1_an_address_before_a_period_is_found(text):
    assert "ipv4" in _scan_one("okf/a.md", text + "\n"), text


def test_r3_failure1_private_regex_with_the_new_lookahead(tmp_path):
    pats = tmp_path / "private.txt"
    pats.write_text("re:(?<![\\d.])192\\.168\\.44\\.\\d{1,3}(?!\\d|\\.\\d)\n")
    hits = rs.scan_text("okf/s.md", "at 192.168" + ".44.20.\n", IDENT, rs.load_patterns(pats))
    assert "private" in {h.category for h in hits}


@pytest.mark.parametrize("text", [
    "SMTP_PASS" + "WORD=CorrectHorse" + "BatteryStaple",
    'pass' + 'word: "CorrectHorse' + 'BatteryStaple"',
    "DB_PA" + "SS=Zq8fK2mR" + "9vXc4LpT",
    'MYSQL_PA' + 'SS: "Zq8fK2mR' + '9vXc4LpT9w"',
    "https://Zq8fK2mR" + "9vXc4LpTq8Rv2Lm4@git.example.net/a/b.git",   # a token as the URL user name
    "ADMIN_PASS" + "WORD=correcthorse" + "batterystaple",               # letters only, all lower case
    "pass" + "word=correct-horse-" + "battery-staple",
    "api_tok" + "en=abcdefghijkl" + "mnopqrstuvwx",
])
def test_r3_failure2_password_shapes(text):
    assert "key" in _scan_one("okf/p.md", text + "\n"), text


@pytest.mark.parametrize("text", [
    "bypass_mode: strict_checking_enabled",
    "compass_heading: northnortheastward",
    "token_kind: refresh_token_rotation",
    "keyword:examplegate examples",
])
def test_r3_failure2_identifiers_are_not_passwords(text):
    assert "key" not in _scan_one("osinthub/q.py", text + "\n"), text


@pytest.mark.parametrize("rel", ["tests/x.py", "osinthub/x.py"])
def test_r3_failure3_tests_and_backend_are_not_exempt(rel):
    assert "ipv4" in _scan_one(rel, "LAN = '192.168" + ".44.7'\n")


def test_r3_failure3_allow_entries_are_narrow():
    assert all(a[0] != r"^osinthub/netlog/fixtures/" for a in rs.ALLOW)
    assert "ipv4" in _scan_one("web/vendor/lib.js", "x='192.168" + ".44.7'\n")


def test_r3_failure4_symlinks_are_scanned_as_their_target_and_unreadable_files_fail(repo):
    import os
    repo.add("okf/ok.md", "fine\n")
    os.symlink("/Users/" + "jdoe/secret-notes.txt", repo.path / "okf" / "link-home")
    os.symlink("/Vol" + "umes/Backup9/x", repo.path / "okf" / "link-vol")
    repo.dirty = True
    hits, _ = rs.scan(repo.root, None)
    got = _cats(hits)
    assert got.get("okf/link-home") == {"home"} and got.get("okf/link-vol") == {"volume"}
    assert rs.main(["--root", str(repo.root), "--summary"]) == 1
