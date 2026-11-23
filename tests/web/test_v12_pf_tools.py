"""Release tooling before the repo goes public (lane pf-tools).

* tools/okf_sources.py --check: renders every generated page, writes nothing, and exits 1 naming each page that
  differs from (or is missing in) okf/; a registry source with no generator input is a clear error, not a KeyError.
* tools/release_scan.py: Slack and Discord webhook URLs, GitLab tokens, 15-character Gotify tokens, reverse-DNS and
  leading-zero IPv4, IPv6 prefixes written without "::" and in ip6.arpa form, `*.home` / `*.ts.net` names, and
  the text chunks of PNG files.

Every flagged value is invented and built from pieces at run time, so this file passes the scan it tests.

    uv run --with pytest pytest tests/web/test_v12_pf_tools.py -q
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GEN = ROOT / "tools" / "okf_sources.py"
_spec = importlib.util.spec_from_file_location("release_scan_pf", ROOT / "tools" / "release_scan.py")
rs = importlib.util.module_from_spec(_spec)
sys.modules["release_scan_pf"] = rs
_spec.loader.exec_module(rs)

IDENT = rs.identity_from("/home/" + "zq" + "owner", "Zed " + "Quill <zq" + "@invented-host.example> 1700000000 +0000",
                         ["https://github.com/" + "zq" + "owner/night-desk.git"])


def _cats(rel: str, text: str) -> set[str]:
    return {h.category for h in rs.scan_text(rel, text + "\n", IDENT)}


def _gen_env(tmp: Path) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("OSINTHUB_")}
    env.update(OSINTHUB_LAKE=str(tmp / "lake"), OSINTHUB_OFFLINE="1", AI_URL="http://127.0.0.1:9")
    return env


def _gen(tmp: Path, *args: str, code: str | None = None) -> subprocess.CompletedProcess:
    cmd = [sys.executable, "-c", code, *args] if code else [sys.executable, str(GEN), *args]
    return subprocess.run(cmd, cwd=ROOT, env=_gen_env(tmp), capture_output=True, text=True, timeout=120)


# ---------------------------------------------------------------- okf_sources --check

def test_generator_check_mode_passes_on_the_committed_docs_and_writes_nothing(tmp_path):
    before = {p: p.stat().st_mtime_ns for p in (ROOT / "okf" / "sources").rglob("*.md")}
    r = _gen(tmp_path, "--check")
    assert r.returncode == 0, r.stdout + r.stderr[-2000:]
    assert r.stdout.startswith("checked ") and "files: all match" in r.stdout, r.stdout
    after = {p: p.stat().st_mtime_ns for p in (ROOT / "okf" / "sources").rglob("*.md")}
    assert before == after, "--check wrote a page"


def test_generator_check_mode_names_each_drifted_or_missing_page(tmp_path):
    out = tmp_path / "okf"
    shutil.copytree(ROOT / "okf", out)
    page = out / "sources" / "current" / "sslbl.md"
    page.write_text(page.read_text() + "a hand edit\n")
    (out / "sources" / "catalog.md").unlink()
    r = _gen(tmp_path, "--check", "--out", str(out))
    assert r.returncode == 1, r.stdout + r.stderr[-2000:]
    assert "differs: sources/current/sslbl.md" in r.stdout and "differs: sources/catalog.md" in r.stdout
    assert "2 differ from the generator" in r.stdout
    assert page.read_text().endswith("a hand edit\n") and not (out / "sources" / "catalog.md").exists()
    r = _gen(tmp_path, "--check", "--only", "sslbl,nvd_recent", "--out", str(out))   # --only checks just those pages
    assert r.returncode == 1 and "1 differs" in r.stdout and "catalog" not in r.stdout, r.stdout


def test_a_source_without_generator_inputs_is_a_clear_error_not_a_keyerror(tmp_path):
    code = ("import runpy, sys; sys.path.insert(0, '.'); "
            "from osinthub.sources import SOURCES; import osinthub.news.sources; "
            "SOURCES['zz_new_feed'] = SOURCES['cisa_kev']; "
            f"sys.argv = [{str(GEN)!r}] + sys.argv[1:]; runpy.run_path({str(GEN)!r}, run_name='__main__')")
    r = _gen(tmp_path, "--check", code=code)
    assert r.returncode != 0
    assert "zz_new_feed" in r.stderr and "KeyError" not in r.stderr, r.stderr[-2000:]
    assert r.returncode == 2
    for only in ("rpki_roas", "epss", "nosuch", "sslbl,nosuch"):     # hand-written or unknown: an error, not a pass
        r = _gen(tmp_path, "--check", "--only", only)
        assert r.returncode == 2 and "KeyError" not in r.stderr, (only, r.stdout + r.stderr[-2000:])
        assert "not one: " + ("nosuch" if "nosuch" in only else only) in r.stderr and "checked" not in r.stdout


# ---------------------------------------------------------------- release scan: keys

SLACK = "https://hooks." + "slack.com/services/" + "T0ZQ8K2M4X" + "/B0ZQ8K2M4Y/" + "q8Rv2Lm4Zt7Wp1Ys9KdE0aGd"
DISCORD = ("https://discord" + ".com/api/webhooks/" + "1234567890123456789" + "/"
           + "Zq8fK2mR9vXc4LpT" + "7wQ1sY6uB3nE5hJ0" + "aGdq8Rv2Lm4Zt7Wp" + "1Ys9KdE0aGdQ1sY6u")
GLPAT = "gl" + "pat-" + "Zq8fK2mR9vXc4LpT7wQ1"
GOTIFY = "Ak3" + "Zq9Lm2Xw7.Tb"          # 15 characters: "A" and 14 random ones
BOX = "zq" + "box" + ".ho" + "me"        # an invented *.home host
ARPA = "router" + ".home" + ".arpa"      # the RFC 8375 example


@pytest.mark.parametrize("text", [
    "NOTIFY_URL=" + SLACK,
    "post to " + SLACK.replace("services", "workflows") + "/123",
    "hook: " + DISCORD,
    "https://canary." + DISCORD.split("://", 1)[1].replace("/api/", "/api/v10/"),
    "git clone https://oauth2:" + GLPAT + "@gitlab.example/x.git",
    "GITLAB_TOKEN " + GLPAT,
    "gl" + "dt-" + "Zq8fK2mR9vXc4LpT7wQ1",           # a deploy token
    "GOTIFY_TOKEN=" + GOTIFY,
    'curl -H "X-Gotify-' + 'Key: ' + GOTIFY + '" https://gotify.lan/message',
    "https://gotify.example/message?to" + "ken=" + "C" + GOTIFY[1:],
    "plugin to" + "ken=" + "P" + GOTIFY[1:],
    "gotify push --to" + "ken " + GOTIFY + " hello",
    "cli --api-" + "key=" + GOTIFY,
    '{"url": "' + SLACK.replace("/", "\\/") + '"}',                # JSON with escaped slashes
    "xa" + "pp-1-" + "A0ZQ8K2M4X-1234567890-abcdef0123456789",       # a Slack app-level token
    "GITLAB_TOKEN_" + GLPAT,                                          # after an underscore
    "gl" + "ffct-" + "Zq8fK2mR9vXc4LpT7wQ1",                          # a feature-flag client token
    '{"tok' + 'en": "' + GOTIFY + '"}',
])
def test_webhook_urls_gitlab_and_gotify_tokens_are_keys(text):
    hits = rs.scan_text("okf/n.md", text + "\n", IDENT)
    assert "key" in {h.category for h in hits}, text
    for secret in (SLACK.rsplit("/", 1)[1], DISCORD.rsplit("/", 1)[1], GLPAT, GOTIFY[1:]):
        assert all(secret not in h.preview for h in hits), (text, hits)


@pytest.mark.parametrize("text", [
    "NOTIFY_URL=https://hooks." + "slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",   # Slack's own doc example
    "NOTIFY_URL=https://hooks." + "slack.com/services/<team>/<hook>/<secret>",
    "https://discord" + ".com/api/webhooks/<id>/<token>",
    "GOTIFY_TOKEN=<your app token>",
    "token = refresh_tokens1",                       # 15 characters, but an identifier: not a Gotify shape
    "tok" + "en: Abcdefghijklmno",                   # letters only, one case after the first: not random
    "key = AppConfigLoader",
    "gl" + "pat-<your token>",
    "gotify push --to" + "ken $GOTIFY_TOKEN",
    "run --api-" + "key-file /run/secrets/x",
])
def test_webhook_and_token_placeholders_pass(text):
    assert "key" not in _cats("okf/n.md", text), text


# ---------------------------------------------------------------- release scan: addresses

HOME4_PTR = "7.44" + ".168.192.in-addr.arpa"         # the reverse name of an invented LAN address
ZONE4_PTR = "44" + ".168.192.in-addr.arpa"            # its /24 zone


@pytest.mark.parametrize("text", [
    "query[PTR] " + HOME4_PTR + " from the router",
    "zone " + ZONE4_PTR + " {",
    "PTR " + "5.12.20" + ".172.IN-ADDR.ARPA",
    "my router is 192.168" + ".044.001",                 # leading zeros, read as decimal
    "nas at 192.168" + ".044.07.",
    "010.000" + ".000.005",                            # decimal ten-dot-..., octal 8.0.0.5: one reading is private
    "100.064" + ".012.007",                            # CGNAT with zero padding
    "0300.0250" + ".054.007",                          # octal parts, as inet_aton reads them
    "192.168" + ".0044.7",                             # four-digit zero padding
    "0xc0.0xa8" + ".0x2c.0x07",                        # hex parts
    # v1.2 flagged these and round 1 did not: the forward reading inside an in-addr.arpa name counts too
    "172.20" + ".5.9.in-addr.arpa",
    "wrong order 192.168" + ".44.7.in-addr.arpa",
    "rev 10.0" + ".5.7.in-addr.arpa",
    "10.1" + ".168.192.in-addr.arpa",                  # reversed it is a textbook example, forward it is private
    # round 2 missed these: a decimal address followed straight by a letter a-f
    "192.168" + ".44.7beta",
    "ip=192.168" + ".44.7e",
    "192.168" + ".44.7Ethernet",
    "host 10.20" + ".30.40a",
    "172.20" + ".5.9Bridge",
])
def test_ptr_form_and_leading_zero_ipv4_are_found(text):
    hits = rs.scan_text("okf/a.md", text + "\n", IDENT)
    assert "ipv4" in {h.category for h in hits}, text
    assert all("[REDACTED]" in h.preview for h in hits)


@pytest.mark.parametrize("text", [
    "query 2.24.86.10.in-addr.arpa from 10.86.24.21",       # the demo home
    "zone 24.86.10.in-addr.arpa",
    "keep 9.113.0.203.in-addr.arpa",                         # documentation
    "zones 10.in-addr.arpa and 168.192.in-addr.arpa",        # whole ranges
    "the textbook 1.1.168.192.in-addr.arpa",                 # 192.168.1.1, a listed example
    "version 10.08.12.05 and 01.2.3.4",                       # two-digit zero padding is a version, not an address
    "version 01.02.03.04 and 192.000.002.010",               # public, and documentation either way
    "demo 010.086.024.030",                                  # the demo read as decimal; octal is public
])
def test_ptr_and_zero_padded_examples_pass(text):
    assert "ipv4" not in _cats("okf/a.md", text), text


ISP6 = "2a0" + "9:5b1c:77"                   # an invented global prefix (3 groups)
ULA6 = "fd1" + "2:3456:789a"                 # an invented unique-local /48


@pytest.mark.parametrize("text", [
    "delegated " + ISP6 + "/48 by the ISP",
    "prefix " + ISP6 + "ab:1200/56",
    "LAN prefix " + ISP6 + "ab:1200: (yours)",
    "ULA " + ULA6 + "/48",
    "ula " + ULA6 + ":1",
    "2a0" + "9:5b1c/32",                                     # two groups with a prefix length
    ".".join(reversed("2a09" + "5b1c0077ab12")) + ".ip6.arpa",   # reverse DNS of a /48
])
def test_partial_and_reverse_ipv6_prefixes_are_found(text):
    assert "ipv6" in _cats("okf/b.md", text), text


@pytest.mark.parametrize("text", [
    "my /48 is 3" + "001:1234:5678",                       # digits only, no suffix: still a prefix (round 2 skipped it)
    "LAN 3" + "001:1234:5678:9",
    "a date-like 2" + "023:13:15 is not a date",           # month 13: not the EXIF shape
])
def test_digits_only_ipv6_prefixes_are_found(text):
    assert "ipv6" in _cats("okf/b.md", text), text


@pytest.mark.parametrize("text", [
    "demo fd4e:6400:d35c/48 and fd4e:6400:d35c:1",
    "docs 2001:db8:1/48 and 2001:db8:0:10/64",
    "a time 12:34:56, a ratio 2000:1, a MAC 02:4e:44:00:00:01",
    "a slice data[2000:4000]",
    "EXIF DateTime 2023:10:15 12:00:00",                       # the shape of the tracked images' EXIF dates
    "Cloudflare 2606:4700:4700/48",
    "a full one " + ISP6 + "::1 is V6's, found once",
    ".".join(reversed("20010db800000001")) + ".ip6.arpa",      # documentation
    "d.f.ip6.arpa",                                            # the whole ULA space
])
def test_partial_ipv6_examples_pass(text):
    cats = [h.category for h in rs.scan_text("okf/b.md", text + "\n", IDENT)]
    if "V6's" in text:
        assert cats == ["ipv6"], text                            # the plain literal, not also a partial hit
    else:
        assert "ipv6" not in cats, text


# ---------------------------------------------------------------- release scan: host names

@pytest.mark.parametrize("rel,text", [
    ("okf/h.md", "open http://" + BOX + ":8080/"),
    ("okf/h.md", "my NAS is " + BOX + "."),
    ("okf/h.md", "ssh zq" + "box.tail9c2e1.ts" + ".net"),
    ("tools/h.py", 'HOST = "' + BOX + '"'),
    ("web/h.js", "fetch('https://zq" + "box.tail9c2e1.ts" + ".net/api')"),
    ("tools/h.sh", "ssh admin@" + BOX),
    # round 1 missed these: shell commands, comments and strings with words in front
    ("tools/h.sh", "ssh " + BOX),
    ("tools/h.sh", "ping -c1 " + BOX),
    ("tools/h.sh", "rsync -a ./ " + BOX + ":/backup"),
    ("tools/h.py", "# backup goes to " + BOX + " every night"),
    ("web/h.js", "// my NAS: " + BOX),
    ("web/h.js", "const h = 'nas " + BOX + "'"),
    ("osinthub/h.sql", "-- the NAS " + BOX + " holds the copy"),
    ("web/h.js", "ICON.plus; // and the NAS " + BOX),        # another name used as an object does not hide it
    # round 2 hid these behind its "receiver" rule
    ("osinthub/r.py", "router = APIRouter()\n@router.get('/x')\nURL = 'http://router.ho" + "me/admin'"),
    ("tools/r.py", "'settings.json'\nHOST = 'settings.ho" + "me'"),
    ("web/r.js", "fetch('http://nd.ho" + "me:8787/api/health')"),
    ("web/r.js", "fetch('http://nd.box.ho" + "me/')"),
    ("osinthub/r.py", "import nas\nnas.mount()\nTARGET = 'admin@nas.ho" + "me'"),
    ("web/r.js", "server.listen(1); fetch('https://server.ho" + "me:8443/api')"),
    ("web/r.js", "${ICON.ho" + "me}"),                              # an attribute outside the allowlisted file: flagged
])
def test_home_and_tailnet_names_are_found(rel, text):
    assert "host" in _cats(rel, text), (rel, text)


@pytest.mark.parametrize("rel,text", [
    ("web/js/panels/world-map.js", "${ICON.plus}${ICON.ho" + "me}</button>"),   # allowlisted in its file
    ("osinthub/netlog/seen.py", "ON p.ip = v0.ho" + "me AND v0.ts >= p.from_ts"),
    ("web/x.js", "registerCommand({ id: 'act.home' })"),
    ("osinthub/x.py", "Path.home() / 'x'"),
    ("okf/x.md", "a tailnet name such as nightdesk.tailnet-name.ts" + ".net"),
    ("okf/x.md", ARPA + " is the RFC 8375 name"),
])
def test_home_attributes_and_examples_pass(rel, text):
    cats = _cats(rel, text)
    if ARPA in text:
        assert cats == {"host"}, text                            # *.home.arpa is still a host, once
    else:
        assert "host" not in cats, (rel, text)


# ---------------------------------------------------------------- release scan: PNG text chunks

def _chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def _png(*chunks: bytes) -> bytes:
    ihdr = _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
    idat = _chunk(b"IDAT", zlib.compress(b"\x00\x00"))
    return rs.PNG_SIG + ihdr + b"".join(chunks) + idat + _chunk(b"IEND", b"")


HOME = "/Users/" + "zqdev"


def test_the_gotify_value_has_the_gotify_length():
    assert len(GOTIFY) == 15 and rs.GOTIFY.fullmatch(GOTIFY)


def test_png_text_chunks_are_read():
    data = _png(_chunk(b"tEXt", b"Comment\0saved from " + HOME.encode() + b"/shots"),
                _chunk(b"zTXt", b"Author\0\0" + zlib.compress(BOX.encode())),
                _chunk(b"iTXt", b"XML:com.adobe.xmp\0\0\0en\0\0<x>192.168" + b".44.7</x>"),
                _chunk(b"iTXt", b"Title\0\x01\0de\0Titel\0" + zlib.compress("\u00fcber ".encode() + GLPAT.encode())))
    chunks, err = rs.png_text(data)
    assert err is None
    assert [(k, dict(f)["keyword"]) for k, f in chunks] == [("tEXt", "Comment"), ("zTXt", "Author"),
                                                           ("iTXt", "XML:com.adobe.xmp"), ("iTXt", "Title")]
    assert chunks[2][1] == [("keyword", "XML:com.adobe.xmp"), ("language", "en"), ("text", "<x>192.168" + ".44.7</x>")]
    assert chunks[3][1] == [("keyword", "Title"), ("language", "de"), ("translated keyword", "Titel"),
                            ("text", "\u00fcber " + GLPAT)]


def _png_hits(*chunks: bytes, tail: bytes = b"") -> list:
    return rs.scan_png("web/x.png", _png(*chunks) + tail, IDENT, rs.Private(), "web/x.png")


def test_png_keyword_and_language_tag_are_scanned_and_never_printed_unredacted():
    hits = _png_hits(_chunk(b"tEXt", BOX.encode() + b"\0clean"))
    assert [(h.line, h.category, h.preview) for h in hits] == [(1, "host", "[PNG tEXt keyword] [REDACTED]")]
    hits = _png_hits(_chunk(b"tEXt", HOME.encode() + b"/shots\0see 192.168" + b".44.7"))
    assert [(h.line, h.category) for h in hits] == [(1, "home"), (2, "ipv4")]
    assert hits[1].preview == "[PNG tEXt /Users/" + "[REDACTED]/shots] see [REDACTED]"    # the label is redacted too
    hits = _png_hits(_chunk(b"iTXt", b"Title\0\0\0" + HOME.encode() + b"\0\0clean"))
    assert [(h.category, h.preview) for h in hits] == [("home", "[PNG iTXt language] /Users/" + "[REDACTED]")]
    hits = _png_hits(_chunk(b"iTXt", b"Title\0\0\0en\0" + BOX.encode() + b"\0clean"))
    assert [(h.category, h.preview) for h in hits] == [("host", "[PNG iTXt translated keyword] [REDACTED]")]
    for h in _png_hits(_chunk(b"tEXt", HOME.encode() + b"\0" + BOX.encode())):
        assert "zqdev" not in h.preview and "zq" + "box" not in h.preview


def test_png_data_after_iend_is_scanned_or_fails():
    hits = _png_hits(tail=b"note " + HOME.encode())
    assert [(h.category, h.preview) for h in hits] == [("home", "[PNG after IEND] note /Users/" + "[REDACTED]")]
    assert [h.category for h in _png_hits(tail=b"\0\x01\x02")] == ["unscanned"]
    assert _png_hits(tail=b"\n") == []


def test_png_text_chunks_are_scanned_in_tracked_files(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", "/home/" + "zq" + "owner")
    monkeypatch.delenv(rs.ENV_PATTERNS, raising=False)
    repo = tmp_path / "repo"
    (repo / "web").mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / "web" / "shot.png").write_bytes(_png(
        _chunk(b"tEXt", b"Comment\0saved from " + HOME.encode() + b"/shots"),
        _chunk(b"zTXt", b"Author\0\0" + zlib.compress(BOX.encode())),
        _chunk(b"iTXt", b"Title\0\x01\0\0\0" + zlib.compress(GLPAT.encode()))))
    (repo / "web" / "clean.png").write_bytes(_png(_chunk(b"tEXt", b"Software\0a drawing app"),
                                                 _chunk(b"iTXt", b"XML:com.adobe.xmp\0\0\0\0\0<x:xmpmeta/>")))
    (repo / "web" / "odd.bin").write_bytes(b"\x00\x01")                          # binary, not a PNG: unscanned as before
    (repo / "web" / "bomb.png").write_bytes(_png(_chunk(b"zTXt", b"Comment\0\0" + zlib.compress(b"a" * (5 << 20)))))
    (repo / "web" / "broken.png").write_bytes(_png(_chunk(b"zTXt", b"Comment\0\0not zlib at all")))
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    hits, _ = rs.scan(repo, None)
    got: dict[str, set[str]] = {}
    for h in hits:
        got.setdefault(h.path, set()).add(h.category)
    assert got.get("web/shot.png") == {"home", "host", "key"}, hits
    assert "web/clean.png" not in got
    assert got.get("web/bomb.png") == {"unscanned"} and got.get("web/broken.png") == {"unscanned"}
    assert rs.main(["--root", str(repo)]) == 1
    out = capsys.readouterr().out
    assert "web/shot.png:2: home: [PNG tEXt Comment] saved from /Users/" + "[REDACTED]/shots" in out
    assert "web/shot.png:4: host: [PNG zTXt Author] [REDACTED]" in out
    assert "web/shot.png:6: key: [PNG iTXt Title] [REDACTED]" in out
    assert HOME not in out and GLPAT not in out and ("zq" + "box") not in out


def test_the_tracked_pngs_carry_text_chunks_that_are_scanned():
    pngs = [p for p in rs.tracked_files(ROOT) if (ROOT / p).read_bytes()[:8] == rs.PNG_SIG]
    assert pngs, "no tracked PNG"
    kinds = [kind for p in pngs for kind, _ in rs.png_text((ROOT / p).read_bytes())[0]]
    assert "iTXt" in kinds, kinds   # the NASA image's XMP: read, and clean
