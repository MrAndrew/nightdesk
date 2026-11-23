#!/usr/bin/env python3
"""Release scan: no personal info, home-network data or secrets in any tracked file.

    python3 tools/release_scan.py [--patterns PATH] [--root DIR] [--summary]

Scans every file `git ls-files` lists, its name and its text, and exits 1 when it finds any of:

* home      this machine's home folder (`Path.home()`, also written `~<user>`), read at run time, and any other
            person's home folder (`/Users/<name>`, `/home/<name>`, `C:\\Users\\<name>`) outside a placeholder list;
* user      the login name (the home folder's last part) as a word, except inside this repo's own GitHub URL;
* identity  the git identity (`git var GIT_AUTHOR_IDENT`: `user.name` / `user.email`, or what git derives from the
            machine when they are unset), read at run time;
* private   every pattern in a private file outside the repo (`--patterns PATH` or `NIGHTDESK_SCAN_PATTERNS`):
            one per line, literal text matched case-insensitively, or `re:<regex>`; `#` starts a comment. A line
            that is a MAC address matches that MAC in any notation (`:`, `-`, `.` or none, any case). Without the
            file this check is skipped with a warning, so a public checkout still runs the rest;
* key       common token formats (GitHub, GitLab `glpat-` and the other `gl…-` tokens, OpenAI/Anthropic-style
            `sk-`, Slack tokens and Slack and Discord webhook URLs, AWS, PEM and PGP private keys, long `Bearer`
            values, `Authorization:` headers, URLs with a password in them), any
            `<name>key|token|secret|password = <16+ chars>` in code, JSON, YAML, headers, a query string or a
            `--flag`, and a Gotify token (15 characters, `A`, `C` or `P` then 14 random ones) set to such a name;
* entropy   long random-looking strings (base64-like, or 40+ hex digits) that are not a recognised hash;
* host      `*.lan` / `*.local` / `*.home` / `*.home.arpa` / `*.internal` / `*.localdomain` names and Tailscale
            `*.ts.net` names that are not generic examples, in code too (the two code attributes ending in
            `.home` on the tree are in ALLOW);
* volume    `/Volumes/<name>` drive names (any case) that are not generic examples;
* ipv6      IPv6 literals that could be a real network (global, or unique-local outside the demo
            `fd4e:6400:d35c::/48`): documentation, the demo or listed public services only (an allowlist on purpose,
            so a real prefix is never written, not even as a hash). Also a prefix written without `::`
            (`<4 groups>/56`, `<3 groups>:`) and the reverse-DNS `….ip6.arpa` form;
* ipv4      private and shared (CGNAT, 100.64.0.0/10) IPv4 addresses outside the demo `10.86.24.0/24`, documentation
            and listed examples, also with zero-led or hex parts (every reading counts) or in reverse-DNS form
            (`….in-addr.arpa`, a whole address or a /24 zone; its forward reading counts too);
* mac       MAC addresses (`:`, `-` or Cisco `.` notation) outside the demo (`02:4e:44:…`), the documentation range
            (`00:00:5e:00:53:…`) and the locally administered space that invented test MACs use.

The address checks cover every tracked file; files that hold addresses as data on purpose are in ALLOW with the
reason. File names get the same checks as text; a hit in a name is reported as line 0 and the name itself is
redacted everywhere it is printed. A file that is not UTF-8 is decoded as UTF-16 when it has a BOM or looks like
UTF-16, else as Latin-1 when it has no NUL byte, with a warning; a file with NUL bytes that is neither is skipped
silently only when its extension is a known binary type. A PNG's text chunks (tEXt, zTXt, iTXt: comments, the
software, XMP metadata) are scanned as text, keyword and language tag included, and so is text after IEND; a hit is
shown as `[PNG <chunk> <keyword>]` with the keyword redacted. A file that cannot be read, binary content with no
known binary extension, a PNG text chunk that cannot be decoded or binary data after IEND is an `unscanned` hit (it fails the scan: nothing unchecked ships). A tracked symlink is scanned as its target path (what
git stores), never followed.

Each hit prints `file:line: category: preview` with every flagged value in the line replaced by `[REDACTED]`, so
the report itself never repeats a value. Deliberate false positives are in ALLOW below, each with its reason.
Standard library only. tests/web/test_repo_hygiene.py runs this scan in the unit suite.
"""
from __future__ import annotations

import argparse
import ipaddress
import math
import os
import re
import struct
import subprocess
import sys
import zlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

ENV_PATTERNS = "NIGHTDESK_SCAN_PATTERNS"


@dataclass(frozen=True)
class Hit:
    path: str          # as printed: redacted when the file name itself holds a flagged value
    line: int          # 0 = the file name
    category: str
    preview: str


@dataclass
class Private:
    """The private patterns: regexes, plus MAC addresses kept as 12 lower-case hex digits for any-notation matching."""
    regexes: list[re.Pattern] = field(default_factory=list)
    macs: set[str] = field(default_factory=set)

    def __len__(self) -> int:
        return len(self.regexes) + len(self.macs)


# ---------------------------------------------------------------- generic examples and allowlists

# Host names that are generic examples in docs and tests (invented devices and services of a made-up home), not
# anyone's real ones, plus code that merely looks like a .local name.
HOST_EXAMPLES = {
    "nightdesk.lan", "nightdesk.local", "desk.lan", "hlta.local", "h.lan",            # the app behind a LAN name
    "ntfy.lan", "gotify.lan", "ha.lan", "homeassistant.local",                         # notification services
    "kitchen-tablet.lan", "living-room-tv.lan", "living-room-tv.local", "demo-laptop.lan",  # demo-home devices
    "act.local", "act.home",                                                           # command-palette ids
    "host.docker.internal",                                                            # Docker's name for the host
    "nightdesk.tailnet-name.ts.net", "nightdesk.example.ts.net",                       # a made-up tailnet
}
# Drive names under /Volumes that are generic examples or test values, not a real drive (a full match, any case).
VOLUME_EXAMPLES = re.compile(r"<[^>]*>|ExternalDrive|MyDrive|Drive|other|ND-test-[\w-]+|\.\.\.|"
                             r"Macintosh", re.I)   # macOS's own boot volume ("/Volumes/Macintosh HD"), on every Mac
# Placeholder account names in home-folder paths of docs and tests (a full match, any case).
HOME_EXAMPLES = re.compile(r"<[^>]*>|you|your-?name|me|x|name|user|username|someone|someuser|example|alice|bob|"
                           r"runner|shared|guest|public|default|all users|\$USER|\$\{USER\}|\.\.\.|\*", re.I)

# (path regex or None for any file, categories regex, regex on the flagged value, reason). A hit is dropped when
# all three match. Categories: those above, plus "key-value" for the value of a key = value pair.
ALLOW: list[tuple[str | None, str, str, str]] = [
    (r"^uv\.lock$", "entropy", r".*", "uv.lock holds package hashes and URLs, nothing secret"),
    (r"^web/vendor/", "entropy|key|key-value", r".*", "vendored third-party libraries: minified code and embedded data"),
    (r"^web/vendor/", "host", r".*", "vendored third-party libraries: minified property names ending in .local"),
    (r"^osinthub/netlog/fixtures/sinkhole/adguard-querylog\.json$", "entropy", r"^EjSBgAAB[A-Za-z0-9+/=]+$",
     "fixture DNS answers: base64 DNS wire data (fixed header EjSBgAAB) for .example names"),
    (r"^tests/sources/fixtures/|^tests/sources/test_abusech\.py$", "entropy", r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|"
     r"^[0-9a-fA-F]{64}$", "feed fixtures: malware-sample hashes and certificate SHA-1 fingerprints, public data"),
    (r"^tests/eval/zeek_planted\.py$", "entropy", r"^0123456789ABCDEF", "the base-62 alphabet the generator draws from"),
    (r"^tests/app/test_help\.py$", "entropy|key|key-value", r"^(tok )?3f9a1c0e[0-9a-f]{40}$|"
     r"^(Authorization: )?Bearer abcdef12345$", "the two invented token and header values that test the redactor"),
    (None, "key", r"(?i)://(user|username|me|<[^>]*>):(pass|password|secret|token|<[^>]*>)@",
     "the user:pass@host form named in docs and comments"),
    (r"^web/js/panels/world-map\.js$", "host", r"^ICON\.home$", "the map's home button: the home icon of ICON"),
    (r"^osinthub/netlog/seen\.py$", "host", r"^v0\.home$", "a SQL column: the home column of the query's v0 rows"),
    (None, "key", r"(?i)^hooks\.slack\.com/services/T0+/B0+/X+$",
     "Slack's own documentation example of a webhook URL (zeros and X's)"),
    (None, "key-value", r"(?i)^(x{8,}|\*{8,}|\.{3,}|<[^>]*>|your[-_a-z]*|(test|fake|dummy|example|invented|sample)"
                        r"[-_][-\w]*)$",
     "a key = value whose whole value is a placeholder, or starts with a word that declares it invented"),
    # The scrubber tests (Settings › About › Copy diagnostics, nightdesk-redact) feed in invented home-network values
    # and check none survives. Each value is listed, so anything else added to these files is still caught.
    (r"^tests/app/test_(diagnostics|redact)\.py$", "ipv4",
     r"^(192\.168\.1\.23|10\.0\.0\.0|10\.0\.0\.5|192\.168\.0\.2|100\.64\.1\.1)$",
     "the scrubber tests' invented private and CGNAT addresses"),
    (r"^tests/app/test_(diagnostics|redact)\.py$", "mac", r"(?i)^(a4\:83\:e7\:12\:34\:56|00\-1B\-63\-84\-45\-E6)$",
     "the scrubber tests' invented MAC addresses (written escaped, so this line is not a MAC itself)"),
    (r"^tests/app/test_(diagnostics|redact)\.py$", "host",
     r"(?i)^(nas\.lan|printer\.local|router\.home\.arpa|laptop\.internal|Alices-MacBook-Pro\.local)$",
     "the scrubber tests' invented home host names"),
    (r"^tests/app/test_redact\.py$", "ipv6", r"(?i)^fd12\:3456\:789a\:\:5$", "the redactor test's invented private IPv6"),
    (r"^tests/app/test_diagnostics\.py$", "key|entropy|key-value", r"^(k3y-of-the-user-0123456789|"
     r"(Bearer )?eyJhbGciOiJIUzI1NiJ9[a-u]{21})$", "the invented key and token the diagnostics scrubber removes"),
]
# Private and shared IPv4 that the code and its tests use as data on purpose, by file (path regex, reason).
IPV4_DATA_FILES: list[tuple[str, str]] = [
    (r"^private/tools/calibrate_|^private/tools/attack_gold\.py$", "calibration scripts: no addresses of a real network"),
]
# Generic examples a reader types: the "e.g. 192.168.1.0/24" home-prefix hint in Settings and docs.
# Plus the handful of textbook addresses tests and backend comments use as data (router 192.168.1.1, a host on it,
# 10.0.0.x, CGNAT 100.64.0.1, benchmark 198.18.0.0): listed by value, so a new real LAN address in any file still hits.
V4_EXAMPLES = {"192.168.1.0", "192.168.1.1", "192.168.1.3", "192.168.1.10", "10.0.0.1", "10.0.0.9", "10.1.1.1",
               "10.1.2.3", "10.255.255.1", "100.64.0.1", "198.18.0.0"}
# A hex string of a hash's exact length is a hash when the line names a hash and no secret word stands right before it
# ("sha256": ["<hex>", "<hex>"] and "commit <hex>" pass; "commit token <hex>" does not).
HASH_WORDS = re.compile(r"(?i)sha-?(1|224|256|384|512)|hash|digest|commit|fingerprint|integrity|etag|checksum|"
                        r"\bmd5\b|blake|\bsri\b|\bjarm\b|\bja3|\bja4|\bsalt\b")
SECRET_BEFORE = re.compile(r"(?i)(key|token|secret|passw(or)?d|auth\w*|bearer|credential)[\"'\s:=,]*$")
HASH_LENGTHS = {32, 40, 56, 64, 96, 128}

# ---------------------------------------------------------------- checks

KEY_PATTERNS = [
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}"),
    re.compile(r"(?<![\w-])sk-(?:ant-|proj-|live-|test-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bxapp-\d-[A-Za-z0-9-]{20,}"),                                    # Slack app-level tokens
    # Slack incoming webhooks and workflow triggers: hooks.slack.com/services/T…/B…/<secret> (also with the
    # slashes escaped, as JSON may write them)
    re.compile(r"(?i)\bhooks\.slack\.com\\?/(?:services|workflows|triggers)\\?/T[A-Z0-9]{6,}\\?/[A-Za-z0-9_/\\-]{16,}"),
    # Discord webhooks: discord(app).com/api/(v10/)webhooks/<id>/<token>
    re.compile(r"(?i)\b(?:ptb\.|canary\.)?discord(?:app)?\.com/api/(?:v\d+/)?webhooks/\d{15,22}/[A-Za-z0-9_-]{30,}"),
    # GitLab personal, deploy, runner, trigger, CI job, OAuth, feed, feature-flag, incoming-mail and agent tokens
    re.compile(r"(?<![A-Za-z0-9])gl(?:pat|dt|rt|ptt|cbt|oas|soat|ft|ffct|imt|agent)-[A-Za-z0-9_.-]{20,}"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    re.compile(r"(?i)\bAuthorization:\s*(?:Basic|Token|Bearer)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@\"'<>]+:[^\s/@\"'<>]{3,}@[^\s/\"'<>]+"),
    re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://(?=[A-Za-z0-9._~-]*\d)(?=[A-Za-z0-9._~-]*[A-Za-z])[A-Za-z0-9._~-]{20,}@"),
]
# <name>key|token|secret|password, an optional closing quote, = or :, an optional opening quote, then the value up to
# whitespace, a quote, a bracket or a separator. Covers `KEY=v`, `key: v`, `"api_key": "v"`, `'Auth-Key': 'v'`,
# `apiKey = "v"` and `?apikey=v&`.
KEY_VALUE = re.compile(r"(?i)(?<![A-Za-z0-9])([A-Za-z0-9_-]*?(?:key|token|secret|password|passwd|pwd|(?<![A-Za-z])pass|(?<=_)pass))[\"']?\s*"
                       r"(?:=|:(?!:))\s*[\"']?([^\s\"'`<>,;&(){}\[\]|\\]{15,})")
# A Gotify app, client or plugin token: "A", "C" or "P" and 14 random characters (gotify/server auth/rand.go),
# shorter than the 16 that make any other key = value a key. It needs upper and lower case and a digit or one of
# . - _ after the first, so 15-letter words (AppConfigLoader) pass; the ~5% of tokens drawn as letters only are missed.
GOTIFY = re.compile(r"[ACP](?=[\w.-]*[a-z])(?=[\w.-]*[A-Z])(?=[\w.-]*[\d._-])[\w.-]{14}")
# The same names given as a command-line flag: `--token <v>`, `--api-key=<v>`.
KEY_FLAG = re.compile(r"(?i)(?<![\w-])--([a-z0-9-]*(?:key|token|secret|password|passwd))(?:=|\s+)[\"']?"
                      r"([^\s\"'`<>,;&(){}\[\]|\\]{15,})")
ENTROPY_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+_=-])[A-Za-z0-9+_=-]{32,}(?![A-Za-z0-9+_=-])")
HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")
# Not followed by "(", "[" or ".name": code such as threading.local() or BASEMAPS.local.label.
HOST = re.compile(r"(?i)(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
                  r"(?:lan|local|localdomain|internal|home\.arpa|home|ts\.net))(?![\w(\[-]|\.\w)")
VOLUME = re.compile(r"(?i)/Volumes" r"/([^/\s\"'`)<>\]]+|<[^>]+>)")
OTHER_HOME = re.compile(r"(?:(?<![\w.~-])/(?:Users|home)|(?i:\b[A-Z]:\\\\?Users))[/\\]{1,2}([^/\\\s\"'`)<>\]:;,]+)")
# A dotted quad; a part may also be 0 and three digits (an octal 0300, zero padding 0044) or hex (0xc0), the forms
# inet_aton reads. A sentence-ending "." still matches.
_V4_PART = r"(?:0[xX][0-9a-fA-F]{1,2}|0\d{3}|\d{1,3})"
# The last part: a hex part may not run on into more hex digits; a decimal part may be followed by a letter
# ("192.0.2.7beta" is still an address).
_V4_LAST = r"(?:0[xX][0-9a-fA-F]{1,2}(?![0-9A-Fa-f])|0\d{3}|\d{1,3})"
V4 = re.compile(r"(?<![\d.])((?:" + _V4_PART + r"\.){3}" + _V4_LAST + r")(?!\d|\.\d)")
PTR4 = re.compile(r"(?i)(?<![\w.-])(\d{1,3}(?:\.\d{1,3}){2,3})\.in-addr\.arpa\b")    # a whole address or a /24 zone
PTR6 = re.compile(r"(?i)(?<![\w.-])((?:[0-9a-f]\.){8,32})ip6\.arpa\b")                # a /32 or longer, nibble by nibble
# A global-unicast or unique-local prefix written without "::": 3 to 7 groups ("<g>:<g>:<g>/48",
# "<g>:<g>:<g>:<g>:" in prose), or 2 with a prefix length. A valid address (8 groups or "::") is V6's.
PART6 = re.compile(r"(?i)(?<![\w:.])((?:[23][0-9a-f]{3}|f[cd][0-9a-f]{2})(?::[0-9a-f]{1,4}){1,6})"
                   r"(/\d{1,3}|:(?![0-9a-f:]))?(?![\w:])")
V6 = re.compile(r"(?<![\w:.])\[?((?:[0-9A-Fa-f]{1,4}:){1,7}:?(?::?[0-9A-Fa-f]{1,4}){0,7}(?:%\w+)?)\]?(?![\w:])")
MAC = re.compile(r"(?<![0-9A-Fa-f:.-])([0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\2){4}[0-9A-Fa-f]{2}|"
                 r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![0-9A-Fa-f:.-]?[0-9A-Fa-f])")
BARE_MAC = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{12}(?![0-9A-Fa-f])")   # only compared with the private MACs

# IPv6 / IPv4 allowlists.
DEMO6 = ipaddress.ip_network("fd4e:6400:d35c::/48")
ULA = ipaddress.ip_network("fc00::/7")
PUBLIC6_OK = [ipaddress.ip_network(n) for n in (
    "2606:4700::/32", "2405:8100::/32", "2405:b500::/32", "2803:f800::/32", "2a06:98c0::/29", "2c0f:f248::/32",  # Cloudflare
    "2001:4860::/32", "2607:f8b0::/32",   # Google (Public DNS, services)
    "2620:fe::/48", "2620:119::/32",      # Quad9, OpenDNS (public resolvers)
    "2a03:2880::/32", "2620:149::/32", "2620:1ec::/32", "2a00:86c0::/32", "2a04:4e42::/32",  # Meta, Apple, Microsoft, Netflix, Fastly
    "200::/7",                            # Yggdrasil overlay (not the internet)
    "64:ff9b::/96",                       # NAT64 well-known prefix (SSRF tests)
    "fc00::/48", "fd00::/48", "fd00:ec2::/32",   # the first ULA of each half (examples), the AWS metadata address
)]
DEMO4 = ipaddress.ip_network("10.86.24.0/24")
DOC4 = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
CGNAT = ipaddress.ip_network("100.64.0.0/10")
MAC_DOC = ("024e44", "00005e0053")   # the demo home's MACs; RFC 7042 documentation MACs


def entropy(s: str) -> float:
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def mac_hex(s: str) -> str:
    """A MAC in any notation as 12 lower-case hex digits ("" when it is not one)."""
    h = re.sub(r"[:.\-]", "", s).lower()
    return h if re.fullmatch(r"[0-9a-f]{12}", h) else ""


def v6_literals(text: str):
    """(start, end, IPv6Address) for each IPv6 literal in text."""
    for m in V6.finditer(text):
        s = m.group(1).split("%")[0]
        if s.count(":") < 2:
            continue
        try:
            yield m.start(1), m.end(1), ipaddress.IPv6Address(s)
        except ValueError:
            continue


EXIF_DATE = re.compile(r"(?:19|20)\d\d:(?:0[1-9]|1[0-2]):(?:0[1-9]|[12]\d|3[01])")


def v6_partials(text: str):
    """(start, end, IPv6Address) for each prefix written without "::" (the network address, zero-filled) and each
    `….ip6.arpa` name of a /32 or longer."""
    for m in PART6.finditer(text):
        groups, suffix = m.group(1).split(":"), m.group(2) or ""
        if len(groups) == 2 and not suffix.startswith("/"):
            continue              # "<g>:<g>" alone is too often a ratio or a time
        if not suffix and EXIF_DATE.fullmatch(m.group(1)):
            continue              # an EXIF date or time stamp (2023:10:15): not a prefix
        try:
            yield m.start(1), m.end(1), ipaddress.IPv6Address(":".join(groups) + "::")
        except ValueError:
            continue
    for m in PTR6.finditer(text):
        nibbles = m.group(1).replace(".", "")[::-1]
        yield m.start(1), m.end(1), ipaddress.IPv6Address(int(nibbles.ljust(32, "0"), 16))


def v6_could_be_real(a: ipaddress.IPv6Address) -> bool:
    if a.ipv4_mapped or a.is_multicast or a.is_link_local or a.is_loopback or a.is_reserved \
            or not (a.is_global or a in ULA):
        return False              # loopback, link-local, multicast, documentation, mapped IPv4: not a home
    return not (a in DEMO6 or any(a in n for n in PUBLIC6_OK))


def _quad(parts: list[int]) -> ipaddress.IPv4Address | None:
    return ipaddress.IPv4Address(".".join(map(str, parts))) if all(0 <= x <= 255 for x in parts) else None


def v4_readings(dotted: str) -> list[ipaddress.IPv4Address]:
    """Every address a dotted quad can mean. Plain parts are decimal. With zero-led or hex parts there are two
    readings: inet_aton's (hex is hex, a zero-led part is octal: "010" is 8, "0300" is 192), and zero padding read as
    decimal ("044" is 44) when each zero-led part has 3 or 4 digits (padding to a width, unlike "08" in a version).
    A reading with a part past 255 or an invalid octal part does not exist."""
    parts = dotted.split(".")
    zero_led = [p for p in parts if len(p) > 1 and p[0] == "0" and p[1] not in "xX"]
    hexed = [p for p in parts if p[:2] in ("0x", "0X")]
    if not zero_led and not hexed:
        a = _quad([int(p) for p in parts])
        return [a] if a else []
    out = []
    if all(re.fullmatch(r"0[0-7]*", p) for p in zero_led):
        out.append(_quad([int(p, 16) if p in hexed else int(p, 8) if p in zero_led else int(p) for p in parts]))
    if not hexed and all(len(p) >= 3 for p in zero_led):
        out.append(_quad([int(p) for p in parts]))
    return [a for a in out if a]


def _v4_flagged(a: ipaddress.IPv4Address) -> bool:
    return bool((a.is_private or a in CGNAT) and not (a.is_loopback or a.is_link_local or a.is_unspecified)
                and a not in DEMO4 and not any(a in n for n in DOC4) and str(a) not in V4_EXAMPLES
                and not a.is_reserved and str(a) != "255.255.255.255")


def private_v4(text: str):
    """(start, end, IPv4Address) for each private or CGNAT IPv4 address that is not the demo, documentation or an
    example: written plainly, with leading zeros or hex parts, or reversed in an `in-addr.arpa` name (a /24 zone is
    checked as its network address)."""
    for m in PTR4.finditer(text):
        parts = m.group(1).split(".")[::-1]
        if any(int(p) > 255 for p in parts):
            continue
        a = ipaddress.IPv4Address(".".join(str(int(p)) for p in parts + ["0"] * (4 - len(parts))))
        if _v4_flagged(a):
            yield m.start(1), m.end(1), a
    for m in V4.finditer(text):
        # Inside an in-addr.arpa name the forward reading counts too: an address written in the wrong order before
        # a reverse zone is still an address (a value is flagged when any reading of it is private).
        cidr = re.match(r"/(\d{1,2})\b", text[m.end(1):])
        for a in v4_readings(m.group(1)):
            if cidr and int(cidr.group(1)) <= 16 and \
                    ipaddress.ip_network(f"{a}/{cidr.group(1)}", strict=False).network_address == a:
                continue          # a whole range named by its base (10.0.0.0/8, 192.168.0.0/16): not one network
            if _v4_flagged(a):
                yield m.start(1), m.end(1), a
                break


def mac_could_be_real(mac: str) -> bool:
    h = mac_hex(mac)
    if not h or h.startswith(MAC_DOC) or h in ("000000000000", "ffffffffffff"):
        return False
    first = int(h[:2], 16)
    return not (first & 0x02) and not (first & 0x01)   # locally administered (invented) or multicast: not hardware


def load_patterns(path: Path) -> Private:
    out = Private()
    for raw in path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("re:"):
            out.regexes.append(re.compile(s[3:], re.I))
        elif MAC.fullmatch(s) or re.fullmatch(r"[0-9A-Fa-f]{12}", s):
            out.macs.add(mac_hex(s))
        else:
            out.regexes.append(re.compile(re.escape(s), re.I))
    return out


# Account names of shared machines, containers and CI runners: ordinary words a scan by name cannot tell from text.
GENERIC_USERS = {"root", "user", "admin", "runner", "ubuntu", "debian", "vagrant", "app", "dev", "test", "guest",
                 "nobody", "home", "build", "ci", "docker", "node", "python", "worker", "owner"}


def _git(root: Path, *args: str) -> str:
    try:
        return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True).stdout.strip()
    except OSError:
        return ""


def repo_url_candidates(root: Path) -> list[str]:
    """This repo's own URLs: `git remote get-url origin` (the development repo in a private checkout), README.md's
    `git clone <url>` lines and the installer's `REPO="<url>"` (the public repo)."""
    readme, inst = root / "README.md", root / "deploy" / "install.sh"
    text = readme.read_text(errors="replace") if readme.is_file() else ""
    itext = inst.read_text(errors="replace") if inst.is_file() else ""
    return [u for u in [_git(root, "remote", "get-url", "origin")] + re.findall(r"git clone (\S+)", text)
            + re.findall(r'(?m)^REPO="([^"]+)"', itext) if u]


def repo_url_pattern(urls: list[str]) -> re.Pattern | None:
    """A regex for this repo's own GitHub URL(s): the one place the GitHub account name may appear. Any other
    github.com URL (another repo of the same account, a gist) is scanned like any text."""
    found = set()
    for url in urls:
        m = re.search(r"(?i)github\.com[/:]([A-Za-z0-9-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?$", url.strip())
        if m:
            found.add((m.group(1), m.group(2)))
    if not found:
        return None
    alts = "|".join(re.escape(o) + "/" + re.escape(r) for o, r in sorted(found))
    return re.compile(r"(?i)github\.com[/:](?:" + alts + r")(?:\.git)?(?![A-Za-z0-9._-])")


def identity_from(home: str, git_ident: str, urls: list[str]) -> dict:
    """The values that name the owner: home folder, login name (its last part), git name and email (from a
    `git var GIT_AUTHOR_IDENT` line), and the repo's own URL (masked before the name checks)."""
    home = home.rstrip("/")
    user = home.rsplit("/", 1)[-1]
    pats: dict = {"home": [], "user": [], "identity": [], "user_name": user.lower(), "repo_url": repo_url_pattern(urls)}
    if len(home) > 3:
        pats["home"].append(re.compile(re.escape(home)))
    if len(user) >= 3 and user.lower() not in GENERIC_USERS:
        pats["home"].append(re.compile(r"~" + re.escape(user) + r"\b", re.I))
        pats["user"].append(re.compile(r"(?<![A-Za-z0-9])" + re.escape(user) + r"(?![A-Za-z0-9])", re.I))
    m = re.match(r"(.*?)\s*<([^>]*)>", git_ident)
    for v in ([m.group(1).strip(), m.group(2).strip()] if m else []):
        if len(v) >= 3 and v.lower() != user.lower() and v.lower() not in GENERIC_USERS:
            pats["identity"].append(re.compile(r"(?<![A-Za-z0-9])" + re.escape(v) + r"(?![A-Za-z0-9])", re.I))
    return pats


def identity(root: Path) -> dict:
    """identity_from() with this machine's values, read at run time."""
    return identity_from(str(Path.home()), _git(root, "var", "GIT_AUTHOR_IDENT"), repo_url_candidates(root))


def _allowed(path: str, category: str, value: str) -> bool:
    for p, cats, rx, _why in ALLOW:
        if re.fullmatch(cats, category) and (p is None or re.search(p, path)) and re.search(rx, value):
            return True
    return False


def _key_value_is_data(v: str) -> bool:
    """A key = value whose value looks like a secret rather than code, a variable, a path or prose."""
    if len(v) < 16 or not re.search(r"[A-Za-z]", v):
        return False
    if not re.search(r"\d", v) and re.search(r"[_:]", v):
        return False                                           # no digit and _ or : in it: an identifier (snake_case, a:b)
    if "$" in v or "%" in v:                                   # a shell or template variable
        return False
    if re.fullmatch(r"[A-Z0-9_]+", v):                         # an environment variable's name
        return False
    if re.fullmatch(r"[\w-]+(\.[\w-]+)+", v):                   # a dotted name: module, attribute, host, file
        return False
    if re.match(r"(?i)[a-z][a-z0-9+.-]*://", v):               # a URL (one with credentials is a KEY_PATTERNS hit)
        return False
    if v.startswith(("/", "~", "./", "../")) or ("/" in v and "." in v):   # a path
        return False
    return True


def line_spans(path: str, line: str, ident: dict, private: Private) -> list[tuple[int, int, str]]:
    """(start, end, category) of every flagged value in one line of text (or a file name). A `<name>.home` in code
    counts as a host too, even when it is an attribute: the few on the tree are in ALLOW with their reason."""
    spans: list[tuple[int, int, str]] = []
    add = lambda a, b, cat: spans.append((a, b, cat))   # noqa: E731
    rx_url = ident.get("repo_url")
    masked = rx_url.sub(lambda m: "#" * len(m.group(0)), line) if rx_url else line   # same length: spans stay put
    for cat in ("home", "user", "identity"):
        for rx in ident.get(cat, []):
            for m in rx.finditer(masked if cat != "home" else line):
                add(m.start(), m.end(), cat)
    for m in OTHER_HOME.finditer(line):
        name = m.group(1)
        if not HOME_EXAMPLES.fullmatch(name) and name.lower() != ident.get("user_name") and \
                not _allowed(path, "home", name):
            add(m.start(1), m.end(1), "home")
    for rx in private.regexes:
        for m in rx.finditer(masked):
            add(m.start(), m.end(), "private")
    if private.macs:
        for rx in (MAC, BARE_MAC):
            for m in rx.finditer(line):
                if mac_hex(m.group(0)) in private.macs:
                    add(m.start(), m.end(), "private")
    for rx in KEY_PATTERNS:
        for m in rx.finditer(line):
            if not _allowed(path, "key", m.group(0)):
                add(m.start(), m.end(), "key")
    for m in (*KEY_VALUE.finditer(line), *KEY_FLAG.finditer(line)):
        v = m.group(2).rstrip(".:")
        data = GOTIFY.fullmatch(v) if len(v) == 15 else _key_value_is_data(v)
        if data and not _allowed(path, "key-value", v):
            add(m.start(2), m.start(2) + len(v), "key")
    for m in ENTROPY_CANDIDATE.finditer(line):
        s = m.group(0)
        if HEX_ONLY.match(s):
            if len(s) < 40 or entropy(s) < 3.5:
                continue
            if len(s) in HASH_LENGTHS and HASH_WORDS.search(line) \
                    and not SECRET_BEFORE.search(line[max(0, m.start() - 24):m.start()]):
                continue          # a hash, on a line that names it as one
        else:
            if not (re.search(r"\d", s) and re.search(r"[a-z]", s) and re.search(r"[A-Z]", s)):
                continue          # identifiers, words joined by _ or -, and constants are not random
            if entropy(s) < 4.5:
                continue
        if not _allowed(path, "entropy", s):
            add(m.start(), m.end(), "entropy")
    for m in HOST.finditer(line):
        if m.group(1).lower() not in HOST_EXAMPLES and not _allowed(path, "host", m.group(1)):
            add(m.start(1), m.end(1), "host")
    for m in VOLUME.finditer(line):
        if not VOLUME_EXAMPLES.fullmatch(m.group(1)) and not _allowed(path, "volume", m.group(1)):
            add(m.start(1), m.end(1), "volume")
    if ":" in line or "ip6.arpa" in line.lower():
        for a, b, ip in (*v6_literals(line), *v6_partials(line)):
            if v6_could_be_real(ip) and not _allowed(path, "ipv6", str(ip)):
                add(a, b, "ipv6")
    if not any(re.search(p, path) for p, _why in IPV4_DATA_FILES):
        for a, b, ip in private_v4(line):
            if not _allowed(path, "ipv4", str(ip)):
                add(a, b, "ipv4")
    for m in MAC.finditer(line):
        if mac_could_be_real(m.group(1)) and not _allowed(path, "mac", m.group(1)):
            add(m.start(1), m.end(1), "mac")
    homes = [(a, b) for a, b, c in spans if c == "home"]
    return [(a, b, c) for a, b, c in spans if c != "user" or not any(h0 <= a and b <= h1 for h0, h1 in homes)]


def scan_text(path: str, text: str, ident: dict, private: Private | None = None, shown: str | None = None) -> list[Hit]:
    """Hits in one file's text; `shown` is the name to print (the redacted name when the name itself is flagged)."""
    private = private or Private()
    hits: list[Hit] = []
    for no, line in enumerate(text.splitlines(), 1):
        spans = line_spans(path, line, ident, private)
        if spans:
            hits.extend(Hit(shown or path, no, cat, redact(line, spans)) for cat in sorted({c for _, _, c in spans}))
    return hits


def scan_name(path: str, ident: dict, private: Private | None = None) -> tuple[str, list[Hit]]:
    """The name to print for this file, and hits in the file name itself (line 0)."""
    spans = line_spans("", path, ident, private or Private())     # "" : no path allowlist applies to a name
    words = re.sub(r"[-_]", " ", path)                            # "box.lan-setup.md": a host name inside a name
    spans += [(m.start(1), m.end(1), "host") for m in HOST.finditer(words) if m.group(1).lower() not in HOST_EXAMPLES]
    spans = [s for s in spans if s[2] not in ("ipv4",) or not any(re.search(p, path) for p, _ in IPV4_DATA_FILES)]
    if not spans:
        return path, []
    shown = redact(path, spans, width=10_000)
    return shown, [Hit(shown, 0, cat, "(file name)") for cat in sorted({c for _, _, c in spans})]


def redact(line: str, spans: list[tuple[int, int, str]], width: int = 140) -> str:
    merged: list[list[int]] = []
    for a, b, _c in sorted(spans):
        if merged and a <= merged[-1][1]:     # overlapping or touching: one redacted stretch
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    out, pos = [], 0
    for a, b in merged:
        out += [line[pos:a], "[REDACTED]"]
        pos = b
    out.append(line[pos:])
    s = "".join(out).strip()
    return s if len(s) <= width else s[:width - 1] + "…"


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, text=True, check=True).stdout
    return [p for p in out.split("\0") if p]


# Extensions of binary formats: files with NUL bytes and one of these are skipped without a warning.
BINARY_EXT = {"png", "jpg", "jpeg", "gif", "webp", "ico", "icns", "bmp", "tif", "tiff", "avif", "woff", "woff2",
              "ttf", "otf", "eot", "pbf", "mvt", "gz", "tgz", "zip", "bz2", "xz", "zst", "7z", "tar", "mmdb",
              "duckdb", "db", "sqlite", "parquet", "pdf", "mp4", "webm", "mov", "mp3", "wav", "ogg", "bin", "wasm",
              "pyc", "so", "dylib", "pcap", "pcapng", "npy", "npz", "pkl", "jar"}


def _looks_utf16(data: bytes) -> str | None:
    head = data[:4096]
    if len(head) < 8:
        return None
    even, odd = head[0::2], head[1::2]
    if odd.count(0) > 0.9 * len(odd) and even.count(0) < 0.1 * len(even):
        return "utf-16-le"
    if even.count(0) > 0.9 * len(even) and odd.count(0) < 0.1 * len(odd):
        return "utf-16-be"
    return None


def read_text(p: Path) -> tuple[str | None, str | None]:
    """(text or None, warning or None). UTF-8 is read silently; other text encodings are decoded with a warning."""
    try:
        data = p.read_bytes()
    except OSError as e:
        return None, f"could not read ({e.__class__.__name__})"
    for bom, enc in ((b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe\x00\x00", "utf-32"), (b"\x00\x00\xfe\xff", "utf-32"),
                     (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16")):
        if data.startswith(bom):
            try:
                return data.decode(enc), (None if enc == "utf-8-sig" else f"{enc} text (scanned)")
            except UnicodeDecodeError:
                break
    if b"\0" in data[:8192]:
        enc = _looks_utf16(data)
        if enc:
            try:
                return data.decode(enc), f"{enc} text without a BOM (scanned)"
            except UnicodeDecodeError:
                pass
        ext = p.name.rsplit(".", 1)[-1].lower() if "." in p.name else ""
        return None, (None if ext in BINARY_EXT else "binary content with no known binary extension (not scanned)")
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return data.decode("latin-1"), "not UTF-8 (scanned as Latin-1)"


PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_TEXT_MAX = 4 << 20        # bytes one compressed text chunk may expand to (a zip bomb is unscanned, not read)


def _inflate(data: bytes) -> bytes:
    d = zlib.decompressobj()
    out = d.decompress(data, PNG_TEXT_MAX)
    if d.unconsumed_tail:
        raise ValueError("text chunk expands past the limit")
    return out


def png_text(data: bytes) -> tuple[list[tuple[str, list[tuple[str, str]]]], str | None]:
    """([(chunk type, [(field, value)])] for every tEXt, zTXt and iTXt chunk, error or None). The fields are the
    keyword, an iTXt's language tag and translated keyword (when not empty), and the text; bytes after IEND are one
    more entry, ("after IEND", [("data", text)]). A chunk that cannot be decoded, or binary data after IEND, is an
    error (not scanned)."""
    out: list[tuple[str, list[tuple[str, str]]]] = []
    pos = len(PNG_SIG)
    while pos + 8 <= len(data):
        n, kind = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + n]
        pos += 12 + n
        if kind == b"IEND":
            tail = data[pos:]
            if tail.strip(b"\0 \r\n\t"):
                if b"\0" in tail:
                    return out, "binary data after the PNG's end (IEND; not scanned)"
                out.append(("after IEND", [("data", tail.decode("latin-1"))]))
            break
        if kind not in (b"tEXt", b"zTXt", b"iTXt"):
            continue
        name = kind.decode()
        try:
            if len(body) < n:
                raise ValueError("chunk cut short")
            key, _, rest = body.partition(b"\0")
            fields = [("keyword", key.decode("latin-1"))]
            if kind == b"tEXt":
                text = rest.decode("latin-1")
            elif kind == b"zTXt":
                text = _inflate(rest[1:]).decode("latin-1")
            else:
                compressed, rest = rest[0], rest[2:]
                lang, _, rest = rest.partition(b"\0")
                tkey, _, rest = rest.partition(b"\0")
                fields += [(f, v) for f, v in (("language", lang.decode("latin-1")),
                                               ("translated keyword", tkey.decode("utf-8"))) if v]
                text = (_inflate(rest) if compressed else rest).decode("utf-8")
        except (ValueError, IndexError, UnicodeDecodeError, zlib.error) as e:
            return out, f"PNG {name} chunk could not be decoded ({e.__class__.__name__}; not scanned)"
        out.append((name, fields + [("text", text)]))
    return out, None


def scan_png(rel: str, data: bytes, ident: dict, private: Private, shown: str) -> list[Hit]:
    """Hits in a PNG's text chunks: the keyword, language tag and translated keyword as well as the text. Each
    preview starts with `[PNG <chunk> <keyword>]` (the keyword redacted like any value) or, for a hit in a field
    other than the text, `[PNG <chunk> <field>]`. Line numbers count every scanned line, in file order."""
    chunks, err = png_text(data)
    hits: list[Hit] = []
    no = 0
    for kind, fields in chunks:
        key = dict(fields).get("keyword")
        label = f"PNG {kind}" + (f" {redact(key, line_spans(rel, key, ident, private), width=80)}" if key else "")
        for part, value in fields:
            for line in value.splitlines() or [""]:
                no += 1
                spans = line_spans(rel, line, ident, private)
                if spans:
                    tag = label if part in ("text", "data") else f"PNG {kind} {part}"
                    hits.extend(Hit(shown, no, cat, f"[{tag}] " + redact(line, spans))
                                for cat in sorted({c for _, _, c in spans}))
    if err:
        hits.append(Hit(shown, 0, "unscanned", err))
    return hits


def scan(root: Path, patterns: Path | None) -> tuple[list[Hit], list[str]]:
    """All hits in the tracked files (names and text) under root, and any warnings."""
    warnings: list[str] = []
    private = Private()
    if patterns is None:
        warnings.append(f"no private patterns file (--patterns or {ENV_PATTERNS}): owner-specific names not checked")
    elif not patterns.is_file():
        warnings.append(f"private patterns file not found: {patterns}; owner-specific names not checked")
    else:
        private = load_patterns(patterns)
    ident = identity(root)
    hits: list[Hit] = []
    for rel in tracked_files(root):
        shown, name_hits = scan_name(rel, ident, private)
        hits += name_hits
        p = root / rel
        if p.is_symlink():                     # git stores the link's target path: scan that, never follow it
            hits += scan_text(rel, os.readlink(p), ident, private, shown)
            continue
        text, warn = read_text(p)
        if warn and text is None:              # could not read, or unknown binary: fail rather than ship it unchecked
            hits.append(Hit(shown, 0, "unscanned", warn))
        elif warn:
            warnings.append(f"{shown}: {warn}")
        if text is not None:
            hits += scan_text(rel, text, ident, private, shown)
        elif not warn:                         # a known binary type: only a PNG's text chunks are text to scan
            try:
                with p.open("rb") as f:
                    if f.read(len(PNG_SIG)) == PNG_SIG:
                        hits += scan_png(rel, PNG_SIG + f.read(), ident, private, shown)
            except OSError as e:
                hits.append(Hit(shown, 0, "unscanned", f"could not read ({e.__class__.__name__})"))
    return hits, warnings


def summary(hits: list[Hit]) -> str:
    by_cat = Counter(h.category for h in hits)
    by_dir = Counter(h.path.split("/", 1)[0] if "/" in h.path else h.path for h in hits)
    files = len({h.path for h in hits})
    lines = [f"{len(hits)} hits in {files} files"]
    lines.append("by category: " + (", ".join(f"{k} {v}" for k, v in sorted(by_cat.items())) or "none"))
    lines.append("by folder:   " + (", ".join(f"{k} {v}" for k, v in sorted(by_dir.items())) or "none"))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--patterns", type=Path, help=f"private patterns file (default: ${ENV_PATTERNS})")
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent, help="repository root")
    ap.add_argument("--summary", action="store_true", help="print only the counts, not each hit")
    a = ap.parse_args(argv)
    patterns = a.patterns or (Path(os.environ[ENV_PATTERNS]).expanduser() if os.environ.get(ENV_PATTERNS) else None)
    hits, warnings = scan(a.root.resolve(), patterns)
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    if not a.summary:
        for h in hits:
            print(f"{h.path}:{h.line}: {h.category}: {h.preview}")
    print(summary(hits) if hits else "release scan: clean")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
