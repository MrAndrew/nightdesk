"""Make a network-log sample safe to share (for a "log format request" issue).

    nightdesk-redact conn.log > conn-redacted.log         (installed command)
    uv run python -m osinthub.redact dns.json > dns-redacted.json

Text in, text out, any log format (Zeek, Suricata, firewall, DNS). Every value is replaced the same way everywhere it
appears in one run, so the sample still makes sense:

* IPv4: private and other local addresses -> 192.0.2.x, public ones -> 203.0.113.x, then 198.51.100.x and
  198.18.x.x (all reserved for documentation or tests). Loopback, 0.0.0.0, broadcast and multicast stay.
* IPv6: -> 2001:db8::x (link-local -> fe80::x). ::, ::1 and multicast stay.
* MAC addresses -> 02:00:00:00:xx:xx (locally administered). All-zero and broadcast stay.
* Domain and host names (and e-mail addresses) -> site1.example, site2.example ... (user1@site1.example).
  File names (conn.log, x.json) and version numbers are left alone.

It cannot know every private thing a log may hold: user names, file paths, free text, device names without a dot
(AdGuard's "CID": "study-laptop") and encoded fields (AdGuard's base64 "Answer") are not changed. Read the result
before you share it, and delete such fields if they hold anything of yours. A summary of what was replaced goes to stderr. okf/project/pre-alpha-release.md#7-feedback-from-testers
"""
from __future__ import annotations

import argparse
import ipaddress
import re
import sys

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
_IPV6 = re.compile(r"(?<![\w:.])(?=[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:)[0-9A-Fa-f:]{2,39}(?:%\w+)?(?![\w:])")
_MAC = re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}([:-]))(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![\w:-])")
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24})(?![\w-])")
_NAME = re.compile(r"(?<![\w.@-])((?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{1,23})\.?(?![\w-])")
# endings that are files or formats, not domains
_FILE_ENDINGS = {"log", "gz", "json", "ndjson", "csv", "tsv", "txt", "zip", "tar", "bz2", "xz", "conf", "cfg", "yaml",
                 "yml", "py", "sh", "js", "html", "htm", "php", "exe", "dll", "so", "pcap", "pem", "crt", "key", "md",
                 "xml", "jpg", "png", "gif", "svg", "css", "rules", "pid", "sock", "db", "duckdb", "parquet", "bin"}
_KEEP_NAMES = {"example", "example.com", "example.net", "example.org", "localhost", "in-addr.arpa", "ip6.arpa"}


class Redactor:
    def __init__(self) -> None:
        self.ips: dict[str, str] = {}
        self.macs: dict[str, str] = {}
        self.names: dict[str, str] = {}
        self._v4 = {"local": 0, "public": 0}
        self._overflow = 0
        self._v6 = {"global": 0, "link": 0}

    # ---- addresses
    def _next_v4(self, kind: str) -> str:
        """192.0.2.x for local addresses and 203.0.113.x for public ones while they last, then one shared overflow
        counter over 198.51.100.x and 198.18.0.0/15, so no two addresses ever get the same placeholder."""
        self._v4[kind] += 1
        n = self._v4[kind]
        if n <= 254:
            return f"192.0.2.{n}" if kind == "local" else f"203.0.113.{n}"
        self._overflow += 1
        k = self._overflow
        if k <= 254:
            return f"198.51.100.{k}"
        return str(ipaddress.ip_address("198.18.0.0") + (k - 254))

    def ipv4(self, m: re.Match) -> str:
        s = m.group(0)
        try:
            a = ipaddress.IPv4Address(s)
        except ValueError:
            return s
        if a.is_loopback or a.is_unspecified or a.is_multicast or s == "255.255.255.255":
            return s
        if s not in self.ips:
            local = a.is_private or a.is_link_local or a in ipaddress.ip_network("100.64.0.0/10")
            self.ips[s] = self._next_v4("local" if local else "public")
        return self.ips[s]

    def ipv6(self, m: re.Match) -> str:
        s = m.group(0)
        bare = s.split("%")[0]
        try:
            a = ipaddress.IPv6Address(bare)
        except ValueError:
            return s
        if a.is_loopback or a.is_unspecified or a.is_multicast:
            return s
        key = str(a)
        if key not in self.ips:
            kind = "link" if a.is_link_local else "global"
            self._v6[kind] += 1
            self.ips[key] = f"{'fe80' if kind == 'link' else '2001:db8'}::{self._v6[kind]:x}"
        return self.ips[key]

    def mac(self, m: re.Match) -> str:
        s = m.group(0)
        sep = m.group(1)
        low = s.lower().replace("-", ":")
        if low in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return s
        if low not in self.macs:
            n = len(self.macs) + 1
            self.macs[low] = f"02:00:00:00:{n >> 8 & 0xff:02x}:{n & 0xff:02x}"
        return self.macs[low].replace(":", sep)

    # ---- names
    def _name_for(self, name: str) -> str:
        low = name.lower().rstrip(".")
        if low in _KEEP_NAMES or low.endswith((".example", ".example.com", ".example.net", ".example.org", ".arpa",
                                               ".invalid", ".test")):
            return name
        if low not in self.names:
            self.names[low] = f"site{len(self.names) + 1}.example"
        return self.names[low]

    def name(self, m: re.Match) -> str:
        s = m.group(1)
        tail = s.rsplit(".", 1)[-1].lower()
        if tail in _FILE_ENDINGS or tail.isdigit():
            return m.group(0)
        return m.group(0).replace(s, self._name_for(s), 1)

    def email(self, m: re.Match) -> str:
        n = len(self.names) + 1
        return f"user{n}@{self._name_for(m.group(1))}"

    # ---- a line
    def line(self, text: str) -> str:
        text = _EMAIL.sub(self.email, text)
        text = _MAC.sub(self.mac, text)
        text = _IPV6.sub(self.ipv6, text)
        text = _IPV4.sub(self.ipv4, text)
        return _NAME.sub(self.name, text)

    def summary(self) -> str:
        return (f"redacted: {len(self.ips)} addresses, {len(self.macs)} MAC addresses, {len(self.names)} names. "
                "Read the result before you share it: user names, paths, free text, device names without a dot and "
                "encoded fields (such as AdGuard's base64 Answer) are not changed.")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="nightdesk-redact", description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="*", help="log files to read (default: standard input)")
    a = ap.parse_args(argv)
    r = Redactor()
    streams = [open(f, encoding="utf-8", errors="replace") for f in a.files] or [sys.stdin]
    try:
        for fh in streams:
            for ln in fh:
                sys.stdout.write(r.line(ln))
    finally:
        for fh in streams:
            if fh is not sys.stdin:
                fh.close()
    print(r.summary(), file=sys.stderr)
    return 0


def cli() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    cli()
