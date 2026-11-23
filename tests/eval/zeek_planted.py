#!/usr/bin/env python3
"""Planted-traffic test for HLTA's network-log feature.

Generates synthetic Zeek JSON logs (conn, dns, ssl, http, ntp, dhcp) for an
invented home network on documentation prefixes, plants contacts with real
threat indicators taken from the seed lake, imports the files into a running
HLTA server and scores the alerts against the build brief's thresholds.

    uv run python tests/eval/zeek_planted.py --base http://127.0.0.1:8801
    uv run python tests/eval/zeek_planted.py --base http://127.0.0.1:8801 --perf
    uv run python tests/eval/zeek_planted.py --out-dir /tmp/zeek-planted   # files only

Ground truth (planted positives and named decoys) is written to
<dir>/manifest.json. The method is described in tests/eval/README.md.
"""

from __future__ import annotations

import argparse
import bisect
import gzip
import heapq
import ipaddress
import json
import os
import random
import re
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_LAKE = os.environ.get("ND_SEED_LAKE", "")   # the seed lake (a real lake from 2026-11-04), set per machine
HOME_PREFIXES = ["192.0.2.0/24", "2001:db8:1::/48"]
LIST_SOURCES = ["feodo_c2", "spamhaus_drop", "tor_exits", "dshield_top", "blocklist_de", "et_compromised"]
ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# Thresholds from tests/eval/README.md, "Pass bars".
RECALL_BAR = 1.0
FALSE_ALERT_BAR = 0
IMPORT_SECONDS_PER_1M = 60.0


def utc(s: str) -> float:
    return datetime.fromisoformat(s).replace(tzinfo=UTC).timestamp()


# Time windows of the synthetic capture (UTC).
OCT = (utc("2026-10-01T00:00:00"), utc("2026-10-02T00:00:00"))     # a month before anything was listed
NOV = (utc("2026-11-04T03:00:00"), utc("2026-11-05T00:00:00"))     # the seed lake's day
EDGE = (utc("2026-11-04T03:15:00"), utc("2026-11-04T04:50:00"))    # hours before the lake's first fetch
LIVE = (utc("2026-11-04T18:36:00"), utc("2026-11-04T23:25:00"))    # where listed-and-active contacts go


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --------------------------------------------------------------------------------------
# Seed lake: listing intervals from record deltas
# --------------------------------------------------------------------------------------

_PATH_TS = re.compile(r"(\d{4})/(\d{2})/(\d{2})/(\d{2})(\d{2})?(\d{2})?\.")


def path_ts(p: Path) -> float | None:
    m = _PATH_TS.search(p.as_posix())
    if not m:
        return None
    y, mo, d, h, mi, s = (int(x) if x else 0 for x in m.groups())
    return datetime(y, mo, d, h, mi, s, tzinfo=UTC).timestamp()


@dataclass
class Seed:
    intervals: dict = field(default_factory=dict)      # (source, value) -> [[start, end|None], ...]
    feodo: dict = field(default_factory=dict)          # ip -> provider record
    earliest_file: dict = field(default_factory=dict)  # source -> ts of earliest raw file of any kind
    last_records: float = 0.0
    all_ips: set = field(default_factory=set)          # every IP any seed list or event ever named
    drop_nets: list = field(default_factory=list)      # every DROP netblock ever listed
    db_copy: str = ""

    def active(self, source: str, value: str, t: float) -> bool:
        for s, e in self.intervals.get((source, value), ()):
            if s <= t and (e is None or t < e):
                return True
        return False

    def window(self, source: str, value: str, lo: float, hi: float, margin: float = 120.0):
        """First sub-range of [lo, hi] inside a listing interval of (source, value), with margin."""
        for s, e in self.intervals.get((source, value), ()):
            a, b = max(lo, s + margin), min(hi, (e if e is not None else hi + margin) - margin)
            if a < b:
                return a, b
        return None

    def first_put(self, source: str, value: str) -> float | None:
        iv = self.intervals.get((source, value))
        return iv[0][0] if iv else None

    def listed_anywhere(self, ip: str) -> bool:
        if ip in self.all_ips:
            return True
        a = ipaddress.ip_address(ip)
        return any(a in n for n in self.drop_nets if n.version == a.version)

    def drop_net_of(self, ip: str):
        a = ipaddress.ip_address(ip)
        return next((n for n in self.drop_nets if n.version == a.version and a in n), None)


def _value_of(source: str, key: str, data) -> str:
    if source == "feodo_c2":
        rec = data[0] if isinstance(data, list) else data
        if isinstance(rec, dict) and rec.get("ip_address"):
            return rec["ip_address"]
        return key.rsplit(":", 1)[0]
    return key


def load_seed(lake: Path, work: Path) -> Seed:
    """Copy the seed's list sources and DuckDB file into `work`, then read only the copies."""
    seed = Seed()
    raw_copy = work / "raw"
    for src in LIST_SOURCES:
        s = lake / "raw" / src
        if s.is_dir() and not (raw_copy / src).exists():
            shutil.copytree(s, raw_copy / src)
    db_src = lake / "db" / "hub.duckdb"
    if db_src.exists():
        (work / "db").mkdir(parents=True, exist_ok=True)
        for f in db_src.parent.glob("hub.duckdb*"):
            shutil.copy2(f, work / "db" / f.name)
        seed.db_copy = str(work / "db" / "hub.duckdb")

    for src in LIST_SOURCES:
        files = sorted((raw_copy / src).rglob("*"), key=lambda p: (path_ts(p) or 0, p.name))
        files = [p for p in files if p.is_file() and path_ts(p) is not None]
        if files:
            seed.earliest_file[src] = min(path_ts(p) for p in files)
        open_since: dict[str, float] = {}
        for p in files:
            if not p.name.endswith(".records.ndjson.gz"):
                continue
            t = path_ts(p)
            seed.last_records = max(seed.last_records, t)
            with gzip.open(p, "rt") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    r = json.loads(line)
                    key, op, data = r["key"], r.get("op"), r.get("data")
                    value = _value_of(src, key, data)
                    if src == "feodo_c2" and op == "put":
                        seed.feodo[value] = data[0] if isinstance(data, list) else data
                    if op == "put":
                        if value not in open_since:
                            open_since[value] = t
                            seed.intervals.setdefault((src, value), []).append([t, None])
                    elif op == "del" and value in open_since:
                        open_since.pop(value)
                        seed.intervals[(src, value)][-1][1] = t
        for (s, value) in [k for k in seed.intervals if k[0] == src]:
            if src == "spamhaus_drop":
                try:
                    seed.drop_nets.append(ipaddress.ip_network(value, strict=False))
                except ValueError:
                    pass
            else:
                seed.all_ips.add(value)

    # Belt and braces: every IP the warehouse knows from any source (full payloads included).
    if seed.db_copy:
        try:
            import duckdb

            con = duckdb.connect(seed.db_copy, read_only=True)
            for (ip,) in con.execute("select distinct ip from events where ip is not null").fetchall():
                seed.all_ips.add(ip)
            for (k,) in con.execute(
                "select key from record_hashes where source='spamhaus_drop'"
            ).fetchall():
                try:
                    seed.drop_nets.append(ipaddress.ip_network(k, strict=False))
                except ValueError:
                    pass
            con.close()
        except Exception as e:  # the generator must still work from the raw files alone
            print(f"note: could not read the DuckDB copy ({e}); using raw record files only", file=sys.stderr)
    seed.drop_nets = sorted(set(seed.drop_nets), key=lambda n: (n.version, int(n.network_address)))
    return seed


# --------------------------------------------------------------------------------------
# The home network
# --------------------------------------------------------------------------------------

V6_LAN = ipaddress.ip_network("2001:db8:1:630::/64")
ROUTER4, ROUTER6 = "192.0.2.1", "2001:db8:1:630::1"


@dataclass
class Device:
    name: str
    mac: str
    ip_oct: str
    ip_nov: str
    v6: bool
    weight: float
    v6_slots: dict = field(default_factory=dict)

    def v4(self, t: float) -> str:
        return self.ip_oct if t < NOV[0] else self.ip_nov

    def v6addr(self, t: float, rng: random.Random) -> str:
        # RFC 8981 temporary addresses: daily in October, every two hours on the busy day.
        slot = ("oct", 0) if t < NOV[0] else ("nov", int((t - NOV[0]) // 7200))
        if slot not in self.v6_slots:
            iid = rng.getrandbits(64) | (1 << 57)
            self.v6_slots[slot] = str(V6_LAN.network_address + iid)
        return self.v6_slots[slot]


def make_devices() -> list[Device]:
    m = lambda n: f"00:00:5e:00:53:{n:02x}"  # RFC 7042 documentation MAC range
    return [
        Device("gw-router", m(0x01), "192.0.2.1", "192.0.2.1", True, 0.3),
        Device("nas", m(0x0a), "192.0.2.10", "192.0.2.10", False, 0.6),
        Device("alice-laptop", m(0x1a), "192.0.2.23", "192.0.2.23", True, 3.0),
        Device("win-desktop", m(0x23), "192.0.2.35", "192.0.2.35", True, 2.5),
        # .57 belongs to bob-iphone in October but to a guest laptop on 4 November.
        Device("bob-iphone", m(0x39), "192.0.2.57", "192.0.2.88", True, 2.0),
        Device("guest-laptop", m(0x5c), "192.0.2.61", "192.0.2.57", False, 0.8),
        Device("ipad", m(0x42), "192.0.2.66", "192.0.2.66", True, 1.2),
        Device("living-room-tv", m(0x65), "192.0.2.101", "192.0.2.101", False, 2.0),
        Device("ip-camera", m(0x8c), "192.0.2.140", "192.0.2.140", False, 0.7),
        Device("thermostat", m(0x8f), "192.0.2.143", "192.0.2.143", False, 0.2),
        Device("printer", m(0xc8), "192.0.2.200", "192.0.2.200", False, 0.1),
    ]


# --------------------------------------------------------------------------------------
# Benign destinations (verified against every seed list)
# --------------------------------------------------------------------------------------

SERVICES = [
    ("google", ["www.google.com", "www.gstatic.com", "fonts.googleapis.com", "play.googleapis.com"],
     ["142.250.0.0/15", "172.217.0.0/16"], ["2607:f8b0:4004::/48"]),
    ("youtube", ["www.youtube.com", "i.ytimg.com", "rr3---sn-a5mekn7s.googlevideo.com"],
     ["142.250.0.0/15", "173.194.0.0/16"], ["2607:f8b0:4004::/48"]),
    ("apple", ["www.apple.com", "gateway.icloud.com", "gsp-ssl.ls.apple.com", "mesu.apple.com"],
     ["17.0.0.0/8"], ["2620:149:a44::/48"]),
    ("microsoft", ["login.microsoftonline.com", "outlook.office365.com", "www.bing.com",
                   "settings-win.data.microsoft.com"], ["13.107.0.0/16", "20.190.128.0/18"], ["2620:1ec::/36"]),
    ("cloudflare", ["www.cloudflare.com", "discord.com", "cdnjs.cloudflare.com"],
     ["104.16.0.0/13", "172.64.0.0/13"], ["2606:4700::/32"]),
    ("fastly", ["www.reddit.com", "stackoverflow.com", "pypi.org", "www.nytimes.com"],
     ["151.101.0.0/16"], ["2a04:4e42::/32"]),
    ("github", ["github.com", "api.github.com", "codeload.github.com"], ["140.82.112.0/20"], []),
    ("meta", ["www.facebook.com", "graph.instagram.com", "mmg.whatsapp.net"],
     ["157.240.0.0/16", "31.13.24.0/21"], ["2a03:2880::/32"]),
    ("netflix", ["www.netflix.com", "occ-0-1168-299.1.nflxso.net", "ipv4-c001-ord001-ix.1.oca.nflxvideo.net"],
     ["45.57.0.0/17", "198.38.96.0/19"], ["2a00:86c0::/32"]),
]
RESOLVERS4 = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222"]
RESOLVERS6 = ["2606:4700:4700::1111", "2001:4860:4860::8888", "2620:fe::fe"]
NTP4 = [("time.apple.com", "17.253.4.125"), ("time.google.com", "216.239.35.0"),
        ("time.google.com", "216.239.35.4"), ("time.cloudflare.com", "162.159.200.1"),
        ("time.cloudflare.com", "162.159.200.123"), ("time-a-g.nist.gov", "129.6.15.28")]
NTP6 = [("time.google.com", "2001:4860:4806::"), ("time.cloudflare.com", "2606:4700:f1::1")]
CHECKS = [("connectivitycheck.gstatic.com", "/generate_204", 204, "google"),
          ("captive.apple.com", "/hotspot-detect.html", 200, "apple"),
          ("www.msftconnecttest.com", "/connecttest.txt", 200, "microsoft"),
          ("ocsp.digicert.com", "/MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ", 200, "fastly")]
UAS = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
       "Microsoft NCSI", "CaptiveNetworkSupport-481.100.1 wispr", "Dalvik/2.1.0 (Linux; U; Android 14; SmartTV)"]


class Pool:
    """Benign remote addresses per service, each one checked against every seed list."""

    def __init__(self, seed: Seed, rng: random.Random, per_service: int):
        self.v4: dict[str, list[str]] = {}
        self.v6: dict[str, list[str]] = {}
        self.names: dict[str, list[str]] = {}
        self.rejected: list[str] = []
        for name, hosts, p4, p6 in SERVICES:
            self.names[name] = hosts
            self.v4[name] = self._draw(seed, rng, p4, per_service)
            self.v6[name] = self._draw(seed, rng, p6, max(4, per_service // 4)) if p6 else []
        self.resolvers4 = [ip for ip in RESOLVERS4 if self._ok(seed, ip)]
        self.resolvers6 = [ip for ip in RESOLVERS6 if self._ok(seed, ip)]
        self.ntp4 = [x for x in NTP4 if self._ok(seed, x[1])]
        self.ntp6 = [x for x in NTP6 if self._ok(seed, x[1])]

    def _ok(self, seed: Seed, ip: str) -> bool:
        if seed.listed_anywhere(ip):
            self.rejected.append(ip)
            return False
        return True

    def _draw(self, seed, rng, prefixes, n):
        out: list[str] = []
        nets = [ipaddress.ip_network(p) for p in prefixes]
        tries = 0
        while len(out) < n and tries < n * 20:
            tries += 1
            net = rng.choice(nets)
            span = min(net.num_addresses - 2, 2**32)
            ip = str(net.network_address + 1 + rng.randrange(span))
            if ip not in out and self._ok(seed, ip):
                out.append(ip)
        return out


# --------------------------------------------------------------------------------------
# Zeek record builders (field names and types as Zeek 6/7 writes them in JSON)
# --------------------------------------------------------------------------------------


class Ids:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.seen: set[str] = set()

    def uid(self, prefix: str = "C") -> str:
        while True:
            u = prefix + "".join(self.rng.choices(ALNUM, k=17))
            if u not in self.seen:
                self.seen.add(u)
                return u


def conn(ts, uid, oh, op, rh, rp, proto="tcp", service=None, state="SF", duration=None,
         ob=0, rb=0, local_orig=True, local_resp=False, opk=None, rpk=None):
    r = {"ts": round(ts, 6), "uid": uid, "id.orig_h": oh, "id.orig_p": op, "id.resp_h": rh, "id.resp_p": rp,
         "proto": proto}
    if service:
        r["service"] = service
    v6 = ":" in oh
    hdr = (60 if v6 else 40) if proto == "tcp" else (48 if v6 else 28)
    if state == "S0":
        opk = opk or 1
        if opk > 1 and duration:
            r["duration"] = round(duration, 6)
        r.update(orig_bytes=0, resp_bytes=0, conn_state="S0", local_orig=local_orig, local_resp=local_resp,
                 missed_bytes=0, history="S", orig_pkts=opk, orig_ip_bytes=opk * (hdr + 4 if proto == "tcp" else hdr),
                 resp_pkts=0, resp_ip_bytes=0)
    elif state == "REJ":
        r.update(duration=round(duration or 0.000213, 6), orig_bytes=0, resp_bytes=0, conn_state="REJ",
                 local_orig=local_orig, local_resp=local_resp, missed_bytes=0, history="Sr", orig_pkts=1,
                 orig_ip_bytes=hdr + 4, resp_pkts=1, resp_ip_bytes=hdr)
    else:
        opk = opk or max(1, ob // 900 + (3 if proto == "tcp" else 1))
        rpk = rpk or max(1, rb // 1200 + (2 if proto == "tcp" else 1))
        r.update(duration=round(duration if duration is not None else 0.05, 6), orig_bytes=ob, resp_bytes=rb,
                 conn_state=state, local_orig=local_orig, local_resp=local_resp, missed_bytes=0,
                 history=("ShADadFf" if proto == "tcp" else "Dd"), orig_pkts=opk, orig_ip_bytes=ob + opk * hdr,
                 resp_pkts=rpk, resp_ip_bytes=rb + rpk * hdr)
    r["ip_proto"] = 6 if proto == "tcp" else 17
    return r


def dns(ts, uid, oh, op, rh, rp, query, answers, qtype=1, ttl=300.0, proto="udp", rcode=0, trans_id=None, rng=None):
    qtn = {1: "A", 28: "AAAA", 12: "PTR", 65: "HTTPS", 16: "TXT"}[qtype]
    r = {"ts": round(ts, 6), "uid": uid, "id.orig_h": oh, "id.orig_p": op, "id.resp_h": rh, "id.resp_p": rp,
         "proto": proto, "trans_id": trans_id if trans_id is not None else (rng.randrange(65536) if rng else 0),
         "query": query, "qclass": 1, "qclass_name": "C_INTERNET", "qtype": qtype, "qtype_name": qtn,
         "rcode": rcode, "rcode_name": {0: "NOERROR", 3: "NXDOMAIN"}[rcode],
         "AA": False, "TC": False, "RD": rp != 5353, "RA": rp != 5353, "Z": 0, "rejected": False}
    if answers:
        r["rtt"] = 0.0182
        r["answers"] = answers
        r["TTLs"] = [float(ttl)] * len(answers)
    return r


def ssl(ts, uid, oh, op, rh, rp, sni=None, version="TLSv13", established=True):
    r = {"ts": round(ts + 0.012, 6), "uid": uid, "id.orig_h": oh, "id.orig_p": op, "id.resp_h": rh, "id.resp_p": rp,
         "version": version,
         "cipher": "TLS_AES_128_GCM_SHA256" if version == "TLSv13" else "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
         "curve": "x25519", "resumed": False, "established": established,
         "ssl_history": "CsiI" if version == "TLSv13" else "CsxknGIi"}
    if sni:
        r["server_name"] = sni
        r["sni_matches_cert"] = True
    return r


def http(ts, uid, oh, op, rh, rp, method, host, uri, status, ua, req_len=0, resp_len=0, fuid=None, mime=None):
    r = {"ts": round(ts + 0.004, 6), "uid": uid, "id.orig_h": oh, "id.orig_p": op, "id.resp_h": rh, "id.resp_p": rp,
         "trans_depth": 1, "method": method, "host": host, "uri": uri, "version": "1.1", "user_agent": ua,
         "request_body_len": req_len, "response_body_len": resp_len, "status_code": status,
         "status_msg": {200: "OK", 204: "No Content", 404: "Not Found"}.get(status, "OK"), "tags": []}
    if fuid and resp_len:
        r["resp_fuids"] = [fuid]
        r["resp_mime_types"] = [mime or "text/plain"]
    return r


def ntp(ts, uid, oh, op, rh, rp, mode):
    r = {"ts": round(ts, 6), "uid": uid, "id.orig_h": oh, "id.orig_p": op, "id.resp_h": rh, "id.resp_p": rp,
         "version": 4, "mode": mode, "stratum": 0 if mode == 3 else 1, "poll": 1.0 if mode == 3 else 8.0,
         "precision": 1.0 if mode == 3 else 2.0 ** -25,
         "root_delay": 0.0 if mode == 3 else 0.000015, "root_disp": 0.0 if mode == 3 else 0.000107,
         "ref_id": "\\x00\\x00\\x00\\x00" if mode == 3 else "GOOG",
         "ref_time": 0.0 if mode == 3 else round(ts - 11.2, 6), "org_time": 0.0 if mode == 3 else round(ts, 6),
         "rec_time": 0.0 if mode == 3 else round(ts + 0.009, 6), "xmt_time": round(ts + (0 if mode == 3 else 0.0091), 7),
         "num_exts": 0}
    return r


def dhcp(ts, uid, dev: Device, ip, lease, msg_types, hostname=True):
    r = {"ts": round(ts, 6), "uids": [uid], "client_addr": ip, "server_addr": ROUTER4, "mac": dev.mac,
         "domain": "home.arpa", "assigned_addr": ip, "lease_time": float(lease), "msg_types": msg_types,
         "duration": 0.004112}
    if hostname:
        r["host_name"] = dev.name
    if "DISCOVER" in msg_types:
        r["requested_addr"] = ip
        r["duration"] = 1.0347
    return r


# --------------------------------------------------------------------------------------
# Output files: several per log type, NDJSON and JSON-array formats
# --------------------------------------------------------------------------------------

# (log, first ts of the part, file name, format, iso timestamps)
PARTS = {
    "conn": [(0, "conn.2026-10-01.log", "ndjson", False),
             (NOV[0], "conn.2026-11-04-03.log", "ndjson", False),
             (utc("2026-11-04T20:00:00"), "conn.2026-11-04-20.json", "array", False),
             (utc("2026-11-04T22:00:00"), "conn.2026-11-04-22.json", "array", True)],
    "dns": [(0, "dns.2026-10-01.log", "ndjson", False),
            (NOV[0], "dns.2026-11-04-03.log", "ndjson", False),
            (utc("2026-11-04T21:00:00"), "dns.2026-11-04-21.json", "array", True)],
    "ssl": [(0, "ssl.1.log", "ndjson", False), (utc("2026-11-04T21:00:00"), "ssl.2.json", "array", False)],
    "http": [(0, "http.1.log", "ndjson", False), (utc("2026-11-04T20:30:00"), "http.2.json", "array", False)],
    "ntp": [(0, "ntp.1.log", "ndjson", False), (utc("2026-11-04T19:00:00"), "ntp.2.json", "array", False)],
    "dhcp": [(0, "dhcp.1.log", "ndjson", False), (utc("2026-11-04T18:00:00"), "dhcp.2.json", "array", False)],
}


class Out:
    def __init__(self, d: Path):
        self.d = d
        self.fh: dict[str, object] = {}
        self.first: dict[str, bool] = {}
        self.fmt: dict[str, tuple[str, bool]] = {}
        self.lines: dict[str, int] = {}
        self.starts = {log: [p[0] for p in parts] for log, parts in PARTS.items()}
        for log, parts in PARTS.items():
            for _, name, fmt, isots in parts:
                f = open(d / name, "w", encoding="utf-8", newline="\n")
                if fmt == "array":
                    f.write("[\n")
                self.fh[name], self.first[name], self.fmt[name], self.lines[name] = f, True, (fmt, isots), 0

    def write(self, log: str, rec: dict):
        idx = bisect.bisect_right(self.starts[log], rec["ts"]) - 1
        name = PARTS[log][max(0, idx)][1]
        fmt, isots = self.fmt[name]
        if isots:
            rec = dict(rec, ts=iso(rec["ts"]))
        s = json.dumps(rec, separators=(",", ":"))
        f = self.fh[name]
        if fmt == "array":
            f.write(s if self.first[name] else ",\n" + s)
        else:
            f.write(s + "\n")
        self.first[name] = False
        self.lines[name] += 1

    def close(self):
        for name, f in self.fh.items():
            if self.fmt[name][0] == "array":
                f.write("\n]\n")
            f.close()

    def files(self, logs):
        return [self.d / p[1] for log in logs for p in PARTS[log]]


# --------------------------------------------------------------------------------------
# Scenario: planted positives, named decoys, benign volume
# --------------------------------------------------------------------------------------


@dataclass
class Truth:
    uid: str
    kind: str          # "positive" or "decoy"
    category: str
    ts: float
    orig: str
    resp: str
    indicator: str
    source: str
    device: str = ""
    mac: str = ""
    note: str = ""


class Scenario:
    def __init__(self, seed: Seed, rng_seed: int, conn_target: int):
        # Separate RNG streams so the planted scenario is identical in normal and --perf runs.
        rng = random.Random(rng_seed)
        self.rng_seed = rng_seed
        self.seed, self.rng, self.ids = seed, rng, Ids(rng)
        self.devices = make_devices()
        self.dev = {d.name: d for d in self.devices}
        self.pool = Pool(seed, random.Random(rng_seed + 1), per_service=60 if conn_target <= 100_000 else 300)
        self.events: list[tuple[float, int, str, dict]] = []   # (ts, seq, log, record) for planted/fixed lines
        self.truth: list[Truth] = []
        self.benign_uids: set[str] = set()
        self.decoy_only_ips: set[str] = set()
        self.conn_target = conn_target
        self._seq = 0

    # helpers --------------------------------------------------------------------------
    def emit(self, log, rec):
        self._seq += 1
        self.events.append((rec["ts"], self._seq, log, rec))

    def eport(self):
        return self.rng.randint(49152, 65535)

    def mark(self, kind, category, uid, ts, dev: Device | None, orig, resp, indicator, source, note=""):
        self.truth.append(Truth(uid, kind, category, ts, orig, resp, indicator, source,
                                dev.name if dev else "", dev.mac if dev else "", note))

    def t_in(self, lo_hi):
        lo, hi = lo_hi
        return self.rng.uniform(lo, hi)

    def outbound(self, kind, category, dev, ts, rip, rport, indicator, source, *, proto="tcp", service=None,
                 state="SF", duration=None, ob=None, rb=None, sni=None, note="", http_req=None):
        uid = self.ids.uid()
        src = dev.v4(ts)
        sp = self.eport()
        if ob is None:
            ob = self.rng.randint(300, 4000) if state == "SF" else 0
        if rb is None:
            rb = self.rng.randint(800, 20000) if state == "SF" else 0
        opk = 3 if state == "S0" else None
        self.emit("conn", conn(ts, uid, src, sp, rip, rport, proto, service, state,
                               duration if duration is not None else (8.9 if state == "S0" else self.rng.uniform(0.2, 3.0)),
                               ob, rb, opk=opk))
        if service == "ssl":
            self.emit("ssl", ssl(ts, uid, src, sp, rip, rport, sni=sni, version="TLSv12"))
        if http_req:
            method, host, uri, ua = http_req
            self.emit("http", http(ts, uid, src, sp, rip, rport, method, host, uri, 200, ua,
                                   req_len=ob - 200 if ob > 200 else ob, resp_len=rb - 300 if rb > 300 else rb,
                                   fuid=self.ids.uid("F"), mime="application/octet-stream"))
        self.mark(kind, category, uid, ts, dev, src, rip, indicator, source, note)
        return uid

    def resolve(self, kind, category, dev, ts, name, ip, indicator, source, note=""):
        uid = self.ids.uid()
        src = dev.v4(ts)
        sp = self.eport()
        self.emit("conn", conn(ts, uid, src, sp, ROUTER4, 53, "udp", "dns", "SF", 0.0181, 37 + len(name), 53 + len(name),
                               local_resp=True, opk=1, rpk=1))
        self.emit("dns", dns(ts, uid, src, sp, ROUTER4, 53, name, [ip], ttl=60.0, rng=self.rng))
        self.mark(kind, category, uid, ts, dev, src, ip, indicator, source, note)
        return uid

    # planted ----------------------------------------------------------------------------
    def plant(self):
        s, rng, d = self.seed, self.rng, self.dev
        feodo = sorted(s.feodo.items())
        if not feodo:
            raise SystemExit("seed lake has no Feodo C2 records; cannot plant C2 contacts")
        infected = [d["win-desktop"], d["ip-camera"], d["alice-laptop"], d["guest-laptop"], d["thermostat"]]
        odd_ports = [4443, 8443, 2222, 7080, 995, 2078, 32100, 6881]
        dns_names = {}
        for i, (ip, rec) in enumerate(feodo):
            port = int(rec.get("port") or 443)
            status = rec.get("status", "")
            note = f"{rec.get('malware')} C2, feodo status {status}, listed port {port}"
            win = s.window("feodo_c2", ip, *LIVE)
            if not win:
                print(f"note: feodo {ip} has no listing interval inside the live window; skipped", file=sys.stderr)
                continue
            dev = infected[i % len(infected)]
            fp = s.first_put("feodo_c2", ip)
            name = f"{''.join(rng.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=10))}.example.net"
            dns_names[ip] = name
            # 1. the listed port, TLS without SNI (or HTTP for the 8080 Emotet tier)
            if port == 443:
                self.outbound("positive", "feodo_listed_port", dev, self.t_in(win), ip, port, ip, "feodo_c2",
                              service="ssl", note=note)
            else:
                self.outbound("positive", "feodo_http", dev, self.t_in(win), ip, port, ip, "feodo_c2", service="http",
                              ob=1840, rb=532, note=note,
                              http_req=("POST", ip, f"/{rng.randrange(10**6)}/", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1)"))
            # 2. an odd port, no recognised service
            self.outbound("positive", "feodo_odd_port", dev, self.t_in(win), ip, odd_ports[i % len(odd_ports)], ip,
                          "feodo_c2", note=note)
            # 3. a long session (90 minutes) from a different device
            self.outbound("positive", "feodo_long_duration", infected[(i + 2) % len(infected)], self.t_in((win[0], win[1] - 5400) if win[1] - win[0] > 6000 else win),
                          ip, port, ip, "feodo_c2", service="ssl" if port == 443 else None, duration=5400.0 + rng.random() * 600,
                          ob=rng.randint(2_000_000, 9_000_000), rb=rng.randint(200_000, 900_000), note=note)
            # 4. DNS answer pointing at the C2, then a connection to it (first three IPs)
            if i < 3:
                t = self.t_in(win)
                self.resolve("positive", "feodo_dns_answer", dev, t, name, ip, ip, "feodo_c2", note=note)
                self.outbound("positive", "feodo_after_dns", dev, t + 0.031, ip, port, ip, "feodo_c2",
                              service="ssl" if port == 443 else None, sni=name if port == 443 else None, note=note)
            # 5. failed outbound beacon attempts (no answer) for two IPs
            if i in (1, 3):
                self.outbound("positive", "feodo_attempt_s0", dev, self.t_in(win), ip, port, ip, "feodo_c2",
                              state="S0", note=note)
            # 6. a beacon series every ~5 minutes for the first IP
            if i == 0:
                t0 = self.t_in((win[0], max(win[0] + 1, win[1] - 1500)))
                for k in range(4):
                    self.outbound("positive", "feodo_beacon", dev, t0 + k * 300 + rng.uniform(-8, 8), ip, port, ip,
                                  "feodo_c2", service="ssl" if port == 443 else None, ob=rng.randint(400, 700),
                                  rb=rng.randint(300, 600), note=note)
            # 7. an edge contact a few minutes after it was first stored
            if i == 2 and fp and s.active("feodo_c2", ip, fp + 240) and fp + 240 < LIVE[1]:
                self.outbound("positive", "feodo_minutes_after_listing", dev, fp + 240 + rng.random() * 30, ip, port, ip,
                              "feodo_c2", service="ssl" if port == 443 else None, note=note)

            # decoys: the same IP before it was listed
            earliest = min(s.earliest_file.values())
            oct_dev = d["bob-iphone"] if dev is d["guest-laptop"] else dev  # .57 was bob-iphone in October
            self.outbound("decoy", "pre_listing_c2", oct_dev, self.t_in(OCT), ip, port, ip, "feodo_c2",
                          service="ssl" if port == 443 else None, note=note + "; 2026-10-01, a month before first stored")
            self.outbound("decoy", "pre_listing_c2", infected[(i + 1) % len(infected)], self.t_in(OCT), ip,
                          odd_ports[i % len(odd_ports)], ip, "feodo_c2", duration=4000.0, ob=900_000, rb=120_000,
                          note=note + "; October, odd port, long")
            if i < 3:
                t = self.t_in(OCT)
                self.resolve("decoy", "pre_listing_c2_dns", dev, t, name, ip, ip, "feodo_c2", note="October DNS answer")
                self.outbound("decoy", "pre_listing_c2", dev, t + 0.03, ip, port, ip, "feodo_c2",
                              service="ssl" if port == 443 else None, note="October conn after DNS")
            if EDGE[0] < earliest - 600:
                self.outbound("decoy", "pre_listing_c2_same_day", dev, self.t_in((EDGE[0], min(EDGE[1], earliest - 600))),
                              ip, port, ip, "feodo_c2", service="ssl" if port == 443 else None,
                              note="2026-11-04 before the lake's first fetch of any list")
            # decoys: neighbours in the same /24 that are on no list
            base = ipaddress.ip_address(ip)
            for delta in (1, -1, 2, -2, 3):
                n = str(base + delta)
                if not s.listed_anywhere(n):
                    self.decoy_only_ips.add(n)
                    self.outbound("decoy", "c2_neighbour", d["alice-laptop"], self.t_in(LIVE), n, port, n, "",
                                  service="ssl" if port == 443 else None, note=f"next to {ip}, on no list")
                    break

        # Spamhaus DROP: addresses inside active netblocks
        nets = [n for n in s.drop_nets if n.version == 4 and n.num_addresses >= 4
                and s.window("spamhaus_drop", str(n), *LIVE)]
        pick = rng.sample(nets, min(9, len(nets)))
        drop_devs = [d["living-room-tv"], d["win-desktop"], d["bob-iphone"], d["ipad"], d["nas"], d["alice-laptop"]]
        for j, net in enumerate(pick):
            while True:
                a = str(net.network_address + 1 + rng.randrange(net.num_addresses - 2))
                if a not in s.all_ips:
                    break
            win = s.window("spamhaus_drop", str(net), *LIVE)
            dev = drop_devs[j % len(drop_devs)]
            note = f"inside DROP {net}"
            if j % 3 == 0:
                self.outbound("positive", "drop_https", dev, self.t_in(win), a, 443, str(net), "spamhaus_drop",
                              service="ssl", sni=None, note=note)
            elif j % 3 == 1:
                self.outbound("positive", "drop_odd_port_long", dev, self.t_in(win), a, rng.choice([8081, 1337, 5222, 9999]),
                              str(net), "spamhaus_drop", duration=3600.0 + rng.random() * 3600,
                              ob=rng.randint(50_000, 900_000), rb=rng.randint(1_000_000, 30_000_000), note=note)
            else:
                self.outbound("positive", "drop_udp", dev, self.t_in(win), a, rng.choice([53, 1194, 51820]), str(net),
                              "spamhaus_drop", proto="udp", duration=rng.uniform(1, 120), ob=rng.randint(200, 9000),
                              rb=rng.randint(200, 9000), note=note)
            if j < 4:
                self.outbound("decoy", "pre_listing_drop", dev, self.t_in(OCT), a, 443, str(net), "spamhaus_drop",
                              service="ssl", note=note + "; October, before DROP was first stored")
            # just outside the netblock
            for edge_ip in (net.broadcast_address + 1, net.network_address - 1):
                e = str(edge_ip)
                if not s.listed_anywhere(e) and len([t for t in self.truth if t.category == "drop_edge"]) < 6:
                    self.decoy_only_ips.add(e)
                    self.outbound("decoy", "drop_edge", d["alice-laptop"], self.t_in(LIVE), e, 443, e, "",
                                  service="ssl", note=f"just outside DROP {net}")
                    break

        self._inbound_and_tor()
        self._dhcp()

    def _clean_other(self, ip, own):
        """True when ip is on no list other than `own` and in no DROP block."""
        s = self.seed
        if s.drop_net_of(ip) or ip in s.feodo:
            return False
        for src in ("tor_exits", "dshield_top", "blocklist_de", "et_compromised"):
            if src != own and (src, ip) in s.intervals:
                return False
        return True

    def _inbound_and_tor(self):
        s, rng = self.seed, self.rng
        targets = [(ROUTER4, [22, 23, 80, 443, 7547, 8080, 37215]), ("192.0.2.10", [22, 445, 3389, 5000, 5555])]
        for src, n in (("dshield_top", 25), ("blocklist_de", 25)):
            cands = sorted(v for (so, v) in s.intervals if so == src and ":" not in v)
            rng.shuffle(cands)
            used = 0
            for ip in cands:
                if used >= n:
                    break
                win = s.window(src, ip, *LIVE, margin=60)
                if not win or not self._clean_other(ip, src):
                    continue
                used += 1
                self.decoy_only_ips.add(ip)
                for _ in range(rng.randint(1, 3)):
                    t = self.t_in(win)
                    host, ports = rng.choice(targets)
                    state = rng.choice(["S0", "S0", "REJ"])
                    uid = self.ids.uid()
                    self.emit("conn", conn(t, uid, ip, rng.randint(1024, 65535), host, rng.choice(ports), "tcp", None,
                                           state, None, local_orig=False, local_resp=True, opk=rng.choice([1, 2])))
                    self.mark("decoy", f"inbound_{src}", uid, t, None, ip, host, ip, src, f"inbound {state} scan")
        # outbound to Tor exits, inside their listing intervals
        tors = sorted(v for (so, v) in s.intervals if so == "tor_exits")
        rng.shuffle(tors)
        users = [self.dev["alice-laptop"], self.dev["win-desktop"], self.dev["nas"]]
        used = 0
        for ip in tors:
            if used >= 15:
                break
            win = s.window("tor_exits", ip, *LIVE)
            if not win or not self._clean_other(ip, "tor_exits") or ":" in ip:
                continue
            used += 1
            self.decoy_only_ips.add(ip)
            dev = users[used % len(users)]
            self.outbound("decoy", "tor_exit_outbound", dev, self.t_in(win), ip, rng.choice([443, 9001, 9001, 8443]),
                          ip, "tor_exits", service="ssl", duration=rng.uniform(30, 7200),
                          ob=rng.randint(20_000, 4_000_000), rb=rng.randint(100_000, 40_000_000), note="Tor exit (relay port)")

    def _dhcp(self):
        rng = self.rng
        for lo, hi in (OCT, NOV):
            for dev in self.devices:
                if dev.name == "gw-router":
                    continue
                t = lo + rng.uniform(5, 600)
                first = True
                while t < hi:
                    ip = dev.v4(t)
                    uid = self.ids.uid()
                    self.benign_uids.add(uid)
                    if first:
                        self.emit("conn", conn(t, uid, "0.0.0.0", 68, "255.255.255.255", 67, "udp", "dhcp", "S0", 1.03,
                                               local_orig=False, local_resp=False, opk=2))
                        self.emit("dhcp", dhcp(t, uid, dev, ip, 7200, ["DISCOVER", "OFFER", "REQUEST", "ACK"],
                                               hostname=dev.name != "ip-camera"))
                    else:
                        self.emit("conn", conn(t, uid, ip, 68, ROUTER4, 67, "udp", "dhcp", "SF", 0.0041, 300, 300,
                                               local_resp=True, opk=1, rpk=1))
                        self.emit("dhcp", dhcp(t, uid, dev, ip, 7200, ["REQUEST", "ACK"], hostname=dev.name != "ip-camera"))
                    first = False
                    t += 3600 + rng.uniform(-60, 60)

    # benign volume ------------------------------------------------------------------------
    def benign(self):
        """Yield (ts, seq, log, rec) for benign traffic, in time order, filling up conn_target."""
        fixed_conn = sum(1 for e in self.events if e[2] == "conn")
        n = max(0, self.conn_target - fixed_conn)
        rng = self.rng = self.ids.rng = random.Random(self.rng_seed + 2)
        n_oct = n // 4
        devs = [x for x in self.devices if x.name not in ("gw-router",)]
        weights = [x.weight for x in devs]
        seq = 10**9
        for (lo, hi), cnt in ((OCT, n_oct), (NOV, n - n_oct)):
            times = sorted(rng.uniform(lo, hi) for _ in range(cnt))
            for t in times:
                dev = rng.choices(devs, weights)[0]
                for log, rec in self._one(t, dev):
                    seq += 1
                    yield (rec["ts"], seq, log, rec)

    def _one(self, t, dev):
        rng, pool = self.rng, self.pool
        uid = self.ids.uid()
        self.benign_uids.add(uid)
        v6 = dev.v6 and rng.random() < 0.35
        src = dev.v6addr(t, rng) if v6 else dev.v4(t)
        sp = self.eport()
        r = rng.random()
        svc = rng.choice(SERVICES)[0]
        if r < 0.30:  # DNS through the home router
            host = rng.choice(pool.names[svc])
            ips = pool.v6[svc] if v6 and pool.v6[svc] else pool.v4[svc]
            ans = rng.sample(ips, min(len(ips), rng.randint(1, 3)))
            if rng.random() < 0.15:
                ans = [f"{host}.cdn.cloudflare.net"] + ans if svc == "cloudflare" else ans
            dst = ROUTER6 if v6 else ROUTER4
            yield "conn", conn(t, uid, src, sp, dst, 53, "udp", "dns", "SF", rng.uniform(0.003, 0.08),
                               30 + len(host), 46 + 16 * len(ans), local_resp=True, opk=1, rpk=1)
            yield "dns", dns(t, uid, src, sp, dst, 53, host, ans, qtype=28 if v6 else 1,
                             ttl=rng.choice([60, 300, 3600]), rng=rng)
        elif r < 0.66:  # HTTPS to a big service
            ips = pool.v6[svc] if v6 and pool.v6[svc] else pool.v4[svc]
            dst = rng.choice(ips)
            dur = rng.expovariate(1 / 20) if rng.random() < 0.95 else rng.uniform(600, 14_400)
            ob, rb = int(rng.expovariate(1 / 3000)) + 517, int(rng.expovariate(1 / 60_000)) + 3000
            if svc in ("netflix", "youtube") and rng.random() < 0.3:
                rb, dur = rng.randint(50_000_000, 900_000_000), rng.uniform(600, 7200)
            yield "conn", conn(t, uid, src, sp, dst, 443, "tcp", "ssl", "SF", dur, ob, rb)
            if rng.random() < 0.3:
                yield "ssl", ssl(t, uid, src, sp, dst, 443, sni=rng.choice(pool.names[svc]))
        elif r < 0.74:  # QUIC
            g = "google" if rng.random() < 0.7 else "meta"
            ips = pool.v6[g] if v6 else pool.v4[g]
            yield "conn", conn(t, uid, src, sp, rng.choice(ips), 443, "udp", "quic,ssl", "SF",
                               rng.uniform(0.5, 120), rng.randint(2000, 60_000), rng.randint(5000, 2_000_000))
        elif r < 0.79:  # straight to public resolvers: Do53, DoT, DoH
            rs = pool.resolvers6 if v6 else pool.resolvers4
            dst = rng.choice(rs)
            k = rng.random()
            if k < 0.6:
                host = rng.choice(pool.names[svc])
                ans = rng.sample(pool.v6[svc] if v6 and pool.v6[svc] else pool.v4[svc], 1)
                yield "conn", conn(t, uid, src, sp, dst, 53, "udp", "dns", "SF", 0.0213, 30 + len(host), 62,
                                   opk=1, rpk=1)
                yield "dns", dns(t, uid, src, sp, dst, 53, host, ans, qtype=28 if v6 else 1, rng=rng)
            else:
                port = 853 if k < 0.8 else 443
                yield "conn", conn(t, uid, src, sp, dst, port, "tcp", "ssl", "SF", rng.uniform(5, 300),
                                   rng.randint(2000, 20000), rng.randint(4000, 60000))
                if rng.random() < 0.5:
                    sni = {"1.1.1.1": "one.one.one.one", "8.8.8.8": "dns.google"}.get(dst, "cloudflare-dns.com")
                    yield "ssl", ssl(t, uid, src, sp, dst, port, sni=sni)
        elif r < 0.82:  # NTP
            name, dst = rng.choice(pool.ntp6 if v6 and pool.ntp6 else pool.ntp4)
            yield "conn", conn(t, uid, src, 123 if dev.name in ("nas", "printer") else sp, dst, 123, "udp", "ntp", "SF",
                               0.0094, 48, 48, opk=1, rpk=1)
            yield "ntp", ntp(t, uid, src, sp, dst, 123, 3)
            yield "ntp", ntp(t + 0.0094, uid, src, sp, dst, 123, 4)
        elif r < 0.89:  # mDNS
            dst = "ff02::fb" if v6 else "224.0.0.251"
            q = rng.choice(["_googlecast._tcp.local", "_airplay._tcp.local", "_companion-link._tcp.local",
                            "_ipp._tcp.local", "_spotify-connect._tcp.local", "_raop._tcp.local"])
            yield "conn", conn(t, uid, src, 5353, dst, 5353, "udp", "dns", "S0", None, local_resp=False, opk=1)
            yield "dns", dns(t, uid, src, 5353, dst, 5353, q, None, qtype=12, trans_id=0)
        elif r < 0.95:  # LAN: NAS, printer, TV casting
            dst, port, service = rng.choice([("192.0.2.10", 445, "smb,gssapi"), ("192.0.2.10", 5001, "ssl"),
                                             ("192.0.2.200", 631, "http"), ("192.0.2.200", 9100, None),
                                             ("192.0.2.101", 8009, "ssl")])
            if dst == dev.v4(t):
                dst, port, service = ROUTER4, 80, "http"
            yield "conn", conn(t, uid, dev.v4(t), sp, dst, port, "tcp", service, "SF", rng.uniform(0.1, 900),
                               rng.randint(500, 5_000_000), rng.randint(500, 50_000_000), local_resp=True)
        else:  # plain HTTP: captive-portal checks, OCSP
            host, uri, status, which = rng.choice(CHECKS)
            dst = rng.choice(pool.v4[which])
            src = dev.v4(t)
            rb = 0 if status == 204 else rng.randint(60, 1500)
            yield "conn", conn(t, uid, src, sp, dst, 80, "tcp", "http", "SF", rng.uniform(0.02, 0.4), 160, rb + 240)
            yield "http", http(t, uid, src, sp, dst, 80, "GET", host, uri, status, rng.choice(UAS), 0, rb,
                               fuid=self.ids.uid("F") if rb else None)


def generate(seed: Seed, out_dir: Path, rng_seed: int, conn_target: int) -> dict:
    sc = Scenario(seed, rng_seed, conn_target)
    sc.plant()
    planted = sorted(sc.events, key=lambda e: (e[0], e[1]))
    out_dir.mkdir(parents=True, exist_ok=True)
    out = Out(out_dir)
    for _, _, log, rec in heapq.merge(planted, sc.benign(), key=lambda e: (e[0], e[1])):
        out.write(log, rec)
    out.close()
    manifest = {
        "generated_by": "tests/eval/zeek_planted.py",
        "rng_seed": rng_seed,
        "home_prefixes": HOME_PREFIXES,
        "conn_lines": sum(v for k, v in out.lines.items() if k.startswith("conn.")),
        "lines_per_file": out.lines,
        "devices": [{"name": d.name, "mac": d.mac, "ipv4_oct": d.ip_oct, "ipv4_nov": d.ip_nov,
                     "ipv6_temporary": sorted(d.v6_slots.values())} for d in sc.devices],
        "rejected_benign_candidates": sorted(set(sc.pool.rejected)),
        "truth": [t.__dict__ | {"ts_iso": iso(t.ts)} for t in sc.truth],
        "listing": {
            ip: {"first_stored": iso(sc.seed.first_put("feodo_c2", ip)), "status": r.get("status"),
                 "malware": r.get("malware"), "port": r.get("port"), "provider_first_seen": r.get("first_seen")}
            for ip, r in sorted(sc.seed.feodo.items())
        },
        "earliest_lake_file": {k: iso(v) for k, v in sc.seed.earliest_file.items()},
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=1))
    return {"scenario": sc, "out": out, "manifest": manifest}


# --------------------------------------------------------------------------------------
# Import and scoring
# --------------------------------------------------------------------------------------


def post_files(client, base, files: list[Path]) -> tuple[float, object]:
    last = None
    for field_name in ("files", "file"):
        handles = [open(f, "rb") for f in files]
        try:
            parts = [(field_name, (f.name, h, "application/json")) for f, h in zip(files, handles)]
            t0 = time.perf_counter()
            r = client.post(f"{base}/api/netlog/import", files=parts)
            dt = time.perf_counter() - t0
        finally:
            for h in handles:
                h.close()
        if r.status_code != 422:
            r.raise_for_status()
            try:
                return dt, r.json()
            except ValueError:
                return dt, r.text
        last = r
    raise SystemExit(f"import rejected: {last.status_code} {last.text[:500]}")


def alerts_list(payload) -> list[dict]:
    if isinstance(payload, list):
        return payload
    for k in ("alerts", "items", "data", "results"):
        if isinstance(payload, dict) and isinstance(payload.get(k), list):
            return payload[k]
    raise SystemExit(f"unexpected /api/netlog/alerts payload: {str(payload)[:300]}")


def evidence_uids(a: dict) -> list[str]:
    ev = a.get("evidence")
    if isinstance(ev, str):
        try:
            ev = json.loads(ev)
        except ValueError:
            ev = {}
    uids = (ev or {}).get("uids") or []
    return [uids] if isinstance(uids, str) else list(uids)


def score(base: str, gen: dict, perf: bool) -> int:
    import httpx

    sc: Scenario = gen["scenario"]
    out: Out = gen["out"]
    client = httpx.Client(timeout=httpx.Timeout(10.0, read=None, write=None))
    try:
        client.get(f"{base}/api/netlog/settings").raise_for_status()
    except Exception as e:
        print(f"server not reachable or netlog API missing at {base}: {e}")
        print(f"files were written to {out.d}")
        return 2
    r = client.put(f"{base}/api/netlog/settings", json={"home_prefixes": HOME_PREFIXES})
    r.raise_for_status()

    other = out.files(["dhcp", "dns", "ssl", "http", "ntp"])
    conns = out.files(["conn"])
    t_other, _ = post_files(client, base, other)
    t_conn, resp = post_files(client, base, conns)
    n_conn = gen["manifest"]["conn_lines"]
    alerts = alerts_list(client.get(f"{base}/api/netlog/alerts", params={"limit": 0}).json())

    hm = [a for a in alerts if str(a.get("severity", "")).lower() in ("high", "medium")]
    pos = {t.uid: t for t in sc.truth if t.kind == "positive"}
    dec = {t.uid: t for t in sc.truth if t.kind == "decoy"}
    hit: dict[str, dict] = {}
    false_alerts = []
    for a in hm:
        uids = evidence_uids(a)
        for u in uids:
            if u in pos and u not in hit:
                hit[u] = a
        bad = [u for u in uids if u in dec or u in sc.benign_uids]
        by_ind = str(a.get("indicator", "")) in sc.decoy_only_ips
        if bad or by_ind:
            false_alerts.append((a, bad))

    # per-category breakdown
    def tally(items, found):
        c: dict[str, list[int]] = {}
        for t in items:
            c.setdefault(t.category, [0, 0])
            c[t.category][1] += 1
            c[t.category][0] += t.uid in found
        return c

    print(f"\nalerts: {len(alerts)} total, {len(hm)} high/medium")
    print("\nplanted positives (found / planted):")
    for cat, (f, n) in sorted(tally(pos.values(), hit).items()):
        print(f"  {cat:32s} {f:3d} / {n}")
    status_c: dict[str, list[int]] = {}
    for t in pos.values():
        if t.source == "feodo_c2":
            st = "online" if "status online" in t.note else "offline"
            status_c.setdefault(st, [0, 0])
            status_c[st][1] += 1
            status_c[st][0] += t.uid in hit
    for st, (f, n) in sorted(status_c.items()):
        print(f"  (feodo status {st:7s})              {f:3d} / {n}")
    missed = [t for t in pos.values() if t.uid not in hit]
    for t in missed[:25]:
        print(f"  MISSED {t.uid} {t.category} {iso(t.ts)} {t.orig} -> {t.resp} ({t.note})")

    touched = {u for a, bad in false_alerts for u in bad}
    print("\ndecoys touched by high/medium alerts (touched / planted):")
    for cat, (f, n) in sorted(tally(dec.values(), touched).items()):
        print(f"  {cat:32s} {f:3d} / {n}")
    nb = len(touched & sc.benign_uids)
    print(f"  {'benign':32s} {nb:3d} / {len(sc.benign_uids)}")
    for a, bad in false_alerts[:15]:
        print(f"  FALSE {a.get('severity')} rule={a.get('rule')} indicator={a.get('indicator')} uids={bad[:3]}")

    # device attribution (informational)
    dev_ok = 0
    for u, a in hit.items():
        t = pos[u]
        dv = json.dumps(a.get("device", "")).lower()
        if t.mac and (t.mac in dv or t.device.lower() in dv or t.orig in dv):
            dev_ok += 1

    recall = len(hit) / len(pos) if pos else 0.0
    per_1m = t_conn / n_conn * 1_000_000 if n_conn else 0.0
    rows = [
        ("recall on planted C2 contacts", f"{recall:.1%} ({len(hit)}/{len(pos)})", f"= {RECALL_BAR:.0%}",
         recall >= RECALL_BAR),
        ("high/medium alerts on decoys", str(len(false_alerts)), f"= {FALSE_ALERT_BAR}", len(false_alerts) <= FALSE_ALERT_BAR),
        (f"conn import ({n_conn:,} lines)", f"{t_conn:.1f} s ({per_1m:.1f} s per 1M)", f"< {IMPORT_SECONDS_PER_1M:.0f} s per 1M",
         (per_1m < IMPORT_SECONDS_PER_1M) if perf else None),
    ]
    print(f"\nother logs import: {t_other:.1f} s; device attribution on found positives (info): {dev_ok}/{len(hit)}")
    print("\n| check | measured | bar | result |\n|---|---|---|---|")
    ok = True
    for name, m, bar, res in rows:
        tag = "PASS" if res else ("SKIP (run --perf)" if res is None else "FAIL")
        ok &= res is not False
        print(f"| {name} | {m} | {bar} | {tag} |")
    print(f"\nOVERALL: {'PASS' if ok else 'FAIL'}" + ("" if perf else " (import speed not measured; use --perf)"))
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", help="HLTA server, e.g. http://127.0.0.1:8801 (omit to only write files)")
    ap.add_argument("--seed", type=int, default=20261104, help="RNG seed (default 20261104)")
    ap.add_argument("--perf", action="store_true", help="generate 1,000,000 conn lines and time their import")
    ap.add_argument("--conn-lines", type=int, help="override the conn line count (default 30,000; 1,000,000 with --perf)")
    ap.add_argument("--out-dir", type=Path, help="only write the files here (no import, no scoring)")
    ap.add_argument("--lake", type=Path, default=Path(DEFAULT_LAKE) if DEFAULT_LAKE else None,
                    help="seed lake to read (copied first; default $ND_SEED_LAKE)")
    args = ap.parse_args(argv)
    if args.lake is None:
        ap.error("no seed lake: pass --lake or set ND_SEED_LAKE")

    n = args.conn_lines or (1_000_000 if args.perf else 30_000)
    work = Path(tempfile.mkdtemp(prefix="zeek-planted-"))
    out_dir = args.out_dir or (work / "logs")
    t0 = time.perf_counter()
    seed = load_seed(args.lake, work / "seed")
    gen = generate(seed, out_dir, args.seed, n)
    m = gen["manifest"]
    npos = sum(1 for t in m["truth"] if t["kind"] == "positive")
    ndec = sum(1 for t in m["truth"] if t["kind"] == "decoy")
    print(f"wrote {sum(m['lines_per_file'].values()):,} lines ({m['conn_lines']:,} conn) to {out_dir} "
          f"in {time.perf_counter() - t0:.1f} s: {npos} planted positives, {ndec} named decoys, "
          f"{len(gen['scenario'].benign_uids):,} benign connections")
    if args.out_dir or not args.base:
        shutil.rmtree(work / "seed", ignore_errors=True)
        print(f"ground truth: {out_dir / 'manifest.json'}")
        return 0
    try:
        return score(args.base.rstrip("/"), gen, args.perf)
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
