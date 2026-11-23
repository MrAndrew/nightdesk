"""DNS sinkhole logs (Pi-hole, AdGuard Home) turned into netlog DNS rows. Format notes: okf/data/netlog.md#dns-sinkhole-logs

Three formats are recognised by content, never by file name:

* ``pihole-log``  the dnsmasq/FTL query log (/var/log/pihole/pihole.log): ``query[A] name from client`` lines followed by
  ``reply`` / ``cached`` / ``gravity blocked`` … ``name is answer`` lines, in plain or ``log-queries=extra`` mode.
* ``pihole-api``  a Pi-hole v6 query export: the JSON body of ``GET /api/queries`` (``{"queries": [...]}``), or just its
  list of query objects.
* ``adguard``     AdGuard Home's ``querylog.json`` (one JSON object per line: ``T``, ``QH``, ``QT``, ``IP``, ``Result`` …).

Every query becomes one Zeek-shaped DNS object (``_path: dns``, ``id.orig_h`` = the client, ``query``, ``qtype_name``,
``answers``) plus the sinkhole's own facts (``sinkhole``, ``blocked``, ``verdict``, ``reason``, ``rule``, ``list_id``,
``client_name``, ``upstream``). The importer loads those objects exactly like a Zeek dns.log, so dedupe, devices and
matching need no special case. The original file is what the lake keeps.
"""
from __future__ import annotations

import base64
import binascii
import datetime as dt
import gzip
import hashlib
import ipaddress
import json
import re
import time
from collections import OrderedDict
from pathlib import Path
from collections.abc import Iterator

HEAD_BYTES = 256 << 10            # how much of a file detection looks at
MAX_JSON_BYTES = 1 << 30          # a Pi-hole API export is parsed whole; refuse a bigger one
MAX_PENDING = 50_000              # pihole.log queries waiting for their answer before the oldest is written out
FORMATS = {"pihole-log": "Pi-hole query log", "pihole-api": "Pi-hole query export", "adguard": "AdGuard Home query log"}
SOURCE = {"pihole-log": "pihole", "pihole-api": "pihole", "adguard": "adguard"}

# ------------------------------------------------------------------ Pi-hole verdicts
# FTL query status (src/enums.h, enum query_status) → blocked? Statuses the API reports by name.
PIHOLE_BLOCKED = {"GRAVITY", "REGEX", "DENYLIST", "BLACKLIST", "EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL",
                  "EXTERNAL_BLOCKED_NXRA", "EXTERNAL_BLOCKED_EDE15", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME",
                  "BLACKLIST_CNAME", "SPECIAL_DOMAIN", "DBBUSY"}
PIHOLE_REASON = {
    "GRAVITY": "on a blocklist", "GRAVITY_CNAME": "on a blocklist (via CNAME)",
    "REGEX": "matched a regex deny rule", "REGEX_CNAME": "matched a regex deny rule (via CNAME)",
    "DENYLIST": "on your deny list", "DENYLIST_CNAME": "on your deny list (via CNAME)",
    "BLACKLIST": "on your deny list", "BLACKLIST_CNAME": "on your deny list (via CNAME)",
    "EXTERNAL_BLOCKED_IP": "blocked by the upstream server", "EXTERNAL_BLOCKED_NULL": "blocked by the upstream server",
    "EXTERNAL_BLOCKED_NXRA": "blocked by the upstream server", "EXTERNAL_BLOCKED_EDE15": "blocked by the upstream server",
    "SPECIAL_DOMAIN": "special domain answered by Pi-hole", "DBBUSY": "refused while the blocklist database was busy",
    "FORWARDED": "forwarded", "CACHE": "answered from cache", "CACHE_STALE": "answered from cache (stale)",
    "RETRIED": "retried", "RETRIED_DNSSEC": "retried (DNSSEC)", "IN_PROGRESS": "in progress", "UNKNOWN": "unknown",
}
# pihole.log: the text before "<name> is <answer>" (dnsmasq log_query source, or FTL's blockingreason). Anything that
# names a block (FTL v6 "gravity blocked", "regex denied", "exactly denied", "blocked upstream with …", v5
# "regex blacklisted", "exactly blacklisted", v4 "/etc/pihole/gravity.list") is a block.
_LOG_BLOCK = re.compile(r"blocked|denied|blacklist|black\.list|gravity\.list|regex\.list|special domain|canary|"
                        r"private relay|designated resolver|rate-limiting|to be (?:refused|dropped)", re.I)
_LOG_ALLOWED = {"reply": "forwarded", "cached": "answered from cache", "cached-stale": "answered from cache (stale)",
                "config": "answered by local config", "DHCP": "local DHCP name", "auth": "authoritative",
                "Pi-hole hostname": "Pi-hole's own name"}

# ------------------------------------------------------------------ AdGuard verdicts (internal/filtering/reason.go)
ADGUARD_REASON = ["not filtered", "allowed by an allowlist rule", "not filtered (filter error)", "on a blocklist",
                  "blocked by safe browsing", "blocked by parental control", "invalid request",
                  "safe search", "blocked service", "rewritten", "rewritten by hosts file", "rewritten by a rule"]
ADGUARD_REASON_ID = ["NotFilteredNotFound", "NotFilteredWhiteList", "NotFilteredError", "FilteredBlackList",
                     "FilteredSafeBrowsing", "FilteredParental", "FilteredInvalid", "FilteredSafeSearch",
                     "FilteredBlockedService", "Rewrite", "RewriteEtcHosts", "RewriteRule"]
ADGUARD_BLOCKED = {3, 4, 5, 6, 8}   # FilteredBlockList, SafeBrowsing, Parental, Invalid, BlockedService
#                                     (7 SafeSearch rewrites to a safe host; 9-11 are rewrites, not blocks)

# ------------------------------------------------------------------ pihole.log line shape
_MON = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}
_LINE = re.compile(
    r"^(?:(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<day>\d{1,2})\s+"
    r"(?P<hms>\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d{1,9}))?"
    r"|(?P<iso>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?))"
    r"\s+(?:[\w.-]+\s+)?(?:dnsmasq|pihole-FTL)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*?)\s*$")
_EXTRA = re.compile(r"^(?:(?:UDP|TCP) )?(?P<id>\d+) (?:(?P<caddr>[0-9A-Fa-f:.%\w]+)/(?P<cport>\d+) )?(?P<rest>.*)$")
_QUERY = re.compile(r"^query\[(?P<qt>[^\]]+)\] (?P<name>\S+) from (?P<client>\S+)$")
_ANSWER = re.compile(r"^(?P<src>.+?) (?P<name>\S+) is (?P<dest>\S+)")
_IGNORE = re.compile(r"^(?:forwarded|validation|dnssec-query|dnssec-retry|ipset add|nftset add|non-query opcode)\b")


# ------------------------------------------------------------------ detection
def _head(path: Path) -> str:
    with gzip.open(path, "rb") as fh:
        return fh.read(HEAD_BYTES).decode("utf-8", "replace").lstrip("﻿ \t\r\n")


def detect(path: Path) -> str | None:
    """The sinkhole format of a (gzipped, lake-stored) file from its first lines, or None."""
    try:
        head = _head(path)
    except (OSError, EOFError):
        return None
    return detect_text(head)


def detect_text(head: str) -> str | None:
    if not head:
        return None
    if head[0] == "{":
        first = head.split("\n", 1)[0].strip()
        try:
            o = json.loads(first)
        except ValueError:
            o = None
        if isinstance(o, dict) and "QH" in o and "T" in o and ("IP" in o or "QT" in o):
            return "adguard"
        if re.search(r'"queries"\s*:\s*\[', head[:4096] if o is None else first[:4096]) and _pihole_obj(head):
            return "pihole-api"
        return None
    if head[0] == "[":
        return "pihole-api" if re.match(r"\[\s*\{", head) and _pihole_obj(head) else None
    lines = [ln for ln in head.split("\n")[:200] if ln.strip()]
    if len(lines) > 1 and not head.endswith("\n"):
        lines = lines[:-1]   # the last line may be cut by HEAD_BYTES
    ours = [m for m in (_LINE.match(ln) for ln in lines) if m]
    if ours and len(ours) * 2 >= len(lines) and any(
            _QUERY.match(_strip_extra(m["msg"])[1]) or _ANSWER.match(_strip_extra(m["msg"])[1]) for m in ours):
        return "pihole-log"
    return None


def _pihole_obj(head: str) -> bool:
    """A Pi-hole API query object: domain, client {ip}, status, all near each other."""
    return bool(re.search(r'"domain"\s*:', head) and re.search(r'"client"\s*:\s*\{\s*"(?:ip|name)"', head)
                and re.search(r'"status"\s*:', head) and re.search(r'"time"\s*:', head))


# ------------------------------------------------------------------ shared helpers
def _ip(s) -> str | None:
    if not s or not isinstance(s, str):
        return None
    s = s.strip().strip("[]")
    if "%" in s:
        s = s.split("%", 1)[0]
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return None
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        return str(a.ipv4_mapped)
    return str(a)


def _name(s) -> str | None:
    if not s or not isinstance(s, str):
        return None
    s = s.strip().rstrip(".").lower()
    return s or None


class _Uids:
    """Deterministic row ids: the same query in an overlapping export gets the same uid, so it dedupes like a Zeek
    row with the same uid. The n-th identical (client, time, name, type) in one file is told apart by n."""
    def __init__(self, prefix: str):
        self.prefix = prefix
        self.seen: dict[str, int] = {}

    def __call__(self, *parts) -> str:
        k = "|".join("" if p is None else str(p) for p in parts)
        n = self.seen.get(k, 0)
        self.seen[k] = n + 1
        return self.prefix + hashlib.sha1(f"{k}|{n}".encode()).hexdigest()[:18]


def _row(src: str, ts: float, client: str | None, name: str, qtype: str | None, *, uid: str, blocked: bool,
         reason: str | None, status: str | None = None, answers: list[str] | None = None, rcode: str | None = None,
         **extra) -> dict:
    r = {"ts": round(ts, 6), "uid": uid, "_path": "dns", "id.orig_h": client, "query": name,
         "qtype_name": qtype, "qtype": qtype, "sinkhole": src, "blocked": blocked,
         "verdict": "blocked" if blocked else "allowed", "reason": reason, "status": status}
    if answers:
        r["answers"] = answers
    if rcode:
        r["rcode_name"] = rcode
    r.update(extra)
    return {k: v for k, v in r.items() if v is not None and v != ""}


# ------------------------------------------------------------------ pihole.log
def _strip_extra(msg: str) -> tuple[dict | None, str]:
    """log-queries=extra puts "<id> <client>/<port> " before the message; returns (that, the message)."""
    m = _EXTRA.match(msg)
    if m and not msg.startswith(("query[", "reply ", "cached ", "forwarded ")):
        return {"id": m["id"], "caddr": m["caddr"], "cport": m["cport"]}, m["rest"]
    return None, msg


def _syslog_ts(m: re.Match, now: float) -> float | None:
    """Epoch seconds. A syslog stamp has no year or zone: it is read as this computer's local time, in the latest
    year that does not put it more than two days in the future."""
    if m["iso"]:
        s = m["iso"].replace(" ", "T")
        s = re.sub(r"(\.\d{6})\d+", r"\1", s).replace("Z", "+00:00")
        try:
            d = dt.datetime.fromisoformat(s)
        except ValueError:
            return None
        return d.timestamp() if d.tzinfo else time.mktime(d.timetuple()) + d.microsecond / 1e6
    mon, day = _MON[m["mon"]], int(m["day"])
    h, mi, se = (int(x) for x in m["hms"].split(":"))
    frac = float("0." + m["frac"]) if m["frac"] else 0.0
    year = time.localtime(now).tm_year
    for y in (year + 1, year, year - 1, year - 2, year - 3, year - 4):   # Feb 29 needs a leap year
        try:
            dt.date(y, mon, day)
            t = time.mktime((y, mon, day, h, mi, se, 0, 0, -1)) + frac
        except (OverflowError, ValueError):
            continue
        if t <= now + 2 * 86400:
            return t
    return None


def _pihole_log(lines: Iterator[str], now: float, stats: dict) -> Iterator[dict]:
    uid = _Uids("PH")
    pending: OrderedDict[tuple, dict] = OrderedDict()   # key -> query waiting for its answer lines
    by_name: dict[str, list[tuple]] = {}
    group: list[tuple] = []          # queries the current run of answer lines belongs to
    gstate = {"name": None, "cname": False, "id": None}

    def emit(key) -> dict | None:
        q = pending.pop(key, None)
        if q is None:
            return None
        ks = by_name.get(q["query"])
        if ks and key in ks:
            ks.remove(key)
            if not ks:
                del by_name[q["query"]]
        ans = list(dict.fromkeys(q["answers"]))
        reason = q["reason"] or ("forwarded, no answer in this log" if q["forwarded"] else None)
        return _row("pihole", q["ts"], q["client"], q["query"], q["qtype"],
                    uid=uid("pihole", q["client"], round(q["ts"], 3), q["query"], q["qtype"]),
                    blocked=q["blocked"], reason=reason, status=q["status"], answers=ans or None,
                    rcode=q["rcode"], upstream=q["upstream"], sinkhole_answer=q["sink"],
                    **({"id.orig_p": q["port"]} if q["port"] else {}))

    def close_group():
        out = [r for r in (emit(k) for k in group) if r]
        group.clear()
        gstate.update(name=None, cname=False, id=None)
        return out

    for raw in lines:
        if not raw.strip():
            continue
        m = _LINE.match(raw)
        if not m:
            stats["skipped"] += 1
            continue
        extra, msg = _strip_extra(m["msg"])
        qid = (m["pid"], extra["id"]) if extra else None
        if (q := _QUERY.match(msg)):
            yield from close_group()
            name = _name(q["name"])
            client = _ip(q["client"]) or (_ip(extra["caddr"]) if extra else None)
            ts = _syslog_ts(m, now)
            if not name or ts is None:
                stats["skipped"] += 1
                continue
            key = qid if qid else (name, client)
            if key in pending:                  # the same query again before an answer: write the first one out
                if (r := emit(key)):
                    yield r
            pending[key] = {"ts": ts, "client": client, "query": name, "qtype": q["qt"], "answers": [],
                            "blocked": False, "reason": None, "status": None, "rcode": None, "sink": None,
                            "upstream": None, "forwarded": False,
                            "port": int(extra["cport"]) if extra and extra.get("cport") else None}
            by_name.setdefault(name, []).append(key)
            stats["queries"] += 1
            while len(pending) > MAX_PENDING:
                if (r := emit(next(iter(pending)))):
                    yield r
            continue
        if msg.startswith("forwarded "):
            yield from close_group()
            parts = msg.split()
            if len(parts) >= 4:
                name = _name(parts[1])
                keys = [qid] if qid in pending else list(by_name.get(name, []))
                for k in keys:
                    pending[k]["forwarded"] = True
                    pending[k]["upstream"] = parts[3]
            continue
        a = _ANSWER.match(msg)
        if not a or _IGNORE.match(msg):
            yield from close_group()
            continue
        src, name, dest = a["src"], _name(a["name"]), a["dest"]
        cont = bool(group) and ((qid is not None and qid == gstate["id"]) or
                                (qid is None and (name == gstate["name"] or gstate["cname"])))
        if not cont:
            yield from close_group()
            keys = ([qid] if qid in pending else []) if qid else list(by_name.get(name, []))
            if not keys:
                continue                     # an answer whose query is not in this file
            group.extend(keys)
        elif gstate["cname"] and name != gstate["name"]:
            for k in group:                  # a CNAME chain: the target name is part of the answer, as in Zeek
                if k in pending:
                    pending[k]["answers"].append(name)
        gstate.update(name=name, cname=dest == "<CNAME>", id=qid)
        blocked = bool(_LOG_BLOCK.search(src))
        for k in group:
            q = pending.get(k)
            if q is None:
                continue
            if blocked:
                q["blocked"] = True
                q["reason"] = src
                q["status"] = src
            elif not q["blocked"] and q["status"] is None:
                q["status"] = src if not src.startswith("/") else "hosts file"
                q["reason"] = _LOG_ALLOWED.get(src) or ("answered from a hosts file" if src.startswith("/") else src)
            if dest == "NXDOMAIN":
                q["rcode"] = "NXDOMAIN"
            elif dest.startswith("NODATA"):
                q["rcode"] = q["rcode"] or "NOERROR"
            elif (ip := _ip(dest)):
                if blocked:
                    q["sink"] = ip
                else:
                    q["answers"].append(ip)
            elif not dest.startswith("<") and not blocked and (nm := _name(dest)):
                q["answers"].append(nm)          # a PTR or local-config answer that is a name
            if q["rcode"] is None and not dest.startswith("<") and _ip(dest):
                q["rcode"] = "NOERROR"
    yield from close_group()
    for k in list(pending):
        if (r := emit(k)):
            yield r


# ------------------------------------------------------------------ Pi-hole v6 API export
def _pihole_api(path: Path, size: int, stats: dict) -> Iterator[dict]:
    if size > MAX_JSON_BYTES:
        raise ValueError(f"Pi-hole query export is larger than {MAX_JSON_BYTES >> 30} GiB")
    with gzip.open(path, "rb") as fh:
        try:
            doc = json.load(fh)
        except ValueError as e:
            raise ValueError(f"Pi-hole query export is not valid JSON: {e}") from None
    qs = doc.get("queries") if isinstance(doc, dict) else doc
    if not isinstance(qs, list):
        raise ValueError("Pi-hole query export has no queries list")
    uid = _Uids("PH")
    for q in qs:
        if not isinstance(q, dict):
            stats["skipped"] += 1
            continue
        name = _name(q.get("domain"))
        try:
            ts = float(q.get("time"))
        except (TypeError, ValueError):
            ts = None
        c = q.get("client") if isinstance(q.get("client"), dict) else {}
        client = _ip(c.get("ip")) or _ip(q.get("client") if isinstance(q.get("client"), str) else None)
        if not name or ts is None:
            stats["skipped"] += 1
            continue
        stats["queries"] += 1
        status = str(q.get("status") or "UNKNOWN").upper()
        blocked = status in PIHOLE_BLOCKED
        reply = q.get("reply") if isinstance(q.get("reply"), dict) else {}
        rtype = str(reply.get("type") or "").upper()
        cname = _name(q.get("cname"))   # the CNAME target that was blocked (deep CNAME inspection)
        cname_name = cname if cname and cname != name else None
        cn = c.get("name")
        yield _row("pihole", ts, client, name, q.get("type"),
                   uid=uid("pihole", client, round(ts, 3), name, q.get("type"), q.get("id")),
                   blocked=blocked, reason=PIHOLE_REASON.get(status, status.lower()), status=status,
                   rcode="NXDOMAIN" if rtype == "NXDOMAIN" else ("NOERROR" if rtype in ("IP", "NODATA", "CNAME", "DOMAIN") else None),
                   list_id=q.get("list_id"), upstream=q.get("upstream"),
                   blocked_cname=cname_name if blocked else None,
                   host_name=_name(cn) if cn and _name(cn) != client else None,
                   client_name=cn if cn and _name(cn) != client else None, pihole_id=q.get("id"))


# ------------------------------------------------------------------ AdGuard Home querylog.json
def _dns_name(msg: bytes, i: int) -> tuple[str, int]:
    labels, jumped, end, hops = [], False, i, 0
    while True:
        if i >= len(msg) or hops > 64:
            raise ValueError("bad name")
        n = msg[i]
        if n & 0xC0 == 0xC0:
            if i + 1 >= len(msg):
                raise ValueError("bad pointer")
            if not jumped:
                end = i + 2
            i = ((n & 0x3F) << 8) | msg[i + 1]
            jumped, hops = True, hops + 1
            continue
        if n == 0:
            if not jumped:
                end = i + 1
            return ".".join(labels).lower(), end
        labels.append(msg[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n


def dns_answers(msg: bytes) -> tuple[str | None, list[str]]:
    """(rcode name, answers) from a wire-format DNS message: A/AAAA addresses and CNAME targets, in order."""
    if len(msg) < 12:
        return None, []
    rc = msg[3] & 0x0F
    rcode = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}.get(rc, str(rc))
    qd, an = int.from_bytes(msg[4:6], "big"), int.from_bytes(msg[6:8], "big")
    out: list[str] = []
    try:
        i = 12
        for _ in range(qd):
            _, i = _dns_name(msg, i)
            i += 4
        for _ in range(min(an, 256)):
            _, i = _dns_name(msg, i)
            typ, ln = int.from_bytes(msg[i:i + 2], "big"), int.from_bytes(msg[i + 8:i + 10], "big")
            rd, i = msg[i + 10:i + 10 + ln], i + 10 + ln
            if typ == 1 and ln == 4:
                out.append(str(ipaddress.IPv4Address(rd)))
            elif typ == 28 and ln == 16:
                out.append(str(ipaddress.IPv6Address(rd)))
            elif typ == 5:
                out.append(_dns_name(msg, i - ln)[0].rstrip("."))
    except (ValueError, IndexError):
        pass
    return rcode, out


def _adguard_ts(s) -> float | None:
    if not isinstance(s, str):
        return None
    s = re.sub(r"(\.\d{6})\d+", r"\1", s.strip()).replace("Z", "+00:00")
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    return d.timestamp() if d.tzinfo else d.replace(tzinfo=dt.UTC).timestamp()


def _adguard(lines: Iterator[str], stats: dict) -> Iterator[dict]:
    uid = _Uids("AG")
    for raw in lines:
        if not raw.strip():
            continue
        try:
            o = json.loads(raw)
        except ValueError:
            stats["skipped"] += 1
            continue
        if not isinstance(o, dict):
            stats["skipped"] += 1
            continue
        name, ts = _name(o.get("QH")), _adguard_ts(o.get("T"))
        if not name or ts is None:
            stats["skipped"] += 1
            continue
        stats["queries"] += 1
        res = o.get("Result") if isinstance(o.get("Result"), dict) else {}
        try:
            reason = int(res.get("Reason") or 0)
        except (TypeError, ValueError):
            reason = 0
        blocked = reason in ADGUARD_BLOCKED or (bool(res.get("IsFiltered")) and reason not in (1, 7, 9, 10, 11))
        rules = [r for r in (res.get("Rules") or []) if isinstance(r, dict)]
        rcode, answers = None, []
        if isinstance(o.get("Answer"), str):
            try:
                rcode, answers = dns_answers(base64.b64decode(o["Answer"], validate=False))
            except (binascii.Error, ValueError):
                pass
        sink = None
        if blocked:
            sink, answers = (answers[0] if answers else None), []
        client = _ip(o.get("IP"))
        cid = o.get("CID") or None
        yield _row("adguard", ts, client, name, o.get("QT"),
                   uid=uid("adguard", client, round(ts, 6), name, o.get("QT")),
                   blocked=blocked, status=ADGUARD_REASON_ID[reason] if 0 <= reason < len(ADGUARD_REASON_ID) else str(reason),
                   reason=ADGUARD_REASON[reason] if 0 <= reason < len(ADGUARD_REASON) else f"reason {reason}",
                   answers=answers or None, rcode=rcode,
                   rule=rules[0].get("Text") if rules else None,
                   list_id=rules[0].get("FilterListID") if rules else None,
                   service_name=res.get("ServiceName"), upstream=o.get("Upstream"), cached=o.get("Cached") or None,
                   client_proto=o.get("CP") or None, client_name=cid, host_name=_name(cid), sinkhole_answer=sink)


# ------------------------------------------------------------------ conversion
def _text_lines(path: Path) -> Iterator[str]:
    with gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="") as fh:
        for ln in fh:
            yield ln.lstrip("﻿")


def rows(path: Path, kind: str, size: int = 0, now: float | None = None, stats: dict | None = None) -> Iterator[dict]:
    """The DNS objects of a gzipped sinkhole file."""
    stats = stats if stats is not None else {"queries": 0, "skipped": 0}
    stats.setdefault("queries", 0)
    stats.setdefault("skipped", 0)
    if kind == "pihole-log":
        return _pihole_log(_text_lines(path), time.time() if now is None else now, stats)
    if kind == "pihole-api":
        return _pihole_api(path, size, stats)
    if kind == "adguard":
        return _adguard(_text_lines(path), stats)
    raise ValueError(f"unknown sinkhole format {kind}")


def convert(path: Path, kind: str, out: Path, size: int = 0, now: float | None = None) -> dict:
    """Write the DNS objects of `path` to `out` (gzipped NDJSON). Returns counts and plain-language notes."""
    stats = {"queries": 0, "skipped": 0, "rows": 0, "blocked": 0}
    with gzip.open(out, "wt", encoding="utf-8", compresslevel=1) as fh:
        for r in rows(path, kind, size, now, stats):
            stats["rows"] += 1
            stats["blocked"] += bool(r.get("blocked"))
            fh.write(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")
    notes = []
    if kind == "pihole-log":
        notes.append("Pi-hole log times have no year or time zone; they were read as this computer's local time, "
                     "in the most recent matching year")
    if stats["skipped"]:
        notes.append(f"{stats['skipped']} line(s) were not DNS queries and were skipped")
    stats["notes"] = notes
    return stats


def load(path: Path, file_id: str, kind: str, size: int, loader, tmp_dir: Path) -> dict:
    """Convert, then hand the DNS objects to the importer's own loader (`loader(path, file_id, 'ndjson')`)."""
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp = tmp_dir / f".sinkhole-{file_id[:16]}-{time.time_ns()}.ndjson.gz"
    try:
        st = convert(path, kind, tmp, size)
        if not st["rows"]:
            raise ValueError(f"no DNS queries found in this {FORMATS[kind]}")
        res = loader(tmp, file_id, "ndjson")
    finally:
        tmp.unlink(missing_ok=True)
    res["warnings"] = st["notes"] + [w for w in res.get("warnings") or [] if "not JSON objects" not in w]
    res["warning"] = "; ".join(res["warnings"]) or None
    res["skipped_lines"] = st["skipped"]
    res["sinkhole"] = {"source": SOURCE[kind], "format": kind, "label": FORMATS[kind],
                       "queries": st["rows"], "blocked": st["blocked"]}
    return res
