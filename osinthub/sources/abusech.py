"""abuse.ch ThreatFox, URLhaus and SSL Blacklist. Docs: okf/sources/current/{threatfox,urlhaus,sslbl}.md

* ThreatFox and URLhaus need a free abuse.ch Auth-Key (env ABUSECH_AUTH_KEY, read in config.py). It is sent
  only in the documented `Auth-Key` header, never in a URL, so it cannot reach a log line, a run record, a
  raw path or an error message. Without a key both stay off and are never fetched (`needs_key`).
* abuse.ch Terms of Use (2026-10-21): the free tier is for not-for-profit use, no redistribution (s7.3), and
  the data may not be used to "customise, train, or otherwise improve" AI models. ThreatFox and URLhaus are
  therefore marked `ai_ok = False`: nothing from them goes into an LLM prompt or an embedding.
* SSLBL's certificate list is CC0 and keyless. Its botnet C2 IP list (sslipblacklist.csv) was deprecated on
  2025-01-03 and is now empty, and abuse.ch warns that its JA3 list has many false positives, so only the
  certificate SHA1 list is used.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import ipaddress
import json
import math
import re
from functools import lru_cache
from urllib.parse import urlsplit

import httpx

from .. import config
from . import caps
from .base import UTC, Event, Source, key_steps, now, to_ts
from .registry import register

LICENSE_KEYED = "abuse.ch Terms of Use: free for not-for-profit use, no redistribution"
KEY_ENV = "ABUSECH_AUTH_KEY"
_HEX = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9_-]{1,63}\.)+[a-z]{2,63}$")


class NeedsKey(RuntimeError):
    """A keyed source was asked to fetch with no key set (the scheduler never starts it, so this is a backstop)."""


def utc(v) -> dt.datetime | None:
    """abuse.ch time strings ("2026-11-09 10:16:33 UTC", "2026-11-09 10:16:33") to aware UTC; None if empty."""
    if v in (None, ""):
        return None
    s = str(v).strip()
    if s.endswith(" UTC"):
        s = s[:-4]
    try:
        d = dt.datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
        return d.replace(tzinfo=UTC)
    except ValueError:
        return to_ts(s)


def canon_ip(s: str | None) -> str | None:
    if not s:
        return None
    try:
        a = ipaddress.ip_address(s.strip().strip("[]").split("%", 1)[0])
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped:
        return str(a.ipv4_mapped)
    return str(a)


def norm_host(h: str | None) -> tuple[str, str] | None:
    """('ip', canonical address) or ('domain', lower-case name without trailing dot); None if neither."""
    if not h:
        return None
    h = h.strip().lower().rstrip(".")
    ip = canon_ip(h)
    if ip:
        return "ip", ip
    try:
        h = h.encode("idna").decode("ascii") if any(ord(c) > 127 for c in h) else h
    except UnicodeError:
        return None
    return ("domain", h) if _DOMAIN.match(h) else None


def norm_url(u: str | None) -> tuple[str, str, str] | None:
    """A malware URL as the netlog matcher sees it: (host kind, host, "host/path?query").

    Scheme, port, user info and fragment are dropped, because Zeek's http.log keeps the Host without its port
    and the request target without a fragment. The host is lower-cased (IPs canonical); the path keeps its case."""
    if not u:
        return None
    u = u.strip()
    if "://" not in u:
        u = "http://" + u
    try:
        p = urlsplit(u)
        host = p.hostname
    except ValueError:
        return None
    nh = norm_host(host)
    if not nh:
        return None
    path = p.path or "/"
    q = f"?{p.query}" if p.query else ("?" if u.split("#", 1)[0].endswith("?") else "")   # Zeek keeps a bare "?"
    return nh[0], nh[1], f"{nh[1]}{path}{q}"


def split_ip_port(s: str, expect_port: bool = False) -> tuple[str | None, int | None]:
    """'198.51.100.7:443' / '[2001:db8::1]:443' / '198.51.100.7' -> (canonical ip, port).

    With expect_port (ThreatFox type ip:port), an unbracketed IPv6 '2001:db8::1:443' is read as address
    2001:db8::1 and port 443: the type says a port is there, and the last group is it."""
    s = (s or "").strip()
    port = None
    if s.startswith("[") and "]" in s:
        host, rest = s[1:].split("]", 1)
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
    elif s.count(":") == 1:
        host, p = s.split(":", 1)
        port = int(p) if p.isdigit() and int(p) <= 65535 else None
    elif expect_port and s.count(":") > 1:
        h, p = s.rsplit(":", 1)
        if p.isdigit() and int(p) <= 65535 and canon_ip(h):
            host, port = h, int(p)
        else:
            host = s
    else:
        host = s
    return canon_ip(host), port


def _tags(v) -> list[str]:
    if isinstance(v, list):
        items = v
    elif isinstance(v, str):
        items = v.split(",")
    else:
        items = []
    out = []
    for t in items:
        t = str(t or "").strip()
        if t and t.lower() not in ("none", "null") and t not in out and len(t) <= 60:
            out.append(t)
    return out


def _uniq(items) -> list[str]:
    """Non-empty, first spelling wins, case-insensitive ("Mozi" and "mozi" are one tag)."""
    out, seen = [], set()
    for t in items:
        if t and t.lower() not in seen:
            seen.add(t.lower())
            out.append(t)
    return out


class _AbuseKeyed(Source):
    """ThreatFox and URLhaus: free Auth-Key, off by default, kept away from AI."""
    provider = "abuse.ch"
    category = "threat"
    default_enabled = False
    license = LICENSE_KEYED
    needs_key = KEY_ENV
    ai_ok = False

    def key(self) -> str | None:
        return config.ABUSECH_AUTH_KEY

    def unavailable(self) -> str | None:
        if not self.key():
            # shown on the Sources page (and on a phone): plain words that say where the key goes; the variable's name
            # (needs_key) goes under Technical details there
            return f"Get a free abuse.ch Auth-Key (https://auth.abuse.ch/), then {key_steps()}."
        return None

    def headers(self) -> dict:
        k = self.key()
        if not k:
            raise NeedsKey(self.unavailable())
        return {"Auth-Key": k}

    @staticmethod
    def _check(r: httpx.Response, what: str) -> bytes:
        if config.OFFLINE:
            raise RuntimeError("offline mode")
        if r.is_redirect:   # fetched with follow_redirects=False: the Auth-Key header must not go anywhere else
            raise RuntimeError(f"{what}: unexpected redirect (HTTP {r.status_code}); not following it with the Auth-Key")
        if r.status_code in (401, 403):
            # never echo the request (headers carry the key); the URL has no key in it
            raise RuntimeError(f"{what}: abuse.ch refused the Auth-Key (HTTP {r.status_code}); check {KEY_ENV}")
        r.raise_for_status()
        return r.content

    def describe(self) -> dict:
        d = super().describe()
        d["key_set"] = bool(self.key())
        return d


# --------------------------------------------------------------------------- ThreatFox
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
# Severity by threat type, scaled by ThreatFox's confidence_level (0-100): fixed scale, batch-independent.
TF_SEV = {"botnet_cc": 0.85, "payload_delivery": 0.7, "cc_skimming": 0.7, "payload": 0.6}
TF_SHORT = {"botnet_cc": "C2", "payload_delivery": "payload delivery", "cc_skimming": "card skimming",
            "payload": "payload"}


def tf_family(r: dict) -> str | None:
    """ThreatFox's display name for the family, or None for its "Unknown malware" placeholder."""
    fam = (r.get("malware_printable") or "").strip()
    if not fam and not re.fullmatch(r"[a-z0-9]+\.[a-z0-9_]+", (r.get("malware") or "").strip()):
        fam = (r.get("malware") or "").strip()   # a plain name, not a Malpedia id like win.dridex
    if not fam or fam.lower() in ("unknown malware", "unknown", "none"):
        return None
    return fam


def tf_ioc(r: dict) -> dict | None:
    """The IOC of one ThreatFox record, normalised: {type, value, ip, port, host_kind, host, url}; None if junk."""
    t = (r.get("ioc_type") or "").strip().lower()
    v = str(r.get("ioc") or r.get("ioc_value") or "").strip()   # API: ioc; export files: ioc_value
    if not v:
        return None
    if not t:   # no type given (hand-made or older records): infer it from the value
        lv = v.lower()
        t = ("url" if "://" in lv else
             f"{ {32: 'md5', 40: 'sha1', 64: 'sha256'}[len(lv)]}_hash" if _HEX.match(lv) else
             "ip:port" if split_ip_port(v)[0] else "domain")
    if t == "ip:port":
        ip, port = split_ip_port(v, expect_port=True)
        return {"type": t, "value": ip, "ip": ip, "port": port} if ip else None
    if t == "domain":
        nh = norm_host(v)
        return {"type": t, "value": nh[1], "host_kind": "domain", "host": nh[1]} if nh and nh[0] == "domain" else None
    if t == "url":
        nu = norm_url(v)
        if not nu:
            return None
        return {"type": t, "value": v, "url": nu[2], "host_kind": nu[0], "host": nu[1],
                "ip": nu[1] if nu[0] == "ip" else None}
    if t in ("md5_hash", "sha1_hash", "sha256_hash", "sha3_384_hash"):
        h = v.lower()
        return {"type": t, "value": h, "hash": h} if _HEX.match(h) else None
    return None


@register
class ThreatFox(_AbuseKeyed):
    id = "threatfox"
    name = "ThreatFox malware IOCs"
    homepage = "https://threatfox.abuse.ch/"
    description = ("IOCs (C2 IP:port, domains, URLs, file hashes) tied to named malware families, shared by the "
                   "abuse.ch community. Needs a free abuse.ch Auth-Key; off by default.")
    # The API returns IOCs first seen in the last `days` (max 7). Hourly with a 1-day window: each IOC is
    # seen ~24 times, so one late run never loses data, at about 1 MB per call.
    interval = 3600
    windowed = True   # a sliding window of new IOCs: one ageing out is not a removal (see netlog TTLs)
    MAX_DAYS = 7      # the API's limit

    def window_days(self) -> int:
        """1 day normally; after a gap (app stopped, laptop asleep, outage) enough days to cover it, up to 7.
        3 (the API default) on the very first run."""
        try:
            from .. import scheduler
            last = scheduler.state(self.id).get("last_ok")
        except Exception:
            last = None
        if not last:
            return 3
        gap = (now() - last).total_seconds() + 3 * 3600   # a margin for late reports
        return max(1, min(self.MAX_DAYS, math.ceil(gap / 86400)))

    async def fetch(self, client):
        if config.OFFLINE:
            raise RuntimeError("offline mode: not fetching ThreatFox")
        r = await caps.get(client, THREATFOX_API, self.id, method="POST", headers=self.headers(),
                           json={"query": "get_iocs", "days": self.window_days()}, timeout=90, follow_redirects=False)
        return self._check(r, "ThreatFox")

    @staticmethod
    def _rows(raw: bytes) -> list[dict]:
        d = json.loads(raw)
        if isinstance(d, dict):
            st = d.get("query_status")
            if st in ("no_result", "no_results"):
                return []
            if st not in (None, "ok"):
                raise RuntimeError(f"ThreatFox API: {str(st)[:80]}")
            d = d.get("data") or []
        if isinstance(d, dict):     # export files are {"<id>": [record], ...}
            d = [dict(x, id=x.get("id") or k) for k, v in d.items() for x in (v if isinstance(v, list) else [v])]
        out, seen = [], set()
        for r in d if isinstance(d, list) else []:
            if not isinstance(r, dict) or r.get("id") in (None, ""):
                continue
            if str(r["id"]) in seen:
                continue
            seen.add(str(r["id"]))
            out.append(r)
        return out

    def records(self, raw):
        return [(str(r["id"]), r) for r in self._rows(raw) if tf_ioc(r)]

    def parse(self, raw):
        evs = []
        for r in self._rows(raw):
            ioc = tf_ioc(r)
            if not ioc:
                continue
            fam = tf_family(r)
            tt = (r.get("threat_type") or "").strip().lower()
            try:
                conf = max(0, min(100, int(r.get("confidence_level"))))
            except (TypeError, ValueError):
                conf = 50
            sev = round(TF_SEV.get(tt, 0.6) * (0.6 + 0.4 * conf / 100), 3)
            first = utc(r.get("first_seen")) or utc(r.get("first_seen_utc")) or now()
            short = TF_SHORT.get(tt, tt or "IOC")
            shown = ioc["value"]
            if ioc["type"] == "ip:port" and ioc.get("port"):
                shown = f"[{ioc['ip']}]:{ioc['port']}" if ":" in ioc["ip"] else f"{ioc['ip']}:{ioc['port']}"
            parts = [r.get("threat_type_desc") or tt, f"{ioc['type']}", f"confidence {conf}%"]
            if r.get("last_seen"):
                parts.append(f"last seen {str(r['last_seen'])[:19]}")
            if r.get("reporter"):
                parts.append(f"reporter {r['reporter']}")
            evs.append(Event(
                source=self.id, kind="malware_ioc", key=(str(r["id"]),), ts=first,
                title=f"{fam or 'Unknown malware'} {short} {shown}"[:300],
                summary=" · ".join(str(p) for p in parts if p)[:600],
                category="threat", severity=sev, ip=ioc.get("ip"), value=conf,
                url=f"https://threatfox.abuse.ch/ioc/{r['id']}/",
                tags=_uniq([fam, tt, *_tags(r.get("tags"))[:6]]),
            ))
        return evs


# --------------------------------------------------------------------------- URLhaus
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"
UH_SEV = {"online": 0.7, "unknown": 0.5, "offline": 0.4}


def uh_url(r: dict) -> tuple[str, str, str] | None:
    return norm_url(r.get("url"))


# URLhaus tags that describe the file or platform, not the family.
UH_GENERIC = set("""32-bit 64-bit elf exe dll zip rar 7z gz tar iso img lnk msi hta js vbs ps1 powershell bat cmd sh
ascii doc docx xls xlsx xlsm pdf apk jar arm arm4 arm5 arm6 arm7 aarch64 mips mipsel mpsl m68k ppc sparc sh4 x86 x86-64
x86_64 i686 amd64 intel opendir payload malware dropper loader encrypted password-protected botnet online offline unknown
ua-wget curl wget github discord telegram dropbox mediafire google-drive onedrive bitbucket gitlab""".split())


UH_GENERIC |= set("""base64 encoded obfuscated phishing html htm php trojan ransomware rat stealer backdoor miner
cryptominer wordpress wp hacked compromised geofenced malware-download malware_download download exploit doc docm xlsm
vba macro script batch loader-script dropper-script ascii-text text sh-script bash shell linux windows android apk macos
ios mirai-like""".split())


@lru_cache(maxsize=4096)
def known_family(name: str) -> str | None:
    """The catalogue name (MISP / Malpedia / ATT&CK, aliases included) of a malware family or tool, else None."""
    try:
        from ..entities.refdata import catalog
        cat = catalog()
        eid = cat.resolve(name, types=("malware", "tool"), fuzzy=False)
        return cat.entities[eid]["name"] if eid else None
    except Exception:
        return None


def uh_family(tags) -> str | None:
    """The family a URLhaus record names: the first tag that resolves through the catalogue. URLhaus tags are
    free text (cve-2017-11882, base64, geofenced, wordpress ...), so a tag the catalogue does not know is not a
    family: no family is better than a wrong one."""
    for t in _tags(tags):
        lt = t.lower()
        if lt in UH_GENERIC or lt.startswith(("cve-", "cve_")) or re.fullmatch(r"[\d.\-_]+|[a-z]{1,3}\d*", lt) or "." in lt:
            continue
        fam = known_family(t)
        if fam:
            return fam
    return None


@register
class URLhaus(_AbuseKeyed):
    id = "urlhaus"
    name = "URLhaus malware URLs"
    homepage = "https://urlhaus.abuse.ch/"
    description = ("URLs distributing malware, with their host, online/offline status and tags. "
                   "Needs a free abuse.ch Auth-Key; off by default.")
    # The recent-URLs API returns the newest 1,000 additions of the last 3 days. abuse.ch asks for no more
    # than one fetch per 5 minutes; hourly is well inside that and covers far more than an hour of additions.
    interval = 3600
    windowed = True

    async def fetch(self, client):
        if config.OFFLINE:
            raise RuntimeError("offline mode: not fetching URLhaus")
        r = await caps.get(client, URLHAUS_API, self.id, headers=self.headers(), timeout=90, follow_redirects=False)
        return self._check(r, "URLhaus")

    @staticmethod
    def _rows(raw: bytes) -> list[dict]:
        d = json.loads(raw)
        if isinstance(d, dict):
            st = d.get("query_status")
            if st in ("no_results", "no_result"):
                return []
            if st not in (None, "ok"):
                raise RuntimeError(f"URLhaus API: {str(st)[:80]}")
            d = d.get("urls") or []
        out, seen = [], set()
        for r in d if isinstance(d, list) else []:
            if isinstance(r, dict) and r.get("id") not in (None, "") and str(r["id"]) not in seen and uh_url(r):
                seen.add(str(r["id"]))
                out.append(r)
        return out

    def records(self, raw):
        return [(str(r["id"]), r) for r in self._rows(raw)]

    def parse(self, raw):
        evs = []
        for r in self._rows(raw):
            hk, host, _ = uh_url(r)
            status = (r.get("url_status") or "unknown").strip().lower()
            tags = _tags(r.get("tags"))
            bl = r.get("blacklists") or {}
            listed = []
            if bl.get("spamhaus_dbl") not in (None, "", "not listed"):
                listed.append(f"Spamhaus DBL {bl['spamhaus_dbl']}")
            if bl.get("surbl") == "listed":
                listed.append("SURBL")
            parts = [f"status {status}", r.get("threat") or "malware_download", f"host {host}"]
            if tags:
                parts.append("tags " + ", ".join(tags[:8]))
            if listed:
                parts.append("also " + ", ".join(listed))
            if r.get("reporter"):
                parts.append(f"reporter {r['reporter']}")
            evs.append(Event(
                source=self.id, kind="malware_url", key=(str(r["id"]),),
                ts=utc(r.get("date_added") or r.get("dateadded")) or now(),
                title=f"Malware URL {str(r.get('url')).strip()}"[:300], summary=" · ".join(parts)[:600],
                category="threat", severity=UH_SEV.get(status, 0.5), ip=host if hk == "ip" else None,
                url=r.get("urlhaus_reference") or f"https://urlhaus.abuse.ch/url/{r['id']}/",
                tags=_uniq([*tags[:8], status]),
            ))
        return evs


# --------------------------------------------------------------------------- SSL Blacklist
SSLBL_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"


SSLBL_NOT_FAMILY = {"malware", "malware distribution", "unknown", "generic", "botnet", "c&c", "c2", "phishing",
                    "malicious", "suspicious", "test"}


def sslbl_family(reason: str | None) -> str | None:
    """'Dridex C&C' -> 'Dridex'. Reasons that are not a family name give None: 'Malware C&C', 'Malware
    distribution', a domain ('doxbin.cy'), anything with a dot, slash or more than three words."""
    r = re.sub(r"\s+(C&C|C2|CnC|botnet C&C)$", "", (reason or "").strip(), flags=re.I).strip()
    if not r or r.lower() in SSLBL_NOT_FAMILY or re.search(r"[./:@]", r) or len(r.split()) > 3:
        return None
    return r


@register
class SslBlacklist(Source):
    id = "sslbl"
    name = "SSL Blacklist (C2 certificates)"
    provider = "abuse.ch"
    homepage = "https://sslbl.abuse.ch/"
    description = ("SHA1 fingerprints of TLS certificates used by botnet C2 servers, with the malware family. "
                   "Matched against certificate hashes in Zeek and Suricata logs.")
    category = "threat"
    # The CSV regenerates every 5 minutes ("do not fetch more often"); it changes a few times a day.
    interval = 6 * 3600
    license = "CC0 (abuse.ch Terms of Use s3.4)"
    raw_ext = "csv"
    windowed = False   # the whole list: a fingerprint that disappears was removed
    ai_ok = False      # abuse.ch ToS s7.3: this data may not go into any LLM prompt or embedding
    # Certificates are indicators, not activity: every listing is a record and a netlog indicator, but events are
    # one summary per family with a listing in the last year ("Vidar: 731 C2 certificates"), never one per cert.
    EVENT_DAYS = 365

    async def fetch(self, client):
        if config.OFFLINE:
            raise RuntimeError("offline mode: not fetching SSLBL")
        r = await caps.get(client, SSLBL_URL, self.id, timeout=60)
        r.raise_for_status()
        return r.content

    @staticmethod
    def _rows(raw: bytes) -> list[dict]:
        out, seen = [], set()
        text = raw.decode("utf-8", "replace")
        for row in csv.reader(io.StringIO(text)):
            if not row or row[0].lstrip().startswith("#") or len(row) < 3:
                continue
            when, sha1, reason = row[0].strip(), row[1].strip().lower(), ",".join(row[2:]).strip()
            if not re.fullmatch(r"[0-9a-f]{40}", sha1) or sha1 in seen or not re.match(r"\d{4}-\d{2}-\d{2}", when):
                continue
            seen.add(sha1)
            out.append({"listing_date": when, "sha1": sha1, "reason": reason})
        return out

    def records(self, raw):
        return [(r["sha1"], r) for r in self._rows(raw)]

    def parse(self, raw):
        cutoff = now() - dt.timedelta(days=self.EVENT_DAYS)
        fams: dict[str, dict] = {}
        for r in self._rows(raw):
            fam = sslbl_family(r["reason"])
            ts = utc(r["listing_date"])
            if not fam or not ts:
                continue
            f = fams.setdefault(fam.lower(), {"name": fam, "n": 0, "recent": 0, "first": ts, "last": ts})
            f["n"] += 1
            f["recent"] += ts >= cutoff
            f["first"], f["last"] = min(f["first"], ts), max(f["last"], ts)
        evs = []
        for k, f in sorted(fams.items()):
            if f["last"] < cutoff:
                continue
            evs.append(Event(
                source=self.id, kind="c2_cert", key=(k,), ts=f["last"],
                title=f"{f['name']}: {f['n']:,} C2 TLS certificate{'s' if f['n'] != 1 else ''} on SSL Blacklist",
                summary=(f"{f['recent']:,} listed in the last {self.EVENT_DAYS} days; latest {f['last']:%Y-%m-%d}, "
                         f"first {f['first']:%Y-%m-%d}. Each fingerprint is matched in network logs."),
                category="threat", severity=0.6, value=f["n"], url="https://sslbl.abuse.ch/ssl-certificates/",
                tags=[f["name"]],
            ))
        return evs
