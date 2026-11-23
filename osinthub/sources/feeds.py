"""Prebuilt batch sources. All free, no API key required."""
from __future__ import annotations

import datetime as dt
import ipaddress
import hashlib
import json
import math
import re

import feedparser
import httpx

from .. import config, geo
from .base import Event, Source, now, to_ts
from .registry import register
from . import caps
from .text import fix_encoded_events, unentity

IP_RE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$")


def _ip_lines(raw: bytes) -> list[str]:
    out = []
    for line in raw.decode(errors="ignore").splitlines():
        m = IP_RE.match(line)
        if m:
            out.append(m.group(1))
    return out


class Offline(RuntimeError):
    """Raised by fetch helpers in offline mode (the scheduler skips before calling them)."""


async def _get(client: httpx.AsyncClient, url: str, sid: str, **kw) -> bytes:
    """GET url, read with the source's byte cap (caps.py: decoded bytes, TooLarge over it)."""
    if config.OFFLINE:
        raise Offline(f"offline mode: not fetching {url}")
    r = await caps.get(client, url, sid, **kw)
    r.raise_for_status()
    return r.content


# --------------------------------------------------------------------------- vulnerabilities
@register
class CisaKev(Source):
    id = "cisa_kev"
    name = "CISA Known Exploited Vulnerabilities"
    provider = "CISA"
    homepage = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    description = "Every CVE CISA has confirmed is being exploited in the wild, with ransomware use flags and federal patch deadlines."
    category = "vuln"
    interval = 6 * 3600
    license = "Public domain (US Gov)"

    async def fetch(self, client):
        return await _get(client, "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", self.id)

    windowed = False

    def records(self, raw):
        return [(v["cveID"], v) for v in json.loads(raw).get("vulnerabilities", [])]

    def parse(self, raw):
        data = json.loads(raw)
        evs = []
        for v in data.get("vulnerabilities", []):
            ransom = (v.get("knownRansomwareCampaignUse") or "").lower() == "known"
            tags = [v.get("vendorProject", ""), v.get("product", "")]
            if ransom:
                tags.append("ransomware")
            evs.append(Event(
                source=self.id, kind="kev", key=(v["cveID"],), ts=to_ts(v.get("dateAdded")),
                title=f"{v['cveID']} · {v.get('vendorProject')} {v.get('product')}",
                summary=f"{v.get('vulnerabilityName')}. {v.get('shortDescription')}",
                category="vuln", severity=0.95 if ransom else 0.8,
                url=f"https://nvd.nist.gov/vuln/detail/{v['cveID']}", tags=[t for t in tags if t],
            ))
        return evs


@register
class NvdRecent(Source):
    id = "nvd_recent"
    name = "NVD — newly published CVEs"
    provider = "NIST NVD"
    homepage = "https://nvd.nist.gov/"
    description = "CVEs published in the last 72 hours with CVSS scores, polled from the NVD 2.0 API."
    category = "vuln"
    interval = 2 * 3600
    license = "Public domain (US Gov)"

    async def fetch(self, client):
        end = now()
        start = end - dt.timedelta(hours=72)
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        params = {"pubStartDate": start.strftime(fmt), "pubEndDate": end.strftime(fmt), "resultsPerPage": 2000}
        return await _get(client, "https://services.nvd.nist.gov/rest/json/cves/2.0", self.id, params=params, timeout=90)

    def records(self, raw):
        return [(i["cve"]["id"], i) for i in json.loads(raw).get("vulnerabilities", [])]

    def prepare(self, raw, collected_at):
        # Events stored before descriptions were decoded and no longer in the 72-hour window (never re-parsed).
        fix_encoded_events(self.id, squash=False)

    def parse(self, raw):
        data = json.loads(raw)
        evs = []
        for item in data.get("vulnerabilities", []):
            c = item["cve"]
            if c.get("vulnStatus") == "Rejected":
                continue
            # Some CNAs submit descriptions with HTML entities ('&#39;', '&quot;', '&amp;'): stored as plain text.
            desc = unentity(next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), ""))
            score, sev = None, None
            m = c.get("metrics", {})
            for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if m.get(k):
                    cd = m[k][0]["cvssData"]
                    score = cd.get("baseScore")
                    sev = cd.get("baseSeverity") or m[k][0].get("baseSeverity")
                    break
            evs.append(Event(
                source=self.id, kind="cve", key=(c["id"],), ts=to_ts(c.get("published")),
                title=f"{c['id']}" + (f" · CVSS {score}" if score else ""),
                summary=desc[:600], category="vuln",
                severity=(score / 10.0) if score else None, value=score,
                url=f"https://nvd.nist.gov/vuln/detail/{c['id']}", tags=[sev.lower()] if sev else [],
            ))
        return evs


# --------------------------------------------------------------------------- threat infrastructure
@register
class FeodoC2(Source):
    id = "feodo_c2"
    name = "Feodo Tracker botnet C2"
    provider = "abuse.ch"
    homepage = "https://feodotracker.abuse.ch/"
    description = "Command-and-control servers for Emotet, Dridex, QakBot and related banking botnets."
    category = "threat"
    interval = 3600
    license = "CC0"
    ai_ok = False   # abuse.ch ToS s7.3 (no AI use) has no CC0 carve-out; as sslbl

    async def fetch(self, client):
        return await _get(client, "https://feodotracker.abuse.ch/downloads/ipblocklist.json", self.id)

    windowed = False

    def records(self, raw):
        return [(f"{r['ip_address']}:{r.get('port')}", r) for r in json.loads(raw)]

    def parse(self, raw):
        evs = []
        for r in json.loads(raw):
            online = r.get("status") == "online"
            evs.append(Event(
                source=self.id, kind="c2", key=(r["ip_address"], r.get("port")),
                ts=to_ts(r.get("last_online") or r.get("first_seen")),
                title=f"{r.get('malware')} C2 {r['ip_address']}:{r.get('port')}",
                summary=f"{r.get('as_name')} (AS{r.get('as_number')}) · status {r.get('status')} · first seen {r.get('first_seen')}",
                category="threat", severity=0.9 if online else 0.5, ip=r["ip_address"],
                asn=f"AS{r.get('as_number')}", country=r.get("country"),
                tags=[t for t in [r.get("malware"), r.get("status")] if t],
            ))
        return evs


@register
class DshieldAttackers(Source):
    id = "dshield_top"
    name = "DShield top attacking IPs"
    provider = "SANS Internet Storm Center"
    homepage = "https://isc.sans.edu/"
    description = "The IPs hitting the most DShield sensors worldwide, ranked by attack count."
    category = "threat"
    interval = 3600
    license = "CC BY-NC-SA 4.0 (own-network use, commercial included; no resale)"
    default_enabled = False   # terms `ask` (feed_terms.py): off until the user turns it on

    async def fetch(self, client):
        return await _get(client, "https://isc.sans.edu/api/sources/attacks/500?json", self.id)

    windowed = False

    def records(self, raw):
        return [(r.get("ip") or r.get("source"), r) for r in json.loads(raw) if r.get("ip") or r.get("source")]

    def parse(self, raw):
        rows = json.loads(raw)
        top = max((int(r.get("attacks") or 0) for r in rows), default=1) or 1
        evs = []
        for r in rows:
            ip = r.get("ip") or r.get("source")
            if not ip:
                continue
            attacks = int(r.get("attacks") or 0)
            evs.append(Event(
                source=self.id, kind="attacker", key=(ip,), ts=to_ts(r.get("lastseen")),
                title=f"Scanner {ip}", summary=f"{attacks:,} targets · {int(r.get('count') or 0):,} reports · since {r.get('firstseen')}",
                category="threat", severity=min(1.0, 0.3 + 0.7 * attacks / top), ip=ip, value=attacks,
                tags=["scanner"],
            ))
        return evs


class _IpListSource(Source):
    """A plain one-IP-per-line blocklist."""
    url: str = ""
    kind_name = "malicious_ip"
    label = "IP"
    sev = 0.5
    cap = 6000
    tags_: list[str] = []

    async def fetch(self, client):
        return await _get(client, self.url, self.id)

    windowed = False

    def records(self, raw):
        return [(ip, ip) for ip in _ip_lines(raw)]

    def parse(self, raw):
        ts = now()
        return [
            Event(source=self.id, kind=self.kind_name, key=(ip,), ts=ts, title=f"{self.label} {ip}",
                  category="threat", severity=self.sev, ip=ip, tags=list(self.tags_))
            for ip in _ip_lines(raw)[: self.cap]
        ]


@register
class TorExits(_IpListSource):
    id = "tor_exits"
    name = "Tor exit nodes"
    provider = "The Tor Project"
    homepage = "https://check.torproject.org/"
    description = "Current Tor exit relays, the IPs anonymised traffic leaves the Tor network from."
    category = "infra"
    interval = 3 * 3600
    license = "CC0 (Tor Metrics data)"
    raw_ext = "txt"
    url = "https://check.torproject.org/torbulkexitlist"
    kind_name, label, sev, tags_ = "tor_exit", "Tor exit", 0.2, ["tor"]


@register
class BlocklistDe(_IpListSource):
    id = "blocklist_de"
    name = "blocklist.de attackers"
    provider = "blocklist.de"
    homepage = "https://www.blocklist.de/"
    description = "IPs reported in the last 48h for SSH, mail, web and FTP brute force by fail2ban sensors."
    default_enabled = False   # terms `ask` (feed_terms.py): off until the user turns it on
    interval = 3 * 3600
    raw_ext = "txt"
    url = "https://lists.blocklist.de/lists/all.txt"
    kind_name, label, sev, tags_ = "bruteforce", "Brute-forcer", 0.45, ["bruteforce"]


@register
class CinsArmy(_IpListSource):
    id = "cins_army"
    name = "CINS Army bad actors"
    provider = "Sentinel IPS / CINS"
    homepage = "https://cinsscore.com/"
    description = "IPs with poor reputation scores across the CINS sensor network."
    interval = 6 * 3600
    raw_ext = "txt"
    default_enabled = False
    url = "https://cinsscore.com/list/ci-badguys.txt"
    kind_name, label, sev, tags_ = "malicious_ip", "Bad actor", 0.4, ["reputation"]


@register
class EtCompromised(_IpListSource):
    id = "et_compromised"
    name = "Emerging Threats compromised hosts"
    provider = "Proofpoint ET"
    homepage = "https://rules.emergingthreats.net/"
    description = "Hosts Emerging Threats has seen compromised and acting maliciously."
    default_enabled = False   # terms `ask` (feed_terms.py): off until the user turns it on
    interval = 6 * 3600
    raw_ext = "txt"
    url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    kind_name, label, sev, tags_ = "compromised", "Compromised host", 0.6, ["compromised"]


@register
class SpamhausDrop(Source):
    id = "spamhaus_drop"
    name = "Spamhaus DROP hijacked netblocks"
    provider = "Spamhaus"
    homepage = "https://www.spamhaus.org/blocklists/do-not-route-or-peer/"
    description = "Netblocks hijacked or leased by spammers and cyber-criminals. Do not route or peer."
    category = "threat"
    # Spamhaus: "The DROP list data should not be downloaded from our website more than once per day."
    # (https://www.spamhaus.org/blocklists/do-not-route-or-peer/ and its FAQ). Excess gets the client firewalled.
    interval = 24 * 3600
    license = "Spamhaus DROP terms"
    default_enabled = False   # terms `ask` (feed_terms.py): off until the user turns it on

    async def fetch(self, client):
        return await _get(client, "https://www.spamhaus.org/drop/drop_v4.json", self.id)

    windowed = False

    def records(self, raw):
        out = []
        for line in raw.decode().splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("cidr"):
                out.append((r["cidr"], r))
        return out

    def parse(self, raw):
        evs = []
        ts = now()
        for line in raw.decode().splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            cidr = r.get("cidr")
            if not cidr:
                continue
            net = ipaddress.ip_network(cidr, strict=False)
            first = str(next(net.hosts(), net.network_address))
            evs.append(Event(
                source=self.id, kind="hijacked_netblock", key=(cidr,), ts=ts,
                title=f"Hijacked netblock {cidr}", summary=f"{r.get('sblid')} · {(r.get('rir') or 'unknown RIR').upper()} · {net.num_addresses:,} addresses",
                category="threat", severity=0.7, ip=first, value=net.num_addresses, tags=[t for t in [r.get("rir")] if t],
            ))
        return evs


@register
class RansomwareLive(Source):
    id = "ransomware_live"
    name = "Ransomware leak-site victims"
    provider = "ransomware.live"
    homepage = "https://www.ransomware.live/"
    description = ("Victims newly posted on ransomware gang leak sites, with group, sector and country. "
                   "Off by default: enable in Sources. Uses the free v2 API (no key, rate-limited); set "
                   "RANSOMWARELIVE_API_KEY (+ URL/header) to use an API PRO key for higher limits.")
    category = "threat"
    default_enabled = False
    interval = 1800
    license = "Non-commercial use with attribution (ransomware.live T&C s5)"

    async def fetch(self, client):
        headers = {}
        if config.RANSOMWARELIVE_API_KEY:
            headers[config.RANSOMWARELIVE_API_KEY_HEADER] = config.RANSOMWARELIVE_API_KEY
        return await _get(client, config.RANSOMWARELIVE_API_URL, self.id, headers=headers, timeout=60)

    @staticmethod
    def _victims(raw):
        # Free tier returns a bare list; PRO wraps it as {"client","count","order","victims":[...]}.
        d = json.loads(raw)
        return d.get("victims", []) if isinstance(d, dict) else d

    def records(self, raw):
        return [(f"{r.get('group') or r.get('group_name')}|{r.get('victim') or r.get('post_title')}", r) for r in self._victims(raw)]

    def prepare(self, raw, collected_at):
        fix_encoded_events(self.id, squash=False)   # victims stored before display text was decoded

    def parse(self, raw):
        evs = []
        for r in self._victims(raw):
            group = r.get("group") or r.get("group_name") or "unknown"
            victim = r.get("victim") or r.get("post_title") or "unknown victim"
            # Scraped from leak-site HTML: the display text is decoded ('Smith &amp; Sons'); the key keeps the
            # provider's text so a stored victim keeps its id.
            shown = unentity(victim)
            cc = (r.get("country") or "").upper() or None
            activity = r.get("activity")
            if activity in ("Not Found", "unknown", ""):  # PRO uses "Not Found" as a null sentinel
                activity = None
            # The event time is when the victim was posted (ransomware.live's "discovered"), so
            # "posted in the last 24h" counts and timelines are right; the attack date, often
            # weeks earlier, is kept in the summary.
            posted = r.get("discovered") or r.get("published") or r.get("attackdate")
            attack = str(r.get("attackdate") or "")[:10]
            desc = unentity(r.get("description")).strip()
            summary = " · ".join(x for x in [f"attack date {attack}" if attack else "", desc] if x)
            evs.append(Event(
                source=self.id, kind="ransomware", key=(group, victim),
                ts=to_ts(posted),
                title=f"{unentity(group)} claims {shown}",
                summary=summary[:400],
                category="threat", severity=0.85, country=cc,
                url=r.get("url") or r.get("permalink") or r.get("post_url") or None,
                tags=[t for t in [group, activity] if t],
            ))
        return evs


# --------------------------------------------------------------------------- internet infrastructure
@register
class IodaOutages(Source):
    id = "ioda_outages"
    name = "IODA internet outages"
    provider = "Georgia Tech IODA"
    homepage = "https://ioda.inetintel.cc.gatech.edu/"
    description = "Country and network-level internet outages detected from BGP, active probing and darknet telescope signals."
    category = "infra"
    interval = 900
    license = "No terms stated (cite IODA, Georgia Tech)"
    default_enabled = False   # terms `ask` (feed_terms.py): off until the user turns it on

    async def fetch(self, client):
        end = int(now().timestamp())
        params = {"from": end - 7 * 86400, "until": end, "limit": 2000, "entityType": "country"}
        country = await _get(client, "https://api.ioda.inetintel.cc.gatech.edu/v2/outages/events", self.id, params=params, timeout=60)
        params["entityType"] = "region"
        region = await _get(client, "https://api.ioda.inetintel.cc.gatech.edu/v2/outages/events", self.id, params=params, timeout=60)
        return json.dumps({"country": json.loads(country), "region": json.loads(region)}).encode()

    def records(self, raw):
        data = json.loads(raw)
        return [(f"{scope}|{r.get('location')}|{r.get('start')}|{r.get('datasource')}", r)
                for scope in ("country", "region") for r in (data.get(scope) or {}).get("data") or []]

    def parse(self, raw):
        data = json.loads(raw)
        evs = []
        for scope in ("country", "region"):
            rows = (data.get(scope) or {}).get("data") or []
            for r in rows:
                loc = r.get("location") or ""
                name = r.get("location_name") or loc
                cc = None
                if loc.startswith("country/"):
                    cc = loc.split("/", 1)[1]
                start = to_ts(r.get("start"))
                try:
                    dur_h = float(r.get("duration") or 0) / 3600
                except (TypeError, ValueError):
                    dur_h = 0.0
                # Fixed log scale (score 100 -> 0.25, 1e6 -> 1.0) so severity doesn't shift with the rest of the window.
                raw_score = r.get("score")
                try:
                    score = float(raw_score or 0)  # null or missing: treated as 0
                    value = None if raw_score is None else score
                except (TypeError, ValueError):
                    score, value = 0.0, None
                # `value` keeps the provider's number as it was (an int stays an int), so content_hash, and with
                # it which events count as changed, is what it was before null scores were handled.
                if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool):
                    value = raw_score
                sev = 0.25 + 0.75 * min(1.0, max(0.0, (math.log10(score) - 2) / 4)) if score > 0 else 0.25
                evs.append(Event(
                    source=self.id, kind="outage", key=(loc, r.get("start"), r.get("datasource")),
                    ts=start, title=f"Outage · {name}",
                    summary=f"{r.get('datasource')} signal drop · {dur_h:.1f}h · score {score:,.0f}",
                    category="infra", severity=sev, country=cc, value=value,
                    tags=[scope, r.get("datasource") or ""],
                ))
        return evs


# --------------------------------------------------------------------------- news & advisories
class _RssSource(Source):
    feeds: list[tuple[str, str]] = []
    category = "news"
    raw_ext = "json"
    interval = 1200

    ERRORS = "__errors__"  # payload key holding {label: error} for feeds that failed this run

    def _parsed(self, xml: str):
        """feedparser's result for one feed body. A run parses each body once: fetch() parses it to check it is a
        feed and keeps the result for that run, and records() and parse() read the same result. A body from an
        earlier run (a re-parse from the lake) is parsed again here."""
        key = hashlib.sha1(xml.encode()).digest()
        hit = getattr(self, "_parses", {}).get(key)
        return hit if hit is not None else feedparser.parse(xml)

    async def fetch(self, client):
        out, errors = {}, {}
        self._parses = {}   # this run's parsed feeds (only the latest run's are kept)
        for label, url in self.feeds:
            try:
                body = (await _get(client, url, self.id, timeout=30)).decode(errors="ignore")
            except caps.TooLarge:   # an oversized feed fails the run: nothing partial is stored
                raise
            except Exception as e:  # one dead feed should not kill the batch...
                errors[label] = f"{type(e).__name__}: {e}"
                continue
            f = feedparser.parse(body)
            if not f.entries and not f.get("version"):  # feedparser found no RSS/Atom at all
                errors[label] = "not a feed (no RSS/Atom content in the response)"
                continue
            out[label] = body
            self._parses[hashlib.sha1(body.encode()).digest()] = f
        if errors and not out:  # ...but a run where every feed failed is a failed run
            raise RuntimeError("; ".join(f"{k}: {v}" for k, v in errors.items()))
        if errors:
            out[self.ERRORS] = errors
        return json.dumps(out).encode()

    def fetch_errors(self, raw):
        return [f"{k}: {v}" for k, v in (json.loads(raw).get(self.ERRORS) or {}).items()]

    def unseen(self, raw):
        # record keys are "<feed label>|<link>": only the dead feeds' keys were not seen
        dead = set(json.loads(raw).get(self.ERRORS) or {})
        return lambda key: key.split("|", 1)[0] in dead

    def _feeds(self, raw):
        return [(k, v) for k, v in json.loads(raw).items() if k != self.ERRORS and isinstance(v, str)]

    def records(self, raw):
        out = []
        for label, xml in self._feeds(raw):
            for e in self._parsed(xml).entries:
                out.append((f"{label}|{e.get('link') or e.get('title')}", {"feed": label, **dict(e)}))
        return out

    def prepare(self, raw, collected_at):
        fix_encoded_events(self.id)

    def parse(self, raw):
        evs = []
        for label, xml in self._feeds(raw):
            for e in self._parsed(xml).entries[:60]:
                title = unentity(e.get("title", "")).strip()
                if not title:
                    continue
                summary = re.sub(r"<[^>]+>", " ", e.get("summary", "") or "")
                summary = re.sub(r"\s+", " ", unentity(summary)).strip()[:500]
                ts = e.get("published") or e.get("updated")
                parsed = e.get("published_parsed") or e.get("updated_parsed")
                when = dt.datetime(*parsed[:6], tzinfo=dt.UTC) if parsed else to_ts(ts)
                ccs = geo.tag_countries(f"{title} {summary}")
                evs.append(Event(
                    source=self.id, kind=self.kind_name, key=(e.get("link") or title,), ts=when,
                    title=title, summary=summary, category="news", url=e.get("link"),
                    country=ccs[0] if ccs else None, severity=self.sev,
                    tags=[label] + ccs,
                ))
        return evs


@register
class SecurityNews(_RssSource):
    id = "security_news"
    name = "Security news wire"
    provider = "BleepingComputer · The Hacker News · Krebs · SANS ISC"
    homepage = ""
    description = "Headlines from major security newsrooms, tagged with the countries they mention."
    kind_name, sev = "news", 0.3
    feeds = [
        ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
        ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
        ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
        ("SANS ISC", "https://isc.sans.edu/rssfeed_full.xml"),
    ]


@register
class CisaAdvisories(Source):
    """CISA's advisories from its machine-readable CSAF repository on GitHub (cisa.gov answers 403 to non-browser
    clients, and its User-Agent is never spoofed). CSAF parsing and fetching: sources/vulns.py."""
    id = "cisa_advisories"
    name = "CISA cybersecurity advisories"
    provider = "CISA (CSAF repository, github.com/cisagov/CSAF)"
    homepage = "https://github.com/cisagov/CSAF"
    description = ("CISA's ICS, ICS medical and IT vulnerability advisories in CSAF 2.0: affected vendors and products, "
                   "CVEs with CVSS, published and revised dates, linked to the cisa.gov advisory page.")
    # Listed with the vulnerability sources; its events stay category "news" (Newswire, article pipeline).
    category = "vuln"
    kind_name, sev = "advisory", 0.6
    interval = 2 * 3600            # 3 small index requests per run; documents only when new or revised
    license = "Public domain (US Gov); CISA notification and privacy & use policy (https://www.cisa.gov/notification)"
    windowed = True                # a 90-day window of published or revised advisories; older ones age out

    async def fetch(self, client):
        from .vulns import fetch_csaf
        return await fetch_csaf(client)

    def fetch_errors(self, raw):
        from .vulns import CSAF_ERRORS
        errs = json.loads(raw).get(CSAF_ERRORS) or {}
        return [f"{k}: {v}" for k, v in list(errs.items())[:5]] + ([f"+{len(errs) - 5} more"] if len(errs) > 5 else [])

    def prepare(self, raw, collected_at):
        from .vulns import csaf_advisories, store_advisory_cves
        store_advisory_cves(csaf_advisories(raw))

    def records(self, raw):
        from .vulns import csaf_advisories
        return [(tid, doc) for tid, (_s, doc) in sorted(csaf_advisories(raw).items())]

    def parse(self, raw):
        from .vulns import advisory_event, csaf_advisories
        return [advisory_event(self.id, s) for _tid, (s, _doc) in sorted(csaf_advisories(raw).items())]
