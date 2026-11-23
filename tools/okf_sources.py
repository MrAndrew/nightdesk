"""Generate the source catalog and storage estimates in okf/sources/ and okf/data/storage-estimates.md.

uv run python tools/okf_sources.py [--only nvd_recent,bluesky_cyber] [--out DIR] [--check]

--check writes nothing: it renders every page and exits 1, naming each page, when a committed page differs from what
the generator makes (or is missing); bad input (an --only id that is not a generated page, a source with no inputs)
exits 2; tests/web/test_v12_pf_tools.py runs it. The pages are the record: a hand edit
to a generated page belongs in the inputs below (MEASURED notes, TERMS_REVIEW, HAND_ENTRIES), then regenerate.

Current-source facts come from the live registry (osinthub.sources) plus measurements of the lake
taken on 2026-11-04 (MEASURED below). Candidate facts come from a reachability/size probe run the
same day with the app's own User-Agent (CANDIDATES below). Re-measure and re-run to refresh.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from osinthub.sources import SOURCES  # noqa: E402
import osinthub.news.sources  # noqa: E402,F401  (registers the research and news feeds into SOURCES)

OKF = ROOT / "okf"
NOW = "2026-11-04T14:00:00Z"
GEN = f"generated: {{ by: claude-code/claude-opus-5-5, at: {NOW} }}"
ROW_BYTES = 610          # measured DuckDB bytes per event row after CHECKPOINT (22,788 rows -> 13.9 MB)
HORIZONS = [("30 days", 30), ("90 days", 90), ("1 year", 365), ("3 years", 1095)]

TRUST = {
    "A": "Primary authority: a government CERT/agency, standards body or the operator of the measurement itself",
    "B": "Established research group, nonprofit or vendor with a published methodology and track record",
    "C": "Community or aggregator feed: useful and widely used, but curation varies; corroborate before acting",
    "D": "Unverified or crowd content (social posts, tips); signal only, never ground truth",
}

# --------------------------------------------------------------------------- current sources
# raw_kb / ev_kb: average bytes per run in the lake (raw payload / normalised NDJSON), measured 2026-11-04.
# For streams, per_day_mb is measured lake growth per day. new_rows: estimated new unique events per day.
# kept: fraction of those bytes still written now that the lake stores gzipped record and event deltas
# (streams: hourly gzip files). Measured by replaying the lake's first 12 hours, steady state (first full
# load excluded). Sources with too little history use 30% of their earlier change-only figure.
MEASURED = {
    "cisa_kev":        dict(kept=0.009, trust="A", auth="none", raw_kb=1829, ev_kb=1345, new_rows=1,
                            corroborates="NVD (CVE details), EUVD exploited list, VulnCheck KEV, EPSS"),
    "nvd_recent":      dict(kept=0.0058, trust="A", auth="none (optional free key raises rate limit)", raw_kb=3655, ev_kb=1167, new_rows=130,
                            corroborates="CVE List V5 (CVE.org), EUVD, GitHub Advisory Database, OSV",
                            gen_at="2026-11-19T01:00:00Z", note="""# Text

Descriptions are stored as plain text: some CNAs submit them with HTML entities (`&#39;`, `&quot;`, `&amp;`, even double-encoded `&amp;amp;`), which the shared decoder (`osinthub/sources/text.py`) turns into the characters they stand for, however many times they were encoded. Only well-formed entities are decoded (`AT&T`, `Q&notes`, `&copy law` stay as written) and line breaks are kept. The CVE id, the NVD link and the stored NVD records (reference URLs included) are never decoded. Decoded markup such as `<script>` is text: clients escape it where they show it. The CVE search documents read descriptions from the lake records and decode them the same way.

Existing lakes: each run's `prepare()` decodes, in place in DuckDB, the stored events that still hold an entity-like `&...`, in or out of the 72-hour window, and gives each the content hash `parse()` gives it today. The same run's parse then finds nothing changed (no event delta is written for the text alone), and the entity linker sees the new hash and extracts the event's mentions again, once. The lake's event files keep the text as it was stored then; nothing is rewritten."""),
    "feodo_c2":        dict(kept=0.005, trust="B", auth="none", raw_kb=2, ev_kb=3, new_rows=1,
                            corroborates="ThreatFox, IPsum, FireHOL level 1"),
    "dshield_top":     dict(kept=0.078, trust="B", auth="none", raw_kb=50, ev_kb=271, new_rows=6700,
                            corroborates="blocklist.de, CINS, IPsum, GreyNoise, AbuseIPDB"),
    "tor_exits":       dict(kept=0.0005, trust="A", auth="none", raw_kb=18, ev_kb=583, new_rows=100,
                            corroborates="Tor Onionoo relay details"),
    "blocklist_de":    dict(kept=0.0063, trust="C", auth="none", raw_kb=369, ev_kb=2958, new_rows=2200,
                            corroborates="DShield, CINS, IPsum, AbuseIPDB",
                            note="The parser keeps the first 6,000 of roughly 25,000 IPs per run; raising the cap scales storage about 4x."),
    "cins_army":       dict(kept=0.0063, trust="C", auth="none", raw_kb=230, ev_kb=1800, new_rows=1500,
                            corroborates="DShield, blocklist.de, IPsum", est=True),
    "et_compromised":  dict(kept=0.006, trust="B", auth="none", raw_kb=7, ev_kb=257, new_rows=50,
                            corroborates="ET block list, FireHOL level 2"),
    "spamhaus_drop":   dict(kept=0.0005, trust="A", auth="none (terms of use apply)", raw_kb=108, ev_kb=939, new_rows=5,
                            corroborates="FireHOL level 1, Spamhaus ASN-DROP",
                            note="# Fetch terms\n\nSpamhaus asks that \"the DROP list data should not be downloaded from our website more than once per day\" "
                                 "and that automated downloads be at least an hour apart; excessive downloads may get the client firewalled "
                                 "([DROP page](https://www.spamhaus.org/blocklists/do-not-route-or-peer/), "
                                 "[DROP FAQ: How often should my system fetch the DROP list?](https://www.spamhaus.org/faqs/do-not-route-or-peer-drop/), "
                                 "checked 2026-11-09). So it runs once every 24 hours, timed from the last successful fetch, so restarts "
                                 "don't fetch again early. Pressing Run now on the Sources page still fetches at once: use it sparingly."),
    "ransomware_live": dict(kept=0.01, trust="C", auth="blocked for automated clients (paid API available)", raw_kb=120, ev_kb=150, new_rows=40,
                            corroborates="RansomLook (open), DataBreaches.net, victim disclosures", est=True,
                            gen_at="2026-11-18T23:55:00Z", note="""# Text

Victim names and descriptions are scraped from leak-site HTML and can carry entities (`Smith &amp; Sons`, `&#8211;`). The event title (`<group> claims <victim>`) and the summary are decoded to plain text by the shared decoder (`osinthub/sources/text.py`, well-formed entities only), so a followed organisation matches its victim posting. The event key and the record key keep the provider's text, so an existing victim keeps its event id instead of appearing twice; the tags (group, activity) and the post URL are not decoded. Victims stored before this are decoded in DuckDB by the source's next run (`prepare()`) and given the content hash `parse()` gives them today, so they are not stored again as changed and the entity linker extracts their mentions again, once."""),
    "ioda_outages":    dict(kept=0.0108, trust="B", auth="none", raw_kb=265, ev_kb=541, new_rows=150,
                            corroborates="Cloudflare Radar outages, RIPE Atlas, GRIP"),
    "security_news":   dict(kept=0.0041, trust="B", auth="none", raw_kb=260, ev_kb=77, new_rows=50,
                            corroborates="The Record, SecurityWeek, CISA and national CERT advisories"),
    "cisa_advisories": dict(kept=0.004, trust="A", auth="none (CSAF repository on GitHub)", raw_kb=40, ev_kb=2, new_rows=5,
                            corroborates="CISA KEV, NVD, vendor advisories", est=True),
    # EPSS stores one record per CVE only when its probability changes (about 21 KB a day after a 2.2 MB first
    # load) and makes no events: scores live in the `epss` table (osinthub/sources/vulns.py).
    "epss":            dict(kept=1.0, trust="B", auth="none", per_day_mb=0.021, new_rows=0, est=True,
                            corroborates="CISA KEV (confirmed exploitation), NVD (CVSS)"),
    "ris_live":        dict(kept=0.13, trust="A", auth="none", per_day_mb=9.6, new_rows=15400,
                            corroborates="RIPE RIS dumps, RouteViews, Cloudflare Radar route leaks/hijacks"),
    "bluesky_cyber":   dict(kept=0.21, trust="D", auth="none", per_day_mb=0.4, new_rows=400,
                            corroborates="Mastodon infosec.exchange, Reddit r/netsec, news wire",
                            gen_at="2026-11-18T23:55:00Z",
                            status="off by default for new lakes (an unvetted social stream; turn it on in Sources). A lake that already ran it keeps it on (`DEFAULT_OFFS` in osinthub/scheduler.py).",
                            note="""# Text

Post text is stored as plain text: posts copied from web pages or made by feed bots can carry HTML entities (`&amp;`, `&#39;`, `&quot;`) that Bluesky stores as typed. The shared decoder (`osinthub/sources/text.py`) decodes well-formed entities only (`AT&T`, `&foo;` stay as written), before the keyword filter runs, so the stored title, summary, tags and the live `social` messages all see the same text. Line breaks are kept. The DID, the record key and the post link are never decoded. Decoded markup such as `<script>` is text: clients escape it where they show it.

Existing lakes: a stream never sees a post twice, so posts stored before the text was decoded are fixed in DuckDB each time the stream connects (only rows that still hold an entity-like `&...` are looked at), each with a new content hash, so the entity linker extracts its mentions again, once. The lake's hourly event files keep the text as it was stored then."""),
    # Research and news feeds added by osinthub/news/sources.py. raw_kb measured from the feed probe on
    # 2026-11-04; ev_kb, kept and new_rows estimated from security_news (same RSS pipeline).
    "news_therecord":       dict(kept=0.02, trust="B", auth="none", raw_kb=5, ev_kb=4, new_rows=15, est=True,
                                 corroborates="BleepingComputer, SecurityWeek, CyberScoop"),
    "news_securityweek":    dict(kept=0.02, trust="B", auth="none", raw_kb=13, ev_kb=7, new_rows=20, est=True,
                                 corroborates="The Hacker News, Help Net Security, BleepingComputer"),
    "news_helpnetsecurity": dict(kept=0.02, trust="C", auth="none", raw_kb=17, ev_kb=7, new_rows=15, est=True,
                                 corroborates="SecurityWeek, vendor advisories"),
    "news_cyberscoop":      dict(kept=0.01, trust="B", auth="none", raw_kb=70, ev_kb=7, new_rows=8, est=True,
                                 corroborates="The Record"),
    "news_darkreading":     dict(kept=0.004, trust="B", auth="none", raw_kb=78, ev_kb=35, new_rows=15, est=True,
                                 corroborates="SecurityWeek, The Record"),
    "news_talos":           dict(kept=0.004, trust="B", auth="none", raw_kb=1026, ev_kb=10, new_rows=1, est=True,
                                 corroborates="Unit 42, Microsoft Threat Intelligence, ESET Research"),
    "news_unit42":          dict(kept=0.02, trust="B", auth="none", raw_kb=24, ev_kb=10, new_rows=1, est=True,
                                 corroborates="Cisco Talos, Microsoft Threat Intelligence"),
    "news_mstic":           dict(kept=0.004, trust="B", auth="none", raw_kb=494, ev_kb=7, new_rows=1, est=True,
                                 corroborates="Google Threat Intelligence Group, Unit 42"),
    "news_eset":            dict(kept=0.004, trust="B", auth="none", raw_kb=70, ev_kb=40, new_rows=3, est=True,
                                 corroborates="Cisco Talos, Check Point Research"),
    "news_elastic":         dict(kept=0.002, trust="B", auth="none", raw_kb=8415, ev_kb=40, new_rows=1, est=True,
                                 corroborates="Cisco Talos, Unit 42",
                                 note="The feed carries full article bodies for about 300 posts (8.4 MB), so it runs every 6 hours; only new or changed entries are stored.",
                                 gen_at="2026-11-19T01:00:00Z"),
    # abuse.ch sources added 2026-11-09 (osinthub/sources/abusech.py). No Auth-Key was available, so ThreatFox and URLhaus
    # sizes are estimates from the documented response shapes; SSLBL was measured from one real download (844 KB).
    "threatfox":       dict(kept=0.05, trust="B", auth="free Auth-Key (ABUSECH_AUTH_KEY)", raw_kb=1000, ev_kb=600, new_rows=1500, est=True,
                            corroborates="Feodo Tracker (the same C2 addresses), URLhaus (the same payload URLs), MalwareBazaar (hashes), C2IntelFeeds",
                            gen_at="2026-11-18T23:45:00Z",
                            note="""# Access and terms

Needs a free abuse.ch Auth-Key from https://auth.abuse.ch/, read from the environment variable `ABUSECH_AUTH_KEY` (osinthub/config.py). The key is sent only in the documented `Auth-Key` HTTP header of `POST https://threatfox-api.abuse.ch/api/v1/` (`{"query": "get_iocs", "days": N}`), never in a URL, and the request does not follow redirects, so the header can never be forwarded to another host; a redirect fails the run. The key never reaches a log line, a run record, a raw path or an error message. Without a key the source is never started or fetched, cannot be switched on or run (both calls answer 409) and the Sources page says "Needs a free key" and that it goes in the `.env` file in Night Desk's install folder, with the variable's name `ABUSECH_AUTH_KEY` under Technical details. A refused key (HTTP 401/403) fails the run with "abuse.ch refused the Auth-Key"; a ThreatFox `query_status` other than ok or no_result fails it with that status.

abuse.ch Terms of Use (last updated 2026-10-21, https://abuse.ch/terms-of-use/): the free tier is for not-for-profit use only (s3.1); no redistribution or derivative works of the platforms (s7.3); no high-volume harvesting; and s7.3 forbids using the data to \"customise, train, or otherwise improve\" AI models. So, conservatively, nothing from ThreatFox goes into an LLM prompt or an embedding: `ai_ok = False` keeps its claims, evidence and mention counts out of the entity brief (osinthub/news/brief.py), and malware families known only from abuse.ch (entity attr `ai_excluded`) are never embedded (osinthub/entities/searcher.py). Event vectors cover news and social kinds only.

# What is ingested

Hourly, the IOCs first seen in the last day. After a gap (the app stopped, the laptop asleep, an outage) the window widens to cover it plus 3 hours, up to the API's maximum of 7 days; the first run asks for 3 days. Each run fetches the whole window; only new or changed IOCs are stored, keyed by ThreatFox's IOC id, so an IOC is stored once and again only if ThreatFox changes it (last_seen, confidence, tags). `windowed = True`: an IOC leaving the window is not a removal. A gap longer than 7 days loses IOCs first seen during it.

* Types: `ip:port` (IPv4, bracketed IPv6, and unbracketed IPv6 whose last group is the port), `domain`, `url`, `md5_hash`, `sha1_hash`, `sha256_hash`. Junk rows (no value, an impossible address, a malformed hash, unknown types) are dropped; a repeated IOC id counts once.
* Event kind `malware_ioc`: `ts` is ThreatFox's `first_seen` (UTC); title "<family> <C2|payload delivery|payload> <ioc>"; severity by threat type (botnet_cc 0.85, payload_delivery and cc_skimming 0.7, payload 0.6) times 0.6-1.0 by confidence_level; `value` is the confidence; tags are the family, the threat type and up to six reporter tags (case-insensitive duplicates folded); `url` is the IOC's ThreatFox page.

# In the app

* **Network logs.** Each IOC becomes an indicator interval ([netlog](/data/netlog.md#abusech)) starting at ThreatFox's `first_seen`: C2 at confidence 75 or more is category `c2` (high; 50 is the community default), weaker C2 reports and delivery infrastructure `reputation` (medium), sample hashes `malware` (high on a home download). URL IOCs match plain-HTTP Host + path, and their host also matches. Listings end 30 days (IP), 90 days (domain, URL) or 180 days (hash) after the latest of the last changed record and ThreatFox's `last_seen` (a re-sighting ThreatFox records renews it; an unchanged record seen again does not).
* **Shared-infrastructure gate** (all ip, domain and URL-host indicators from abuse.ch): private, loopback and special-purpose addresses and public resolvers are never indicators; an address in a big cloud/CDN/platform ASN is kept as `reputation` (medium) when the IOC names it directly and skipped when it is only a URL's host; a domain owned by a popular or shared service (the Tranco top list and built-in list, at or below its registrable domain, so github.com and raw.githubusercontent.com are shared but evil.duckdns.org is not) is never an indicator. Counts and samples are in `GET /api/netlog/status` → `abusech_gate`.
* **Alerts.** ThreatFox corroborates the other lists instead of duplicating them: a contact with an address Feodo (or any list) also carries is that list's alert, with ThreatFox under "Also listed by"; only contacts no other list explains get a ThreatFox alert ([cross-source](/data/netlog.md#cross-source)).
* **Entities.** The family resolves through ThreatFox's Malpedia id (`win.dridex`) and then the name and aliases against the MISP/Malpedia/ATT&CK catalogue; the IOC gets an observed `hosts-malware`, `delivers` or `indicates` claim to it, which merges with the same claim from Feodo (two tier-B sources: high confidence). The family is not mentioned once per IOC, so feed volume does not outrank reports in the entity directory.
* **Map and panels.** Every address counts once on the dashboard, whichever feeds list it ([counting addresses](/architecture/api.md#counting-addresses)): an address another list already carries, or several ThreatFox IOCs for one address, is not counted again, and the original listing (Feodo) stands for it. ThreatFox does add to the "N feeds" corroboration count beside the address, which says that some feeds copy each other.
* **Explorer** lists every event; global search does not index feed events (it covers news and social events), but finds their indicator and family entities.
* **Stories and entity pages** show the lists that hold an IoC ("listed · threatfox")."""),
    "urlhaus":         dict(kept=0.1, trust="B", auth="free Auth-Key (ABUSECH_AUTH_KEY)", raw_kb=400, ev_kb=300, new_rows=1000, est=True,
                            corroborates="ThreatFox (payload URLs), Spamhaus DBL and SURBL (carried in each record), OpenPhish",
                            note="""# Access and terms

Needs the same free abuse.ch Auth-Key as ThreatFox (`ABUSECH_AUTH_KEY`), sent only in the `Auth-Key` header of `GET https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/` (the newest 1,000 URLs of the last 3 days), without following redirects. The export files would need the key in the URL path, so they are not used. abuse.ch asks for no more than one fetch per 5 minutes; the source runs hourly. Without a key it is never started or fetched and the Sources page says so.

abuse.ch Terms of Use (last updated 2026-10-21, https://abuse.ch/terms-of-use/): the free tier is for not-for-profit use only (s3.1); no redistribution or derivative works of the platforms (s7.3); no high-volume harvesting; and s7.3 forbids using the data to \"customise, train, or otherwise improve\" AI models. URLhaus is `ai_ok = False` like ThreatFox.

# What is ingested

Keyed by URLhaus's URL id; `windowed = True`. Limits of the recent-URLs API: more than 1,000 new URLs between two runs (a burst, or an outage of more than a few hours) are lost, and a URL that has dropped out of the newest 1,000 is not seen again, so its going offline is never seen either: its listing then lapses after 30 days.

* Event kind `malware_url`: `ts` is `date_added` (UTC); severity online 0.7, unknown 0.5, offline 0.4; tags are the URLhaus tags plus the status; the summary carries the host, the threat, Spamhaus DBL / SURBL listings and the reporter. `ip` is set when the host is an address.
* Family: URLhaus tags are free text (cve-2017-11882, base64, geofenced, wordpress ...), so a tag counts as the family only if it resolves through the MISP/Malpedia/ATT&CK catalogue; otherwise there is no family. No family is better than a wrong one.
* Rows with no parsable URL and repeated ids are dropped.

# In the app

* **Network logs.** Each online URL is a `url` indicator (category `reputation`, medium) from its `date_added`, matched against plain-HTTP Host + request target; its host (domain or IP) is an indicator too. A URL that goes offline closes its listing; otherwise it lapses 30 days after the record last changed. The same URL on ThreatFox gives one alert citing both.
* **Shared-infrastructure gate** (all ip, domain and URL-host indicators from abuse.ch): private, loopback and special-purpose addresses and public resolvers are never indicators; an address in a big cloud/CDN/platform ASN is kept as `reputation` (medium) when the IOC names it directly and skipped when it is only a URL's host; a domain owned by a popular or shared service (the Tranco top list and built-in list, at or below its registrable domain, so github.com and raw.githubusercontent.com are shared but evil.duckdns.org is not) is never an indicator. Counts and samples are in `GET /api/netlog/status` → `abusech_gate`.
* **Entities.** URL and domain entities with an observed `delivers` claim to a family named in the tags (resolved through the catalogue; unknown tags are not turned into families).
* **Map and panels** count an address once, as for ThreatFox.
* **Explorer** lists every event; global search does not index feed events (it covers news and social events), but finds their indicator and family entities."""),
    "sslbl":           dict(kept=0.002, trust="B", auth="none", raw_kb=844, ev_kb=40, new_rows=1, est=True,
                            corroborates="ThreatFox (C2 servers of the same families), Censys and JARM/JA3S certificate fingerprints",
                            note="""# Access and terms

No key. The certificate list is CC0 (abuse.ch Terms of Use s3.4). It regenerates every 5 minutes and abuse.ch asks not to fetch more often; it changes a few times a day, so the source runs every 6 hours. Although the data is CC0, the source is also `ai_ok = False`, to keep every abuse.ch dataset on one rule.

# What is ingested

`sslblacklist.csv`: listing date, certificate SHA1 and listing reason ("Dridex C&C"), 11,202 rows on 2026-11-09 going back to 2014. It is a list (`windowed = False`): a fingerprint that disappears was removed.

* **Certificates are indicators, not activity.** Every row is a record and a netlog indicator, but no row becomes an event, an entity, a mention or a claim. Events are one summary per family with a listing in the last 365 days (kind `c2_cert`, key = family, `value` = certificates listed, `ts` = the latest listing): "Vidar: 731 C2 TLS certificates on SSL Blacklist". Listing reasons that are not family names ("Malware C&C", "Malware distribution", a domain such as "doxbin.cy", long phrases) give no summary.
* Not used: `sslipblacklist.csv` (botnet C2 IP:port) was deprecated on 2025-01-03 and is now an empty header (checked 2026-11-09), and the `.txt` variant is gone too. `ja3_fingerprints.csv` is skipped: abuse.ch warns of many false positives, and Zeek and Suricata compute JA3 only with extra configuration.

# In the app

* **Network logs.** Each fingerprint is a `hash` indicator, category `c2`, listed from its SSLBL listing date. It matches Zeek `files.log` `sha1` (Zeek's file analysis hashes the certificates it sees) and Suricata `tls.fingerprint` (SHA1 with colons, the default). Zeek's `x509.log` `fingerprint` and `ssl.log` `cert_chain_fps` are SHA256 on current Zeek, so they match only on a sensor configured for SHA1. A home device receiving a listed certificate is a high alert.
* **Entities.** A family summary event adds `attrs.sslbl_certificates` and `attrs.sslbl_last_listed` to a family the catalogue already knows (`CobaltStrike` is Cobalt Strike, `PureLogsStealer` is PureLogs Stealer), with one mention per family. Names the catalogue does not know make no entity.
* **Panels.** One summary event per family, so Top Offenders' tag ranking sees each family once, not once per certificate.
* **Explorer** lists the family summaries; the individual fingerprints are in the lake's record files and in `indicator_intervals`."""),
}


def runs_per_day(src) -> float:
    return 0 if src.mode == "stream" or not src.interval else 86400 / src.interval


def lake_mb_per_day(sid: str, src) -> float:
    m = MEASURED[sid]
    if "per_day_mb" in m:
        return m["per_day_mb"]
    return runs_per_day(src) * (m["raw_kb"] + m["ev_kb"]) / 1000


def db_mb_per_day(sid: str) -> float:
    return MEASURED[sid]["new_rows"] * ROW_BYTES / 1e6


def human_interval(sec: int) -> str:
    if not sec:
        return "continuous"
    if sec % 86400 == 0:
        return f"every {sec // 86400}d"
    if sec % 3600 == 0:
        return f"every {sec // 3600}h"
    return f"every {sec // 60}m"


def gb(mb: float) -> str:
    v = mb / 1000
    return f"{v:,.2f} GB" if v < 10 else f"{v:,.0f} GB"


def yaml_str(s: str) -> str:
    return '"' + s.replace('"', "'") + '"'


def write(path: Path, text: str) -> None:
    """Write one page, or in --check mode compare it with the page on disk and note it when it differs."""
    WRITTEN.append(path)
    data = text.encode("utf-8")
    if CHECK:
        if not path.is_file() or path.read_bytes() != data:
            DRIFT.append(path)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


# --------------------------------------------------------------------------- terms (pre-alpha terms review)
# Every page's "Terms" section: what the terms page said when read on TERMS_READ, with its link, and the review's
# answers for commercial use, redistribution and AI use ("?" = not stated). Source: the pre-alpha terms review
# (okf/project/pre-alpha-release.md, workstream 8). The in-app wording is osinthub/feed_terms.py.
TERMS_READ = "2026-11-19"
TERMS_AT = "2026-11-19T20:00:00Z"     # generated.at of every page whose Terms section this review wrote
_ABUSECH = ("abuse.ch Terms of Use (updated 2026-10-21) s3.4: Feodo Tracker and SSLBL data are \"free to use without "
            "limitations ... (CC0)\"; s7.3 forbids using abuse.ch data to \"customise, train, or otherwise improve any "
            "artificial intelligence model\" and has no CC0 carve-out, so the source is `ai_ok = False` (kept out of every "
            "prompt and embedding)")
_ABUSECH_KEYED = ("abuse.ch Terms of Use (updated 2026-10-21) s3.1: the free tier is \"for not-for-profit purposes\"; s4.1 "
                  "commercial use needs a paid Spamhaus subscription; s7.3 no derivative works, no high-volume harvesting "
                  "and no AI use (`ai_ok = False`)")
_NEWS = ("Publisher copyright. Night Desk reads the public RSS feed (headline, summary and link), then fetches each "
         "article page (robots.txt honoured, bot checks never bypassed), keeps it on this machine for the local AI and "
         "never re-serves the text. No licence for the feed was found")
TERMS_REVIEW = {
    "cisa_kev": dict(url="https://www.cisa.gov/sites/default/files/licenses/kev/license.txt", comm="yes", redist="yes", ai="yes",
                     text="CC0 1.0. No CISA logo and no CISA endorsement implied"),
    "nvd_recent": dict(url="https://nvd.nist.gov/developers/terms-of-use", comm="yes", redist="yes (not as NVD data once modified)", ai="yes",
                       text="US Government data. Apps must show \"This product uses the NVD API but is not endorsed or certified by the NVD\" (Help › Sources › Credits shows it)"),
    "feodo_c2": dict(url="https://abuse.ch/terms-of-use/", comm="yes", redist="yes", ai="no (unclear: s7.3, no CC0 carve-out)", text=_ABUSECH),
    "sslbl": dict(url="https://abuse.ch/terms-of-use/", comm="yes", redist="yes", ai="no (unclear: s7.3, no CC0 carve-out)", text=_ABUSECH),
    "threatfox": dict(url="https://abuse.ch/terms-of-use/", comm="no", redist="no", ai="no", text=_ABUSECH_KEYED),
    "urlhaus": dict(url="https://abuse.ch/terms-of-use/", comm="no", redist="no", ai="no", text=_ABUSECH_KEYED),
    "tor_exits": dict(url="https://metrics.torproject.org/", comm="yes", redist="yes", ai="yes",
                      text="CC0: \"Data on this site is freely available under a CC0 no copyright declaration\". The CC BY 3.0 US licence on Tor Metrics covers its graphs only, not the exit list"),
    "dshield_top": dict(url="https://isc.sans.edu/api/", comm="own network only (\"ok to use this data for commercial purposes, for example to protect your own company's network\")",
                        redist="share-alike; no resale", ai="yes",
                        text="CC BY-NC-SA 4.0. No resale; own-network use, commercial included. \"Do not resell the data\"; put a contact in the User-Agent. Credit SANS ISC"),
    "blocklist_de": dict(url="https://www.blocklist.de/en/terms.html", comm="?", redist="?", ai="?",
                         text="No licence on the [site](https://www.blocklist.de/en/index.html) or the [download page](https://www.blocklist.de/en/download.html); the terms (s5) exclude downloads of \"zu großem Volumen\" (too large a volume) from free use"),
    "cins_army": dict(url="https://cinsscore.com/", comm="likely", redist="?", ai="likely",
                      text="\"Parse and use in any way you see fit\"; no formal licence"),
    "et_compromised": dict(url="https://rules.emergingthreats.net/", comm="?", redist="?", ai="?",
                           text="Only \"© 2026 Proofpoint Inc\"; no licence found for `compromised-ips.txt` (ET Open rules are BSD/GPL by sid range according to community posts only)"),
    "spamhaus_drop": dict(url="https://www.spamhaus.org/blocklists/drop-fair-use-policy/", comm="not stated", redist="not stated", ai="not stated",
                          text="DROP fair use policy s3.1: the data is \"protected by copyright and database right\" and no licence is granted; s3.3 the right to use it can be revoked \"for any reason\". The [DROP page](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) asks products to credit \"The Spamhaus Project\" (Help › Sources › Credits does) and to fetch at most once a day"),
    "ioda_outages": dict(url="https://ioda.inetintel.cc.gatech.edu/", comm="?", redist="?", ai="?",
                         text="No terms, acceptable-use or citation page was found for the IODA data or API; cite \"IODA, Georgia Tech\""),
    "ransomware_live": dict(url="https://www.ransomware.live/t&c", comm="no", redist="no", ai="not stated",
                            text="Non-commercial. T&C s5.1: \"freely available for non-commercial use\" with attribution; s5.2 commercial use is \"strictly prohibited without prior written approval\"; s6 name ransomware.live and link back (Help › Sources › Credits does)"),
    "bluesky_cyber": dict(url="https://docs.bsky.app/docs/support/developer-guidelines", comm="?", redist="no", ai="contested",
                          text="The docs site's guidelines page now redirects to an empty page; the guidelines' source in Bluesky's docs repository ([developer-guidelines.md](https://github.com/bluesky-social/bsky-docs/blob/main/docs/support/developer-guidelines.md), archived by Bluesky on 2026-08-18) says, as item 3, \"All services must have a method for deleting content a user has requested to be deleted\". The owner's reading (2026-11-20): each Night Desk runs on its user's machine, and that user manages the data (NOTICE, \"Your data and the sources you turn on\"). The stream records each delete of a post it stored in the `deletion_requests` table and keeps the post; deletes made while Night Desk is stopped are not seen"),
    "security_news": dict(url="https://www.bleepingcomputer.com/terms-of-use/", comm="no", redist="no", ai="unclear",
                          text=_NEWS + ". [BleepingComputer's terms](https://www.bleepingcomputer.com/terms-of-use/) s4: content \"may not be stored in a computer ... except for personal and non-commercial use\"; [SANS ISC](https://isc.sans.edu/about.html) is CC BY-NC-SA 4.0; The Hacker News' terms page gave 404. On by default for personal use"),
}
for _sid, _home, _extra in (
        ("news_therecord", "https://therecord.media/", "Its terms page gave 404 or was not found"),
        ("news_securityweek", "https://www.securityweek.com/", "Its terms page gave 404 or was not found"),
        ("news_darkreading", "https://www.darkreading.com/", "Informa's terms for Dark Reading were not found"),
        ("news_helpnetsecurity", "https://www.helpnetsecurity.com/", ""), ("news_cyberscoop", "https://cyberscoop.com/", ""),
        ("news_talos", "https://blog.talosintelligence.com/", ""), ("news_unit42", "https://unit42.paloaltonetworks.com/", ""),
        ("news_mstic", "https://www.microsoft.com/en-us/security/blog/", ""), ("news_eset", "https://www.welivesecurity.com/", ""),
        ("news_elastic", "https://www.elastic.co/security-labs", "")):
    TERMS_REVIEW[_sid] = dict(url=_home, comm="no", redist="no", ai="unclear",
                              text=_NEWS + (f". {_extra}" if _extra else "") + ". On by default for personal use")


def terms_section(sid: str) -> str:
    t = TERMS_REVIEW.get(sid)
    if not t:   # a hand-written page (HAND_WRITTEN) carries its own terms section
        return ""
    return (f"# Terms\n\nRead {TERMS_READ} ([terms]({t['url']})): {t['text']}.\n\n"
            f"Commercial use: {t['comm']}. Redistribution: {t['redist']}. AI use: {t['ai']}.\n")


def status_line(sid: str, src, m: dict) -> str:
    """The page's "Status in Night Desk": the code default, and for an `ask` source what the first-run box does."""
    from osinthub import feed_terms
    from osinthub.scheduler import TERMS_OFFS
    if src.withheld:   # before any hand-written status: it overrides every default
        return ("left out of the pre-alpha (`withheld` in the source class): never started, not offered in the first-run "
                "\"Choose your sources\" box, and Sources says why: " + src.withheld)
    if m.get("status"):
        return m["status"]
    if src.default_enabled:
        return "on by default"
    if sid in TERMS_OFFS:
        return ("off by default (since the 2026-11-19 terms review): unticked in the first-run \"Choose your sources\" "
                "box and never fetched before the user turns it on. An install that ran it before and answered that box "
                "with Keep, or was never offered it, keeps it on (`TERMS_OFFS` in osinthub/scheduler.py)")
    if feed_terms.row(sid)["local_default"] == "ask":
        return "off by default; unticked in the first-run \"Choose your sources\" box"
    return "off by default"


# Source pages maintained by hand (their design notes do not fit the template); listed in the indexes only.
HAND_WRITTEN = {"epss", "cisa_advisories", "ris_live"}

# Index line and catalog row (after the name) of the routing-watch sources, whose pages are hand-written: the wording
# of those pages, not the in-app registry text. rpki_roas, cf_radar_bgp and ripestat have no MEASURED entry (their
# storage is tiny and per watchlist). "after": listed right after that source, so the routing sources stay together.
HAND_ENTRIES = {
    "ris_live": dict(index="Live BGP updates for the routing watchlist only. Off by default (Advanced); never connects without a watchlist.",
                     row="advanced | stream | A | none | off (watchlist only) | — |"),
    "rpki_roas": dict(after="ris_live",
                      index="The daily validated-ROA file, filtered locally to the routing watchlist. No stated terms: off until the user says yes.",
                      row="infra | batch | A | none | off (ask); Routing watch asks | small (watched ROAs only) |"),
    "cf_radar_bgp": dict(after="rpki_roas",
                         index="Recent hijack and leak events, listed without naming a network and matched locally. Needs the user's own token; CC BY-NC 4.0.",
                         row="infra | batch | B | own token | on with a token | small (matched events only) |"),
    "ripestat": dict(after="cf_radar_bgp",
                     index="Origins, visibility, upstreams and update counts per watched network. Off by default: RIPE sees the lookups.",
                     row="infra | batch | A | none | off (opt-in) | small |"),
}
CATALOG_AT = "2026-11-20T03:00:00Z"   # generated.at of the catalog pages (last changed by a regeneration)
STORAGE_AT = "2026-11-19T20:00:00Z"   # generated.at of the storage page
WRITTEN: list[Path] = []              # every file this run wrote (in --check mode: rendered)
DRIFT: list[Path] = []                # --check: pages that differ from the generator's output, or are missing
CHECK = False


def missing_inputs(sources=None) -> list[str]:
    """Registry sources with neither a MEASURED entry (a generated page) nor a HAND_ENTRIES entry (a hand-written
    page's index line and catalog row): the generator cannot describe them."""
    return [sid for sid in (SOURCES if sources is None else sources) if sid not in MEASURED and sid not in HAND_ENTRIES]


def ordered_sources() -> list:
    """SOURCES in registry order, each HAND_ENTRIES source with an "after" moved right behind that source."""
    moved = {sid: e["after"] for sid, e in HAND_ENTRIES.items() if e.get("after") in SOURCES}
    out = [(sid, s) for sid, s in SOURCES.items() if sid not in moved]
    for sid, anchor in moved.items():
        if sid in SOURCES:
            i = next(i for i, (k, _) in enumerate(out) if k == anchor)
            out.insert(i + 1, (sid, SOURCES[sid]))
    return out


def current_docs(only: set[str] | None = None) -> list[tuple[str, str, str]]:
    """Write the current-source pages (`only`: just these ids). A source with no MEASURED entry (the routing
    sources) has a hand-written page: it is listed in the indexes only."""
    rows = []
    for sid, src in ordered_sources():
        if sid not in MEASURED:
            rows.append((sid, src.name, HAND_ENTRIES.get(sid, {}).get("index", src.description)))
            continue
        m = MEASURED[sid]
        d = src.describe()
        lake_raw = lake_mb_per_day(sid, src)
        lake = lake_raw * m["kept"]
        dbd = db_mb_per_day(sid)
        enabled = "left out of this release" if src.withheld else "on by default" if src.default_enabled else "off by default"
        status = status_line(sid, src, m)
        measured = "estimated" if m.get("est") else "measured 2026-11-04"
        size_rows = "\n".join(
            f"| {label} | {gb(lake * days)} | {gb(dbd * days)} |" for label, days in HORIZONS)
        per_run = (f"{m['raw_kb']:,} KB raw + {m['ev_kb']:,} KB normalised per run ({measured})"
                   if "raw_kb" in m else f"{m['per_day_mb']} MB of normalised events per day ({measured})")
        body = f"""---
type: Data Source
title: {yaml_str(d['name'])}
description: {yaml_str(d['description'])}
resource: {d['homepage'] or 'n/a'}
tags: [{d['category']}, {d['mode']}, current]
provider: {yaml_str(d['provider'])}
mode: {d['mode']}
cadence: {yaml_str(human_interval(d['interval']))}
trust_tier: {m['trust']}
auth: {yaml_str(m['auth'])}
license: {yaml_str(d['license'] or 'see provider terms')}
in_app: {enabled}
{GEN.replace(NOW, max(m.get('gen_at', NOW), TERMS_AT))}
---

# Summary

{d['description']}

| | |
|---|---|
| Source id | `{sid}` |
| Provider | {d['provider']} |
| Mode | {d['mode']} ({human_interval(d['interval'])}) |
| Trust tier | {m['trust']}: {TRUST[m['trust']]} |
| Access | {m['auth']} |
| License | {d['license'] or 'see provider terms'} |
| Status in Night Desk | {status} |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: {m['corroborates']}.

{terms_section(sid)}{('' if not m.get('note') else chr(10) + m['note'] + chr(10))}
# Storage

{per_run}, or {lake_raw:,.1f} MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves {m['kept'] * 100:.2f}% of it ({lake:,.2f} MB/day, measured). DuckDB grows only by new unique events (about {m['new_rows']:,} per day at {ROW_BYTES} bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
{size_rows}

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
"""
        if sid not in HAND_WRITTEN and (only is None or sid in only):
            write(OKF / "sources" / "current" / f"{sid}.md", body)
        rows.append((sid, d["name"], HAND_ENTRIES.get(sid, {}).get("index", d["description"])))
    return rows


# --------------------------------------------------------------------------- candidates
# probe: HTTP result with the app's User-Agent on 2026-11-04 ("200", "403", "key", ...). kb: payload per fetch.
# runs: suggested fetches per day. rows: estimated new unique events per day.
CANDIDATES = {
    "vulnerabilities": ("Vulnerabilities and exploitation", [
        dict(name="CVE List V5 (CVE.org)", provider="CVE Program / MITRE", url="https://github.com/CVEProject/cvelistV5", trust="A", auth="none", probe="200", kb=37071, runs=4, rows=150,
             why="Authoritative CVE records, published before NVD enrichment; use deltaLog.json for incremental pulls.", overlap="NVD", sizing="delta log is 37 MB; the incremental delta files are a few hundred KB per pull", kb_effective=600),
        dict(name="CISA Vulnrichment", provider="CISA", url="https://github.com/cisagov/vulnrichment", trust="A", auth="none", probe="200", kb=500, runs=4, rows=150,
             why="CISA's SSVC decisions and CWE/CVSS added to new CVEs.", overlap="NVD, CVE List"),
        dict(name="ENISA EU Vulnerability Database (EUVD)", provider="ENISA", url="https://euvd.enisa.europa.eu/", trust="A", auth="none", probe="200", kb=5, runs=24, rows=60,
             why="EU's official vulnerability database with its own exploited list; independent of NVD.", overlap="KEV, NVD"),
        dict(name="GitHub Advisory Database", provider="GitHub", url="https://github.com/github/advisory-database", trust="B", auth="none (git) / free token (API)", probe="200", kb=800, runs=4, rows=60,
             why="Package-level advisories with affected version ranges.", overlap="OSV, NVD"),
        dict(name="OSV.dev", provider="Google Open Source Security", url="https://osv.dev/", trust="B", auth="none", probe="200", kb=157800, runs=1, rows=200,
             why="Aggregates GHSA, PyPA, Go, RustSec and distro advisories in one schema.", overlap="GHSA, NVD", sizing="modified_id.csv is 158 MB; pull only changed IDs (a few MB/day)", kb_effective=4000),
        dict(name="Exploit-DB", provider="OffSec", url="https://gitlab.com/exploit-database/exploitdb", trust="B", auth="none", probe="200", kb=10185, runs=1, rows=5,
             why="Public exploit code mapped to CVEs; a strong 'weaponised' signal.", overlap="Metasploit, Nuclei"),
        dict(name="Metasploit module metadata", provider="Rapid7", url="https://github.com/rapid7/metasploit-framework", trust="B", auth="none", probe="200", kb=11413, runs=1, rows=3,
             why="CVEs with a ready-made Metasploit module.", overlap="Exploit-DB, Nuclei"),
        dict(name="Nuclei templates (CVE index)", provider="ProjectDiscovery", url="https://github.com/projectdiscovery/nuclei-templates", trust="C", auth="none", probe="200", kb=2290, runs=1, rows=5,
             why="CVEs with a public mass-scanning template; predicts scanning waves.", overlap="Exploit-DB"),
        dict(name="Project Zero 0day In-the-Wild", provider="Google Project Zero", url="https://googleprojectzero.blogspot.com/p/0day.html", trust="A", auth="none", probe="200", kb=60, runs=1, rows=0.2,
             why="Curated list of zero-days exploited in the wild, with root cause analysis.", overlap="KEV"),
        dict(name="CERT/CC Vulnerability Notes", provider="CERT/CC (Carnegie Mellon SEI)", url="https://kb.cert.org/vuls/", trust="A", auth="none", probe="200", kb=192, runs=4, rows=1,
             why="Coordinated disclosures, often multi-vendor.", overlap="NVD"),
        dict(name="MSRC security update guide (CVRF)", provider="Microsoft", url="https://api.msrc.microsoft.com/cvrf/v3.0/", trust="A", auth="none", probe="200", kb=51, runs=4, rows=4,
             why="Microsoft's own CVE and exploitation-status data for Patch Tuesday and out-of-band fixes.", overlap="NVD, KEV"),
        dict(name="JVN iPedia", provider="JPCERT/CC and IPA (Japan)", url="https://jvndb.jvn.jp/en/", trust="A", auth="none", probe="503 (retry)", kb=60, runs=4, rows=20,
             why="Japanese national vulnerability database; covers Asian vendors NVD misses.", overlap="NVD"),
        dict(name="VulnCheck KEV", provider="VulnCheck", url="https://vulncheck.com/kev", trust="B", auth="free community key", probe="key", kb=8000, runs=1, rows=5,
             why="Larger exploited-vulnerability list than CISA KEV, with exploitation evidence links.", overlap="CISA KEV"),
    ]),
    "threat-infrastructure": ("Threat infrastructure and indicators", [
        dict(name="IPsum", provider="stamparm (Miroslav Štampar)", url="https://github.com/stamparm/ipsum", trust="C", auth="none", probe="200", kb=2254, runs=1, rows=20000,
             why="Daily list of about 140k IPs scored by how many of 30+ blocklists include them. Built-in corroboration count.", overlap="all IP lists"),
        dict(name="FireHOL level 1-3", provider="FireHOL", url="https://github.com/firehol/blocklist-ipsets", trust="C", auth="none", probe="200", kb=225, runs=4, rows=500,
             why="Curated aggregate netsets with low false-positive levels.", overlap="Spamhaus, DShield, Feodo"),
        dict(name="Spamhaus DROP v6 and ASN-DROP", provider="Spamhaus", url="https://www.spamhaus.org/blocklists/do-not-route-or-peer/", trust="A", auth="none", probe="200", kb=46, runs=2, rows=2,
             why="Adds IPv6 hijacked ranges and whole criminal ASNs to the DROP list we already ingest.", overlap="Spamhaus DROP"),
        dict(name="SANS ISC intel feed", provider="SANS Internet Storm Center", url="https://isc.sans.edu/api/", trust="B", auth="none", probe="200", kb=5950, runs=1, rows=3000,
             why="112k IPs tagged by category (miner, scanner, research...); explains what an IP is.", overlap="DShield"),
        dict(name="SANS ISC research scanners", provider="SANS Internet Storm Center", url="https://isc.sans.edu/api/", trust="B", auth="none", probe="200", kb=1388, runs=1, rows=50,
             why="Known benign research scanners (Shodan, Censys...) to suppress false positives.", overlap="GreyNoise benign"),
        dict(name="DShield top /24 blocks", provider="SANS Internet Storm Center", url="https://feeds.dshield.org/block.txt", trust="B", auth="none", probe="200", kb=2, runs=24, rows=5,
             why="The 20 most aggressive /24 networks right now.", overlap="DShield top IPs"),
        dict(name="abuse.ch MalwareBazaar", provider="abuse.ch", url="https://bazaar.abuse.ch/", trust="B", auth="free Auth-Key", probe="key (410 without)", kb=800, runs=4, rows=1000,
             why="New malware samples with family, tags and delivery.", overlap="ThreatFox"),
        dict(name="Feodo Tracker aggressive list", provider="abuse.ch", url="https://feodotracker.abuse.ch/", trust="B", auth="none", probe="200", kb=623, runs=4, rows=20,
             why="Historic C2s as well as current ones; context for the 5-IP live list.", overlap="Feodo C2"),
        dict(name="C2IntelFeeds", provider="drb-ra (community, Censys-derived)", url="https://github.com/drb-ra/C2IntelFeeds", trust="C", auth="none", probe="200", kb=9, runs=4, rows=30,
             why="Cobalt Strike and other C2 servers found by internet-wide scanning.", overlap="ThreatView C2"),
        dict(name="ThreatView.io feeds", provider="ThreatView", url="https://threatview.io/", trust="C", auth="none", probe="200", kb=405, runs=1, rows=500,
             why="High-confidence malicious IPs and Cobalt Strike C2s.", overlap="C2IntelFeeds, IPsum"),
        dict(name="Emerging Threats block IPs", provider="Proofpoint ET", url="https://rules.emergingthreats.net/fwrules/", trust="B", auth="none", probe="200", kb=30, runs=4, rows=20,
             why="ET's firewall block list (includes DROP and DShield top).", overlap="ET compromised, Spamhaus"),
        dict(name="Binary Defense banlist", provider="Binary Defense", url="https://www.binarydefense.com/banlist.txt", trust="C", auth="none", probe="200", kb=11, runs=4, rows=50,
             why="Artillery honeypot attackers.", overlap="blocklist.de, DShield"),
        dict(name="CIRCL OSINT MISP feed", provider="CIRCL (Luxembourg national CERT)", url="https://www.circl.lu/doc/misp/feed-osint/", trust="A", auth="none", probe="200", kb=1429, runs=4, rows=200,
             why="Analyst-curated MISP events with IOCs from public reports.", overlap="Botvrij, vendor research"),
        dict(name="Botvrij.eu MISP feed", provider="Botvrij.eu", url="https://www.botvrij.eu/", trust="C", auth="none", probe="200", kb=353, runs=4, rows=50,
             why="IOCs extracted from public threat reports, in MISP format.", overlap="CIRCL OSINT"),
        dict(name="OpenPhish community feed", provider="OpenPhish", url="https://github.com/openphish/public_feed", trust="B", auth="none", probe="200", kb=17, runs=12, rows=300,
             why="Live phishing URLs (now published on GitHub).", overlap="Phishing.Database, URLhaus"),
        dict(name="Tweetfeed", provider="Tweetfeed.live (community)", url="https://tweetfeed.live/", trust="D", auth="none", probe="200", kb=49, runs=24, rows=180,
             why="IOCs shared by researchers on X, extracted automatically.", overlap="ThreatFox"),
        dict(name="AlienVault OTX", provider="LevelBlue (AT&T Cybersecurity)", url="https://otx.alienvault.com/", trust="C", auth="free key", probe="key", kb=300, runs=24, rows=3000,
             why="Large community 'pulses' of IOCs grouped by campaign.", overlap="ThreatFox, MISP feeds"),
        dict(name="AbuseIPDB blacklist", provider="AbuseIPDB", url="https://www.abuseipdb.com/", trust="C", auth="free key (10k IPs/day list)", probe="key", kb=400, runs=1, rows=3000,
             why="Crowd-reported abusive IPs with confidence scores.", overlap="DShield, blocklist.de"),
        dict(name="GreyNoise community API", provider="GreyNoise", url="https://www.greynoise.io/", trust="B", auth="free key (lookups only)", probe="key", kb=1, runs=500, rows=0,
             why="Tells mass scanners and benign crawlers apart from targeted traffic. Best used to enrich IPs, not as a feed.", overlap="SANS research scanners"),
        dict(name="Shadowserver reports", provider="The Shadowserver Foundation", url="https://www.shadowserver.org/", trust="A", auth="vetted registration (free for network owners/CERTs)", probe="registration", kb=20000, runs=1, rows=5000,
             why="Exposure, compromise and honeypot data from one of the largest scanning nonprofits.", overlap="DShield, GreyNoise"),
    ]),
    "ransomware": ("Ransomware and extortion", [
        dict(name="RansomLook", provider="RansomLook.io (open source, AGPL)", url="https://www.ransomlook.io/", trust="C", auth="none", probe="200", kb=69, runs=48, rows=40,
             why="Open API of leak-site posts and group profiles. Live, unlike ransomwatch. Drop-in for the blocked ransomware.live feed.", overlap="ransomware.live"),
        dict(name="ransomware.live PRO API", provider="ransomware.live", url="https://www.ransomware.live/", trust="C", auth="paid key", probe="403/404 (public)", kb=120, runs=48, rows=40,
             why="The richer victim feed, including sector and country, once API access is arranged.", overlap="RansomLook"),
        dict(name="ransomwatch", provider="joshhighet", url="https://github.com/joshhighet/ransomwatch", trust="C", auth="none", probe="200 but stale (last post 2025-06-16)", kb=2288, runs=0, rows=0,
             why="Historical leak-site posts only; no longer updated. Useful once for backfill.", overlap="RansomLook"),
        dict(name="DataBreaches.net", provider="DataBreaches.net", url="https://databreaches.net/", trust="C", auth="none", probe="200", kb=15, runs=12, rows=10,
             why="Journalist-verified breach and extortion reporting; confirms leak-site claims.", overlap="RansomLook, news"),
        dict(name="HHS OCR breach portal", provider="US Department of Health and Human Services", url="https://ocrportal.hhs.gov/ocr/breach/", trust="A", auth="none (form-based export)", probe="200", kb=500, runs=1, rows=2,
             why="Legally required US healthcare breach notices; ground truth for healthcare ransomware.", overlap="RansomLook"),
        dict(name="Have I Been Pwned breach list", provider="Troy Hunt / HIBP", url="https://haveibeenpwned.com/API/v3", trust="B", auth="none (breach list endpoint)", probe="200", kb=1130, runs=1, rows=1,
             why="Verified data breaches with record counts and data classes.", overlap="DataBreaches.net"),
    ]),
    "internet-infrastructure": ("Internet infrastructure, routing and outages", [
        dict(name="Cloudflare Radar API", provider="Cloudflare", url="https://radar.cloudflare.com/", trust="B", auth="free API token", probe="key (400 without)", kb=300, runs=96, rows=200,
             why="Outages, DDoS attack trends (L3/L7), BGP hijacks and route leaks, traffic anomalies by country/ASN. The main missing DDoS source.", overlap="IODA, RIS Live"),
        dict(name="IODA raw signals", provider="Georgia Tech IODA", url="https://ioda.inetintel.cc.gatech.edu/", trust="B", auth="none", probe="200", kb=13, runs=96, rows=0,
             why="The underlying BGP, active-probe and telescope time series for each country; chartable context for outage events.", overlap="IODA outages"),
        dict(name="GRIP BGP hijack detection", provider="Georgia Tech INET", url="https://grip.inetintel.cc.gatech.edu/", trust="B", auth="restricted (403 to automated clients)", probe="403", kb=200, runs=24, rows=50,
             why="Classified hijack/leak events with confidence; would corroborate our own origin-change detector.", overlap="RIS Live, Cloudflare Radar"),
        dict(name="RIPEstat Data API", provider="RIPE NCC", url="https://stat.ripe.net/docs/data_api", trust="A", auth="none", probe="200", kb=5, runs=2000, rows=0,
             why="On-demand routing history, visibility and RIR data for any prefix/ASN; enrichment for BGP events.", overlap="RIS Live"),
        dict(name="RIPE Atlas", provider="RIPE NCC", url="https://atlas.ripe.net/", trust="A", auth="none for public results", probe="not probed", kb=500, runs=24, rows=100,
             why="Latency/reachability measurements from 12k+ probes; confirms outages independently of BGP.", overlap="IODA"),
        dict(name="RouteViews", provider="University of Oregon", url="https://www.routeviews.org/", trust="A", auth="none", probe="not probed", kb=200000, runs=4, rows=0,
             why="Second independent BGP collector network (MRT dumps); corroborates RIS.", overlap="RIS Live", sizing="full update dumps are large; keep only derived events", kb_effective=0),
        dict(name="PeeringDB", provider="PeeringDB", url="https://www.peeringdb.com/", trust="B", auth="none", probe="200", kb=30000, runs=0.14, rows=0,
             why="Who operates each ASN, IXPs and facilities; reference data for naming networks.", overlap="CAIDA AS Rank"),
        dict(name="CAIDA AS Rank", provider="CAIDA (UC San Diego)", url="https://asrank.caida.org/", trust="A", auth="none", probe="200", kb=1, runs=500, rows=0,
             why="ASN size, rank and relationships; lets the map weight impact by network size.", overlap="PeeringDB"),
        dict(name="RIR delegation files", provider="ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC", url="https://ftp.arin.net/pub/stats/", trust="A", auth="none", probe="200", kb=60000, runs=0.14, rows=0,
             why="Which country/registry each block and ASN is delegated to; ground truth for 'whose network'.", overlap="DB-IP"),
        dict(name="Tor Onionoo", provider="The Tor Project", url="https://metrics.torproject.org/onionoo.html", trust="A", auth="none", probe="200", kb=15000, runs=1, rows=50,
             why="Full relay details (flags, bandwidth, families), beyond the exit list.", overlap="Tor exits"),
        dict(name="Certificate Transparency (crt.sh / CT logs)", provider="Sectigo crt.sh, Google CT log list", url="https://crt.sh/", trust="A", auth="none", probe="crt.sh timeout; log list 200", kb=65, runs=1, rows=0,
             why="New certificates for watched domains (phishing look-alikes). Query per watched domain, not as a firehose.", overlap="CertStream (down)"),
    ]),
    "advisories": ("Government and vendor advisories", [
        dict(name="NCSC UK", provider="UK National Cyber Security Centre", url="https://www.ncsc.gov.uk/", trust="A", auth="none", probe="200", kb=11, runs=12, rows=2,
             why="UK government alerts and guidance.", overlap="CISA, CERT-EU"),
        dict(name="CERT-EU security advisories", provider="CERT-EU", url="https://cert.europa.eu/publications/security-advisories", trust="A", auth="none", probe="200", kb=10, runs=12, rows=2,
             why="EU institutions' CERT; high-signal advisories.", overlap="CISA, NCSC UK"),
        dict(name="CERT-FR (ANSSI)", provider="ANSSI, France", url="https://www.cert.ssi.gouv.fr/", trust="A", auth="none", probe="200", kb=23, runs=12, rows=5,
             why="French national alerts and advisories.", overlap="CERT-EU, BSI"),
        dict(name="BSI CERT-Bund WID", provider="BSI, Germany", url="https://wid.cert-bund.de/", trust="A", auth="none", probe="200", kb=135, runs=12, rows=30,
             why="German federal advisories with severity ratings.", overlap="CERT-FR"),
        dict(name="Canadian Centre for Cyber Security", provider="CCCS, Canada", url="https://www.cyber.gc.ca/", trust="A", auth="none", probe="200", kb=155, runs=12, rows=5,
             why="Canadian national alerts and vendor advisory roundups.", overlap="CISA"),
        dict(name="JPCERT/CC", provider="JPCERT/CC, Japan", url="https://www.jpcert.or.jp/english/", trust="A", auth="none", probe="200", kb=3, runs=4, rows=1,
             why="Japanese national alerts.", overlap="JVN"),
        dict(name="ACSC (Australia)", provider="Australian Signals Directorate", url="https://www.cyber.gov.au/", trust="A", auth="none", probe="timeout (retry)", kb=20, runs=12, rows=2,
             why="Australian national alerts.", overlap="CISA"),
        dict(name="Cisco PSIRT", provider="Cisco", url="https://sec.cloudapps.cisco.com/security/center/publicationListing.x", trust="A", auth="none (RSS) / free key (openVuln API)", probe="200", kb=147, runs=4, rows=3,
             why="First-party advisories for the most-targeted network vendor.", overlap="NVD, KEV"),
        dict(name="Fortinet PSIRT", provider="Fortinet", url="https://www.fortiguard.com/psirt", trust="A", auth="none", probe="200", kb=49, runs=4, rows=2,
             why="First-party advisories; Fortinet bugs are KEV regulars.", overlap="NVD, KEV"),
        dict(name="Palo Alto Networks advisories", provider="Palo Alto Networks", url="https://security.paloaltonetworks.com/", trust="A", auth="none", probe="200", kb=8, runs=4, rows=1,
             why="First-party advisories for PAN-OS and Prisma.", overlap="NVD, KEV"),
        dict(name="MITRE ATT&CK (STIX)", provider="MITRE", url="https://github.com/mitre-attack/attack-stix-data", trust="A", auth="none", probe="200", kb=55271, runs=0.03, rows=0,
             why="Reference taxonomy of techniques, groups and software; tags events with TTPs.", overlap="Malpedia"),
        dict(name="Malpedia", provider="Fraunhofer FKIE", url="https://malpedia.caad.fkie.fraunhofer.de/", trust="B", auth="none (families list)", probe="200", kb=60, runs=1, rows=0,
             why="Reference names and aliases for malware families; normalises ThreatFox/Feodo family names.", overlap="ATT&CK"),
    ]),
    "research-and-news": ("Research blogs and news", [
        dict(name="The Record (Recorded Future News)", provider="Recorded Future", url="https://therecord.media/", trust="B", auth="none", probe="200; added as news_therecord", kb=6, runs=72, rows=15,
             why="Dedicated cyber newsroom with named sources.", overlap="BleepingComputer, SecurityWeek"),
        dict(name="SecurityWeek", provider="SecurityWeek", url="https://www.securityweek.com/", trust="B", auth="none", probe="200; added as news_securityweek", kb=13, runs=72, rows=20,
             why="Broad vulnerability and incident coverage.", overlap="The Hacker News"),
        dict(name="Dark Reading", provider="Informa TechTarget", url="https://www.darkreading.com/", trust="B", auth="none", probe="200; added as news_darkreading", kb=78, runs=72, rows=15,
             why="Industry news and analysis.", overlap="SecurityWeek"),
        dict(name="Help Net Security", provider="Help Net Security", url="https://www.helpnetsecurity.com/", trust="B", auth="none", probe="200; added as news_helpnetsecurity", kb=18, runs=72, rows=15,
             why="Daily vulnerability and product security news.", overlap="SecurityWeek"),
        dict(name="CyberScoop", provider="Scoop News Group", url="https://cyberscoop.com/", trust="B", auth="none", probe="200; added as news_cyberscoop", kb=66, runs=72, rows=8,
             why="Policy, government and nation-state reporting.", overlap="The Record"),
        dict(name="Cisco Talos blog", provider="Cisco Talos", url="https://blog.talosintelligence.com/", trust="B", auth="none", probe="200; added as news_talos", kb=1026, runs=12, rows=1,
             why="Primary threat research with IOCs.", overlap="Unit 42, GTIG"),
        dict(name="Unit 42", provider="Palo Alto Networks", url="https://unit42.paloaltonetworks.com/", trust="B", auth="none", probe="200; added as news_unit42", kb=24, runs=12, rows=1,
             why="Primary threat research with IOCs.", overlap="Talos"),
        dict(name="Google Threat Intelligence Group blog", provider="Google (Mandiant + TAG)", url="https://cloud.google.com/blog/topics/threat-intelligence", trust="B", auth="none", probe="200 (HTML at feed URL; needs correct feed path)", kb=190, runs=12, rows=1,
             why="Nation-state and zero-day research.", overlap="Microsoft Threat Intelligence"),
        dict(name="Microsoft Threat Intelligence blog", provider="Microsoft", url="https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/", trust="B", auth="none", probe="200; added as news_mstic", kb=494, runs=12, rows=1,
             why="Actor tracking (Storm-xxxx, Typhoon...) and campaign reports.", overlap="GTIG"),
        dict(name="ESET Research (WeLiveSecurity)", provider="ESET", url="https://www.welivesecurity.com/en/eset-research/", trust="B", auth="none", probe="200; added as news_eset", kb=70, runs=12, rows=3,
             why="APT and malware research, strong on Eastern Europe.", overlap="Talos, Check Point Research"),
        dict(name="Elastic Security Labs", provider="Elastic", url="https://www.elastic.co/security-labs/", trust="B", auth="none", probe="200; added as news_elastic", kb=8415, runs=4, rows=1,
             why="Malware and detection-engineering research.", overlap="Talos, Unit 42"),
        dict(name="Check Point Research", provider="Check Point Software", url="https://research.checkpoint.com/", trust="B", auth="none", probe="202 AWS WAF challenge (blocks automated clients); skipped", kb=275, runs=0, rows=0,
             why="Primary threat research; off until it serves automated clients.", overlap="ESET, Talos"),
        dict(name="SentinelLabs", provider="SentinelOne", url="https://www.sentinelone.com/labs/", trust="B", auth="none", probe="feed 200, articles 429 Vercel Security Checkpoint; skipped", kb=241, runs=0, rows=0,
             why="Primary threat research; article pages sit behind a bot check.", overlap="Unit 42"),
        dict(name="Securelist (Kaspersky)", provider="Kaspersky", url="https://securelist.com/", trust="B", auth="none", probe="connection refused; skipped", kb=0, runs=0, rows=0,
             why="APT research; unreachable from this network.", overlap="ESET"),
        dict(name="Sophos X-Ops", provider="Sophos", url="https://news.sophos.com/en-us/category/threat-research/", trust="B", auth="none", probe="timeout (30 s); skipped", kb=0, runs=0, rows=0,
             why="Threat research; feed timed out on every probe.", overlap="Talos"),
        dict(name="MSRC blog", provider="Microsoft", url="https://msrc.microsoft.com/blog/", trust="A", auth="none", probe="200 (HTML; RSS path changed)", kb=93, runs=4, rows=0.3,
             why="Microsoft's incident disclosures.", overlap="MSRC CVRF"),
    ]),
    "social": ("Social and community signal", [
        dict(name="Mastodon (infosec.exchange)", provider="infosec.exchange", url="https://infosec.exchange/", trust="D", auth="free account token (public tag timelines disabled)", probe="422 without token", kb=60, runs=288, rows=300,
             why="Where much of the infosec community moved; hashtag timelines (#cve, #threatintel).", overlap="Bluesky"),
        dict(name="Reddit r/netsec", provider="Reddit", url="https://www.reddit.com/r/netsec/", trust="D", auth="none (RSS)", probe="200", kb=38, runs=48, rows=15,
             why="Curated technical research links.", overlap="Hacker News"),
        dict(name="Hacker News (Algolia API)", provider="Y Combinator / Algolia", url="https://hn.algolia.com/api", trust="D", auth="none", probe="200", kb=29, runs=48, rows=20,
             why="Early discussion of major vulnerabilities and outages.", overlap="Reddit"),
    ]),
}

CAT_DESC = {
    "vulnerabilities": "Candidate feeds for CVEs, exploitation evidence and exploit availability.",
    "threat-infrastructure": "Candidate feeds of malicious IPs, C2 servers, URLs and IOCs, plus enrichment services.",
    "ransomware": "Candidate feeds of ransomware leak-site posts and verified breach disclosures.",
    "internet-infrastructure": "Candidate feeds for routing, outages, DDoS and reference data about networks.",
    "advisories": "Candidate government CERT and vendor PSIRT advisory feeds, plus reference taxonomies.",
    "research-and-news": "Candidate newsroom and vendor research feeds.",
    "social": "Candidate community and social channels for early signal.",
}


def cand_lake_mb_day(c: dict) -> float:
    kb = c.get("kb_effective", c["kb"])
    return kb * c["runs"] * 2 / 1000  # raw + normalised NDJSON (~1x raw on average for these formats)


def cand_db_mb_day(c: dict) -> float:
    return c["rows"] * ROW_BYTES / 1e6


def candidate_docs() -> list[tuple[str, str, str, float, float, int]]:
    out = []
    for slug, (title, items) in CANDIDATES.items():
        lines = []
        for c in items:
            lake = cand_lake_mb_day(c); dbd = cand_db_mb_day(c)
            lines.append(
                f"| [{c['name']}]({c['url']}) | {c['provider']} | {c['trust']} | {c['auth']} | {c['probe']} | "
                f"{c['kb']:,} KB | {c['runs'] if c['runs'] >= 1 else '≤1'} | {lake:,.1f} MB | {gb(lake * 365)} | {gb(dbd * 365)} | {c['why']} | {c['overlap']} |")
        notes = [f"* **{c['name']}**: {c['sizing']}." for c in items if c.get("sizing")]
        lake_total = sum(cand_lake_mb_day(c) for c in items)
        db_total = sum(cand_db_mb_day(c) for c in items)
        body = f"""---
type: Source Candidates
title: {yaml_str('Candidate sources: ' + title)}
description: {yaml_str(CAT_DESC[slug])}
tags: [sources, candidates, {slug}]
status: draft
{GEN}
---

# Candidates

Probe = HTTP result fetching the feed with Night Desk's own User-Agent on 2026-11-04 ("key" means it needs a free or paid key and was not fetched). Size per fetch is measured where probed and estimated otherwise. Runs/day is a suggested cadence. Lake/day counts raw plus normalised copies of every fetch; the 1-year columns assume that cadence with no compression. Trust tiers are defined in [trust model](/sources/trust-model.md).

| Source | Provider | Trust | Access | Probe | Size/fetch | Runs/day | Lake/day | Lake 1y | DuckDB 1y | Why add it | Corroborates |
|---|---|---|---|---|---|---|---|---|---|---|---|
{chr(10).join(lines)}

Category total if all were added at the suggested cadence: about {lake_total:,.0f} MB/day in the lake ({gb(lake_total * 365)}/year uncompressed) and {db_total:,.1f} MB/day in DuckDB.
{(chr(10) + '# Sizing notes' + chr(10) + chr(10) + chr(10).join(notes) + chr(10)) if notes else ''}"""
        write(OKF / "sources" / "candidates" / f"{slug}.md", body)
        out.append((slug, title, CAT_DESC[slug], lake_total, db_total, len(items)))
    return out


def storage_doc(cand_summary) -> None:
    now_mb = lambda sid, s: lake_mb_per_day(sid, s) * MEASURED[sid]["kept"]
    measured = {sid: s for sid, s in SOURCES.items() if sid in MEASURED}
    old_lake = sum(lake_mb_per_day(sid, s) for sid, s in measured.items() if s.default_enabled)
    cur_lake = sum(now_mb(sid, s) for sid, s in measured.items() if s.default_enabled)
    cur_db = sum(db_mb_per_day(sid) for sid, s in measured.items() if s.default_enabled)
    rows = []
    for sid, s in sorted(measured.items(), key=lambda kv: -now_mb(*kv) - db_mb_per_day(kv[0])):
        lake, dbd = now_mb(sid, s), db_mb_per_day(sid)
        rows.append(f"| [{s.name}](/sources/current/{sid}.md) | {'on' if s.default_enabled else 'off'} | {human_interval(s.interval)} | "
                    f"{lake_mb_per_day(sid, s):,.1f} MB | {lake:,.2f} MB | {dbd:,.2f} MB | " + " | ".join(gb((lake + dbd) * d) for _, d in HORIZONS) + " |")
    cand_lake = sum(x[3] for x in cand_summary)
    cand_db = sum(x[4] for x in cand_summary)
    tot = lambda lake, dbd, f=1.0: " | ".join(gb((lake * f + dbd) * d) for _, d in HORIZONS)
    body = f"""---
type: Analysis
title: Storage estimates
description: Disk needed to keep current and candidate sources locally for 30 days, 90 days, 1 year and 3 years, measured with gzipped record and event deltas.
tags: [storage, capacity, data-lake, duckdb]
{GEN.replace(NOW, STORAGE_AT)}
stale_after: 2027-02-01T00:00:00Z
---

# Method

* **Uncompressed lake** growth per source = fetches per day × (raw payload + normalised NDJSON), from files written to the owner's live lake (`<lake>/raw`) over the first 8.5 hours of running (2026-11-04). Streams use their measured bytes per day.
* **As built** applies each source's measured *kept* fraction. The lake's first 12 hours of history were replayed through the same record and event comparison the scheduler uses, counting only the gzipped new, changed and removed records. Streams use hourly gzip files. The first full load of each source is a one-time cost of a few MB and is excluded. See [data architecture](/data/architecture.md#what-the-lake-stores).
* **DuckDB** growth = new unique events per day × {ROW_BYTES} bytes per row (measured after `CHECKPOINT`: 22,788 rows in 13.9 MB). Repeat sightings of the same IP, CVE or prefix update the row in place, so snapshot feeds grow the database far more slowly than the lake.
* Candidates have no history yet, so they are counted at 10× gzip with every fetch assumed to change completely. Current sources came in 10-2000× lower than that, so this is a deliberately high bound.
* Reference data (GeoIP, ASN, cables, countries) is a fixed ~138 MB and is not included below.

# Current sources

| Source | In app | Cadence | Lake/day uncompressed | Lake/day as built | DuckDB/day | 30 days | 90 days | 1 year | 3 years |
|---|---|---|---|---|---|---|---|---|---|
{chr(10).join(rows)}

Retention columns are as built (lake + DuckDB). **Enabled today:** {cur_lake:,.1f} MB/day in the lake (down from {old_lake:,.0f} MB/day in the original design, {old_lake / cur_lake:,.0f}× less) plus {cur_db:,.1f} MB/day in DuckDB.

# Totals

| Scenario | 30 days | 90 days | 1 year | 3 years |
|---|---|---|---|---|
| Current sources, as built (gzipped deltas, measured) | {tot(cur_lake, cur_db)} |
| Current sources, original design (full uncompressed copy every run) | {tot(old_lake, cur_db)} |
| Current + all {sum(x[5] for x in cand_summary)} candidates, as built (candidates ~10× gzip) | {tot(cur_lake + cand_lake * 0.1, cur_db + cand_db)} |
| Current + all candidates, uncompressed | {tot(old_lake + cand_lake, cur_db + cand_db)} |

# Candidate categories

Uncompressed; divide the lake figure by about 10 for as-built storage.

| Category | Sources | Lake/day | DuckDB/day |
|---|---|---|---|
""" + "\n".join(f"| [{t}](/sources/candidates/{s}.md) | {n} | {l:,.0f} MB | {d:,.1f} MB |" for s, t, _, l, d, n in cand_summary) + """

# Where the bytes go

* **DuckDB is now nearly all of the growth**, mostly RIS Live's BGP events. The lake adds only a few MB a day.
* Overlapping-window feeds are still fetched in full every run, so late or revised data is caught, but only changed records are stored: NVD 5% and IODA 11% of a gzipped snapshot. IODA's remaining changes are ongoing outages whose duration and score grow each run.
* DShield's top-500 list changes almost entirely every hour, so it gains least.
* Streams are kept as one gzipped file per hour, about 3× smaller than per-flush files.
* The biggest candidate costs are bulk reference datasets (OSV, PeeringDB, RIR files, ATT&CK) if pulled daily in full. With record deltas only their changes would be stored after the first load.

# Recommendations

1. Retention is off by default. At these rates there is little reason to turn it on: 3 years of every current and candidate source fits on a small fraction of one external drive.
2. If disk does matter, set a lake limit in the Sources view. It deletes old files and re-stores still-active records, so the window stays complete.
"""
    write(OKF / "data" / "storage-estimates.md", body)


def index_doc(cur, cand) -> None:
    cur_lines = "\n".join(f"* [{n}](/sources/current/{sid}.md) - {d}" for sid, n, d in cur)
    cand_lines = "\n".join(f"* [{t}](/sources/candidates/{s}.md) - {d} ({n} sources)" for s, t, d, _, _, n in cand)
    write(OKF / "sources" / "index.md", f"""# Overview

* [Source catalog](/sources/catalog.md) - Every current and candidate source in one table, with trust tier, access and storage.
* [Trust model](/sources/trust-model.md) - How sources are graded and how corroboration across sources is used.

# Current sources

{cur_lines}

# Candidate sources

{cand_lines}
""")


def sub_indexes(cur, cand) -> None:
    write(OKF / "sources" / "current" / "index.md", "# Current sources\n\n" + "\n".join(f"* [{n}]({sid}.md) - {d}" for sid, n, d in cur) + "\n")
    write(OKF / "sources" / "candidates" / "index.md", "# Candidate sources\n\n" + "\n".join(f"* [{t}]({s}.md) - {d} ({n} sources)" for s, t, d, _, _, n in cand) + "\n")


def catalog_doc(cur, cand) -> None:
    cur_rows = []
    for sid, s in ordered_sources():
        if sid in HAND_ENTRIES:
            cur_rows.append(f"| [{s.name}](/sources/current/{sid}.md) | {HAND_ENTRIES[sid]['row']}")
            continue
        m = MEASURED[sid]
        cur_rows.append(f"| [{s.name}](/sources/current/{sid}.md) | {s.category} | {s.mode} | {m['trust']} | {m['auth']} | "
                        f"{'left out' if s.withheld else 'on' if s.default_enabled else 'off'} | {lake_mb_per_day(sid, s) * m['kept']:,.2f} MB |")
    cand_rows = []
    for slug, (_title, items) in CANDIDATES.items():
        for c in items:
            cand_rows.append(f"| [{c['name']}](/sources/candidates/{slug}.md) | {slug} | {c['trust']} | {c['auth']} | {c['probe']} | {cand_lake_mb_day(c):,.1f} MB |")
    n_cand = sum(len(v[1]) for v in CANDIDATES.values())
    write(OKF / "sources" / "catalog.md", f"""---
type: Source Catalog
title: Source catalog
description: Every source Night Desk ingests today and every candidate found in the 2026-11-04 search, with trust tier, access requirements and daily storage.
tags: [sources, catalog]
{GEN.replace(NOW, CATALOG_AT)}
---

# Current ({len(SOURCES)})

| Source | Category | Mode | Trust | Access | In app | Lake/day (as built) |
|---|---|---|---|---|---|---|
{chr(10).join(cur_rows)}

# Candidates ({n_cand})

| Source | Category | Trust | Access | Probe 2026-11-04 | Lake/day (suggested cadence, uncompressed) |
|---|---|---|---|---|---|
{chr(10).join(cand_rows)}

Storage totals and retention scenarios are in [storage estimates](/data/storage-estimates.md).
""")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Generate the source pages, catalog and storage estimates in okf/.")
    ap.add_argument("--only", help="comma-separated source ids: write only these current-source pages, nothing else")
    ap.add_argument("--out", type=Path, help="write into this folder (same layout as okf/) instead of okf/")
    ap.add_argument("--check", action="store_true",
                    help="write nothing; exit 1 if any page in okf/ (or --out) differs from what would be written")
    a = ap.parse_args()
    if a.out:
        OKF = a.out
    CHECK = a.check
    gaps = missing_inputs()
    if gaps:
        print("okf_sources: no MEASURED or HAND_ENTRIES entry for " + ", ".join(gaps) + " (add measurements for a "
              "generated page, or an index line and catalog row for a hand-written one)", file=sys.stderr)
        sys.exit(2)
    if a.only:
        only = {s.strip() for s in a.only.split(",") if s.strip()}
        bad = sorted(s for s in only if s not in SOURCES or s not in MEASURED or s in HAND_WRITTEN)
        if bad or not only:
            print("okf_sources: --only takes ids of generated source pages; not one: " + (", ".join(bad) or "(none)")
                  + " (unknown, or a hand-written page: " + ", ".join(sorted(HAND_WRITTEN | set(HAND_ENTRIES))) + ")",
                  file=sys.stderr)
            sys.exit(2)
        current_docs(only)
    else:
        cur = current_docs()
        cand = candidate_docs()
        storage_doc(cand)
        catalog_doc(cur, cand)
        index_doc(cur, cand)
        sub_indexes(cur, cand)
    if CHECK:
        for p in DRIFT:
            print(f"differs: {p.relative_to(OKF) if p.is_relative_to(OKF) else p}")
        print(f"checked {len(WRITTEN)} files: " + (f"{len(DRIFT)} {'differs' if len(DRIFT) == 1 else 'differ'} from "
                                                   "the generator (regenerate, or move the hand edit into the "
                                                   "generator's inputs)" if DRIFT else "all match"))
        sys.exit(1 if DRIFT else 0)
    if a.only:
        print(f"wrote {len(WRITTEN)} files: " + ", ".join(p.name for p in WRITTEN))
        sys.exit(0)
    pages = [p for p in WRITTEN if p.parent == OKF / "sources" / "current" and p.name != "index.md"]
    print(f"wrote {len(WRITTEN)} files: {len(pages)} current-source pages (of {len(cur)} sources; the rest are "
          f"hand-written), {sum(len(v[1]) for v in CANDIDATES.values())} candidates in {len(cand)} categories")
