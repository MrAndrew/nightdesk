---
type: Data Source
title: "ThreatFox malware IOCs"
description: "IOCs (C2 IP:port, domains, URLs, file hashes) tied to named malware families, shared by the abuse.ch community. Needs a free abuse.ch Auth-Key; off by default."
resource: https://threatfox.abuse.ch/
tags: [threat, batch, current]
provider: "abuse.ch"
mode: batch
cadence: "every 1h"
trust_tier: B
auth: "free Auth-Key (ABUSECH_AUTH_KEY)"
license: "abuse.ch Terms of Use: free for not-for-profit use, no redistribution"
in_app: off by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

IOCs (C2 IP:port, domains, URLs, file hashes) tied to named malware families, shared by the abuse.ch community. Needs a free abuse.ch Auth-Key; off by default.

| | |
|---|---|
| Source id | `threatfox` |
| Provider | abuse.ch |
| Mode | batch (every 1h) |
| Trust tier | B: Established research group, nonprofit or vendor with a published methodology and track record |
| Access | free Auth-Key (ABUSECH_AUTH_KEY) |
| License | abuse.ch Terms of Use: free for not-for-profit use, no redistribution |
| Status in Night Desk | off by default; unticked in the first-run "Choose your sources" box |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: Feodo Tracker (the same C2 addresses), URLhaus (the same payload URLs), MalwareBazaar (hashes), C2IntelFeeds.

# Terms

Read 2026-11-19 ([terms](https://abuse.ch/terms-of-use/)): abuse.ch Terms of Use (updated 2026-10-21) s3.1: the free tier is "for not-for-profit purposes"; s4.1 commercial use needs a paid Spamhaus subscription; s7.3 no derivative works, no high-volume harvesting and no AI use (`ai_ok = False`).

Commercial use: no. Redistribution: no. AI use: no.

# Access and terms

Needs a free abuse.ch Auth-Key from https://auth.abuse.ch/, read from the environment variable `ABUSECH_AUTH_KEY` (osinthub/config.py). The key is sent only in the documented `Auth-Key` HTTP header of `POST https://threatfox-api.abuse.ch/api/v1/` (`{"query": "get_iocs", "days": N}`), never in a URL, and the request does not follow redirects, so the header can never be forwarded to another host; a redirect fails the run. The key never reaches a log line, a run record, a raw path or an error message. Without a key the source is never started or fetched, cannot be switched on or run (both calls answer 409) and the Sources page says "Needs a free key" and that it goes in the `.env` file in Night Desk's install folder, with the variable's name `ABUSECH_AUTH_KEY` under Technical details. A refused key (HTTP 401/403) fails the run with "abuse.ch refused the Auth-Key"; a ThreatFox `query_status` other than ok or no_result fails it with that status.

abuse.ch Terms of Use (last updated 2026-10-21, https://abuse.ch/terms-of-use/): the free tier is for not-for-profit use only (s3.1); no redistribution or derivative works of the platforms (s7.3); no high-volume harvesting; and s7.3 forbids using the data to "customise, train, or otherwise improve" AI models. So, conservatively, nothing from ThreatFox goes into an LLM prompt or an embedding: `ai_ok = False` keeps its claims, evidence and mention counts out of the entity brief (osinthub/news/brief.py), and malware families known only from abuse.ch (entity attr `ai_excluded`) are never embedded (osinthub/entities/searcher.py). Event vectors cover news and social kinds only.

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
* **Stories and entity pages** show the lists that hold an IoC ("listed · threatfox").

# Storage

1,000 KB raw + 600 KB normalised per run (estimated), or 38.4 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 5.00% of it (1.92 MB/day, measured). DuckDB grows only by new unique events (about 1,500 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.06 GB | 0.03 GB |
| 90 days | 0.17 GB | 0.08 GB |
| 1 year | 0.70 GB | 0.33 GB |
| 3 years | 2.10 GB | 1.00 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
