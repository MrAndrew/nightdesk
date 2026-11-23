---
type: Data Source
title: "URLhaus malware URLs"
description: "URLs distributing malware, with their host, online/offline status and tags. Needs a free abuse.ch Auth-Key; off by default."
resource: https://urlhaus.abuse.ch/
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

URLs distributing malware, with their host, online/offline status and tags. Needs a free abuse.ch Auth-Key; off by default.

| | |
|---|---|
| Source id | `urlhaus` |
| Provider | abuse.ch |
| Mode | batch (every 1h) |
| Trust tier | B: Established research group, nonprofit or vendor with a published methodology and track record |
| Access | free Auth-Key (ABUSECH_AUTH_KEY) |
| License | abuse.ch Terms of Use: free for not-for-profit use, no redistribution |
| Status in Night Desk | off by default; unticked in the first-run "Choose your sources" box |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: ThreatFox (payload URLs), Spamhaus DBL and SURBL (carried in each record), OpenPhish.

# Terms

Read 2026-11-19 ([terms](https://abuse.ch/terms-of-use/)): abuse.ch Terms of Use (updated 2026-10-21) s3.1: the free tier is "for not-for-profit purposes"; s4.1 commercial use needs a paid Spamhaus subscription; s7.3 no derivative works, no high-volume harvesting and no AI use (`ai_ok = False`).

Commercial use: no. Redistribution: no. AI use: no.

# Access and terms

Needs the same free abuse.ch Auth-Key as ThreatFox (`ABUSECH_AUTH_KEY`), sent only in the `Auth-Key` header of `GET https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/` (the newest 1,000 URLs of the last 3 days), without following redirects. The export files would need the key in the URL path, so they are not used. abuse.ch asks for no more than one fetch per 5 minutes; the source runs hourly. Without a key it is never started or fetched and the Sources page says so.

abuse.ch Terms of Use (last updated 2026-10-21, https://abuse.ch/terms-of-use/): the free tier is for not-for-profit use only (s3.1); no redistribution or derivative works of the platforms (s7.3); no high-volume harvesting; and s7.3 forbids using the data to "customise, train, or otherwise improve" AI models. URLhaus is `ai_ok = False` like ThreatFox.

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
* **Explorer** lists every event; global search does not index feed events (it covers news and social events), but finds their indicator and family entities.

# Storage

400 KB raw + 300 KB normalised per run (estimated), or 16.8 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 10.00% of it (1.68 MB/day, measured). DuckDB grows only by new unique events (about 1,000 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.05 GB | 0.02 GB |
| 90 days | 0.15 GB | 0.05 GB |
| 1 year | 0.61 GB | 0.22 GB |
| 3 years | 1.84 GB | 0.67 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
