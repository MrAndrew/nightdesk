---
type: Data Source
title: "blocklist.de attackers"
description: "IPs reported in the last 48h for SSH, mail, web and FTP brute force by fail2ban sensors."
resource: https://www.blocklist.de/
tags: [threat, batch, current]
provider: "blocklist.de"
mode: batch
cadence: "every 3h"
trust_tier: C
auth: "none"
license: "see provider terms"
in_app: off by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

IPs reported in the last 48h for SSH, mail, web and FTP brute force by fail2ban sensors.

| | |
|---|---|
| Source id | `blocklist_de` |
| Provider | blocklist.de |
| Mode | batch (every 3h) |
| Trust tier | C: Community or aggregator feed: useful and widely used, but curation varies; corroborate before acting |
| Access | none |
| License | see provider terms |
| Status in Night Desk | off by default (since the 2026-11-19 terms review): unticked in the first-run "Choose your sources" box and never fetched before the user turns it on. An install that ran it before and answered that box with Keep, or was never offered it, keeps it on (`TERMS_OFFS` in osinthub/scheduler.py) |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: DShield, CINS, IPsum, AbuseIPDB.

# Terms

Read 2026-11-19 ([terms](https://www.blocklist.de/en/terms.html)): No licence on the [site](https://www.blocklist.de/en/index.html) or the [download page](https://www.blocklist.de/en/download.html); the terms (s5) exclude downloads of "zu großem Volumen" (too large a volume) from free use.

Commercial use: ?. Redistribution: ?. AI use: ?.

The parser keeps the first 6,000 of roughly 25,000 IPs per run; raising the cap scales storage about 4x.

# Storage

369 KB raw + 2,958 KB normalised per run (measured 2026-11-04), or 26.6 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 0.63% of it (0.17 MB/day, measured). DuckDB grows only by new unique events (about 2,200 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.01 GB | 0.04 GB |
| 90 days | 0.02 GB | 0.12 GB |
| 1 year | 0.06 GB | 0.49 GB |
| 3 years | 0.18 GB | 1.47 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
