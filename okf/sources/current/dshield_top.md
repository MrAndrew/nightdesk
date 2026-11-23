---
type: Data Source
title: "DShield top attacking IPs"
description: "The IPs hitting the most DShield sensors worldwide, ranked by attack count."
resource: https://isc.sans.edu/
tags: [threat, batch, current]
provider: "SANS Internet Storm Center"
mode: batch
cadence: "every 1h"
trust_tier: B
auth: "none"
license: "CC BY-NC-SA 4.0 (own-network use, commercial included; no resale)"
in_app: off by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

The IPs hitting the most DShield sensors worldwide, ranked by attack count.

| | |
|---|---|
| Source id | `dshield_top` |
| Provider | SANS Internet Storm Center |
| Mode | batch (every 1h) |
| Trust tier | B: Established research group, nonprofit or vendor with a published methodology and track record |
| Access | none |
| License | CC BY-NC-SA 4.0 (own-network use, commercial included; no resale) |
| Status in Night Desk | off by default (since the 2026-11-19 terms review): unticked in the first-run "Choose your sources" box and never fetched before the user turns it on. An install that ran it before and answered that box with Keep, or was never offered it, keeps it on (`TERMS_OFFS` in osinthub/scheduler.py) |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: blocklist.de, CINS, IPsum, GreyNoise, AbuseIPDB.

# Terms

Read 2026-11-19 ([terms](https://isc.sans.edu/api/)): CC BY-NC-SA 4.0. No resale; own-network use, commercial included. "Do not resell the data"; put a contact in the User-Agent. Credit SANS ISC.

Commercial use: own network only ("ok to use this data for commercial purposes, for example to protect your own company's network"). Redistribution: share-alike; no resale. AI use: yes.

# Storage

50 KB raw + 271 KB normalised per run (measured 2026-11-04), or 7.7 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 7.80% of it (0.60 MB/day, measured). DuckDB grows only by new unique events (about 6,700 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.02 GB | 0.12 GB |
| 90 days | 0.05 GB | 0.37 GB |
| 1 year | 0.22 GB | 1.49 GB |
| 3 years | 0.66 GB | 4.48 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
