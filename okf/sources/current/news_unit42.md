---
type: Data Source
title: "Unit 42"
description: "Primary threat research from Palo Alto Networks Unit 42, usually with IOCs."
resource: https://unit42.paloaltonetworks.com/
tags: [news, batch, current]
provider: "Palo Alto Networks"
mode: batch
cadence: "every 2h"
trust_tier: B
auth: "none"
license: "Publisher copyright; headlines and links only, articles fetched for local reading"
in_app: on by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

Primary threat research from Palo Alto Networks Unit 42, usually with IOCs.

| | |
|---|---|
| Source id | `news_unit42` |
| Provider | Palo Alto Networks |
| Mode | batch (every 2h) |
| Trust tier | B: Established research group, nonprofit or vendor with a published methodology and track record |
| Access | none |
| License | Publisher copyright; headlines and links only, articles fetched for local reading |
| Status in Night Desk | on by default |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: Cisco Talos, Microsoft Threat Intelligence.

# Terms

Read 2026-11-19 ([terms](https://unit42.paloaltonetworks.com/)): Publisher copyright. Night Desk reads the public RSS feed (headline, summary and link), then fetches each article page (robots.txt honoured, bot checks never bypassed), keeps it on this machine for the local AI and never re-serves the text. No licence for the feed was found. On by default for personal use.

Commercial use: no. Redistribution: no. AI use: unclear.

# Storage

24 KB raw + 10 KB normalised per run (estimated), or 0.4 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 2.00% of it (0.01 MB/day, measured). DuckDB grows only by new unique events (about 1 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.00 GB | 0.00 GB |
| 90 days | 0.00 GB | 0.00 GB |
| 1 year | 0.00 GB | 0.00 GB |
| 3 years | 0.01 GB | 0.00 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
