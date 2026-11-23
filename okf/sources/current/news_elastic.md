---
type: Data Source
title: "Elastic Security Labs"
description: "Malware and detection research from Elastic Security Labs. Its list of articles is large (8 MB), so it is read every 6 hours."
resource: https://www.elastic.co/security-labs/
tags: [news, batch, current]
provider: "Elastic"
mode: batch
cadence: "every 6h"
trust_tier: B
auth: "none"
license: "Publisher copyright; headlines and links only, articles fetched for local reading"
in_app: on by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

Malware and detection research from Elastic Security Labs. Its list of articles is large (8 MB), so it is read every 6 hours.

| | |
|---|---|
| Source id | `news_elastic` |
| Provider | Elastic |
| Mode | batch (every 6h) |
| Trust tier | B: Established research group, nonprofit or vendor with a published methodology and track record |
| Access | none |
| License | Publisher copyright; headlines and links only, articles fetched for local reading |
| Status in Night Desk | on by default |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: Cisco Talos, Unit 42.

# Terms

Read 2026-11-19 ([terms](https://www.elastic.co/security-labs)): Publisher copyright. Night Desk reads the public RSS feed (headline, summary and link), then fetches each article page (robots.txt honoured, bot checks never bypassed), keeps it on this machine for the local AI and never re-serves the text. No licence for the feed was found. On by default for personal use.

Commercial use: no. Redistribution: no. AI use: unclear.

The feed carries full article bodies for about 300 posts (8.4 MB), so it runs every 6 hours; only new or changed entries are stored.

# Storage

8,415 KB raw + 40 KB normalised per run (estimated), or 33.8 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 0.20% of it (0.07 MB/day, measured). DuckDB grows only by new unique events (about 1 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.00 GB | 0.00 GB |
| 90 days | 0.01 GB | 0.00 GB |
| 1 year | 0.02 GB | 0.00 GB |
| 3 years | 0.07 GB | 0.00 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
