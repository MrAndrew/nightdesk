---
type: Data Source
title: "The Record"
description: "Cyber newsroom of Recorded Future: incidents, policy and nation-state reporting with named sources."
resource: https://therecord.media/
tags: [news, batch, current]
provider: "Recorded Future News"
mode: batch
cadence: "every 20m"
trust_tier: B
auth: "none"
license: "Publisher copyright; headlines and links only, articles fetched for local reading"
in_app: on by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

Cyber newsroom of Recorded Future: incidents, policy and nation-state reporting with named sources.

| | |
|---|---|
| Source id | `news_therecord` |
| Provider | Recorded Future News |
| Mode | batch (every 20m) |
| Trust tier | B: Established research group, nonprofit or vendor with a published methodology and track record |
| Access | none |
| License | Publisher copyright; headlines and links only, articles fetched for local reading |
| Status in Night Desk | on by default |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: BleepingComputer, SecurityWeek, CyberScoop.

# Terms

Read 2026-11-19 ([terms](https://therecord.media/)): Publisher copyright. Night Desk reads the public RSS feed (headline, summary and link), then fetches each article page (robots.txt honoured, bot checks never bypassed), keeps it on this machine for the local AI and never re-serves the text. No licence for the feed was found. Its terms page gave 404 or was not found. On by default for personal use.

Commercial use: no. Redistribution: no. AI use: unclear.

# Storage

5 KB raw + 4 KB normalised per run (estimated), or 0.6 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 2.00% of it (0.01 MB/day, measured). DuckDB grows only by new unique events (about 15 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.00 GB | 0.00 GB |
| 90 days | 0.00 GB | 0.00 GB |
| 1 year | 0.00 GB | 0.00 GB |
| 3 years | 0.01 GB | 0.01 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
