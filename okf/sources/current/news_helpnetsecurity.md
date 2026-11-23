---
type: Data Source
title: "Help Net Security"
description: "Daily vulnerability, product security and research news; many items are vendor product announcements."
resource: https://www.helpnetsecurity.com/
tags: [news, batch, current]
provider: "Help Net Security"
mode: batch
cadence: "every 20m"
trust_tier: C
auth: "none"
license: "Publisher copyright; headlines and links only, articles fetched for local reading"
in_app: on by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

Daily vulnerability, product security and research news; many items are vendor product announcements.

| | |
|---|---|
| Source id | `news_helpnetsecurity` |
| Provider | Help Net Security |
| Mode | batch (every 20m) |
| Trust tier | C: Community or aggregator feed: useful and widely used, but curation varies; corroborate before acting |
| Access | none |
| License | Publisher copyright; headlines and links only, articles fetched for local reading |
| Status in Night Desk | on by default |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: SecurityWeek, vendor advisories.

# Terms

Read 2026-11-19 ([terms](https://www.helpnetsecurity.com/)): Publisher copyright. Night Desk reads the public RSS feed (headline, summary and link), then fetches each article page (robots.txt honoured, bot checks never bypassed), keeps it on this machine for the local AI and never re-serves the text. No licence for the feed was found. On by default for personal use.

Commercial use: no. Redistribution: no. AI use: unclear.

# Storage

17 KB raw + 7 KB normalised per run (estimated), or 1.7 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 2.00% of it (0.03 MB/day, measured). DuckDB grows only by new unique events (about 15 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.00 GB | 0.00 GB |
| 90 days | 0.00 GB | 0.00 GB |
| 1 year | 0.01 GB | 0.00 GB |
| 3 years | 0.04 GB | 0.01 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
