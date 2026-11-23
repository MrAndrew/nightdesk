---
type: Data Source
title: "Security news wire"
description: "Headlines from major security newsrooms, tagged with the countries they mention."
resource: n/a
tags: [news, batch, current]
provider: "BleepingComputer · The Hacker News · Krebs · SANS ISC"
mode: batch
cadence: "every 20m"
trust_tier: B
auth: "none"
license: "see provider terms"
in_app: on by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

Headlines from major security newsrooms, tagged with the countries they mention.

| | |
|---|---|
| Source id | `security_news` |
| Provider | BleepingComputer · The Hacker News · Krebs · SANS ISC |
| Mode | batch (every 20m) |
| Trust tier | B: Established research group, nonprofit or vendor with a published methodology and track record |
| Access | none |
| License | see provider terms |
| Status in Night Desk | on by default |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: The Record, SecurityWeek, CISA and national CERT advisories.

# Terms

Read 2026-11-19 ([terms](https://www.bleepingcomputer.com/terms-of-use/)): Publisher copyright. Night Desk reads the public RSS feed (headline, summary and link), then fetches each article page (robots.txt honoured, bot checks never bypassed), keeps it on this machine for the local AI and never re-serves the text. No licence for the feed was found. [BleepingComputer's terms](https://www.bleepingcomputer.com/terms-of-use/) s4: content "may not be stored in a computer ... except for personal and non-commercial use"; [SANS ISC](https://isc.sans.edu/about.html) is CC BY-NC-SA 4.0; The Hacker News' terms page gave 404. On by default for personal use.

Commercial use: no. Redistribution: no. AI use: unclear.

# Storage

260 KB raw + 77 KB normalised per run (measured 2026-11-04), or 24.3 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 0.41% of it (0.10 MB/day, measured). DuckDB grows only by new unique events (about 50 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.00 GB | 0.00 GB |
| 90 days | 0.01 GB | 0.00 GB |
| 1 year | 0.04 GB | 0.01 GB |
| 3 years | 0.11 GB | 0.03 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
