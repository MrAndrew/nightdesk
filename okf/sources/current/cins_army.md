---
type: Data Source
title: "CINS Army bad actors"
description: "IPs with poor reputation scores across the CINS sensor network."
resource: https://cinsscore.com/
tags: [threat, batch, current]
provider: "Sentinel IPS / CINS"
mode: batch
cadence: "every 6h"
trust_tier: C
auth: "none"
license: "see provider terms"
in_app: off by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

IPs with poor reputation scores across the CINS sensor network.

| | |
|---|---|
| Source id | `cins_army` |
| Provider | Sentinel IPS / CINS |
| Mode | batch (every 6h) |
| Trust tier | C: Community or aggregator feed: useful and widely used, but curation varies; corroborate before acting |
| Access | none |
| License | see provider terms |
| Status in Night Desk | off by default; unticked in the first-run "Choose your sources" box |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: DShield, blocklist.de, IPsum.

# Terms

Read 2026-11-19 ([terms](https://cinsscore.com/)): "Parse and use in any way you see fit"; no formal licence.

Commercial use: likely. Redistribution: ?. AI use: likely.

# Storage

230 KB raw + 1,800 KB normalised per run (estimated), or 8.1 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 0.63% of it (0.05 MB/day, measured). DuckDB grows only by new unique events (about 1,500 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.00 GB | 0.03 GB |
| 90 days | 0.00 GB | 0.08 GB |
| 1 year | 0.02 GB | 0.33 GB |
| 3 years | 0.06 GB | 1.00 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
