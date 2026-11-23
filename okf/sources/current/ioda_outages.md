---
type: Data Source
title: "IODA internet outages"
description: "Country and network-level internet outages detected from BGP, active probing and darknet telescope signals."
resource: https://ioda.inetintel.cc.gatech.edu/
tags: [infra, batch, current]
provider: "Georgia Tech IODA"
mode: batch
cadence: "every 15m"
trust_tier: B
auth: "none"
license: "No terms stated (cite IODA, Georgia Tech)"
in_app: off by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

Country and network-level internet outages detected from BGP, active probing and darknet telescope signals.

| | |
|---|---|
| Source id | `ioda_outages` |
| Provider | Georgia Tech IODA |
| Mode | batch (every 15m) |
| Trust tier | B: Established research group, nonprofit or vendor with a published methodology and track record |
| Access | none |
| License | No terms stated (cite IODA, Georgia Tech) |
| Status in Night Desk | off by default (since the 2026-11-19 terms review): unticked in the first-run "Choose your sources" box and never fetched before the user turns it on. An install that ran it before and answered that box with Keep, or was never offered it, keeps it on (`TERMS_OFFS` in osinthub/scheduler.py) |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: Cloudflare Radar outages, RIPE Atlas, GRIP.

# Terms

Read 2026-11-19 ([terms](https://ioda.inetintel.cc.gatech.edu/)): No terms, acceptable-use or citation page was found for the IODA data or API; cite "IODA, Georgia Tech".

Commercial use: ?. Redistribution: ?. AI use: ?.

# Storage

265 KB raw + 541 KB normalised per run (measured 2026-11-04), or 77.4 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 1.08% of it (0.84 MB/day, measured). DuckDB grows only by new unique events (about 150 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.03 GB | 0.00 GB |
| 90 days | 0.08 GB | 0.01 GB |
| 1 year | 0.31 GB | 0.03 GB |
| 3 years | 0.92 GB | 0.10 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
