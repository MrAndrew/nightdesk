---
type: Data Source
title: "Tor exit nodes"
description: "Current Tor exit relays, the IPs anonymised traffic leaves the Tor network from."
resource: https://check.torproject.org/
tags: [infra, batch, current]
provider: "The Tor Project"
mode: batch
cadence: "every 3h"
trust_tier: A
auth: "none"
license: "CC0 (Tor Metrics data)"
in_app: on by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

Current Tor exit relays, the IPs anonymised traffic leaves the Tor network from.

| | |
|---|---|
| Source id | `tor_exits` |
| Provider | The Tor Project |
| Mode | batch (every 3h) |
| Trust tier | A: Primary authority: a government CERT/agency, standards body or the operator of the measurement itself |
| Access | none |
| License | CC0 (Tor Metrics data) |
| Status in Night Desk | on by default |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: Tor Onionoo relay details.

# Terms

Read 2026-11-19 ([terms](https://metrics.torproject.org/)): CC0: "Data on this site is freely available under a CC0 no copyright declaration". The CC BY 3.0 US licence on Tor Metrics covers its graphs only, not the exit list.

Commercial use: yes. Redistribution: yes. AI use: yes.

# Storage

18 KB raw + 583 KB normalised per run (measured 2026-11-04), or 4.8 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 0.05% of it (0.00 MB/day, measured). DuckDB grows only by new unique events (about 100 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.00 GB | 0.00 GB |
| 90 days | 0.00 GB | 0.01 GB |
| 1 year | 0.00 GB | 0.02 GB |
| 3 years | 0.00 GB | 0.07 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
