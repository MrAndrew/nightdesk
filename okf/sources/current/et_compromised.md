---
type: Data Source
title: "Emerging Threats compromised hosts"
description: "Hosts Emerging Threats has seen compromised and acting maliciously."
resource: https://rules.emergingthreats.net/
tags: [threat, batch, current]
provider: "Proofpoint ET"
mode: batch
cadence: "every 6h"
trust_tier: B
auth: "none"
license: "see provider terms"
in_app: off by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

Hosts Emerging Threats has seen compromised and acting maliciously.

| | |
|---|---|
| Source id | `et_compromised` |
| Provider | Proofpoint ET |
| Mode | batch (every 6h) |
| Trust tier | B: Established research group, nonprofit or vendor with a published methodology and track record |
| Access | none |
| License | see provider terms |
| Status in Night Desk | off by default (since the 2026-11-19 terms review): unticked in the first-run "Choose your sources" box and never fetched before the user turns it on. An install that ran it before and answered that box with Keep, or was never offered it, keeps it on (`TERMS_OFFS` in osinthub/scheduler.py) |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: ET block list, FireHOL level 2.

# Terms

Read 2026-11-19 ([terms](https://rules.emergingthreats.net/)): Only "© 2026 Proofpoint Inc"; no licence found for `compromised-ips.txt` (ET Open rules are BSD/GPL by sid range according to community posts only).

Commercial use: ?. Redistribution: ?. AI use: ?.

# Storage

7 KB raw + 257 KB normalised per run (measured 2026-11-04), or 1.1 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 0.60% of it (0.01 MB/day, measured). DuckDB grows only by new unique events (about 50 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.00 GB | 0.00 GB |
| 90 days | 0.00 GB | 0.00 GB |
| 1 year | 0.00 GB | 0.01 GB |
| 3 years | 0.01 GB | 0.03 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
