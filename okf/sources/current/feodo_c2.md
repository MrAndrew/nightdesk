---
type: Data Source
title: "Feodo Tracker botnet C2"
description: "Command-and-control servers for Emotet, Dridex, QakBot and related banking botnets."
resource: https://feodotracker.abuse.ch/
tags: [threat, batch, current]
provider: "abuse.ch"
mode: batch
cadence: "every 1h"
trust_tier: B
auth: "none"
license: "CC0"
in_app: on by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

Command-and-control servers for Emotet, Dridex, QakBot and related banking botnets.

| | |
|---|---|
| Source id | `feodo_c2` |
| Provider | abuse.ch |
| Mode | batch (every 1h) |
| Trust tier | B: Established research group, nonprofit or vendor with a published methodology and track record |
| Access | none |
| License | CC0 |
| Status in Night Desk | on by default |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: ThreatFox, IPsum, FireHOL level 1.

# Terms

Read 2026-11-19 ([terms](https://abuse.ch/terms-of-use/)): abuse.ch Terms of Use (updated 2026-10-21) s3.4: Feodo Tracker and SSLBL data are "free to use without limitations ... (CC0)"; s7.3 forbids using abuse.ch data to "customise, train, or otherwise improve any artificial intelligence model" and has no CC0 carve-out, so the source is `ai_ok = False` (kept out of every prompt and embedding).

Commercial use: yes. Redistribution: yes. AI use: no (unclear: s7.3, no CC0 carve-out).

# Storage

2 KB raw + 3 KB normalised per run (measured 2026-11-04), or 0.1 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 0.50% of it (0.00 MB/day, measured). DuckDB grows only by new unique events (about 1 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.00 GB | 0.00 GB |
| 90 days | 0.00 GB | 0.00 GB |
| 1 year | 0.00 GB | 0.00 GB |
| 3 years | 0.00 GB | 0.00 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
