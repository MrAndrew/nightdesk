---
type: Data Source
title: "CISA Known Exploited Vulnerabilities"
description: "Every CVE CISA has confirmed is being exploited in the wild, with ransomware use flags and federal patch deadlines."
resource: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
tags: [vuln, batch, current]
provider: "CISA"
mode: batch
cadence: "every 6h"
trust_tier: A
auth: "none"
license: "Public domain (US Gov)"
in_app: on by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

Every CVE CISA has confirmed is being exploited in the wild, with ransomware use flags and federal patch deadlines.

| | |
|---|---|
| Source id | `cisa_kev` |
| Provider | CISA |
| Mode | batch (every 6h) |
| Trust tier | A: Primary authority: a government CERT/agency, standards body or the operator of the measurement itself |
| Access | none |
| License | Public domain (US Gov) |
| Status in Night Desk | on by default |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: NVD (CVE details), EUVD exploited list, VulnCheck KEV, EPSS.

# Terms

Read 2026-11-19 ([terms](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt)): CC0 1.0. No CISA logo and no CISA endorsement implied.

Commercial use: yes. Redistribution: yes. AI use: yes.

# Storage

1,829 KB raw + 1,345 KB normalised per run (measured 2026-11-04), or 12.7 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 0.90% of it (0.11 MB/day, measured). DuckDB grows only by new unique events (about 1 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.00 GB | 0.00 GB |
| 90 days | 0.01 GB | 0.00 GB |
| 1 year | 0.04 GB | 0.00 GB |
| 3 years | 0.13 GB | 0.00 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
