---
type: Data Source
title: "NVD — newly published CVEs"
description: "CVEs published in the last 72 hours with CVSS scores, polled from the NVD 2.0 API."
resource: https://nvd.nist.gov/
tags: [vuln, batch, current]
provider: "NIST NVD"
mode: batch
cadence: "every 2h"
trust_tier: A
auth: "none (optional free key raises rate limit)"
license: "Public domain (US Gov)"
in_app: on by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

CVEs published in the last 72 hours with CVSS scores, polled from the NVD 2.0 API.

| | |
|---|---|
| Source id | `nvd_recent` |
| Provider | NIST NVD |
| Mode | batch (every 2h) |
| Trust tier | A: Primary authority: a government CERT/agency, standards body or the operator of the measurement itself |
| Access | none (optional free key raises rate limit) |
| License | Public domain (US Gov) |
| Status in Night Desk | on by default |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: CVE List V5 (CVE.org), EUVD, GitHub Advisory Database, OSV.

# Terms

Read 2026-11-19 ([terms](https://nvd.nist.gov/developers/terms-of-use)): US Government data. Apps must show "This product uses the NVD API but is not endorsed or certified by the NVD" (Help › Sources › Credits shows it).

Commercial use: yes. Redistribution: yes (not as NVD data once modified). AI use: yes.

# Text

Descriptions are stored as plain text: some CNAs submit them with HTML entities (`&#39;`, `&quot;`, `&amp;`, even double-encoded `&amp;amp;`), which the shared decoder (`osinthub/sources/text.py`) turns into the characters they stand for, however many times they were encoded. Only well-formed entities are decoded (`AT&T`, `Q&notes`, `&copy law` stay as written) and line breaks are kept. The CVE id, the NVD link and the stored NVD records (reference URLs included) are never decoded. Decoded markup such as `<script>` is text: clients escape it where they show it. The CVE search documents read descriptions from the lake records and decode them the same way.

Existing lakes: each run's `prepare()` decodes, in place in DuckDB, the stored events that still hold an entity-like `&...`, in or out of the 72-hour window, and gives each the content hash `parse()` gives it today. The same run's parse then finds nothing changed (no event delta is written for the text alone), and the entity linker sees the new hash and extracts the event's mentions again, once. The lake's event files keep the text as it was stored then; nothing is rewritten.

# Storage

3,655 KB raw + 1,167 KB normalised per run (measured 2026-11-04), or 57.9 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 0.58% of it (0.34 MB/day, measured). DuckDB grows only by new unique events (about 130 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.01 GB | 0.00 GB |
| 90 days | 0.03 GB | 0.01 GB |
| 1 year | 0.12 GB | 0.03 GB |
| 3 years | 0.37 GB | 0.09 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
