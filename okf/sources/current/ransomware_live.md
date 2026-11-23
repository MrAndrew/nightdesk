---
type: Data Source
title: "Ransomware leak-site victims"
description: "Victims newly posted on ransomware gang leak sites, with group, sector and country. Off by default: enable in Sources. Uses the free v2 API (no key, rate-limited); set RANSOMWARELIVE_API_KEY (+ URL/header) to use an API PRO key for higher limits."
resource: https://www.ransomware.live/
tags: [threat, batch, current]
provider: "ransomware.live"
mode: batch
cadence: "every 30m"
trust_tier: C
auth: "blocked for automated clients (paid API available)"
license: "Non-commercial use with attribution (ransomware.live T&C s5)"
in_app: off by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

Victims newly posted on ransomware gang leak sites, with group, sector and country. Off by default: enable in Sources. Uses the free v2 API (no key, rate-limited); set RANSOMWARELIVE_API_KEY (+ URL/header) to use an API PRO key for higher limits.

| | |
|---|---|
| Source id | `ransomware_live` |
| Provider | ransomware.live |
| Mode | batch (every 30m) |
| Trust tier | C: Community or aggregator feed: useful and widely used, but curation varies; corroborate before acting |
| Access | blocked for automated clients (paid API available) |
| License | Non-commercial use with attribution (ransomware.live T&C s5) |
| Status in Night Desk | off by default; unticked in the first-run "Choose your sources" box |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: RansomLook (open), DataBreaches.net, victim disclosures.

# Terms

Read 2026-11-19 ([terms](https://www.ransomware.live/t&c)): Non-commercial. T&C s5.1: "freely available for non-commercial use" with attribution; s5.2 commercial use is "strictly prohibited without prior written approval"; s6 name ransomware.live and link back (Help › Sources › Credits does).

Commercial use: no. Redistribution: no. AI use: not stated.

# Text

Victim names and descriptions are scraped from leak-site HTML and can carry entities (`Smith &amp; Sons`, `&#8211;`). The event title (`<group> claims <victim>`) and the summary are decoded to plain text by the shared decoder (`osinthub/sources/text.py`, well-formed entities only), so a followed organisation matches its victim posting. The event key and the record key keep the provider's text, so an existing victim keeps its event id instead of appearing twice; the tags (group, activity) and the post URL are not decoded. Victims stored before this are decoded in DuckDB by the source's next run (`prepare()`) and given the content hash `parse()` gives them today, so they are not stored again as changed and the entity linker extracts their mentions again, once.

# Storage

120 KB raw + 150 KB normalised per run (estimated), or 13.0 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 1.00% of it (0.13 MB/day, measured). DuckDB grows only by new unique events (about 40 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.00 GB | 0.00 GB |
| 90 days | 0.01 GB | 0.00 GB |
| 1 year | 0.05 GB | 0.01 GB |
| 3 years | 0.14 GB | 0.03 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
