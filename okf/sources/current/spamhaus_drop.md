---
type: Data Source
title: "Spamhaus DROP hijacked netblocks"
description: "Netblocks hijacked or leased by spammers and cyber-criminals. Do not route or peer."
resource: https://www.spamhaus.org/blocklists/do-not-route-or-peer/
tags: [threat, batch, current]
provider: "Spamhaus"
mode: batch
cadence: "every 1d"
trust_tier: A
auth: "none (terms of use apply)"
license: "Spamhaus DROP terms"
in_app: off by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

Netblocks hijacked or leased by spammers and cyber-criminals. Do not route or peer.

| | |
|---|---|
| Source id | `spamhaus_drop` |
| Provider | Spamhaus |
| Mode | batch (every 1d) |
| Trust tier | A: Primary authority: a government CERT/agency, standards body or the operator of the measurement itself |
| Access | none (terms of use apply) |
| License | Spamhaus DROP terms |
| Status in Night Desk | off by default (since the 2026-11-19 terms review): unticked in the first-run "Choose your sources" box and never fetched before the user turns it on. An install that ran it before and answered that box with Keep, or was never offered it, keeps it on (`TERMS_OFFS` in osinthub/scheduler.py) |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: FireHOL level 1, Spamhaus ASN-DROP.

# Terms

Read 2026-11-19 ([terms](https://www.spamhaus.org/blocklists/drop-fair-use-policy/)): DROP fair use policy s3.1: the data is "protected by copyright and database right" and no licence is granted; s3.3 the right to use it can be revoked "for any reason". The [DROP page](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) asks products to credit "The Spamhaus Project" (Help › Sources › Credits does) and to fetch at most once a day.

Commercial use: not stated. Redistribution: not stated. AI use: not stated.

# Fetch terms

Spamhaus asks that "the DROP list data should not be downloaded from our website more than once per day" and that automated downloads be at least an hour apart; excessive downloads may get the client firewalled ([DROP page](https://www.spamhaus.org/blocklists/do-not-route-or-peer/), [DROP FAQ: How often should my system fetch the DROP list?](https://www.spamhaus.org/faqs/do-not-route-or-peer-drop/), checked 2026-11-09). So it runs once every 24 hours, timed from the last successful fetch, so restarts don't fetch again early. Pressing Run now on the Sources page still fetches at once: use it sparingly.

# Storage

108 KB raw + 939 KB normalised per run (measured 2026-11-04), or 1.0 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 0.05% of it (0.00 MB/day, measured). DuckDB grows only by new unique events (about 5 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.00 GB | 0.00 GB |
| 90 days | 0.00 GB | 0.00 GB |
| 1 year | 0.00 GB | 0.00 GB |
| 3 years | 0.00 GB | 0.00 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
