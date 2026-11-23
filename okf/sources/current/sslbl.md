---
type: Data Source
title: "SSL Blacklist (C2 certificates)"
description: "SHA1 fingerprints of TLS certificates used by botnet C2 servers, with the malware family. Matched against certificate hashes in Zeek and Suricata logs."
resource: https://sslbl.abuse.ch/
tags: [threat, batch, current]
provider: "abuse.ch"
mode: batch
cadence: "every 6h"
trust_tier: B
auth: "none"
license: "CC0 (abuse.ch Terms of Use s3.4)"
in_app: on by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

SHA1 fingerprints of TLS certificates used by botnet C2 servers, with the malware family. Matched against certificate hashes in Zeek and Suricata logs.

| | |
|---|---|
| Source id | `sslbl` |
| Provider | abuse.ch |
| Mode | batch (every 6h) |
| Trust tier | B: Established research group, nonprofit or vendor with a published methodology and track record |
| Access | none |
| License | CC0 (abuse.ch Terms of Use s3.4) |
| Status in Night Desk | on by default |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: ThreatFox (C2 servers of the same families), Censys and JARM/JA3S certificate fingerprints.

# Terms

Read 2026-11-19 ([terms](https://abuse.ch/terms-of-use/)): abuse.ch Terms of Use (updated 2026-10-21) s3.4: Feodo Tracker and SSLBL data are "free to use without limitations ... (CC0)"; s7.3 forbids using abuse.ch data to "customise, train, or otherwise improve any artificial intelligence model" and has no CC0 carve-out, so the source is `ai_ok = False` (kept out of every prompt and embedding).

Commercial use: yes. Redistribution: yes. AI use: no (unclear: s7.3, no CC0 carve-out).

# Access and terms

No key. The certificate list is CC0 (abuse.ch Terms of Use s3.4). It regenerates every 5 minutes and abuse.ch asks not to fetch more often; it changes a few times a day, so the source runs every 6 hours. Although the data is CC0, the source is also `ai_ok = False`, to keep every abuse.ch dataset on one rule.

# What is ingested

`sslblacklist.csv`: listing date, certificate SHA1 and listing reason ("Dridex C&C"), 11,202 rows on 2026-11-09 going back to 2014. It is a list (`windowed = False`): a fingerprint that disappears was removed.

* **Certificates are indicators, not activity.** Every row is a record and a netlog indicator, but no row becomes an event, an entity, a mention or a claim. Events are one summary per family with a listing in the last 365 days (kind `c2_cert`, key = family, `value` = certificates listed, `ts` = the latest listing): "Vidar: 731 C2 TLS certificates on SSL Blacklist". Listing reasons that are not family names ("Malware C&C", "Malware distribution", a domain such as "doxbin.cy", long phrases) give no summary.
* Not used: `sslipblacklist.csv` (botnet C2 IP:port) was deprecated on 2025-01-03 and is now an empty header (checked 2026-11-09), and the `.txt` variant is gone too. `ja3_fingerprints.csv` is skipped: abuse.ch warns of many false positives, and Zeek and Suricata compute JA3 only with extra configuration.

# In the app

* **Network logs.** Each fingerprint is a `hash` indicator, category `c2`, listed from its SSLBL listing date. It matches Zeek `files.log` `sha1` (Zeek's file analysis hashes the certificates it sees) and Suricata `tls.fingerprint` (SHA1 with colons, the default). Zeek's `x509.log` `fingerprint` and `ssl.log` `cert_chain_fps` are SHA256 on current Zeek, so they match only on a sensor configured for SHA1. A home device receiving a listed certificate is a high alert.
* **Entities.** A family summary event adds `attrs.sslbl_certificates` and `attrs.sslbl_last_listed` to a family the catalogue already knows (`CobaltStrike` is Cobalt Strike, `PureLogsStealer` is PureLogs Stealer), with one mention per family. Names the catalogue does not know make no entity.
* **Panels.** One summary event per family, so Top Offenders' tag ranking sees each family once, not once per certificate.
* **Explorer** lists the family summaries; the individual fingerprints are in the lake's record files and in `indicator_intervals`.

# Storage

844 KB raw + 40 KB normalised per run (estimated), or 3.5 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 0.20% of it (0.01 MB/day, measured). DuckDB grows only by new unique events (about 1 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.00 GB | 0.00 GB |
| 90 days | 0.00 GB | 0.00 GB |
| 1 year | 0.00 GB | 0.00 GB |
| 3 years | 0.01 GB | 0.00 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
