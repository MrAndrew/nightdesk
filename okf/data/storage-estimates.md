---
type: Analysis
title: Storage estimates
description: Disk needed to keep current and candidate sources locally for 30 days, 90 days, 1 year and 3 years, measured with gzipped record and event deltas.
tags: [storage, capacity, data-lake, duckdb]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
stale_after: 2027-02-01T00:00:00Z
---

# Method

* **Uncompressed lake** growth per source = fetches per day × (raw payload + normalised NDJSON), from files written to the owner's live lake (`<lake>/raw`) over the first 8.5 hours of running (2026-11-04). Streams use their measured bytes per day.
* **As built** applies each source's measured *kept* fraction. The lake's first 12 hours of history were replayed through the same record and event comparison the scheduler uses, counting only the gzipped new, changed and removed records. Streams use hourly gzip files. The first full load of each source is a one-time cost of a few MB and is excluded. See [data architecture](/data/architecture.md#what-the-lake-stores).
* **DuckDB** growth = new unique events per day × 610 bytes per row (measured after `CHECKPOINT`: 22,788 rows in 13.9 MB). Repeat sightings of the same IP, CVE or prefix update the row in place, so snapshot feeds grow the database far more slowly than the lake.
* Candidates have no history yet, so they are counted at 10× gzip with every fetch assumed to change completely. Current sources came in 10-2000× lower than that, so this is a deliberately high bound.
* Reference data (GeoIP, ASN, cables, countries) is a fixed ~138 MB and is not included below.

# Current sources

| Source | In app | Cadence | Lake/day uncompressed | Lake/day as built | DuckDB/day | 30 days | 90 days | 1 year | 3 years |
|---|---|---|---|---|---|---|---|---|---|
| [RIPE RIS Live — live updates for watched networks](/sources/current/ris_live.md) | off | continuous | 9.6 MB | 1.25 MB | 9.39 MB | 0.32 GB | 0.96 GB | 3.88 GB | 12 GB |
| [DShield top attacking IPs](/sources/current/dshield_top.md) | off | every 1h | 7.7 MB | 0.60 MB | 4.09 MB | 0.14 GB | 0.42 GB | 1.71 GB | 5.13 GB |
| [ThreatFox malware IOCs](/sources/current/threatfox.md) | off | every 1h | 38.4 MB | 1.92 MB | 0.92 MB | 0.09 GB | 0.26 GB | 1.03 GB | 3.10 GB |
| [URLhaus malware URLs](/sources/current/urlhaus.md) | off | every 1h | 16.8 MB | 1.68 MB | 0.61 MB | 0.07 GB | 0.21 GB | 0.84 GB | 2.51 GB |
| [blocklist.de attackers](/sources/current/blocklist_de.md) | off | every 3h | 26.6 MB | 0.17 MB | 1.34 MB | 0.05 GB | 0.14 GB | 0.55 GB | 1.65 GB |
| [CINS Army bad actors](/sources/current/cins_army.md) | off | every 6h | 8.1 MB | 0.05 MB | 0.92 MB | 0.03 GB | 0.09 GB | 0.35 GB | 1.06 GB |
| [IODA internet outages](/sources/current/ioda_outages.md) | off | every 15m | 77.4 MB | 0.84 MB | 0.09 MB | 0.03 GB | 0.08 GB | 0.34 GB | 1.02 GB |
| [NVD — newly published CVEs](/sources/current/nvd_recent.md) | on | every 2h | 57.9 MB | 0.34 MB | 0.08 MB | 0.01 GB | 0.04 GB | 0.15 GB | 0.45 GB |
| [Bluesky firehose — cyber chatter](/sources/current/bluesky_cyber.md) | off | continuous | 0.4 MB | 0.08 MB | 0.24 MB | 0.01 GB | 0.03 GB | 0.12 GB | 0.36 GB |
| [Ransomware leak-site victims](/sources/current/ransomware_live.md) | off | every 30m | 13.0 MB | 0.13 MB | 0.02 MB | 0.00 GB | 0.01 GB | 0.06 GB | 0.17 GB |
| [Security news wire](/sources/current/security_news.md) | on | every 20m | 24.3 MB | 0.10 MB | 0.03 MB | 0.00 GB | 0.01 GB | 0.05 GB | 0.14 GB |
| [CISA Known Exploited Vulnerabilities](/sources/current/cisa_kev.md) | on | every 6h | 12.7 MB | 0.11 MB | 0.00 MB | 0.00 GB | 0.01 GB | 0.04 GB | 0.13 GB |
| [Elastic Security Labs](/sources/current/news_elastic.md) | on | every 6h | 33.8 MB | 0.07 MB | 0.00 MB | 0.00 GB | 0.01 GB | 0.02 GB | 0.07 GB |
| [Tor exit nodes](/sources/current/tor_exits.md) | on | every 3h | 4.8 MB | 0.00 MB | 0.06 MB | 0.00 GB | 0.01 GB | 0.02 GB | 0.07 GB |
| [CyberScoop](/sources/current/news_cyberscoop.md) | on | every 20m | 5.5 MB | 0.06 MB | 0.00 MB | 0.00 GB | 0.01 GB | 0.02 GB | 0.07 GB |
| [Cisco Talos](/sources/current/news_talos.md) | on | every 2h | 12.4 MB | 0.05 MB | 0.00 MB | 0.00 GB | 0.00 GB | 0.02 GB | 0.06 GB |
| [Help Net Security](/sources/current/news_helpnetsecurity.md) | on | every 20m | 1.7 MB | 0.03 MB | 0.01 MB | 0.00 GB | 0.00 GB | 0.02 GB | 0.05 GB |
| [Dark Reading](/sources/current/news_darkreading.md) | on | every 20m | 8.1 MB | 0.03 MB | 0.01 MB | 0.00 GB | 0.00 GB | 0.02 GB | 0.05 GB |
| [SecurityWeek](/sources/current/news_securityweek.md) | on | every 20m | 1.4 MB | 0.03 MB | 0.01 MB | 0.00 GB | 0.00 GB | 0.01 GB | 0.04 GB |
| [Emerging Threats compromised hosts](/sources/current/et_compromised.md) | off | every 6h | 1.1 MB | 0.01 MB | 0.03 MB | 0.00 GB | 0.00 GB | 0.01 GB | 0.04 GB |
| [Microsoft Threat Intelligence](/sources/current/news_mstic.md) | on | every 2h | 6.0 MB | 0.02 MB | 0.00 MB | 0.00 GB | 0.00 GB | 0.01 GB | 0.03 GB |
| [The Record](/sources/current/news_therecord.md) | on | every 20m | 0.6 MB | 0.01 MB | 0.01 MB | 0.00 GB | 0.00 GB | 0.01 GB | 0.02 GB |
| [FIRST EPSS exploit prediction scores](/sources/current/epss.md) | on | every 3h | 0.0 MB | 0.02 MB | 0.00 MB | 0.00 GB | 0.00 GB | 0.01 GB | 0.02 GB |
| [Unit 42](/sources/current/news_unit42.md) | on | every 2h | 0.4 MB | 0.01 MB | 0.00 MB | 0.00 GB | 0.00 GB | 0.00 GB | 0.01 GB |
| [SSL Blacklist (C2 certificates)](/sources/current/sslbl.md) | on | every 6h | 3.5 MB | 0.01 MB | 0.00 MB | 0.00 GB | 0.00 GB | 0.00 GB | 0.01 GB |
| [ESET Research](/sources/current/news_eset.md) | on | every 2h | 1.3 MB | 0.01 MB | 0.00 MB | 0.00 GB | 0.00 GB | 0.00 GB | 0.01 GB |
| [CISA cybersecurity advisories](/sources/current/cisa_advisories.md) | on | every 2h | 0.5 MB | 0.00 MB | 0.00 MB | 0.00 GB | 0.00 GB | 0.00 GB | 0.01 GB |
| [Spamhaus DROP hijacked netblocks](/sources/current/spamhaus_drop.md) | off | every 1d | 1.0 MB | 0.00 MB | 0.00 MB | 0.00 GB | 0.00 GB | 0.00 GB | 0.00 GB |
| [Feodo Tracker botnet C2](/sources/current/feodo_c2.md) | on | every 1h | 0.1 MB | 0.00 MB | 0.00 MB | 0.00 GB | 0.00 GB | 0.00 GB | 0.00 GB |

Retention columns are as built (lake + DuckDB). **Enabled today:** 0.9 MB/day in the lake (down from 175 MB/day in the original design, 194× less) plus 0.2 MB/day in DuckDB.

# Totals

| Scenario | 30 days | 90 days | 1 year | 3 years |
|---|---|---|---|---|
| Current sources, as built (gzipped deltas, measured) | 0.03 GB | 0.10 GB | 0.41 GB | 1.23 GB |
| Current sources, original design (full uncompressed copy every run) | 5.27 GB | 16 GB | 64 GB | 192 GB |
| Current + all 81 candidates, as built (candidates ~10× gzip) | 2.48 GB | 7.44 GB | 30 GB | 91 GB |
| Current + all candidates, uncompressed | 23 GB | 70 GB | 285 GB | 854 GB |

# Candidate categories

Uncompressed; divide the lake figure by about 10 for as-built storage.

| Category | Sources | Lake/day | DuckDB/day |
|---|---|---|---|
| [Vulnerabilities and exploitation](/sources/candidates/vulnerabilities.md) | 13 | 90 MB | 0.4 MB |
| [Threat infrastructure and indicators](/sources/candidates/threat-infrastructure.md) | 20 | 107 MB | 22.5 MB |
| [Ransomware and extortion](/sources/candidates/ransomware.md) | 6 | 22 MB | 0.1 MB |
| [Internet infrastructure, routing and outages](/sources/candidates/internet-infrastructure.md) | 11 | 170 MB | 0.2 MB |
| [Government and vendor advisories](/sources/candidates/advisories.md) | 12 | 14 MB | 0.0 MB |
| [Research blogs and news](/sources/candidates/research-and-news.md) | 16 | 137 MB | 0.0 MB |
| [Social and community signal](/sources/candidates/social.md) | 3 | 41 MB | 0.2 MB |

# Where the bytes go

* **DuckDB is now nearly all of the growth**, mostly RIS Live's BGP events. The lake adds only a few MB a day.
* Overlapping-window feeds are still fetched in full every run, so late or revised data is caught, but only changed records are stored: NVD 5% and IODA 11% of a gzipped snapshot. IODA's remaining changes are ongoing outages whose duration and score grow each run.
* DShield's top-500 list changes almost entirely every hour, so it gains least.
* Streams are kept as one gzipped file per hour, about 3× smaller than per-flush files.
* The biggest candidate costs are bulk reference datasets (OSV, PeeringDB, RIR files, ATT&CK) if pulled daily in full. With record deltas only their changes would be stored after the first load.

# Recommendations

1. Retention is off by default. At these rates there is little reason to turn it on: 3 years of every current and candidate source fits on a small fraction of one external drive.
2. If disk does matter, set a lake limit in the Sources view. It deletes old files and re-stores still-active records, so the window stays complete.
