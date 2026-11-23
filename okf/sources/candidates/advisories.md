---
type: Source Candidates
title: "Candidate sources: Government and vendor advisories"
description: "Candidate government CERT and vendor PSIRT advisory feeds, plus reference taxonomies."
tags: [sources, candidates, advisories]
status: draft
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-04T14:00:00Z }
---

# Candidates

Probe = HTTP result fetching the feed with Night Desk's own User-Agent on 2026-11-04 ("key" means it needs a free or paid key and was not fetched). Size per fetch is measured where probed and estimated otherwise. Runs/day is a suggested cadence. Lake/day counts raw plus normalised copies of every fetch; the 1-year columns assume that cadence with no compression. Trust tiers are defined in [trust model](/sources/trust-model.md).

| Source | Provider | Trust | Access | Probe | Size/fetch | Runs/day | Lake/day | Lake 1y | DuckDB 1y | Why add it | Corroborates |
|---|---|---|---|---|---|---|---|---|---|---|---|
| [NCSC UK](https://www.ncsc.gov.uk/) | UK National Cyber Security Centre | A | none | 200 | 11 KB | 12 | 0.3 MB | 0.10 GB | 0.00 GB | UK government alerts and guidance. | CISA, CERT-EU |
| [CERT-EU security advisories](https://cert.europa.eu/publications/security-advisories) | CERT-EU | A | none | 200 | 10 KB | 12 | 0.2 MB | 0.09 GB | 0.00 GB | EU institutions' CERT; high-signal advisories. | CISA, NCSC UK |
| [CERT-FR (ANSSI)](https://www.cert.ssi.gouv.fr/) | ANSSI, France | A | none | 200 | 23 KB | 12 | 0.6 MB | 0.20 GB | 0.00 GB | French national alerts and advisories. | CERT-EU, BSI |
| [BSI CERT-Bund WID](https://wid.cert-bund.de/) | BSI, Germany | A | none | 200 | 135 KB | 12 | 3.2 MB | 1.18 GB | 0.01 GB | German federal advisories with severity ratings. | CERT-FR |
| [Canadian Centre for Cyber Security](https://www.cyber.gc.ca/) | CCCS, Canada | A | none | 200 | 155 KB | 12 | 3.7 MB | 1.36 GB | 0.00 GB | Canadian national alerts and vendor advisory roundups. | CISA |
| [JPCERT/CC](https://www.jpcert.or.jp/english/) | JPCERT/CC, Japan | A | none | 200 | 3 KB | 4 | 0.0 MB | 0.01 GB | 0.00 GB | Japanese national alerts. | JVN |
| [ACSC (Australia)](https://www.cyber.gov.au/) | Australian Signals Directorate | A | none | timeout (retry) | 20 KB | 12 | 0.5 MB | 0.18 GB | 0.00 GB | Australian national alerts. | CISA |
| [Cisco PSIRT](https://sec.cloudapps.cisco.com/security/center/publicationListing.x) | Cisco | A | none (RSS) / free key (openVuln API) | 200 | 147 KB | 4 | 1.2 MB | 0.43 GB | 0.00 GB | First-party advisories for the most-targeted network vendor. | NVD, KEV |
| [Fortinet PSIRT](https://www.fortiguard.com/psirt) | Fortinet | A | none | 200 | 49 KB | 4 | 0.4 MB | 0.14 GB | 0.00 GB | First-party advisories; Fortinet bugs are KEV regulars. | NVD, KEV |
| [Palo Alto Networks advisories](https://security.paloaltonetworks.com/) | Palo Alto Networks | A | none | 200 | 8 KB | 4 | 0.1 MB | 0.02 GB | 0.00 GB | First-party advisories for PAN-OS and Prisma. | NVD, KEV |
| [MITRE ATT&CK (STIX)](https://github.com/mitre-attack/attack-stix-data) | MITRE | A | none | 200 | 55,271 KB | ≤1 | 3.3 MB | 1.21 GB | 0.00 GB | Reference taxonomy of techniques, groups and software; tags events with TTPs. | Malpedia |
| [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) | Fraunhofer FKIE | B | none (families list) | 200 | 60 KB | 1 | 0.1 MB | 0.04 GB | 0.00 GB | Reference names and aliases for malware families; normalises ThreatFox/Feodo family names. | ATT&CK |

Category total if all were added at the suggested cadence: about 14 MB/day in the lake (4.96 GB/year uncompressed) and 0.0 MB/day in DuckDB.
