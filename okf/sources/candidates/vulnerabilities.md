---
type: Source Candidates
title: "Candidate sources: Vulnerabilities and exploitation"
description: "Candidate feeds for CVEs, exploitation evidence and exploit availability."
tags: [sources, candidates, vulnerabilities]
status: draft
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-04T14:00:00Z }
---

# Candidates

Probe = HTTP result fetching the feed with Night Desk's own User-Agent on 2026-11-04 ("key" means it needs a free or paid key and was not fetched). Size per fetch is measured where probed and estimated otherwise. Runs/day is a suggested cadence. Lake/day counts raw plus normalised copies of every fetch; the 1-year columns assume that cadence with no compression. Trust tiers are defined in [trust model](/sources/trust-model.md).

| Source | Provider | Trust | Access | Probe | Size/fetch | Runs/day | Lake/day | Lake 1y | DuckDB 1y | Why add it | Corroborates |
|---|---|---|---|---|---|---|---|---|---|---|---|
| [CVE List V5 (CVE.org)](https://github.com/CVEProject/cvelistV5) | CVE Program / MITRE | A | none | 200 | 37,071 KB | 4 | 4.8 MB | 1.75 GB | 0.03 GB | Authoritative CVE records, published before NVD enrichment; use deltaLog.json for incremental pulls. | NVD |
| [CISA Vulnrichment](https://github.com/cisagov/vulnrichment) | CISA | A | none | 200 | 500 KB | 4 | 4.0 MB | 1.46 GB | 0.03 GB | CISA's SSVC decisions and CWE/CVSS added to new CVEs. | NVD, CVE List |
| [ENISA EU Vulnerability Database (EUVD)](https://euvd.enisa.europa.eu/) | ENISA | A | none | 200 | 5 KB | 24 | 0.2 MB | 0.09 GB | 0.01 GB | EU's official vulnerability database with its own exploited list; independent of NVD. | KEV, NVD |
| [GitHub Advisory Database](https://github.com/github/advisory-database) | GitHub | B | none (git) / free token (API) | 200 | 800 KB | 4 | 6.4 MB | 2.34 GB | 0.01 GB | Package-level advisories with affected version ranges. | OSV, NVD |
| [OSV.dev](https://osv.dev/) | Google Open Source Security | B | none | 200 | 157,800 KB | 1 | 8.0 MB | 2.92 GB | 0.04 GB | Aggregates GHSA, PyPA, Go, RustSec and distro advisories in one schema. | GHSA, NVD |
| [Exploit-DB](https://gitlab.com/exploit-database/exploitdb) | OffSec | B | none | 200 | 10,185 KB | 1 | 20.4 MB | 7.44 GB | 0.00 GB | Public exploit code mapped to CVEs; a strong 'weaponised' signal. | Metasploit, Nuclei |
| [Metasploit module metadata](https://github.com/rapid7/metasploit-framework) | Rapid7 | B | none | 200 | 11,413 KB | 1 | 22.8 MB | 8.33 GB | 0.00 GB | CVEs with a ready-made Metasploit module. | Exploit-DB, Nuclei |
| [Nuclei templates (CVE index)](https://github.com/projectdiscovery/nuclei-templates) | ProjectDiscovery | C | none | 200 | 2,290 KB | 1 | 4.6 MB | 1.67 GB | 0.00 GB | CVEs with a public mass-scanning template; predicts scanning waves. | Exploit-DB |
| [Project Zero 0day In-the-Wild](https://googleprojectzero.blogspot.com/p/0day.html) | Google Project Zero | A | none | 200 | 60 KB | 1 | 0.1 MB | 0.04 GB | 0.00 GB | Curated list of zero-days exploited in the wild, with root cause analysis. | KEV |
| [CERT/CC Vulnerability Notes](https://kb.cert.org/vuls/) | CERT/CC (Carnegie Mellon SEI) | A | none | 200 | 192 KB | 4 | 1.5 MB | 0.56 GB | 0.00 GB | Coordinated disclosures, often multi-vendor. | NVD |
| [MSRC security update guide (CVRF)](https://api.msrc.microsoft.com/cvrf/v3.0/) | Microsoft | A | none | 200 | 51 KB | 4 | 0.4 MB | 0.15 GB | 0.00 GB | Microsoft's own CVE and exploitation-status data for Patch Tuesday and out-of-band fixes. | NVD, KEV |
| [JVN iPedia](https://jvndb.jvn.jp/en/) | JPCERT/CC and IPA (Japan) | A | none | 503 (retry) | 60 KB | 4 | 0.5 MB | 0.18 GB | 0.00 GB | Japanese national vulnerability database; covers Asian vendors NVD misses. | NVD |
| [VulnCheck KEV](https://vulncheck.com/kev) | VulnCheck | B | free community key | key | 8,000 KB | 1 | 16.0 MB | 5.84 GB | 0.00 GB | Larger exploited-vulnerability list than CISA KEV, with exploitation evidence links. | CISA KEV |

Category total if all were added at the suggested cadence: about 90 MB/day in the lake (33 GB/year uncompressed) and 0.4 MB/day in DuckDB.

# Sizing notes

* **CVE List V5 (CVE.org)**: delta log is 37 MB; the incremental delta files are a few hundred KB per pull.
* **OSV.dev**: modified_id.csv is 158 MB; pull only changed IDs (a few MB/day).
