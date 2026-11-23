---
type: Source Candidates
title: "Candidate sources: Research blogs and news"
description: "Candidate newsroom and vendor research feeds."
tags: [sources, candidates, research-and-news]
status: draft
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-04T14:00:00Z }
---

# Candidates

Probe = HTTP result fetching the feed with Night Desk's own User-Agent on 2026-11-04 ("key" means it needs a free or paid key and was not fetched). Size per fetch is measured where probed and estimated otherwise. Runs/day is a suggested cadence. Lake/day counts raw plus normalised copies of every fetch; the 1-year columns assume that cadence with no compression. Trust tiers are defined in [trust model](/sources/trust-model.md).

| Source | Provider | Trust | Access | Probe | Size/fetch | Runs/day | Lake/day | Lake 1y | DuckDB 1y | Why add it | Corroborates |
|---|---|---|---|---|---|---|---|---|---|---|---|
| [The Record (Recorded Future News)](https://therecord.media/) | Recorded Future | B | none | 200; added as news_therecord | 6 KB | 72 | 0.9 MB | 0.32 GB | 0.00 GB | Dedicated cyber newsroom with named sources. | BleepingComputer, SecurityWeek |
| [SecurityWeek](https://www.securityweek.com/) | SecurityWeek | B | none | 200; added as news_securityweek | 13 KB | 72 | 1.9 MB | 0.68 GB | 0.00 GB | Broad vulnerability and incident coverage. | The Hacker News |
| [Dark Reading](https://www.darkreading.com/) | Informa TechTarget | B | none | 200; added as news_darkreading | 78 KB | 72 | 11.2 MB | 4.10 GB | 0.00 GB | Industry news and analysis. | SecurityWeek |
| [Help Net Security](https://www.helpnetsecurity.com/) | Help Net Security | B | none | 200; added as news_helpnetsecurity | 18 KB | 72 | 2.6 MB | 0.95 GB | 0.00 GB | Daily vulnerability and product security news. | SecurityWeek |
| [CyberScoop](https://cyberscoop.com/) | Scoop News Group | B | none | 200; added as news_cyberscoop | 66 KB | 72 | 9.5 MB | 3.47 GB | 0.00 GB | Policy, government and nation-state reporting. | The Record |
| [Cisco Talos blog](https://blog.talosintelligence.com/) | Cisco Talos | B | none | 200; added as news_talos | 1,026 KB | 12 | 24.6 MB | 8.99 GB | 0.00 GB | Primary threat research with IOCs. | Unit 42, GTIG |
| [Unit 42](https://unit42.paloaltonetworks.com/) | Palo Alto Networks | B | none | 200; added as news_unit42 | 24 KB | 12 | 0.6 MB | 0.21 GB | 0.00 GB | Primary threat research with IOCs. | Talos |
| [Google Threat Intelligence Group blog](https://cloud.google.com/blog/topics/threat-intelligence) | Google (Mandiant + TAG) | B | none | 200 (HTML at feed URL; needs correct feed path) | 190 KB | 12 | 4.6 MB | 1.66 GB | 0.00 GB | Nation-state and zero-day research. | Microsoft Threat Intelligence |
| [Microsoft Threat Intelligence blog](https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/) | Microsoft | B | none | 200; added as news_mstic | 494 KB | 12 | 11.9 MB | 4.33 GB | 0.00 GB | Actor tracking (Storm-xxxx, Typhoon...) and campaign reports. | GTIG |
| [ESET Research (WeLiveSecurity)](https://www.welivesecurity.com/en/eset-research/) | ESET | B | none | 200; added as news_eset | 70 KB | 12 | 1.7 MB | 0.61 GB | 0.00 GB | APT and malware research, strong on Eastern Europe. | Talos, Check Point Research |
| [Elastic Security Labs](https://www.elastic.co/security-labs/) | Elastic | B | none | 200; added as news_elastic | 8,415 KB | 4 | 67.3 MB | 25 GB | 0.00 GB | Malware and detection-engineering research. | Talos, Unit 42 |
| [Check Point Research](https://research.checkpoint.com/) | Check Point Software | B | none | 202 AWS WAF challenge (blocks automated clients); skipped | 275 KB | ≤1 | 0.0 MB | 0.00 GB | 0.00 GB | Primary threat research; off until it serves automated clients. | ESET, Talos |
| [SentinelLabs](https://www.sentinelone.com/labs/) | SentinelOne | B | none | feed 200, articles 429 Vercel Security Checkpoint; skipped | 241 KB | ≤1 | 0.0 MB | 0.00 GB | 0.00 GB | Primary threat research; article pages sit behind a bot check. | Unit 42 |
| [Securelist (Kaspersky)](https://securelist.com/) | Kaspersky | B | none | connection refused; skipped | 0 KB | ≤1 | 0.0 MB | 0.00 GB | 0.00 GB | APT research; unreachable from this network. | ESET |
| [Sophos X-Ops](https://news.sophos.com/en-us/category/threat-research/) | Sophos | B | none | timeout (30 s); skipped | 0 KB | ≤1 | 0.0 MB | 0.00 GB | 0.00 GB | Threat research; feed timed out on every probe. | Talos |
| [MSRC blog](https://msrc.microsoft.com/blog/) | Microsoft | A | none | 200 (HTML; RSS path changed) | 93 KB | 4 | 0.7 MB | 0.27 GB | 0.00 GB | Microsoft's incident disclosures. | MSRC CVRF |

Category total if all were added at the suggested cadence: about 137 MB/day in the lake (50 GB/year uncompressed) and 0.0 MB/day in DuckDB.
