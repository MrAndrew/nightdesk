---
type: Source Catalog
title: Source catalog
description: Every source Night Desk ingests today and every candidate found in the 2026-11-04 search, with trust tier, access requirements and daily storage.
tags: [sources, catalog]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-20T03:00:00Z }
---

# Current (32)

| Source | Category | Mode | Trust | Access | In app | Lake/day (as built) |
|---|---|---|---|---|---|---|
| [CISA Known Exploited Vulnerabilities](/sources/current/cisa_kev.md) | vuln | batch | A | none | on | 0.11 MB |
| [NVD — newly published CVEs](/sources/current/nvd_recent.md) | vuln | batch | A | none (optional free key raises rate limit) | on | 0.34 MB |
| [Feodo Tracker botnet C2](/sources/current/feodo_c2.md) | threat | batch | B | none | on | 0.00 MB |
| [DShield top attacking IPs](/sources/current/dshield_top.md) | threat | batch | B | none | off | 0.60 MB |
| [Tor exit nodes](/sources/current/tor_exits.md) | infra | batch | A | none | on | 0.00 MB |
| [blocklist.de attackers](/sources/current/blocklist_de.md) | threat | batch | C | none | off | 0.17 MB |
| [CINS Army bad actors](/sources/current/cins_army.md) | threat | batch | C | none | off | 0.05 MB |
| [Emerging Threats compromised hosts](/sources/current/et_compromised.md) | threat | batch | B | none | off | 0.01 MB |
| [Spamhaus DROP hijacked netblocks](/sources/current/spamhaus_drop.md) | threat | batch | A | none (terms of use apply) | off | 0.00 MB |
| [Ransomware leak-site victims](/sources/current/ransomware_live.md) | threat | batch | C | blocked for automated clients (paid API available) | off | 0.13 MB |
| [IODA internet outages](/sources/current/ioda_outages.md) | infra | batch | B | none | off | 0.84 MB |
| [Security news wire](/sources/current/security_news.md) | news | batch | B | none | on | 0.10 MB |
| [CISA cybersecurity advisories](/sources/current/cisa_advisories.md) | vuln | batch | A | none (CSAF repository on GitHub) | on | 0.00 MB |
| [RIPE RIS Live — live updates for watched networks](/sources/current/ris_live.md) | advanced | stream | A | none | off (watchlist only) | — |
| [RPKI signed routes (daily file)](/sources/current/rpki_roas.md) | infra | batch | A | none | off (ask); Routing watch asks | small (watched ROAs only) |
| [Cloudflare Radar — BGP hijacks and leaks](/sources/current/cf_radar_bgp.md) | infra | batch | B | own token | on with a token | small (matched events only) |
| [RIPEstat — lookups for the networks you watch](/sources/current/ripestat.md) | infra | batch | A | none | off (opt-in) | small |
| [Bluesky firehose — cyber chatter](/sources/current/bluesky_cyber.md) | social | stream | D | none | off | 0.08 MB |
| [FIRST EPSS exploit prediction scores](/sources/current/epss.md) | vuln | batch | B | none | on | 0.02 MB |
| [ThreatFox malware IOCs](/sources/current/threatfox.md) | threat | batch | B | free Auth-Key (ABUSECH_AUTH_KEY) | off | 1.92 MB |
| [URLhaus malware URLs](/sources/current/urlhaus.md) | threat | batch | B | free Auth-Key (ABUSECH_AUTH_KEY) | off | 1.68 MB |
| [SSL Blacklist (C2 certificates)](/sources/current/sslbl.md) | threat | batch | B | none | on | 0.01 MB |
| [The Record](/sources/current/news_therecord.md) | news | batch | B | none | on | 0.01 MB |
| [SecurityWeek](/sources/current/news_securityweek.md) | news | batch | B | none | on | 0.03 MB |
| [Help Net Security](/sources/current/news_helpnetsecurity.md) | news | batch | C | none | on | 0.03 MB |
| [CyberScoop](/sources/current/news_cyberscoop.md) | news | batch | B | none | on | 0.06 MB |
| [Dark Reading](/sources/current/news_darkreading.md) | news | batch | B | none | on | 0.03 MB |
| [Cisco Talos](/sources/current/news_talos.md) | news | batch | B | none | on | 0.05 MB |
| [Unit 42](/sources/current/news_unit42.md) | news | batch | B | none | on | 0.01 MB |
| [Microsoft Threat Intelligence](/sources/current/news_mstic.md) | news | batch | B | none | on | 0.02 MB |
| [ESET Research](/sources/current/news_eset.md) | news | batch | B | none | on | 0.01 MB |
| [Elastic Security Labs](/sources/current/news_elastic.md) | news | batch | B | none | on | 0.07 MB |

# Candidates (81)

| Source | Category | Trust | Access | Probe 2026-11-04 | Lake/day (suggested cadence, uncompressed) |
|---|---|---|---|---|---|
| [CVE List V5 (CVE.org)](/sources/candidates/vulnerabilities.md) | vulnerabilities | A | none | 200 | 4.8 MB |
| [CISA Vulnrichment](/sources/candidates/vulnerabilities.md) | vulnerabilities | A | none | 200 | 4.0 MB |
| [ENISA EU Vulnerability Database (EUVD)](/sources/candidates/vulnerabilities.md) | vulnerabilities | A | none | 200 | 0.2 MB |
| [GitHub Advisory Database](/sources/candidates/vulnerabilities.md) | vulnerabilities | B | none (git) / free token (API) | 200 | 6.4 MB |
| [OSV.dev](/sources/candidates/vulnerabilities.md) | vulnerabilities | B | none | 200 | 8.0 MB |
| [Exploit-DB](/sources/candidates/vulnerabilities.md) | vulnerabilities | B | none | 200 | 20.4 MB |
| [Metasploit module metadata](/sources/candidates/vulnerabilities.md) | vulnerabilities | B | none | 200 | 22.8 MB |
| [Nuclei templates (CVE index)](/sources/candidates/vulnerabilities.md) | vulnerabilities | C | none | 200 | 4.6 MB |
| [Project Zero 0day In-the-Wild](/sources/candidates/vulnerabilities.md) | vulnerabilities | A | none | 200 | 0.1 MB |
| [CERT/CC Vulnerability Notes](/sources/candidates/vulnerabilities.md) | vulnerabilities | A | none | 200 | 1.5 MB |
| [MSRC security update guide (CVRF)](/sources/candidates/vulnerabilities.md) | vulnerabilities | A | none | 200 | 0.4 MB |
| [JVN iPedia](/sources/candidates/vulnerabilities.md) | vulnerabilities | A | none | 503 (retry) | 0.5 MB |
| [VulnCheck KEV](/sources/candidates/vulnerabilities.md) | vulnerabilities | B | free community key | key | 16.0 MB |
| [IPsum](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | C | none | 200 | 4.5 MB |
| [FireHOL level 1-3](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | C | none | 200 | 1.8 MB |
| [Spamhaus DROP v6 and ASN-DROP](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | A | none | 200 | 0.2 MB |
| [SANS ISC intel feed](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | B | none | 200 | 11.9 MB |
| [SANS ISC research scanners](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | B | none | 200 | 2.8 MB |
| [DShield top /24 blocks](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | B | none | 200 | 0.1 MB |
| [abuse.ch MalwareBazaar](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | B | free Auth-Key | key (410 without) | 6.4 MB |
| [Feodo Tracker aggressive list](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | B | none | 200 | 5.0 MB |
| [C2IntelFeeds](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | C | none | 200 | 0.1 MB |
| [ThreatView.io feeds](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | C | none | 200 | 0.8 MB |
| [Emerging Threats block IPs](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | B | none | 200 | 0.2 MB |
| [Binary Defense banlist](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | C | none | 200 | 0.1 MB |
| [CIRCL OSINT MISP feed](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | A | none | 200 | 11.4 MB |
| [Botvrij.eu MISP feed](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | C | none | 200 | 2.8 MB |
| [OpenPhish community feed](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | B | none | 200 | 0.4 MB |
| [Tweetfeed](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | D | none | 200 | 2.4 MB |
| [AlienVault OTX](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | C | free key | key | 14.4 MB |
| [AbuseIPDB blacklist](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | C | free key (10k IPs/day list) | key | 0.8 MB |
| [GreyNoise community API](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | B | free key (lookups only) | key | 1.0 MB |
| [Shadowserver reports](/sources/candidates/threat-infrastructure.md) | threat-infrastructure | A | vetted registration (free for network owners/CERTs) | registration | 40.0 MB |
| [RansomLook](/sources/candidates/ransomware.md) | ransomware | C | none | 200 | 6.6 MB |
| [ransomware.live PRO API](/sources/candidates/ransomware.md) | ransomware | C | paid key | 403/404 (public) | 11.5 MB |
| [ransomwatch](/sources/candidates/ransomware.md) | ransomware | C | none | 200 but stale (last post 2025-06-16) | 0.0 MB |
| [DataBreaches.net](/sources/candidates/ransomware.md) | ransomware | C | none | 200 | 0.4 MB |
| [HHS OCR breach portal](/sources/candidates/ransomware.md) | ransomware | A | none (form-based export) | 200 | 1.0 MB |
| [Have I Been Pwned breach list](/sources/candidates/ransomware.md) | ransomware | B | none (breach list endpoint) | 200 | 2.3 MB |
| [Cloudflare Radar API](/sources/candidates/internet-infrastructure.md) | internet-infrastructure | B | free API token | key (400 without) | 57.6 MB |
| [IODA raw signals](/sources/candidates/internet-infrastructure.md) | internet-infrastructure | B | none | 200 | 2.5 MB |
| [GRIP BGP hijack detection](/sources/candidates/internet-infrastructure.md) | internet-infrastructure | B | restricted (403 to automated clients) | 403 | 9.6 MB |
| [RIPEstat Data API](/sources/candidates/internet-infrastructure.md) | internet-infrastructure | A | none | 200 | 20.0 MB |
| [RIPE Atlas](/sources/candidates/internet-infrastructure.md) | internet-infrastructure | A | none for public results | not probed | 24.0 MB |
| [RouteViews](/sources/candidates/internet-infrastructure.md) | internet-infrastructure | A | none | not probed | 0.0 MB |
| [PeeringDB](/sources/candidates/internet-infrastructure.md) | internet-infrastructure | B | none | 200 | 8.4 MB |
| [CAIDA AS Rank](/sources/candidates/internet-infrastructure.md) | internet-infrastructure | A | none | 200 | 1.0 MB |
| [RIR delegation files](/sources/candidates/internet-infrastructure.md) | internet-infrastructure | A | none | 200 | 16.8 MB |
| [Tor Onionoo](/sources/candidates/internet-infrastructure.md) | internet-infrastructure | A | none | 200 | 30.0 MB |
| [Certificate Transparency (crt.sh / CT logs)](/sources/candidates/internet-infrastructure.md) | internet-infrastructure | A | none | crt.sh timeout; log list 200 | 0.1 MB |
| [NCSC UK](/sources/candidates/advisories.md) | advisories | A | none | 200 | 0.3 MB |
| [CERT-EU security advisories](/sources/candidates/advisories.md) | advisories | A | none | 200 | 0.2 MB |
| [CERT-FR (ANSSI)](/sources/candidates/advisories.md) | advisories | A | none | 200 | 0.6 MB |
| [BSI CERT-Bund WID](/sources/candidates/advisories.md) | advisories | A | none | 200 | 3.2 MB |
| [Canadian Centre for Cyber Security](/sources/candidates/advisories.md) | advisories | A | none | 200 | 3.7 MB |
| [JPCERT/CC](/sources/candidates/advisories.md) | advisories | A | none | 200 | 0.0 MB |
| [ACSC (Australia)](/sources/candidates/advisories.md) | advisories | A | none | timeout (retry) | 0.5 MB |
| [Cisco PSIRT](/sources/candidates/advisories.md) | advisories | A | none (RSS) / free key (openVuln API) | 200 | 1.2 MB |
| [Fortinet PSIRT](/sources/candidates/advisories.md) | advisories | A | none | 200 | 0.4 MB |
| [Palo Alto Networks advisories](/sources/candidates/advisories.md) | advisories | A | none | 200 | 0.1 MB |
| [MITRE ATT&CK (STIX)](/sources/candidates/advisories.md) | advisories | A | none | 200 | 3.3 MB |
| [Malpedia](/sources/candidates/advisories.md) | advisories | B | none (families list) | 200 | 0.1 MB |
| [The Record (Recorded Future News)](/sources/candidates/research-and-news.md) | research-and-news | B | none | 200; added as news_therecord | 0.9 MB |
| [SecurityWeek](/sources/candidates/research-and-news.md) | research-and-news | B | none | 200; added as news_securityweek | 1.9 MB |
| [Dark Reading](/sources/candidates/research-and-news.md) | research-and-news | B | none | 200; added as news_darkreading | 11.2 MB |
| [Help Net Security](/sources/candidates/research-and-news.md) | research-and-news | B | none | 200; added as news_helpnetsecurity | 2.6 MB |
| [CyberScoop](/sources/candidates/research-and-news.md) | research-and-news | B | none | 200; added as news_cyberscoop | 9.5 MB |
| [Cisco Talos blog](/sources/candidates/research-and-news.md) | research-and-news | B | none | 200; added as news_talos | 24.6 MB |
| [Unit 42](/sources/candidates/research-and-news.md) | research-and-news | B | none | 200; added as news_unit42 | 0.6 MB |
| [Google Threat Intelligence Group blog](/sources/candidates/research-and-news.md) | research-and-news | B | none | 200 (HTML at feed URL; needs correct feed path) | 4.6 MB |
| [Microsoft Threat Intelligence blog](/sources/candidates/research-and-news.md) | research-and-news | B | none | 200; added as news_mstic | 11.9 MB |
| [ESET Research (WeLiveSecurity)](/sources/candidates/research-and-news.md) | research-and-news | B | none | 200; added as news_eset | 1.7 MB |
| [Elastic Security Labs](/sources/candidates/research-and-news.md) | research-and-news | B | none | 200; added as news_elastic | 67.3 MB |
| [Check Point Research](/sources/candidates/research-and-news.md) | research-and-news | B | none | 202 AWS WAF challenge (blocks automated clients); skipped | 0.0 MB |
| [SentinelLabs](/sources/candidates/research-and-news.md) | research-and-news | B | none | feed 200, articles 429 Vercel Security Checkpoint; skipped | 0.0 MB |
| [Securelist (Kaspersky)](/sources/candidates/research-and-news.md) | research-and-news | B | none | connection refused; skipped | 0.0 MB |
| [Sophos X-Ops](/sources/candidates/research-and-news.md) | research-and-news | B | none | timeout (30 s); skipped | 0.0 MB |
| [MSRC blog](/sources/candidates/research-and-news.md) | research-and-news | A | none | 200 (HTML; RSS path changed) | 0.7 MB |
| [Mastodon (infosec.exchange)](/sources/candidates/social.md) | social | D | free account token (public tag timelines disabled) | 422 without token | 34.6 MB |
| [Reddit r/netsec](/sources/candidates/social.md) | social | D | none (RSS) | 200 | 3.6 MB |
| [Hacker News (Algolia API)](/sources/candidates/social.md) | social | D | none | 200 | 2.8 MB |

Storage totals and retention scenarios are in [storage estimates](/data/storage-estimates.md).
