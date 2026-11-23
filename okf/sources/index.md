# Overview

* [Source catalog](/sources/catalog.md) - Every current and candidate source in one table, with trust tier, access and storage.
* [Trust model](/sources/trust-model.md) - How sources are graded and how corroboration across sources is used.

# Current sources

* [CISA Known Exploited Vulnerabilities](/sources/current/cisa_kev.md) - Every CVE CISA has confirmed is being exploited in the wild, with ransomware use flags and federal patch deadlines.
* [NVD — newly published CVEs](/sources/current/nvd_recent.md) - CVEs published in the last 72 hours with CVSS scores, polled from the NVD 2.0 API.
* [Feodo Tracker botnet C2](/sources/current/feodo_c2.md) - Command-and-control servers for Emotet, Dridex, QakBot and related banking botnets.
* [DShield top attacking IPs](/sources/current/dshield_top.md) - The IPs hitting the most DShield sensors worldwide, ranked by attack count.
* [Tor exit nodes](/sources/current/tor_exits.md) - Current Tor exit relays, the IPs anonymised traffic leaves the Tor network from.
* [blocklist.de attackers](/sources/current/blocklist_de.md) - IPs reported in the last 48h for SSH, mail, web and FTP brute force by fail2ban sensors.
* [CINS Army bad actors](/sources/current/cins_army.md) - IPs with poor reputation scores across the CINS sensor network.
* [Emerging Threats compromised hosts](/sources/current/et_compromised.md) - Hosts Emerging Threats has seen compromised and acting maliciously.
* [Spamhaus DROP hijacked netblocks](/sources/current/spamhaus_drop.md) - Netblocks hijacked or leased by spammers and cyber-criminals. Do not route or peer.
* [Ransomware leak-site victims](/sources/current/ransomware_live.md) - Victims newly posted on ransomware gang leak sites, with group, sector and country. Off by default: enable in Sources. Uses the free v2 API (no key, rate-limited); set RANSOMWARELIVE_API_KEY (+ URL/header) to use an API PRO key for higher limits.
* [IODA internet outages](/sources/current/ioda_outages.md) - Country and network-level internet outages detected from BGP, active probing and darknet telescope signals.
* [Security news wire](/sources/current/security_news.md) - Headlines from major security newsrooms, tagged with the countries they mention.
* [CISA cybersecurity advisories](/sources/current/cisa_advisories.md) - CISA's ICS, ICS medical and IT vulnerability advisories in CSAF 2.0: affected vendors and products, CVEs with CVSS, published and revised dates, linked to the cisa.gov advisory page.
* [RIPE RIS Live — live updates for watched networks](/sources/current/ris_live.md) - Live BGP updates for the routing watchlist only. Off by default (Advanced); never connects without a watchlist.
* [RPKI signed routes (daily file)](/sources/current/rpki_roas.md) - The daily validated-ROA file, filtered locally to the routing watchlist. No stated terms: off until the user says yes.
* [Cloudflare Radar — BGP hijacks and leaks](/sources/current/cf_radar_bgp.md) - Recent hijack and leak events, listed without naming a network and matched locally. Needs the user's own token; CC BY-NC 4.0.
* [RIPEstat — lookups for the networks you watch](/sources/current/ripestat.md) - Origins, visibility, upstreams and update counts per watched network. Off by default: RIPE sees the lookups.
* [Bluesky firehose — cyber chatter](/sources/current/bluesky_cyber.md) - Every public Bluesky post, filtered live for cyber keywords (CVE IDs, ransomware, zero-days, breaches, DDoS, botnets). Posts are tagged with mentioned CVEs and countries.
* [FIRST EPSS exploit prediction scores](/sources/current/epss.md) - Daily probability (0-1) that each CVE will see exploitation activity in the next 30 days, with its percentile, for every scored CVE. Shown next to CVSS and KEV wherever CVEs appear.
* [ThreatFox malware IOCs](/sources/current/threatfox.md) - IOCs (C2 IP:port, domains, URLs, file hashes) tied to named malware families, shared by the abuse.ch community. Needs a free abuse.ch Auth-Key; off by default.
* [URLhaus malware URLs](/sources/current/urlhaus.md) - URLs distributing malware, with their host, online/offline status and tags. Needs a free abuse.ch Auth-Key; off by default.
* [SSL Blacklist (C2 certificates)](/sources/current/sslbl.md) - SHA1 fingerprints of TLS certificates used by botnet C2 servers, with the malware family. Matched against certificate hashes in Zeek and Suricata logs.
* [The Record](/sources/current/news_therecord.md) - Cyber newsroom of Recorded Future: incidents, policy and nation-state reporting with named sources.
* [SecurityWeek](/sources/current/news_securityweek.md) - Broad vulnerability, incident and industry coverage.
* [Help Net Security](/sources/current/news_helpnetsecurity.md) - Daily vulnerability, product security and research news; many items are vendor product announcements.
* [CyberScoop](/sources/current/news_cyberscoop.md) - Policy, government and nation-state reporting.
* [Dark Reading](/sources/current/news_darkreading.md) - Industry news and analysis.
* [Cisco Talos](/sources/current/news_talos.md) - Primary threat research from Cisco Talos, usually with IOCs.
* [Unit 42](/sources/current/news_unit42.md) - Primary threat research from Palo Alto Networks Unit 42, usually with IOCs.
* [Microsoft Threat Intelligence](/sources/current/news_mstic.md) - Actor tracking (Storm-xxxx, Typhoon, Blizzard) and campaign reports.
* [ESET Research](/sources/current/news_eset.md) - ESET's WeLiveSecurity blog: APT and malware research plus security news.
* [Elastic Security Labs](/sources/current/news_elastic.md) - Malware and detection research from Elastic Security Labs. Its list of articles is large (8 MB), so it is read every 6 hours.

# Candidate sources

* [Vulnerabilities and exploitation](/sources/candidates/vulnerabilities.md) - Candidate feeds for CVEs, exploitation evidence and exploit availability. (13 sources)
* [Threat infrastructure and indicators](/sources/candidates/threat-infrastructure.md) - Candidate feeds of malicious IPs, C2 servers, URLs and IOCs, plus enrichment services. (20 sources)
* [Ransomware and extortion](/sources/candidates/ransomware.md) - Candidate feeds of ransomware leak-site posts and verified breach disclosures. (6 sources)
* [Internet infrastructure, routing and outages](/sources/candidates/internet-infrastructure.md) - Candidate feeds for routing, outages, DDoS and reference data about networks. (11 sources)
* [Government and vendor advisories](/sources/candidates/advisories.md) - Candidate government CERT and vendor PSIRT advisory feeds, plus reference taxonomies. (12 sources)
* [Research blogs and news](/sources/candidates/research-and-news.md) - Candidate newsroom and vendor research feeds. (16 sources)
* [Social and community signal](/sources/candidates/social.md) - Candidate community and social channels for early signal. (3 sources)
