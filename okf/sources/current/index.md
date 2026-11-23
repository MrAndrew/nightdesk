# Current sources

* [CISA Known Exploited Vulnerabilities](cisa_kev.md) - Every CVE CISA has confirmed is being exploited in the wild, with ransomware use flags and federal patch deadlines.
* [NVD — newly published CVEs](nvd_recent.md) - CVEs published in the last 72 hours with CVSS scores, polled from the NVD 2.0 API.
* [Feodo Tracker botnet C2](feodo_c2.md) - Command-and-control servers for Emotet, Dridex, QakBot and related banking botnets.
* [DShield top attacking IPs](dshield_top.md) - The IPs hitting the most DShield sensors worldwide, ranked by attack count.
* [Tor exit nodes](tor_exits.md) - Current Tor exit relays, the IPs anonymised traffic leaves the Tor network from.
* [blocklist.de attackers](blocklist_de.md) - IPs reported in the last 48h for SSH, mail, web and FTP brute force by fail2ban sensors.
* [CINS Army bad actors](cins_army.md) - IPs with poor reputation scores across the CINS sensor network.
* [Emerging Threats compromised hosts](et_compromised.md) - Hosts Emerging Threats has seen compromised and acting maliciously.
* [Spamhaus DROP hijacked netblocks](spamhaus_drop.md) - Netblocks hijacked or leased by spammers and cyber-criminals. Do not route or peer.
* [Ransomware leak-site victims](ransomware_live.md) - Victims newly posted on ransomware gang leak sites, with group, sector and country. Off by default: enable in Sources. Uses the free v2 API (no key, rate-limited); set RANSOMWARELIVE_API_KEY (+ URL/header) to use an API PRO key for higher limits.
* [IODA internet outages](ioda_outages.md) - Country and network-level internet outages detected from BGP, active probing and darknet telescope signals.
* [Security news wire](security_news.md) - Headlines from major security newsrooms, tagged with the countries they mention.
* [CISA cybersecurity advisories](cisa_advisories.md) - CISA's ICS, ICS medical and IT vulnerability advisories in CSAF 2.0: affected vendors and products, CVEs with CVSS, published and revised dates, linked to the cisa.gov advisory page.
* [RIPE RIS Live — live updates for watched networks](ris_live.md) - Live BGP updates for the routing watchlist only. Off by default (Advanced); never connects without a watchlist.
* [RPKI signed routes (daily file)](rpki_roas.md) - The daily validated-ROA file, filtered locally to the routing watchlist. No stated terms: off until the user says yes.
* [Cloudflare Radar — BGP hijacks and leaks](cf_radar_bgp.md) - Recent hijack and leak events, listed without naming a network and matched locally. Needs the user's own token; CC BY-NC 4.0.
* [RIPEstat — lookups for the networks you watch](ripestat.md) - Origins, visibility, upstreams and update counts per watched network. Off by default: RIPE sees the lookups.
* [Bluesky firehose — cyber chatter](bluesky_cyber.md) - Every public Bluesky post, filtered live for cyber keywords (CVE IDs, ransomware, zero-days, breaches, DDoS, botnets). Posts are tagged with mentioned CVEs and countries.
* [FIRST EPSS exploit prediction scores](epss.md) - Daily probability (0-1) that each CVE will see exploitation activity in the next 30 days, with its percentile, for every scored CVE. Shown next to CVSS and KEV wherever CVEs appear.
* [ThreatFox malware IOCs](threatfox.md) - IOCs (C2 IP:port, domains, URLs, file hashes) tied to named malware families, shared by the abuse.ch community. Needs a free abuse.ch Auth-Key; off by default.
* [URLhaus malware URLs](urlhaus.md) - URLs distributing malware, with their host, online/offline status and tags. Needs a free abuse.ch Auth-Key; off by default.
* [SSL Blacklist (C2 certificates)](sslbl.md) - SHA1 fingerprints of TLS certificates used by botnet C2 servers, with the malware family. Matched against certificate hashes in Zeek and Suricata logs.
* [The Record](news_therecord.md) - Cyber newsroom of Recorded Future: incidents, policy and nation-state reporting with named sources.
* [SecurityWeek](news_securityweek.md) - Broad vulnerability, incident and industry coverage.
* [Help Net Security](news_helpnetsecurity.md) - Daily vulnerability, product security and research news; many items are vendor product announcements.
* [CyberScoop](news_cyberscoop.md) - Policy, government and nation-state reporting.
* [Dark Reading](news_darkreading.md) - Industry news and analysis.
* [Cisco Talos](news_talos.md) - Primary threat research from Cisco Talos, usually with IOCs.
* [Unit 42](news_unit42.md) - Primary threat research from Palo Alto Networks Unit 42, usually with IOCs.
* [Microsoft Threat Intelligence](news_mstic.md) - Actor tracking (Storm-xxxx, Typhoon, Blizzard) and campaign reports.
* [ESET Research](news_eset.md) - ESET's WeLiveSecurity blog: APT and malware research plus security news.
* [Elastic Security Labs](news_elastic.md) - Malware and detection research from Elastic Security Labs. Its list of articles is large (8 MB), so it is read every 6 hours.
