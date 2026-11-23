---
type: Source Candidates
title: "Candidate sources: Threat infrastructure and indicators"
description: "Candidate feeds of malicious IPs, C2 servers, URLs and IOCs, plus enrichment services."
tags: [sources, candidates, threat-infrastructure]
status: draft
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-04T14:00:00Z }
---

# Candidates

Probe = HTTP result fetching the feed with Night Desk's own User-Agent on 2026-11-04 ("key" means it needs a free or paid key and was not fetched). Size per fetch is measured where probed and estimated otherwise. Runs/day is a suggested cadence. Lake/day counts raw plus normalised copies of every fetch; the 1-year columns assume that cadence with no compression. Trust tiers are defined in [trust model](/sources/trust-model.md).

| Source | Provider | Trust | Access | Probe | Size/fetch | Runs/day | Lake/day | Lake 1y | DuckDB 1y | Why add it | Corroborates |
|---|---|---|---|---|---|---|---|---|---|---|---|
| [IPsum](https://github.com/stamparm/ipsum) | stamparm (Miroslav Štampar) | C | none | 200 | 2,254 KB | 1 | 4.5 MB | 1.65 GB | 4.45 GB | Daily list of about 140k IPs scored by how many of 30+ blocklists include them. Built-in corroboration count. | all IP lists |
| [FireHOL level 1-3](https://github.com/firehol/blocklist-ipsets) | FireHOL | C | none | 200 | 225 KB | 4 | 1.8 MB | 0.66 GB | 0.11 GB | Curated aggregate netsets with low false-positive levels. | Spamhaus, DShield, Feodo |
| [Spamhaus DROP v6 and ASN-DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | Spamhaus | A | none | 200 | 46 KB | 2 | 0.2 MB | 0.07 GB | 0.00 GB | Adds IPv6 hijacked ranges and whole criminal ASNs to the DROP list we already ingest. | Spamhaus DROP |
| [SANS ISC intel feed](https://isc.sans.edu/api/) | SANS Internet Storm Center | B | none | 200 | 5,950 KB | 1 | 11.9 MB | 4.34 GB | 0.67 GB | 112k IPs tagged by category (miner, scanner, research...); explains what an IP is. | DShield |
| [SANS ISC research scanners](https://isc.sans.edu/api/) | SANS Internet Storm Center | B | none | 200 | 1,388 KB | 1 | 2.8 MB | 1.01 GB | 0.01 GB | Known benign research scanners (Shodan, Censys...) to suppress false positives. | GreyNoise benign |
| [DShield top /24 blocks](https://feeds.dshield.org/block.txt) | SANS Internet Storm Center | B | none | 200 | 2 KB | 24 | 0.1 MB | 0.04 GB | 0.00 GB | The 20 most aggressive /24 networks right now. | DShield top IPs |
| [abuse.ch MalwareBazaar](https://bazaar.abuse.ch/) | abuse.ch | B | free Auth-Key | key (410 without) | 800 KB | 4 | 6.4 MB | 2.34 GB | 0.22 GB | New malware samples with family, tags and delivery. | ThreatFox |
| [Feodo Tracker aggressive list](https://feodotracker.abuse.ch/) | abuse.ch | B | none | 200 | 623 KB | 4 | 5.0 MB | 1.82 GB | 0.00 GB | Historic C2s as well as current ones; context for the 5-IP live list. | Feodo C2 |
| [C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds) | drb-ra (community, Censys-derived) | C | none | 200 | 9 KB | 4 | 0.1 MB | 0.03 GB | 0.01 GB | Cobalt Strike and other C2 servers found by internet-wide scanning. | ThreatView C2 |
| [ThreatView.io feeds](https://threatview.io/) | ThreatView | C | none | 200 | 405 KB | 1 | 0.8 MB | 0.30 GB | 0.11 GB | High-confidence malicious IPs and Cobalt Strike C2s. | C2IntelFeeds, IPsum |
| [Emerging Threats block IPs](https://rules.emergingthreats.net/fwrules/) | Proofpoint ET | B | none | 200 | 30 KB | 4 | 0.2 MB | 0.09 GB | 0.00 GB | ET's firewall block list (includes DROP and DShield top). | ET compromised, Spamhaus |
| [Binary Defense banlist](https://www.binarydefense.com/banlist.txt) | Binary Defense | C | none | 200 | 11 KB | 4 | 0.1 MB | 0.03 GB | 0.01 GB | Artillery honeypot attackers. | blocklist.de, DShield |
| [CIRCL OSINT MISP feed](https://www.circl.lu/doc/misp/feed-osint/) | CIRCL (Luxembourg national CERT) | A | none | 200 | 1,429 KB | 4 | 11.4 MB | 4.17 GB | 0.04 GB | Analyst-curated MISP events with IOCs from public reports. | Botvrij, vendor research |
| [Botvrij.eu MISP feed](https://www.botvrij.eu/) | Botvrij.eu | C | none | 200 | 353 KB | 4 | 2.8 MB | 1.03 GB | 0.01 GB | IOCs extracted from public threat reports, in MISP format. | CIRCL OSINT |
| [OpenPhish community feed](https://github.com/openphish/public_feed) | OpenPhish | B | none | 200 | 17 KB | 12 | 0.4 MB | 0.15 GB | 0.07 GB | Live phishing URLs (now published on GitHub). | Phishing.Database, URLhaus |
| [Tweetfeed](https://tweetfeed.live/) | Tweetfeed.live (community) | D | none | 200 | 49 KB | 24 | 2.4 MB | 0.86 GB | 0.04 GB | IOCs shared by researchers on X, extracted automatically. | ThreatFox |
| [AlienVault OTX](https://otx.alienvault.com/) | LevelBlue (AT&T Cybersecurity) | C | free key | key | 300 KB | 24 | 14.4 MB | 5.26 GB | 0.67 GB | Large community 'pulses' of IOCs grouped by campaign. | ThreatFox, MISP feeds |
| [AbuseIPDB blacklist](https://www.abuseipdb.com/) | AbuseIPDB | C | free key (10k IPs/day list) | key | 400 KB | 1 | 0.8 MB | 0.29 GB | 0.67 GB | Crowd-reported abusive IPs with confidence scores. | DShield, blocklist.de |
| [GreyNoise community API](https://www.greynoise.io/) | GreyNoise | B | free key (lookups only) | key | 1 KB | 500 | 1.0 MB | 0.36 GB | 0.00 GB | Tells mass scanners and benign crawlers apart from targeted traffic. Best used to enrich IPs, not as a feed. | SANS research scanners |
| [Shadowserver reports](https://www.shadowserver.org/) | The Shadowserver Foundation | A | vetted registration (free for network owners/CERTs) | registration | 20,000 KB | 1 | 40.0 MB | 15 GB | 1.11 GB | Exposure, compromise and honeypot data from one of the largest scanning nonprofits. | DShield, GreyNoise |

Category total if all were added at the suggested cadence: about 107 MB/day in the lake (39 GB/year uncompressed) and 22.5 MB/day in DuckDB.
