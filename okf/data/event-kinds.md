---
type: Reference
title: Event kinds
description: Every event kind, its category and display group, and the sources that produce it.
tags: [data, taxonomy]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-18T23:45:00Z }
---

# Kinds

| Kind | Label | Category | Display group | Produced by |
|---|---|---|---|---|
| `kev` | Exploited vuln | vuln | Vulnerabilities | [CISA KEV](/sources/current/cisa_kev.md) |
| `cve` | New CVE | vuln | Vulnerabilities | [NVD](/sources/current/nvd_recent.md) |
| `c2` | Botnet C2 | threat | Threat infrastructure | [Feodo Tracker](/sources/current/feodo_c2.md) |
| `attacker` | Top scanner | threat | Threat infrastructure | [DShield](/sources/current/dshield_top.md) |
| `bruteforce` | Brute-forcer | threat | Threat infrastructure | [blocklist.de](/sources/current/blocklist_de.md) |
| `compromised` | Compromised host | threat | Threat infrastructure | [Emerging Threats](/sources/current/et_compromised.md) |
| `malicious_ip` | Bad reputation | threat | Threat infrastructure | [CINS Army](/sources/current/cins_army.md) |
| `hijacked_netblock` | Hijacked netblock | threat | Threat infrastructure | [Spamhaus DROP](/sources/current/spamhaus_drop.md) |
| `ransomware` | Ransomware victim | threat | Threat infrastructure | [ransomware.live](/sources/current/ransomware_live.md) (off) |
| `malware_ioc` | Malware IOC | threat | Threat infrastructure | [ThreatFox](/sources/current/threatfox.md) (off: needs a free key) |
| `malware_url` | Malware URL | threat | Threat infrastructure | [URLhaus](/sources/current/urlhaus.md) (off: needs a free key) |
| `c2_cert` | C2 certificates (per family) | threat | Threat infrastructure | [SSL Blacklist](/sources/current/sslbl.md) |
| `tor_exit` | Tor exit | infra | Internet infrastructure | [Tor exits](/sources/current/tor_exits.md) |
| `outage` | Internet outage | infra | Internet infrastructure | [IODA](/sources/current/ioda_outages.md) |
| `bgp_origin_change` | BGP origin change | infra | Internet infrastructure | [RIS Live](/sources/current/ris_live.md) (derived) |
| `bgp_withdrawal_burst` | BGP withdrawals | infra | Internet infrastructure | [RIS Live](/sources/current/ris_live.md) (derived) |
| `news` | News | news | Media | [Security news wire](/sources/current/security_news.md) |
| `advisory` | Advisory | news | Media | [CISA advisories](/sources/current/cisa_advisories.md) (CSAF; title starts with the tracking id) |
| `social` | Social | social | Media | [Bluesky](/sources/current/bluesky_cyber.md) |
| `indicator` | Custom indicator | custom | Custom | User uploads |

Colours and labels are defined once in `web/js/core/util.js` and shared by every panel.

`malware_ioc` and `malware_url` events often repeat an address another list already carries (a Feodo C2 on ThreatFox) or one address several times (one ThreatFox IOC per port). Every dashboard count (the world map, Threat Origins, Top Offenders, the Activity timeline and the kind totals) counts an address once, whichever feeds list it, and shows how many feeds did beside it ([counting addresses](/architecture/api.md#counting-addresses)); Explorer lists every event (global search covers news and social events, and finds these through their indicator and family entities). A `c2_cert` event is one summary per malware family ("Vidar: 731 C2 TLS certificates on SSL Blacklist"), for families with a listing in the last 365 days; the certificates themselves are netlog indicators only.

A `ransomware` event's `ts` is when the victim was posted to the leak site (ransomware.live's `discovered`), not the attack date, which is often weeks earlier and is kept at the start of the summary (`attack date YYYY-MM-DD`). The Ransomware pulse index and timelines therefore count postings. Rows loaded before this change keep the attack date until the victim is fetched again.

[FIRST EPSS](/sources/current/epss.md) makes no events: a score is enrichment of a CVE, read from the `epss` table wherever CVEs show, and never counts as activity.
