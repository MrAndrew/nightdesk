---
type: Methodology
title: Trust model
description: How sources are graded A-D for trustworthiness, and how agreement between independent sources is used to raise confidence.
tags: [sources, trust, methodology]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-04T14:00:00Z }
---

# Tiers

| Tier | Meaning | Examples |
|---|---|---|
| A | Primary authority: a government CERT or agency, a standards body, or the operator of the measurement itself | CISA KEV, NVD, CVE.org, ENISA EUVD, national CERTs, RIPE NCC, Tor Project, Spamhaus, vendor PSIRTs for their own products |
| B | Established research group, nonprofit or vendor with a published methodology and a track record | SANS ISC, abuse.ch, IODA, Cloudflare Radar, FIRST EPSS, OSV, major newsrooms, vendor threat research |
| C | Community or aggregator feed: widely used, but curation varies. Corroborate before acting | blocklist.de, CINS, IPsum, FireHOL, RansomLook, OTX, AbuseIPDB |
| D | Unverified or crowd content: social posts, tips, auto-extracted IOCs. Signal only, never ground truth | Bluesky, Mastodon, Reddit, Hacker News, Tweetfeed |

How a source is graded:

* Who operates it, and whether they are the origin of the data or a re-publisher.
* Whether the method is documented.
* Whether there is a false-positive or removal process.
* How long it has been running, and whether it is still updated. For example, ransomwatch stopped in June 2025.

# Corroboration

The user's guidance is that duplication is welcome: the same fact reported by independent sources is stronger evidence. Each source doc lists what it corroborates. Planned use in the app:

1. **Count independent sightings per entity.** Join on IP, CVE, prefix or ASN across sources and count distinct sources, weighting A=3, B=2, C=1, D=0.5.
2. **Show the count.** Put it in the event drawer and on the map ("seen by 4 sources") and use it to boost severity.
3. **Don't double-count re-publishers.** Aggregators that already merge other lists count once. IPsum's own count of 30+ lists is a ready-made corroboration score for IPs.
4. **Use benign lists to subtract.** SANS research scanners and GreyNoise "benign" lower an IP's score instead of raising it.

# Access policy

* Night Desk uses the provider's documented access method with an honest User-Agent.
* Providers that block automated clients (ransomware.live's public API, CISA's RSS) stay off until there is sanctioned access: an API key, or an alternate official channel such as CISA's CSAF repository.
* Licences and terms are recorded per source. Some lists (Spamhaus DROP, DShield) restrict commercial use.
