---
type: Plan
title: Routing watch (replacing the RIS Live firehose)
description: Why the global BGP firehose is off, what it cost and produced, the research on smaller and more private routing data, the owner's design for a per-network routing watch, and what v1.2 built.
tags: [project, plan, bgp, routing, sources, privacy, terms]
status: stable
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-20T03:00:00Z }
sources:
  - { id: rislive-manual, resource: "https://ris-live.ripe.net/manual/", title: "RIS Live manual", author: "RIPE NCC" }
  - { id: ripestat-api, resource: "https://stat.ripe.net/docs/data_api", title: "RIPEstat Data API", author: "RIPE NCC" }
  - { id: ripestat-terms, resource: "https://www.ripe.net/about-us/legal/ripestat-service-terms-and-conditions", title: "RIPEstat Service Terms and Conditions", author: "RIPE NCC" }
  - { id: radar-bgp, resource: "https://developers.cloudflare.com/radar/investigate/bgp-anomalies/", title: "Cloudflare Radar: BGP anomalies", author: "Cloudflare" }
  - { id: radar-overview, resource: "https://developers.cloudflare.com/radar/", title: "Cloudflare Radar docs (licence statement)", author: "Cloudflare" }
  - { id: rpki-console, resource: "https://console.rpki-client.org/", title: "rpki-client console (rpki.csv / rpki.json)", author: "rpki-client" }
  - { id: rpki-cf, resource: "https://rpki.cloudflare.com/rpki.json", title: "Cloudflare RPKI validated ROAs", author: "Cloudflare" }
  - { id: routinator, resource: "https://routinator.docs.nlnetlabs.nl/", title: "Routinator documentation", author: "NLnet Labs" }
usage_window: { from: 2026-11-17, to: 2026-11-17 }
---

# Why

On 2026-11-17 the owner's router flagged about 5 GB downloaded since 16:30. The cause was the
[RIS Live source](/sources/current/ris_live.md): one WebSocket subscribed to every BGP UPDATE from RIPE's `rrc00`
collector, unfiltered. The live app had received 26 GB in about two days, 99% of it on that one connection.
The source was turned off on the live app the same day (`POST /api/sources/ris_live/enable?enabled=false`; persisted).

What it produced was noise for a home user: in about 17 hours at least 5,000 "origin change" events (every one at
severity 0.65, mostly from Google, Amazon, Akamai-style anycast and large carriers) and at least 5,000 "withdrawal burst"
events across about 2,100 networks (94% at severity 0.6). None concerned the owner's network or anything they could act on.

# Measured cost per subscription (rrc00, 15 s samples, 2026-11-17)

| Subscription | Bandwidth | Per day |
|---|---|---|
| Everything (the old default) | 149 KB/s | ~13 GB |
| `require: announcements` | 135 KB/s | ~12 GB |
| `require: withdrawals` | 6 KB/s | ~0.5 GB |
| One peer (of 79) | 5–22 KB/s | 0.5–2 GB |
| `path: "<ASN>$"` (one origin AS, e.g. 13335) | 0.8 KB/s | ~70 MB |
| One prefix and its more-specifics | ~0 | ~0 |

The volume is BGP's design, not a list of addresses: each of ~80 peers reports every change from its own view, routes
are constantly re-announced (about 690 announcements/s against 20 withdrawals/s), and each JSON message is ~430 bytes.
The manual allows several filters on one connection (`host`, `type`, `require`, `peer`, `path`, `prefix`,
`moreSpecific`, `lessSpecific`) and says a client that cannot keep up is disconnected; it states no rate limit or
fair-use policy[^rislive-manual].

# Research: smaller and more private sources

| Source | What it gives | Size | Access | Terms | Privacy |
|---|---|---|---|---|---|
| Bulk validated ROAs (rpki-client console `rpki.csv`/`rpki.json`; Cloudflare `rpki.json`) | is an announcement RPKI-valid | ~5 MB gzipped, ~1.05M entries; Cloudflare's has an ETag and `max-age=14400`, so unchanged = 304 | no account | none stated[^rpki-console][^rpki-cf] | checked locally: nobody learns the watchlist |
| Routinator (self-run validator) | same, from the repositories directly | 1 GB RAM, 4 GB disk, 2M inodes | install | BSD-3-Clause[^routinator] | repositories see the IP, not the watchlist |
| Cloudflare Radar `GET /radar/bgp/hijacks/events`, `/radar/bgp/leaks/events` | suspected hijacks (confidence 1–10) and provider-customer-provider leaks | small (volume not stated) | free API, needs a free account and a token with Radar read | "CC BY-NC 4.0"[^radar-overview] | list all recent events, filter locally: private[^radar-bgp] |
| RIPEstat Data API (`routing-status`, `rpki-validation`, `asn-neighbours`, `bgp-update-activity`, `visibility`, `announced-prefixes`) | per network: origins, more-specifics, RPKI, upstreams, update counts, visibility | small per call | no account; 8 concurrent requests per IP; "register if you plan to regularly do more than 1000 requests/day"; `sourceapp` recommended[^ripestat-api] | analysis/monitoring/research; no redistribution or commercial use without written permission; open-source use not addressed[^ripestat-terms] | RIPE sees each looked-up network |
| RIS Live, filtered to the watchlist | instant updates for watched networks | ~70 MB/day per watched origin-AS class | no account | not stated in the manual | RIPE sees the filters |

Open questions: Radar's event volume, rate limits and exact token permission (the docs disagree:
"Account:Radar" vs "User Details Read"); the exact rpki.csv layout; RIS raw-data terms; RIPE's view on RIPEstat
inside distributed open-source software.

# Owner's design (decided 2026-11-17)

* **Choose what to watch.** Presets for big services (e.g. Cloudflare, Google, Amazon, Microsoft, public DNS resolvers)
  and custom ASNs/prefixes typed by the user (validated as typed). Not in v1: suggestions from the user's own logs.
* **One card per watch**: normal / changed / couldn't check, a plain sentence, a short timeline.
* **What is flagged.** Needs-you by default: an unexpected origin (incl. a more-specific announced by someone else) and
  an RPKI-invalid announcement; a watched prefix gone for longer than a set time. Informational ("abnormal activity
  within the network"): new or changed upstreams, update/withdrawal spikes against the network's own two-week baseline,
  visibility drops, newly announced prefixes.
* **Two user settings only**: *Check every* 1 h / 6 h (default) / 24 h, with 15 min as advanced; *Daily data limit*
  (default 50 MB; pauses and says why). Jitter, backoff after errors, caching and request batching are automatic.
  The RIPEstat default interval is 6 h so 25 watches stay well under 1,000 requests/day.
* **Defaults and privacy.** Everything off until the user creates a watchlist. With a watchlist: the bulk RPKI check
  (private), once the user says yes: its publishers state no terms, so the page asks once (since 2026-11-19; it was
  switched on with the first watch before). With a Cloudflare token (like the abuse.ch key): Radar hijacks and leaks, filtered locally (private).
  **RIPE is off by default** and must be turned on explicitly, with the line "RIPE will see which networks you look
  up". The RIS Live stream moves under Advanced, off, and only ever subscribes to the watchlist, with a usage meter.
* Offline mode stops all of it. No RIPE, Radar or RPKI data ships in the repo; tests use fake servers only.

# What was built

The implementation (the watchlist, the two settings and data limit, the four sources, the detection rules,
the cards and the migration) is documented in [architecture: routing watch](/architecture/routing-watch.md).
The design above was built as decided; it was not verified against the real Radar/RIPEstat services while
building (no token, no real routing requests).

# Before the repo goes public

Terms adherence for these sources is tracked in [open issues](/project/open-issues.md#before-the-repo-goes-public).

[^rislive-manual]: RIS Live manual, read 2026-11-17.
[^ripestat-api]: RIPEstat Data API page, "Rules of Usage".
[^ripestat-terms]: RIPEstat Service Terms and Conditions, Art. 3.1–3.3, 6.1.
[^radar-bgp]: Radar BGP anomalies page and the hijacks/leaks events API reference.
[^radar-overview]: "Data available via Radar API endpoints is made available under the CC BY-NC 4.0 license."
[^rpki-console]: rpki-client console page; sizes from response headers on 2026-11-17.
[^rpki-cf]: Response headers of `rpki.cloudflare.com/rpki.json` on 2026-11-17.
[^routinator]: Routinator installation and output-format docs (0.16.1).
