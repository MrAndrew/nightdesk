---
type: Data Source
title: "RIPEstat — lookups for the networks you watch"
description: "Per watched network: origins, more-specifics, visibility, upstreams and update counts from the RIPEstat Data API. Off by default: RIPE sees which networks are looked up."
resource: https://stat.ripe.net/docs/data_api
tags: [infra, batch, current, routing]
provider: "RIPE NCC"
mode: batch
cadence: "Check every (6 h default)"
trust_tier: A
auth: "none"
license: "RIPEstat Service Terms (no redistribution or commercial use without written permission)"
in_app: "off; explicit opt-in in Routing watch"
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
sources:
  - { id: ripestat-api, resource: "https://stat.ripe.net/docs/data_api", title: "RIPEstat Data API", author: "RIPE NCC" }
  - { id: ripestat-terms, resource: "https://www.ripe.net/about-us/legal/ripestat-service-terms-and-conditions", title: "RIPEstat Service Terms and Conditions", author: "RIPE NCC" }
---

# Summary

Source id `ripestat` (osinthub/sources/routing_ripestat.py), part of the [routing watch](/project/routing-watch.md).
Off by default and only ever run after the user turns it on next to the line "RIPE will see which networks you look
up" (a stray *Run now* on an un-opted source fails without a request).

| | |
|---|---|
| Endpoints | `routing-status` (every watch), `asn-neighbours` (AS watches), `bgp-update-activity` (since the last check), `rpki-validation` per origin and prefix (prefix watches, only when the local [RPKI file](/sources/current/rpki_roas.md) is not loaded; at most 5) |
| Requests | 2-3 per watch per check: 25 watches every 6 h is about 300 a day |
| Politeness | `sourceapp=night-desk` on every request (nothing personal), at most 4 in flight, a short random wait before each, 429/5xx retried twice with growing pauses, a cap of 900 requests a day |
| Data limit | counts against the routing daily data limit; stops when it is reached |

# Terms

Read 2026-11-19 ([RIPEstat Service Terms](https://www.ripe.net/about-us/legal/ripestat-service-terms-and-conditions)):
s3.3 no commercial use "unless permission ... is granted in writing" and the data "may not" be re-packaged, compiled
or re-distributed; s3.2 attribute the RIPE NCC (Help › Sources › Credits does). Commercial use: no. Redistribution:
no. AI use: not stated.

The Data API asks clients to register when they regularly make more than 1,000 requests a day and recommends a
`sourceapp`[^ripestat-api]; the cap keeps a single install under that. The service terms allow analysis, monitoring
and research, and forbid redistribution or commercial use without written permission; they do not address
open-source clients[^ripestat-terms]. Before a public release: email stat@ripe.net describing a distributed, opt-in,
low-rate client with a `sourceapp` id, and record the answer ([open issues](/project/open-issues.md#before-the-repo-goes-public)).

The response fields read (`origins`, `more_specifics`, `visibility.v4/v6.ris_peers_seeing/total_ris_peers`,
`last_seen.time`, `announced_space`, `neighbours[].type == "left"`, `updates[].announcements/withdrawals`,
`status`) follow the documented layouts; they were not checked against the live service while building (tests use a
fake server).

[^ripestat-api]: RIPEstat Data API page, "Rules of Usage".
[^ripestat-terms]: RIPEstat Service Terms and Conditions, Art. 3.1-3.3, 6.1.
