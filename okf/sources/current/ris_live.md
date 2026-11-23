---
type: Data Source
title: "RIPE RIS Live — live updates for watched networks"
description: "Live BGP updates from RIPE's rrc00 collector for the routing watchlist only (one prefix or path filter per watch). Off by default, under Advanced; never connects without a watchlist."
resource: https://ris-live.ripe.net/
tags: [infra, stream, current]
provider: "RIPE NCC"
mode: stream
cadence: "continuous"
trust_tier: A
auth: "none"
license: "RIPE NCC terms"
in_app: "off by default (Advanced); watchlist-only when on"
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

**Watchlist-only since v1.2.** Unfiltered it used about 13 GB a day and produced thousands of low-value events a day
(see [routing watch](/project/routing-watch.md) for the measurements). It is now part of the routing watch: off by
default, listed under **Advanced** (catalog group `advanced`), and when on it follows only the watched networks.

| | |
|---|---|
| Source id | `ris_live` (osinthub/sources/streams.py `RisLive`) |
| Provider | RIPE NCC |
| Mode | stream (one WebSocket, `wss://ris-live.ripe.net/v1/ws/?client=night-desk`; env `OSINTHUB_RISLIVE_URL`) |
| Trust tier | A: Primary authority: a government CERT/agency, standards body or the operator of the measurement itself |
| Access | none |
| License | RIPE NCC terms (the manual states none; RIS raw-data terms to confirm before a public release) |
| Status in Night Desk | off by default; Advanced in Settings › Sources › Routing watch |

# Terms

Read 2026-11-19: no RIS Live terms of use were found. The
[RIS commercial-use page](https://ripe.net/analyse/internet-measurements/routing-information-service-ris/commercial-use)
says commercial products must show the RIPE NCC logo, a link and its boilerplate, and that permission "can be revoked
at any time". `ask` in the first-run box; Help › Sources › Credits credits the RIPE NCC (RIPEstat and RIS). Ask the
RIS team before a public release ([pre-alpha release](/project/pre-alpha-release.md)).

Commercial use: with conditions. Redistribution: ?. AI use: ?.

# Behaviour

* **No watchlist, no connection.** `unavailable()` returns "Add a network to watch ..." while the watchlist is empty,
  so the source is never started (status `needs_key`), even on a lake where it was switched on as the old firehose;
  emptying the watchlist stops a running connection. The stream itself also refuses to connect with an empty list.
* **Subscriptions** on one connection, collector `rrc00`: per watched prefix
  `{"type": "UPDATE", "host": "rrc00", "prefix": P, "moreSpecific": true}`, per watched AS
  `{"type": "UPDATE", "host": "rrc00", "path": "<ASN>$"}` (measured: about 70 MB a day for one large origin AS, about
  nothing for one prefix). A watchlist change reconnects with the new list.
* **Data limit.** Every message's bytes count against the routing daily data limit. At the limit (its own bytes, or
  another routing source's, checked every second) it shows "paused" with the reason, closes its socket, and only then
  waits; it reconnects after midnight or within a minute of the limit being raised. A cancelled stream never waits
  with its socket open.
* **What it flags.** Each new (watch, prefix, origin) seen on the connection goes to the routing watch rules within a
  second (a timer, not the next message, so one announcement on a quiet prefix counts; a restart or disconnect
  flushes first): an RPKI-invalid announcement of a watched prefix (checked against the local RPKI file), or an origin
  that differs from the reference (RPKI records or RIPEstat). The stream never sets the reference itself; with none,
  several origins are information only. These events clear after a day without being seen again. The old global "origin change" and "withdrawal burst" events
  are no longer produced; the `bgp.*` rate metrics and the map pulses still are, for the watched networks.

# Corroboration

Other sources that report the same facts, so agreement raises confidence: RIPE RIS dumps, RouteViews, Cloudflare Radar route leaks/hijacks.

# Storage

Nothing per message is stored any more: findings are routing-watch events (settings `routing.state`) and the rate
metrics. The old figures (9.6 MB of events a day) described the unfiltered firehose.
