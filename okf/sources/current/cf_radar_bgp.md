---
type: Data Source
title: "Cloudflare Radar — BGP hijacks and leaks"
description: "Recent suspected BGP hijacks and route leaks from Cloudflare Radar, listed without naming any network and matched to the routing watchlist locally. Needs the user's own free API token."
resource: https://developers.cloudflare.com/radar/investigate/bgp-anomalies/
tags: [infra, batch, current, routing]
provider: "Cloudflare Radar"
mode: batch
cadence: "Check every (1 h / 6 h / 24 h; 15 min advanced)"
trust_tier: B
auth: "the user's own free Cloudflare API token with Radar read"
license: "CC BY-NC 4.0"
in_app: "on once a token is saved and a network is watched"
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
sources:
  - { id: radar-bgp, resource: "https://developers.cloudflare.com/radar/investigate/bgp-anomalies/", title: "Cloudflare Radar: BGP anomalies", author: "Cloudflare" }
  - { id: radar-overview, resource: "https://developers.cloudflare.com/radar/", title: "Cloudflare Radar docs (licence statement)", author: "Cloudflare" }
---

# Summary

Source id `cf_radar_bgp` (osinthub/sources/routing_radar.py), part of the [routing watch](/project/routing-watch.md).
Each check lists every recent event from `GET https://api.cloudflare.com/client/v4/radar/bgp/hijacks/events` and
`.../leaks/events`[^radar-bgp] with only `dateRange` (1d, or 2d when checking daily), `sortBy=TIME`,
`sortOrder=DESC`, `page`, `per_page=100` and `format=json` (at most 10 pages each). No ASN, prefix or country
parameter is ever sent; the events are matched to the watchlist on this computer, so Cloudflare does not learn what
is watched.

| | |
|---|---|
| Source id | `cf_radar_bgp` |
| Mode | batch, at the routing watch's *Check every* interval, with up to 5% jitter |
| Access | the user's own free token, entered in Settings › Sources › Routing watch (saved in `radar.token` next to the database, mode 600) or `CLOUDFLARE_RADAR_TOKEN` |
| License | CC BY-NC 4.0[^radar-overview] (non-commercial, attribution "Cloudflare Radar") |
| Status in Night Desk | off until a token is saved and a network is watched, then on |

# Terms

Read 2026-11-19 ([Radar docs](https://developers.cloudflare.com/radar/)): "made available under the CC BY-NC 4.0
license". Non-commercial, credit "Cloudflare Radar" (Help › Sources › Credits does); each user supplies their own token.
`ask` in the first-run box.

Commercial use: no. Redistribution: non-commercial only. AI use: yes.

# Token handling

The token goes only in the `Authorization: Bearer` header. It is never in a URL, a log line, a run record, a
source message or an API answer (`GET /api/routing` says only `token: "saved" | "env" | null`), and it is kept out of
the settings table, which the SQL console can read. A 401/403 fails the run with "Cloudflare refused the token
(HTTP 403). Check that it is valid and has Radar read access." The docs disagree on the exact permission name
("Account:Radar" vs "User Details Read"); the UI asks for "Account › Radar › Read".

# Matching

* Hijack event: involves a watched AS when it is among `victim_asns` or is the `hijacker_asn`; involves a watched
  prefix when one of its `prefixes` overlaps it. Confidence 8-10 is *needs you*, lower is *information*.
* Leak event: involves a watched AS on `leak_asn` or in `leak_seg` (leak events carry no prefixes). Information:
  a large network often sits in a leaked path with nothing for the user to do.
* Only matched events are stored in the lake. An event clears when it falls out of the listed window.

Event volume and rate limits are not documented; the routing daily data limit bounds the traffic.

[^radar-bgp]: Radar BGP anomalies page and the hijacks/leaks events API reference, read 2026-11-17.
[^radar-overview]: "Data available via Radar API endpoints is made available under the CC BY-NC 4.0 license."
