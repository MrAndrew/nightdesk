---
type: Architecture
title: Routing watch
description: What v1.2 built for the per-network routing watch - the watchlist, the two settings and data limit, the four sources, detection rules, the cards and migration.
tags: [architecture, routing, bgp, sources]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-20T03:00:00Z }
---

Built in v1.2, replacing the global RIS Live BGP firehose with a watch of only the networks
the user chooses. The rationale, the measured firehose cost and the research on alternatives are in
[the routing-watch plan](/project/routing-watch.md). Settings › Sources › **Routing watch**
(`#settings/sources/routing`).

# Watchlist

`osinthub/routing/watchlist.py` (setting `routing.watchlist`): up to 25 watches, each an AS number or a prefix
with a label; its id is the canonical value (`AS13335`, `1.1.1.0/24`). Presets: Cloudflare AS13335, Google
AS15169, Amazon AS16509, Microsoft AS8075, Quad9 AS19281, and the resolver prefixes 1.1.1.0/24, 8.8.8.0/24,
9.9.9.0/24; one tap adds or removes. Typed entries are checked as typed (`GET /api/routing/validate`): ASNs 1
to 4294967295 outside the private, documentation and reserved blocks; prefixes /8-/24 (IPv4) or /16-/48 (IPv6)
of globally routed space, with a plain reason otherwise. A saved watch is not re-checked when the list is
saved again.

# Settings and the data limit

`routing.settings`: *Check every* 1 h / 6 h (default) / 24 h, 15 min under Advanced; *Daily data limit*
(default 50 MB). Bytes received (compressed) are counted per source per local day (`routing.usage`,
`osinthub/routing/usage.py`); at the limit every routing source pauses (status `paused`, also when a run crosses
it midway; never "error") with a plain message. A paused batch source looks again every 10 minutes (a local
check, no request) and raising the limit re-checks at once; RIS Live waits and reconnects. The RPKI download is
cut off if it would cross the limit. RIPEstat's own cap (900 lookups a day) is exact and also pauses.

# Sources

Each is its own module with a fake-server test; all obey offline mode; none starts while the watchlist is empty
(`unavailable()` = "Add a network to watch … first").

* [RPKI file](/sources/current/rpki_roas.md) `rpki_roas` — no terms stated, so never switched on by itself. The user can answer before any network is watched (its box in "Choose your sources", or its toggle on this page, which works before the first network); with a network watched and no answer saved, the page asks once (`ask` in `GET /api/routing`, `ASK_FIRST` in `osinthub/routing/api.py`) and the answer is saved like the toggle. An install where it is already on keeps it.
* [Cloudflare Radar](/sources/current/cf_radar_bgp.md) `cf_radar_bgp` — switched on when a token is saved (token
  in a 0600 file, never returned or logged).
* [RIPEstat](/sources/current/ripestat.md) `ripestat` — off; explicit opt-in beside "RIPE will see which
  networks you look up"; `sourceapp=night-desk`, 4 at once, 900 a day at most.
* [RIS Live](/sources/current/ris_live.md) `ris_live` — off, Advanced, watchlist filters only, byte-counted.

"Switched on" sets only an unset flag, so a source the user turned off stays off. Any change of the list, the
token or *Check every* re-syncs them (`routing.api.sync`): stop what cannot run, start what now can, reconnect
RIS Live with the new filters, re-filter the cached RPKI file about a second after the edit, and check the
network sources once 45 s after the last edit. Raising the limit re-checks the paused sources at once.

# Detection

`osinthub/routing/detect.py`; state in `routing.state`, the RPKI records per watch in `routing.roas`.

* **Needs you:** an origin AS not seen before for a watched prefix or one of its more-specifics (learned on the
  first check, plus every AS its RPKI records allow; an origin present for a week becomes normal); an
  RPKI-invalid announcement (local RFC 6811 check; RIPEstat `rpki-validation` when the file is not loaded); a
  Radar hijack with confidence 8-10; and a watched prefix not seen for 2 hours. The reference ("usual") origins
  come only from the RPKI records and RIPEstat, never from the RIS Live stream; with neither, the card says "no
  reference origin yet".
* **Information:** Radar hijacks below confidence 8, Radar route leaks involving a watch, new or lost upstreams
  (for a day), update rate at least 4x the watch's own 14-day median (and at least 60 an hour, after 6 checks),
  visibility below 60% of its median, more announced prefixes than usual (1.2x and +5).

One open event per watch and kind; repeats refresh it; the source that opened it clears it when a later check
no longer finds it; RIS Live findings clear after a quiet day.

# Cards

`GET /api/routing/watches`: per watch a state (*normal*, *changed*, *couldn't check*, or *not checked yet*),
each source's own state (the card shows the worst, so a working RIS Live connection never hides a failed RPKI
or RIPEstat check, and a source that has not looked at a new watch yet shows "Checking…"), a plain sentence
(the top open event, or facts such as "Announced by AS19281; seen by 99% of RIPE's route collectors; signed
with RPKI for AS19281 (up to /24)."), when it was last checked and its last few events. Routing events live
only here for now (not on Watch, Ops or in notifications).

# Migration

RIS Live's default is now off, and a lake where it was on does not reconnect until a watchlist exists; the
Cyber Pulse routing input therefore reads "off" unless RIS Live is on with a watchlist.

Not verified against the real services (no token, and no real routing requests while building): the exact Radar
and RIPEstat response fields, Radar's token permission name and page-size limit, and real-world volumes.
