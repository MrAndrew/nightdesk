"""Routing watch: a per-network watch on BGP routing, replacing the global RIS Live firehose.

* `watchlist` - the networks the user chose (ASNs and prefixes), presets, validation, the two settings, the Radar token.
* `usage` - bytes and requests per source per day, and the daily data limit.
* `net` - the one HTTP helper the routing sources use (counts bytes, honours the limit and offline mode).
* `detect` - the rules, per-watch state, de-duplicated events and the cards the UI shows.
* `api` - GET/PUT the watchlist and settings, GET the cards; `sync()` starts and stops the sources on a change.

The sources themselves live in osinthub/sources/routing_*.py (RPKI file, Cloudflare Radar, RIPEstat) and
osinthub/sources/streams.py (RIS Live, watchlist-only). Nothing runs until the watchlist has an entry.
Design and measurements: okf/project/routing-watch.md
"""
