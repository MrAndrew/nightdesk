---
type: Data Source
title: "RPKI signed routes (daily file)"
description: "The public daily list of validated ROAs (who may announce which addresses), downloaded whole and filtered on this computer to the routing watchlist. Runs only once a network is watched."
resource: https://rpki.cloudflare.com/rpki.json
tags: [infra, batch, current, routing]
provider: "Cloudflare · rpki-client"
mode: batch
cadence: "every 24h (conditional GET)"
trust_tier: A
auth: "none"
license: "No terms stated"
in_app: "off; ask in the first-run box; Routing watch asks once a network is watched"
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-20T03:00:00Z }
sources:
  - { id: rpki-cf, resource: "https://rpki.cloudflare.com/rpki.json", title: "Cloudflare RPKI validated ROAs", author: "Cloudflare" }
  - { id: rpki-console, resource: "https://console.rpki-client.org/", title: "rpki-client console (rpki.json)", author: "rpki-client" }
---

# Summary

Source id `rpki_roas` (osinthub/sources/routing_rpki.py), part of the [routing watch](/project/routing-watch.md).
Once a day it downloads the bulk file of validated ROAs[^rpki-cf] (about 5 MB compressed, about a million entries),
parses it locally and keeps only the ROAs that name a watched AS or overlap a watched prefix. The provider never
learns the watchlist, and neither the file nor anything unrelated to the watchlist is stored in the lake.

| | |
|---|---|
| Source id | `rpki_roas` |
| Default URL | `https://rpki.cloudflare.com/rpki.json` (env `OSINTHUB_RPKI_URL`) |
| Fallback | `https://console.rpki-client.org/rpki.json`[^rpki-console] (env `OSINTHUB_RPKI_FALLBACK_URL`) |
| Mode | batch, every 24 h, `If-None-Match` / `If-Modified-Since` (an unchanged file is a 304) |
| Access | none |
| License | no terms stated by either publisher |
| Status in Night Desk | off in code and never switched on by itself. `ask` (unticked) in the first-run "Choose your sources" box, where it can be answered before any network is watched; its Routing watch toggle works before the first network too. With a network watched and no saved answer, Routing watch asks once (Yes / No). A saved answer is never overridden |

# How it is used

* **Cache and conditional GET.** The last download is kept gzipped in `lake/cache/rpki-cache.json.gz` (one file, replaced
  each time, counted as "Working cache" in Settings › Data and retention, deleted when the watchlist is emptied; not
  part of any run's records). A changed watchlist is filtered again from it at once (about a second after the edit),
  with no download. A request is made only when the daily check is due, and it is conditional (ETag / Last-Modified of the
  cached file), so an unchanged file is a 304. The parse runs in a worker thread.
* **Formats.** Both publishers' JSON (`asn` as a number or as `"AS13335"`, `maxLength`, `ta`) are read with a
  streaming-free regex pass and a cheap first-octet pre-filter.
* **Local validation** (RFC 6811): an announcement is valid when a covering ROA names its origin with a long enough
  `maxLength`, invalid when covering ROAs exist but none match, unknown otherwise. The routing watch uses it for
  announcements seen by RIPEstat or RIS Live ([detection](/architecture/routing-watch.md#detection)).
* **Data limit.** The download counts against the routing daily data limit and is stopped (the source pauses, no run
  recorded) if it would cross it. Offline mode stops it.

# Terms

Read 2026-11-19: neither file states terms[^rpki-console][^rpki-cf]. The [rpki-client console](https://console.rpki-client.org/)
lists only a contact. Cloudflare's [website terms](https://www.cloudflare.com/website-terms/) (effective 2025-08-01) s6
say "Except as expressly authorized by Cloudflare you may not make use of the Materials"; whether that covers
`rpki.cloudflare.com` is unclear. So the first-run box lists it as `ask` (`feed_terms.py`): silence never upgrades a
policy. Commercial use, redistribution and AI use: not stated.

Before a public release, ask the operators whether many installs
fetching once a day (conditional) is acceptable, or document running a local validator such as Routinator instead
([open issues](/project/open-issues.md#before-the-repo-goes-public)).

[^rpki-cf]: Response headers of `rpki.cloudflare.com/rpki.json` (ETag, `max-age=14400`), 2026-11-17.
[^rpki-console]: rpki-client console page, 2026-11-17.
