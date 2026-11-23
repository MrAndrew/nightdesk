---
type: Reference
title: Open issues and backlog
description: Known bugs and limitations that are not fixed yet, and follow-ups that were deferred, with what is known about each.
tags: [project, backlog, bugs]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-22T18:25:00Z }
---

# How to use this page

Each entry says what happens, where, what is known about the cause, and what a fix would need. Remove an entry when it is fixed. Feature plans that are not bugs live in their own pages (for example the [Ask page](/project/ideas/ask-page.md)).

# Bugs

Found by the round-2 bug hunt on 2026-11-09, after the round-1 fixes were merged. Every confirmed bug has
been fixed; none is open (Medium, Low and Cosmetic). Known behaviours deliberately left alone are listed under
[known behaviours left alone](#known-behaviours-left-alone) below.

# Known behaviours left alone

Deliberate or low-value quirks the housekeeping pass (2026-11-18) checked and chose not to change.

* **Some netlog text filters do not escape LIKE wildcards.** The alert and incident `q`/`not_q` filter
  (`osinthub/netlog/api.py`, the alert where-clause), the device list `q` (`list_devices`) and the log-search
  `service` filter (`_conn_where`) pass the text straight into `ILIKE '%…%'` with no `ESCAPE`, so a literal `%` or `_` a user
  types is read as a wildcard. It is parameterised, so not an injection, only a search nicety; left as is. (The
  notes search and the my-stack news matching and vendor suggestions in `stack.py` do escape, via
  `apiutil.like(...)` with `ESCAPE '\\'`.)
* **`net/common.js ts()` reads a zone-less timestamp as browser-local.** The one clock (`core/time.js`) reads a
  timestamp without a zone as UTC; the Network tables' own `ts()` passes the value to `new Date(t)` first, so a
  zone-less string is parsed as local time there. Changing it would shift displayed times for zone-less values,
  so it is logged, not changed.

# v1.1: known gaps

Left open by the v1.1 revision, each reported by the lane that built it or its evaluator.

* **The AI helper's colour:** it shows red only when `AI_HELPER=1` (or `on`/`required`) is set or it answered during this run; otherwise a stopped helper is grey "Not running — optional".
* **Ops Activity brush:** dragging on the Ops Activity panel zooms only that panel. The shared range control can't show a from–to window there, because the other Ops panels only accept "last N hours"; it needs `until` parameters in the stats endpoints.
* **Notifications:** a message that fails all three tries is logged and not retried later, and the send queue lives in memory (lost on restart). Never tested against a real internet service; internet destinations need an explicit opt-in.
* **Connect logs:** the OPNsense steps use a configd action; whether its description appears in the Cron command list was not confirmed. Pi-hole, AdGuard and pfSense file locations are worded "usually …; check with `ls`".
* **DNS sinkhole import:** `pihole.log` has no year or time zone and is read as this computer's local time; the same query imported from both the log and the API export is stored twice; the Pi-hole v5 API format is not supported.
* **My stack:** the shipped "What do you run?" chips were checked against the test lake's KEV rows, not CISA's live catalog. Re-check after the first real KEV fetch.
* **Devices:** model-style hostnames (for example "Galaxy-S21") still count as names; there is no MAC-vendor table, so a vendor shows only when a `known_devices` log provides one.
* **Entity merges:** a verdict on a link that both merged entities had stays on the kept entity after Undo (the Undo preview says so).
* **Search:** the first query after the search index is rebuilt (after an entity merge or a large import) is slower while the background rebuild runs.
* **Small leftovers from the last check (2026-11-11):** Esc on an open alert leaves its id in the URL.
* **Seen only in tests:** the "Found later" badge (the demo can't produce a retro match), KEV due dates and EPSS percentiles (the test lake has no KEV record files or EPSS rows), and the sensor-silent alert layout.

# Guided tour: known limitations

The [guided tour](/architecture/web-client.md#guided-tour) was checked with a Playwright harness (49 steps on 7 pages at 1440×900, geometry assertions and screenshots) and five rounds of independent screenshot review. The reviewers never returned a "ship it" verdict; the owner accepted it for now (2026-11-09). What remains:

* **Wide panels get wide, short beams.** A panel spanning the full screen width has no room beside it, so it is lit from just above or below, and its beam is a broad, low band rather than a cone. This is a geometry limit, not a tuning issue.
* **Components that float over the Cyber Cinema globe** (the Up next list, the HUD controls) show globe arcs and starfield through their lit area, so they look less evenly lit than solid panels.
* **Components taller than the screen** (for example Explorer's results table) are clipped at the screen edge; the highlight frame stops 8 px from it.
* **The lamp can still stand over dimmed UI.** Placement avoids text and controls under the lamp where it can, and a shadow pool hides what is beneath, but on dense pages there is not always empty ground.
* **The harness runs at 1440×900 only.** The phone tour (its own steps on Watch, since 2026-11-16) was checked by screenshots at 390 px on 2026-11-21, not by the harness; the narrower [top-bar tiers](/architecture/web-client.md#top-bar) were not run.
* **A component that fills the screen is lit without the lamp** (for example the setup checklist on a phone): there is no open ground beside it, so the lamp and beam fade out for that step rather than stand on its text.
* **Live components can change mid-step.** Cyber Cinema's focus card changes on autopilot. The tour re-measures when the lamp lands, but not continuously after that.

# Before the repo goes public

The full release plan is [Pre-alpha release plan](/project/pre-alpha-release.md); this section keeps the terms items.
Terms adherence, to finish before a public or open-source release (owner, 2026-11-17). Existing licence readings:
[Docker sources](/project/distribution.md) and the in-app feed terms (`osinthub/feed_terms.py`).

* **Every enabled-by-default source** (2026-11-19, ✓): terms re-read; each [source page](/sources/catalog.md) has a
  "Terms" section (link, read date, commercial, redistribution and AI use) and `feed_terms.py` matches. Every source
  whose terms are unclear, unstated or non-commercial is off in code and unticked in the first-run box (a unit test
  holds this); existing installs keep what they ran ([pre-alpha plan](/project/pre-alpha-release.md#8-terms-and-licences)).
* **abuse.ch** (ThreatFox, URLhaus; SSLBL and Feodo are CC0): free tier is not-for-profit only (s3.1), commercial use
  needs a subscription (s4.1), s7.3 forbids redistribution, derivative works, high-volume harvesting and using the
  data to train or improve AI models. Every abuse.ch source is `ai_ok = False`, Feodo included (2026-11-19, ✓; a
  one-off purge on upgrade removes vectors and cached brief texts derived from it); keep it out of any shipped data.
* **FIRST EPSS:** attribution shown in the app and docs (✓).
* **RIPEstat** (built in v1.2, off by default, explicit opt-in; [routing watch](/project/routing-watch.md)): terms
  forbid redistribution and commercial use without written permission and do not address open-source clients. Email
  stat@ripe.net (describe a distributed, opt-in, low-rate client with a `sourceapp` id) and record the answer.
* **RIS Live:** the manual states no terms; read the RIS raw-data terms and confirm the watchlist-filtered stream is fine.
* **Bulk RPKI files** (rpki-client console, Cloudflare `rpki.json`): no terms stated, so `ask` in the first-run box and
  never switched on by itself: Routing watch asks once a network is watched (2026-11-19); ask the operators whether many installs fetching daily (conditional GET) is acceptable, or document
  running Routinator instead.
* **Cloudflare Radar:** CC BY-NC 4.0; each user supplies their own free token; licence shown in Routing watch and
  credited in Help › Sources › Credits (✓).
* **Reference data and libraries:** DB-IP Lite attribution (CC BY 4.0) linked on the world map and in Help (✓), MISP
  galaxy / Malpedia (CC BY-NC-SA 3.0 for the Malpedia cluster) credited in Help (✓); basemap tiles and vendored JS
  libraries: keep every AGPL/MIT/BSD licence text and notice (✓ `NOTICE`, `LICENSE`, the glyph OFL file, 2026-11-20).
  Online basemaps only with the user's own CARTO key, credited on the map; Esri removed (✓). TeleGeography cables
  opt-in with an on-screen credit (✓); NASA globe images replace the unsourced three-globe ones (✓). Cyber Cinema's
  globe shows geolocated events without the DB-IP line (the credit is in Help).
* **Repo hygiene:** clean history; no real home addresses, MACs, hostnames or IPv6 prefixes anywhere; no feed data,
  lakes or model files committed; a NOTICE/THIRD-PARTY file listing every source and its terms. The third-party
  Sitdeck marketing screenshots were removed from the working tree (2026-11-18, ✓); they remain in git history
  under the `v1.0` tag, so a public release still needs a clean export or a history scrub.
* **Owner-specific names and secrets in tracked files** (2026-11-19, ✓): the owner's host, drive and user names
  were replaced with generic examples, and `tools/release_scan.py` now fails the unit suite on any home folder, user
  name, git identity, key-like string, unlisted `*.lan` or `/Volumes/<name>`, or real address or MAC in a tracked file
  ([environment](/environment.md#release-scan)). The owner's own names are checked from a private patterns file
  outside the repo, so a public checkout runs every other check without it. Since 2026-11-22 it also catches Slack
  and Discord webhook URLs, GitLab and Gotify tokens, reverse-DNS and zero-padded IPv4, IPv6 prefixes written without
  `::`, `*.home` / `*.ts.net` names and PNG text chunks (✓). Still to do: run a secrets scanner (gitleaks or
  trufflehog) over the clean export once, from outside the repo; JPEG/WebP metadata and PNG `eXIf` are not read.
* **Bundled fixtures** (✓ 2026-11-20): the Tranco-derived lists are gone (the demo's sites are hand-made, on
  documentation addresses). Bluesky stays: authors' deletes are recorded in `deletion_requests`, the posts are kept,
  and NOTICE says the user manages their data.

# Deferred follow-ups

* **Other key and setting texts that are not per install** (2026-11-22, pf-ui eval): the world map's CARTO hints ("set CARTO_API_KEY in .env and restart"), the ransomware.live card's primary text naming `RANSOMWARELIVE_API_KEY`, and the offline texts ("restart with offline mode turned off", which in Docker needs `.env` plus the install line). `sources.base.key_steps()` fits the key ones. The Watch checklist's "two more demo scenarios" for the abuse.ch key is not true: no demo scenario uses ThreatFox or URLhaus.
* **Size caps not yet measured or not yet applied (v1.2 harden).** The caps for `rpki_roas`, `cf_radar_bgp`, `ripestat`, `threatfox` and `urlhaus` come from estimates, not measured responses: re-measure on the first real runs and adjust [size limits](/data/size-limits.md).
* **URLhaus misses bursts over 1,000 URLs an hour.** The API returns at most the newest 1,000 URLs per call and the source polls hourly ([urlhaus](/sources/current/urlhaus.md)).
* **ThreatFox and URLhaus fixtures are hand-made from the documented formats.** No Auth-Key was available when they were built, so check the first real runs once `ABUSECH_AUTH_KEY` is set, and re-measure their storage estimates.
* **ATT&CK technique extraction: the body-text gold is agent-judged and favours the extractor.** Against the vendor tables it scored
  precision 0.653, recall 0.450; the 2026-11-19 re-adjudication (`tests/eval/README.md`, "ATT&CK re-adjudication")
  scores what the body describes: 0.939 / 0.560 with the LLM (0.531 recall over the vendor's own entries), 0.915 /
  0.376 without, after the defender-text fix below (0.910 and 0.896 before it). Still open: the owner has not reviewed the agent's judgement calls (28 additions, 58 described table
  ids and 25 exclusions marked unsure); the 23 `--no-llm`-only predictions were never adjudicated; techniques that
  neither the vendor nor the extractor named stay invisible, so recall is optimistic. Extractor fixes the audit
  ranked: the first, ignoring defender text (hunting queries, KQL, "Verify Microsoft Defender…" advice: 8 of
  Microsoft's 12 remaining errors; analyst "To deobfuscate …" sentences), landed on 2026-11-19
  ([defender text](/data/entities.md#defender-text): body precision 0.910 → 0.939 with the model, 0.896 → 0.915
  without, recall unchanged). Not made yet: let high-precision command cues survive the gate
  without model agreement (20 table ids lost with the LLM on), then re-fit the score fusion on realistic
  pseudo-reports. Details in
  [entities](/data/entities.md#known-limits). The UI labels article techniques Named in the article / Likely / Possible,
  with the sentence each came from ([technique labels](/data/entities.md#technique-labels)).
