---
type: Feature List
title: Features
description: What Night Desk can do today, grouped by area.
tags: [features, product]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-22T18:07:00Z }
---

Night Desk is the analysis desk for the sensor you already run: it matches your Zeek and Suricata logs against threat lists as they were at the time, re-checks old logs when the lists change, matches indicators from the news to your network, and explains every alert with an evidence chain anyone can read ([network logs](/data/netlog.md)). The world view below is the context around that.

# Since v1.0

The v1.0 app (the UI built against the reference tool, tagged `v1.0` in git) grew two revisions:
the v1.1 usability pass and the v1.2 polish-and-mobile pass.

## New in v1.2

* **Phone layout:** a real phone UI, not just a narrow desktop — pages and Back between URL pages only, a bottom tab bar, bottom sheets, row swipes with Undo, and the vendor chart/map/globe libraries loaded on demand so the first phone screen downloads none of them ([phone layout](/architecture/phone.md)).
* **Routing watch:** the global BGP firehose (RIS Live) is off; in its place a per-network watch of ASNs and prefixes you choose, with private sources by default and RIPEstat opt-in ([routing watch](/project/routing-watch.md)).
* **Inbox folder** is a setting, and imported files are kept unless you turn deleting on.
* **Update bar:** a browser left open across an upgrade gets a "Night Desk was updated · Reload" bar, and a stale-cached tab can recover its scripts in one click ([web client](/architecture/web-client.md#updates)).
* Responses are gzip-compressed and web files are revalidated on each load.

## New in v1.1

* **Watch**, the front page: what changed since you last pressed "Caught up", in a fixed order (your network, things that touch you, newly exploited, news you follow, big stories, feed problems), with a first-run setup checklist ([watch](/architecture/watch.md)).
* **Alerts that read right:** a plain headline, "What to do" and "Why this severity" for every alert kind; incidents that span days; "This is expected" rules; one needs-you count; Pi-hole/AdGuard "blocked by your DNS filter" verdicts ([network logs](/data/netlog.md)).
* **Devices:** rename, type, owner, note, merge; readable fallback names; "logs cover up to …" freshness; new-device alerts after a learning period; your own indicator lists.
* **Connect logs:** guided setup for OPNsense, pfSense, Security Onion, Zeek/Suricata sensors, Pi-hole, AdGuard Home or plain files, ending in a live "waiting for the first check-in"; Pi-hole and AdGuard Home DNS logs import directly.
* **Seen on your network** chips on stories, KEV rows, drawers and entity pages, a verdict strip for IPs and domains, and one shared "Why this matters / What to do" block.
* **Notes** on incidents, entities, stories and articles, and **Copy summary** as Markdown with "redact my network" on by default.
* **Notifications** (opt-in): webhooks to ntfy, Gotify, Home Assistant, Discord or plain JSON, local network by default, counts-only daily summary ([notifications](/architecture/notifications.md)).
* **Help desk** behind "?": help for the page you're on with buttons that do the step, a live "Is everything working?" check, a 79-term glossary with hover definitions, guides, shortcuts, data sources and their terms, About and redacted diagnostics ([help](/architecture/help.md)).
* **Global search** across incidents, devices, news, entities, CVEs, settings, notes and commands, with prefix and typo tolerance; one way to open things (click for Details, Cmd/middle-click for the full page); one time-range control everywhere.
* **Honest status:** Pulse says "warming up" or "stale" instead of a reassuring score, one Live/Idle/Offline status, an offline banner, and the optional AI helper shown as optional.

# Data collection

* Prebuilt public sources, batch and live streams, covering vulnerabilities, threat infrastructure, internet infrastructure, news and social signal; the current list and which are on by default are in the [source catalog](/sources/catalog.md). The Bluesky chatter stream is off by default for new lakes.
* Each source runs on its own schedule; streams reconnect automatically with backoff.
* Turn any source on or off, or run a batch source immediately, from the Sources page.
* **AI, turned on in the app** (Settings › AI): nothing AI comes with the install. Search by meaning runs on this Mac with a small search model (about 1.2 GB). Chat (story summaries, entity briefs) runs on the built-in helper (the recommended 28 GB model on a Mac with at least 48 GB, or any MLX model already downloaded), on Ollama or LM Studio (found automatically, with the models you already have), or on any OpenAI-compatible server with an API key, with a Test button first. You see sizes, memory and free space before anything downloads, and Night Desk starts and stops the helper itself. Turning it off can delete what it downloaded ([turning AI on](/architecture/local-ai.md#turning-ai-on), [chat connection](/architecture/local-ai.md#chat-connection)).
* A **Local pipeline** status on the Sources page: AI helper up or down with its models and queue, vector index counts per collection, the article fetch queue with blocked counts per outlet, the entity pipeline and network-log matching.
* Upload your own CSV, JSON, NDJSON or plain IP list; columns are detected automatically and IPs are geolocated.
* Every source fetches its full feed each run, so late or revised data is caught, but the data lake stores only new, changed or removed records, gzipped. History can be replayed, including which IPs were on a list at any time.
* Live streams are kept as one compressed file per hour.
* Optional retention for lake files and database events, set from the Sources page. Off by default: nothing is deleted unless you choose a limit.
* IP addresses are enriched with location (city, country, coordinates) and network (ASN and owner).
* Reference data is downloaded automatically on first start.

# Across the app

* One global search in the top bar, over CVEs, news articles, entities and events. Results are grouped, keyboard-driven and labelled SEMANTIC (by meaning, with the local AI) or KEYWORD (when the AI helper is down) ([web client](/architecture/web-client.md#global-search)).
* Entity chips everywhere: IPs, prefixes, CVEs, ASNs, domains, actors, malware and tools in feeds, Explorer rows, the event drawer, Cyber Cinema, map popups and network alert evidence. They show a hover card and open the shared entity panel.
* A "needs you" badge in the top bar: untriaged, unsuppressed high and medium network incidents (demo excluded), the same number everywhere, updated live. It links to Network › Alerts.
* Works with no internet: all libraries, fonts and textures are bundled, and the World Map falls back to an offline basemap ([vendored web libraries](/environment.md#vendored-web-libraries)).
* Tabs: Watch, Network, News, Intel, Ops, Cinema; a gear menu for Settings (with Sources) and the SQL console; a "?" Help desk. Narrow desktop windows get a bottom bar (Watch, Network, News, Intel, Ops, More); phones with a touch screen get the phone tab bar, Watch · Network · News · Intel · More, with Ops, Notes, Cinema, the SQL console, Sources, Settings, Help and the tour in More, and a top bar with the page title, a health pill (Logs stale, source errors, Offline or Healthy; a tap opens the Status sheet) and search. Watch is the default landing view; any tab can be chosen instead in Settings › Display, and `#cinema?kiosk` gives a chrome-free wall display.

# Dashboards (Ops Center)

* A grid of panels you can drag, resize, maximise, add and remove.
* Four starter decks (Cyber Ops, Threat Infrastructure, Vulnerabilities, Internet Health) and custom saved decks.
* A global time range (1h to all time). Panels also follow the global search query.
* Panels: World Map, Cyber Pulse, BGP Live, Exploited Vulns, New CVEs, Threat Newswire, Social OSINT, Internet Outages, Activity Timeline, Threat Origins 3D, Top Offenders and Feed Health.
* A shared detail drawer for any event, with related sightings of the same IP or ASN and, for an address, "Listed by N feeds" with when each last listed it.
* Live updates pushed from the server; new items appear without reloading.

# Network (home lab)

* Import Zeek JSON logs by drag and drop (several files at once, with progress and a per-file result: types detected, rows, new, duplicates, rejected lines and why) or by copying them into the watched inbox.
* Overview dashboard: untriaged alerts by severity, a connections-and-alerts timeline you can drag to zoom, top talkers, destinations by country and ASN, ports, services and names, and a calm empty state that explains the three setup steps.
* Alerts grouped by rule, indicator or device, with acknowledge, dismiss and bulk actions. Each alert shows its evidence chain: device, the connections or DNS lookups, the indicator, and the threat list with its trust tier and listing interval drawn against the contact times, so you can see why it fired.
* Hunt: include and exclude filters on any field (including raw Zeek fields), presets, group-by pivots on one or two fields, a time histogram with brush-to-zoom, and rows that expand to the raw JSON. Click any value to pivot.
* Devices identified by MAC (DHCP, layer 2, EUI-64) or behaviour, with confidence, activity, hostnames, top destinations and alerts.
* IPs, ASNs and countries link to the event drawer and to Explorer. Works at phone width.

# Maps and 3D

* World map with switchable base maps, layers per event kind, undersea cables and landing points, a country heat layer, clustering or heat display, live BGP pulses, a legend, jump-to-country and cursor coordinates.
* Threat Origins 3D: bars or raised countries on a 3D globe (globe.gl), by country, with a hover card per country. (Until v1.2 it was echarts-gl with a flat extruded map; echarts-gl needs eval, which the Content-Security-Policy refuses.)
* Cyber Cinema: a full-screen 3D globe that tours notable events automatically, with event cards, leader lines, links to the nearest cable landing and to the same network elsewhere, a timeline you can brush, a live ticker and optional sound.

# Analytics

* Cyber Pulse: a 0-100 composite risk score with five sub-indices and 24-hour change ([definition](/data/cyber-pulse.md)).
* Activity timeline by event kind with linear/log scales and brush-to-zoom. Like the map and Top offenders it counts each address once, however many feeds list it.
* Top offenders by ASN, country, tag or IP; the IP tab shows how many feeds list each address (names on hover or focus) and ranks by severity or by feeds; live BGP update, announcement and withdrawal rates.
* **Routing watch** (v1.2): unexpected-origin, RPKI-invalid, hijack/leak and prefix-gone detection for the ASNs and prefixes you choose, replacing the old global firehose ([routing watch](/project/routing-watch.md)).

# News

* A News tab of clustered stories from 14 research and news outlets, with source counts and trust tiers, first and last seen, "new since your last visit" and entity chips ([web client](/architecture/web-client.md#news-view), [news data](/data/news.md)).
* Story detail with a coverage timeline, merged entities, IoCs and ATT&CK technique ids with copy, CSV and Navigator layer export, and similar stories.
* An article reader with entity highlights in the text, a "why this is here" line and a link to the original.
* Meaning-based search over article passages that falls back to keywords, with a visible badge, when the local AI is down.
* "What you follow" (My stack): vendors and products, entities and keywords, matched across KEV/CVEs, news, your network incidents, EPSS jumps and ransomware victims ([my stack](/architecture/my-stack.md)).

# Entities

* An Entities tab ([web client](/architecture/web-client.md#entities-view), [entities data](/data/entities.md)): a directory of 17 entity types with counts, search by name, alias or meaning, activity sparklines, confidence and last seen.
* Entity pages: aliases, KPI tiles, what it is, a per-source activity swimlane with a time brush, claims grouped by origin with quoted evidence, source tiers and confidence bands, confirm and reject, contested attributions side by side, an ATT&CK strip (confirmed versus suggested), indicators with CSV and STIX 2.1 export, related entities, and whether its indicators touched your network.
* An expandable entity graph with edge styles by origin, width by confidence, ASN bubbles for IP sets and a time slider.
* Merge duplicate entities ("Same as…", "Wrong type…", undoable), suggested duplicates, one "Disagree…" action with reasons, and a Review queue. Links the hub computes itself are labelled hypotheses and hidden by default. (The campaign metro map is hidden behind `#entities/metro?lab=1`.)
* Hover cards and the entity drawer for any `data-entity` chip anywhere in the app.

# Explorer

* A read-only SQL console over DuckDB with examples, a schema browser and automatic charts, off unless Night Desk is started with `OSINTHUB_SQL_CONSOLE=1`.
* Result table with sorting and CSV export; event search with filters and paging.

# Operations

* One-line Docker install (`deploy/install.sh`): asks where to keep the data, who can open it (this computer, or the network with a password it makes) and whether to trust the certificate; builds, starts and opens `https://nightdesk.localhost/`, served over HTTPS by Caddy ([deployment](/architecture/deployment.md#one-line-install-docker)). Without Docker (`uv run python -m osinthub`, or the `nightdesk` command), data goes to the platform's app-data folder unless `OSINTHUB_LAKE` is set.
* Works on desktop and phone widths.
