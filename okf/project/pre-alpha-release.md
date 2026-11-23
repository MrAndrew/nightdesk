---
type: Plan
title: Pre-alpha release plan
description: What has to be true before Night Desk goes into a public repo for a first pre-alpha round with colleagues, in workstreams, with the order to do them in and the decisions the owner still has to make.
tags: [project, release, plan, security, distribution]
status: draft
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-22T12:00:00Z }
---

# Goal

A public GitHub repo that a few colleagues can install with one line, try on demo data or their own logs, and
send feedback through GitHub issues. Pre-alpha means: rough edges are fine, but nothing personal, no keys, no known
security holes, and no feed data or third-party content that the terms forbid sharing (owner, 2026-11-18).

# Exit criteria

1. The public repo starts from a clean export with no history from the private `HLTA` repo.
2. A scan of every tracked file finds no personal info: no owner names, home folder, host or drive names, real
   addresses, MACs or IPv6 prefixes, and no keys, tokens or secrets.
3. Every item in [the terms checklist](/project/open-issues.md#before-the-repo-goes-public) is done or its source is
   off by default.
4. A security review of every HTTP endpoint is finished, its findings are fixed or written down as accepted, and the
   app refuses to listen beyond loopback without a password.
5. One line installs and starts it on a clean Mac and a clean Linux box, and it opens on a working page with demo data
   available. The installer may ask a few questions, each with a default (owner, 2026-11-20).
6. The README explains what it is, how to install, how to remove it, what it sends over the network, and how to give
   feedback; LICENSE, NOTICE (third-party terms), SECURITY.md and issue templates exist.
7. The merge gate passes on the release commit, tagged `v0.1.0-prealpha`.

# Workstreams

## 1. Clean public repo

* New public repo from a clean export of the release commit (one initial commit), rather than scrubbing the private
  history: the old history holds the Sitdeck screenshots (`v1.0` tag) and was already rewritten once for the IPv6
  prefix. The private `HLTA` repo stays the place for development until the switch.
* `okf/` ships (owner, 2026-11-19): repo-level context stays, anything specific to the owner's machine or dev setup
  goes. That means a pass over [start here](/start-here.md) (worktree paths, "the owner's live app", lane workflow),
  [environment](/environment.md) and the project pages, keeping how-to-run and how-to-test generic. `tools/` lab
  scripts (critic-loop helpers, calibration) move to `tools/dev/` or stay private. `tests/eval/` ships without its
  caches (already ignored).
* Name: public name Night Desk, public repo `nightdesk` (created by the owner 2026-11-21). Development moved
  from the private `HLTA` repo to the private `nightdesk-private` (full history and branches, 2026-11-21).

## 2. No personal info or keys

* **Done (v1.2 scrub, 2026-11-19):** `tools/release_scan.py` (standard library, tracked) scans every tracked file
  and fails on the run-time home folder, user name and git identity; key-like strings and long random strings that
  are not a known hash; `*.lan` / `*.local` host names and `/Volumes/<name>` drives outside a generic-examples list;
  MACs, IPv6 literals and private IPv4 outside the demo and documentation ranges. The owner's own names (drives,
  LAN host names, home prefixes and MACs) are patterns in a **private file outside the repo**
  (`NIGHTDESK_SCAN_PATTERNS`), never in tracked files; without it that one check is skipped, so the public repo runs
  the rest. It replaces the old hygiene checks and runs in the unit suite ([release scan](/environment.md#release-scan)).
  Every hit was fixed (the drive name, LAN host names and the user name were in 17 tracked files, 48 hits; a second pass found the drive name's stem in 2 more lines): docs and tests
  now use generic examples (`nightdesk.lan`, `/Volumes/ExternalDrive`), and the eval tools read the seed and live
  lakes from `ND_SEED_LAKE` / `ND_LIVE_LAKE`. The owner's machine-specific context (drive, host names, the live
  app's start command and lake) moved to the private machine page (outside the repo). The final scan is clean.
* **Done:** `.env` stays ignored and `.env.example` lists every variable the app and its tools read (a unit test keeps
  it complete); [environment](/environment.md#settings) documents each one, its default and where to set it. The app
  does not read `.env` itself: Docker Compose does, and native runs take the shell's environment. Keys stay
  environment-only (`ABUSECH_AUTH_KEY`, `RANSOMWARELIVE_API_KEY`, `QDRANT_API_KEY`, `CLOUDFLARE_RADAR_TOKEN`).
* Still to do: run a secrets scanner over the export as a second opinion (gitleaks or trufflehog, run once from
  outside the repo, not added as a dependency), and run the release scan with the private patterns on the export.
* Fixtures and screenshots: only demo or documentation data; the Tranco snapshot needs its licence checked.

## 3. Security settled

* **Done (v1.2 pre-alpha auth, 2026-11-19), security review C1:** LAN use is in scope for pre-alpha (owner,
  2026-11-19), never without a password. The app refuses any non-loopback bind unless `OSINTHUB_PASSWORD` is set
  (one line at start); with it, every request needs HTTP Basic (any user name; `/api/health` from this machine is
  exempt), ten different wrong passwords block an address for 15 minutes, and 50 block an IPv6 /64 (a stale tab's old
  password counts once; a correct one clears only its own address's count; bounded at 4096 addresses and 1024 networks), and the Host and CSRF checks stay as they were.
  Docker Compose keeps Caddy as the one sign-in (`OSINTHUB_TRUST_PROXY_AUTH=1`). The docs show the LAN setup and say
  that plain HTTP can be sniffed beyond a trusted home network ([who can reach it](/architecture/deployment.md#who-can-reach-it)).
* **Done (same lane):** the AI helper has the app's Host allowlist and cross-site refusal and needs `AI_TOKEN` beyond
  loopback (M2); FastAPI's `/docs`, `/redoc` and `/openapi.json` are off unless `OSINTHUB_DEBUG=1` (M3); a real
  Content-Security-Policy on every response, with no external origin at all in offline mode (M5,
  [CSP](/architecture/deployment.md#content-security-policy)); request bodies are capped at 16 MB outside the two
  upload routes, and network-log imports are capped at 2 GB per request (L2).
* Review every endpoint that reads input: SQL console (fix round 3 found two holes that predate it: a file path
  written as `schema.table` reads local files, and DuckDB auto-installs extensions from the internet even offline;
  see [open issues](/project/open-issues.md)), network-log upload and import, notes, settings, source enable, search,
  the AI helper routes. Use the project's `/security-review` pass plus a separate harsh evaluator, as for lanes.
* Switch off DuckDB's extension auto-install and auto-load app-wide, and ship or document the few extensions the app
  needs, so offline mode really means no egress.
* **Done (v1.2 sqlgate):** the SQL console is off unless Night Desk is started with `OSINTHUB_SQL_CONSOLE=1` (owner,
  2026-11-19): off, `POST /api/sql` answers 403 with how to turn it on, the client hides every way in and Explorer
  explains, and Settings › About shows the state; no app feature needs it. When on, its answers never name a server
  path: settings, database-file and environment functions and views are refused, and DuckDB's own folders sit in the
  lake instead of `~/.duckdb` ([API](/architecture/api.md#sql-console), [switches](/environment.md#switches)).
* **Done (v1.2 harden, 2026-11-20): pre-alpha security review findings M1, M4, L1, L3, L5.**
  * ✓ **M1** robots.txt is fetched hop by hop with the public-address check (an internal hop makes it unavailable,
    nothing stored), and article and robots requests connect to the address that was checked, with the real name
    in `Host` and SNI ([news fetching](/data/news.md#fetching)).
  * ✓ **M4** `/api/upload` streams rows (`fetchmany`) and loads them in 20,000-row parts, keeps at most 200,000 rows
    (and says so) and takes at most 64 MB; JSON and NDJSON are read with a streaming decoder. The review's
    300,000-row CSV went from +961 MB to +191 MB of server memory, a 300,000-row JSON array or NDJSON +187/+189 MB
    ([size limits](/data/size-limits.md#uploads)).
  * ✓ **L1** the article role is whitelisted before it becomes a class name, and the other API values found in class
    and attribute values are escaped (help status, claim origin and verdict, technique kind, device timeline kind,
    push sender id and upload status, story counts, search score, IODA country); a unit test keeps them so.
  * ✓ **L3** every source download has a byte cap (about 4x its largest measured response), counted after decoding
    with bounded inflating and redirects followed by hand (a 3xx body is never read), so a gzip bomb stops at the
    cap; over it the run fails and stores nothing
    ([size limits](/data/size-limits.md)).
  * ✓ **L5** the upload and log-import answers (and inbox scan and push results) give lake-relative paths only. GET
    routes for settings, about and paths keep absolute paths; the `PUT` settings routes that answer with the same
    document as their GET (inbox folder, push listener) keep it too, since the GET serves it anyway.
* ✓ Defence in depth for the SQL console: the app database runs with DuckDB's `enable_external_access = false` and
  `allowed_directories` limited to the lake and its own folder, so even a missed bypass cannot read other files
  (`tests/security/test_sql_allowlist.py`). The other two DuckDB connections are shut as tight as their feature
  allows (pre-public fix round): the vector index reads no file at all, an upload's CSV reader only that upload
  (`db.restrict`, `tests/security/test_v12_pf_sql.py`).
* ✓ **Dependency audit (2026-11-21):** `pip-audit` (run with `uvx`, nothing added) over every locked package of
  `uv.lock`, with and without the AI groups: no known vulnerabilities. The vendored web libraries were checked
  against OSV: cytoscape 3.30.2, globe.gl 2.32.4 (three r163 inside) and gridstack 10.3.1 have none. ECharts 5.5.1 has
  GHSA-fgmj-fm8m-jvvx (XSS through a Lines series tooltip): not affected, Night Desk draws no Lines series. MapLibre
  4.7.1 had GHSA-jrc7-96c5-q579 (the attribution sanitizer skipped attributes; attribution comes from the map
  style, so CARTO's styles with the user's key): upgraded to 5.24.1, which carries the fix (the CSP already blocked
  inline handlers). Run it again before the tag.
* ✓ The Docker image runs as an unprivileged user (`nightdesk`, uid 1000).
* ✓ The Tranco download (online installs, netlog allowlist) has a byte cap like every source (40 MB, `ref_tranco`),
  and only its first 20,000 lines are unpacked.
* ✓ SECURITY.md: how to report a problem privately (GitHub private vulnerability reporting), what is in scope, and
  the security model in short.

## 4. Clean code base

* ✓ **Tech-debt pass (2026-11-21):** no TODO or FIXME markers left; vulture's dead-code candidates checked by hand
  (most are routes, registered sources and tool-only helpers): the unused `write_events`, the `client_key` alias and
  the `NEWSROOM` interval are gone; the two CSS rules no page uses are gone (the rest of app.css is reached from
  the code or styles library elements).
* ✓ **Lint pass (2026-11-21):** `[tool.ruff]` in `pyproject.toml` checks faults and safe upgrades, run with
  `uvx ruff check osinthub tests tools`, and the tree is at zero. No formatter: it would rewrite 226 files and undo
  the dense house style (lead's call). The pass found one real bug (event addresses kept each feed's spelling, so the
  same IPv6 address from two feeds did not match; now normalised) and a test that never tested what it named.
* Keep the follow-up lists short before release: [open issues](/project/open-issues.md) and the fix-round
  follow-ups either fixed or listed as known limits in the release notes.

## 5. One-line install and run

Principle (owner, 2026-11-20): **HTTPS by default.** The install sets up Caddy in front of the app with a
certificate, and a LAN name where the platform allows it. After the download the installer may ask a few questions,
each with a default (`--yes` takes all defaults), then starts the app. Everything else has a safe default and is
changed later in the app or in `.env`. Priority: Apple silicon macOS, then Linux, then Windows.

| Setting | Default | Changed where |
|---|---|---|
| Reach | **this computer only**: `https://nightdesk.localhost` (browsers send `*.localhost` to this machine; no DNS) | installer question; `--reconfigure` (`--lan`) |
| LAN name (when LAN is chosen) | `nightdesk.local`, announced over mDNS by `nightdesk` (`dns-sd` on macOS, `avahi-publish` on Linux); Windows, with no built-in announcer, uses `<computer>.local` | installer question; `.env` |
| Certificate | Caddy's local CA (`tls internal`), trusted on this computer with `caddy trust` (one admin password prompt); other devices get a small page with the CA file and per-device steps | installer question |
| LAN sign-in | a generated password, printed once (Caddy basic auth); the app stays on `127.0.0.1:8787` behind Caddy | `.env` |
| HTTPS port | 443 when free, else the first free of 8443–8449 (Docker publishes it, so no admin rights are needed); never touching a port that is already taken | `--port`; `.env` |
| Data folder | the platform's app-data folder (`~/Library/Application Support/Night Desk`, `~/.local/share/nightdesk`, `%LOCALAPPDATA%\Night Desk`), for the container too (a host folder, so a later native install finds the same data) | an installer question ("Where should Night Desk keep its data?"); later in Settings › Data ("Change…"): a native run copies the lake to the new folder, records the choice in a small settings file outside the lake and restarts; a container cannot change its own mount, so Settings shows the folder and a ready command that moves it and restarts the container; `--lake` / `OSINTHUB_LAKE` / `LAKE_DIR` still win |
| Start at login | no; `nightdesk service install` (launchd, systemd user unit, Task Scheduler) | command |
| Feeds | only sources whose terms allow it, keyless | Sources view |
| API keys | none | `.env` (no secrets UI) |
| AI helper | not installed: no AI libraries and no models are downloaded by the install line; keyword search fallback | an optional feature turned on in the app (Apple silicon only for pre-alpha). Turning it on shows one confirmation dialog with two choices, each with its size, where it goes and the memory it needs: the search model (about 1.2 GB) and the chat model (about 28 GB, ticked only when the Mac has enough memory). Nothing is downloaded before the user confirms, and never in offline mode (owner, 2026-11-20: models only when the user turns the feature on, so each person decides from their machine and needs). The libraries come with the same download rather than with the install, so the one switch controls all of AI (lead's design); the helper stays a separate process. Turning AI off stops the helper and offers to delete the models. ✓ Built 2026-11-21 as Settings › AI: the libraries go into Night Desk's config folder (`uv pip install --target`), the app starts and stops the helper, and in Docker the page explains that the helper runs on the Mac outside the container ([turning AI on](/architecture/local-ai.md#turning-ai-on)) |
| Demo data | offered on the empty Network page | Network view |

**Order (owner, 2026-11-20): the first release installs as a container**, on every OS, with Caddy and a
certificate as above. The Python package comes first because the image installs it; the native Mac path below
(needed for local AI on the Mac GPU) follows after the release. Native Linux and Windows installs are not planned.

**Native path (after the first release, macOS): a Python package plus a short install script** (from the GitHub
release tag, not PyPI):

* `curl -fsSL https://github.com/MrAndrew/nightdesk/releases/latest/download/install.sh | sh` (macOS, Linux) and
  `irm https://github.com/MrAndrew/nightdesk/releases/latest/download/install.ps1 | iex` (Windows). The script installs uv if missing,
  installs Night Desk with `uv tool install` from the release tag (uv brings Python 3.14 and every dependency,
  DuckDB included), downloads Caddy's official release for the OS and checks its checksum, asks the questions above
  (reading from the terminal, since stdin is the pipe), starts the app, waits for `/api/health`, prints the address
  and opens the browser. Readable, short, and the README also shows the manual commands.
* `nightdesk` starts the app and Caddy (and the mDNS announcement when LAN is on) as one unit and stops them
  together; `nightdesk upgrade`, `nightdesk uninstall` (asks before deleting the data folder).
* ✓ The repo is a real package, `nightdesk` (lane v12-pkg, 2026-11-20): the `nightdesk` command, `web/` and `okf/`
  inside the wheel, the platform's app-data folder as the default lake ([the package](/architecture/deployment.md#the-package)).
* Qdrant is not needed: vectors fall back to DuckDB (`OSINTHUB_VECTORS=auto`).

**First release: the container (any OS).** The one line checks Docker, fetches the release's Compose setup (app and
Caddy; Qdrant optional), asks the questions above, starts it, trusts Caddy's certificate on the host and opens the
browser. No local AI inside the container (Docker cannot use the Mac GPU).

* ✓ Built (lane v12-container, 2026-11-20): `deploy/install.sh`, the two-stage non-root image that installs the
  package, Caddy at the site root with the `ND_BIND` reach rule, optional Qdrant
  ([one-line install](/architecture/deployment.md#one-line-install-docker)). Tested on macOS with Docker Desktop:
  install, update, LAN reconfigure (password rule), uninstall.
* ✓ Settings › Data "Change…" (lane v12-datamove, 2026-11-20): a native run moves its own data folder and restarts;
  Docker shows the `install.sh --move-data` command ([moving the data folder](/architecture/deployment.md#moving-the-data-folder)).
* ✓ The release URL (2026-11-21): `install.sh` names the `nightdesk` repo and `VERSION="v0.1.0-prealpha"`, the tag
  of the first cut, which is pushed there while the repo stays private for the owner's review. Re-cut on 2026-11-22
  after the pre-public fixes, with the first `CHANGELOG.md`: still one commit, the same tag name.
* Still to do for the release: publish `install.sh` as a release asset when the repo opens (the one-line install
  downloads the tag's archive, which needs the repo to be public); the owner tests on a clean Mac and a Linux machine.

Test both paths on clean machines (a fresh macOS user account, a Linux VM, a Windows VM).

## 6. README and the video

* README: one-paragraph pitch, a short animation, install, first steps (demo data, add a feed key, import Zeek
  logs), what it sends over the network (and `OSINTHUB_OFFLINE=1`), privacy statement (no telemetry), uninstall,
  feedback, licence.
* Video: the animation exists and runs a little under a minute. Upload it through GitHub's editor so it is stored as
  a GitHub attachment and plays inline in the README; re-encode it (H.264, 720p or 1080p, muted) to fit GitHub's
  attachment limit (10 MB on free plans), or trim a 20-30 s cut for the README. Demo data only. Do not commit it to the repo (it
  stays in history forever and a repo-path MP4 does not play inline). A longer walkthrough can go on YouTube, linked
  from a thumbnail image, since a README cannot embed a YouTube player. A GIF or WebP fallback is optional.

## 7. Feedback from testers

* ✓ **Issue forms (2026-11-21):** `.github/ISSUE_TEMPLATE/` has bug, feedback, feed request and log format request
  forms (version, install path, OS and steps where they help); blank issues are off, so every issue starts from a form,
  and each opens with the notice: keep your own network out of it, use Copy diagnostics and `nightdesk-redact`, and
  report security problems privately (SECURITY.md).
* ✓ **Copy diagnostics (2026-11-21):** Settings › About copies (and shows) a plain-text summary: version, install
  path, machine, switches, counts, source health with each error, local AI and extension errors, with addresses,
  MACs, local host names, folders and keys removed ([diagnostics](/architecture/api.md#diagnostics)).
* Other network logs: testers are asked to try log formats beyond Zeek (Suricata, firewall and router logs, DNS
  resolvers). A "log format request" form asks for a short **synthetic or redacted** sample. ✓ `nightdesk-redact`
  (2026-11-21, `osinthub/redact.py`, also `python -m osinthub.redact`) maps addresses onto the documentation and test
  ranges (local and public kept apart), MACs onto locally administered ones and names onto `siteN.example`,
  consistently within a run; it says what it cannot see (user names, paths, free text, dotless device names, encoded
  fields such as AdGuard's base64 answers).
* Automated issue triage is a maintenance idea kept outside the public repo (owner, 2026-11-19).

## 8. Terms and licences

Finish [the terms checklist](/project/open-issues.md#before-the-repo-goes-public) and write NOTICE / THIRD-PARTY
from it. The licence is set out [below](#licence-owner-2026-11-19); check that every vendored library's licence
allows it to be shipped with the project.

The terms review (every terms page read 2026-11-19; each [source page](/sources/catalog.md) has its "Terms" section)
left ten things to do before pre-alpha:

1. ✓ **`ask` sources off in code** (v1.2 feeds lane): Spamhaus DROP, DShield, blocklist.de, ET compromised and IODA
   are `default_enabled = False`, so a new install fetches none of them before "Choose your sources" is answered
   (they show unticked). An install that ran them before and answered the box with Keep, or was never offered it,
   keeps them on once (`TERMS_OFFS` in `osinthub/scheduler.py`); "Apply" had saved a flag for every source, which is
   never changed. A unit test holds every source to "on in code only when `feed_terms` says `on`".
2. ✓ **rpki_roas is `ask`** in `feed_terms.py`, and nothing switches it on by itself. A fresh user can answer before
   any network is watched: its box in "Choose your sources" can be ticked or left unticked (Apply saves the answer
   either way), and its Routing watch toggle works before the first network. If a network is watched and no answer
   is saved, Routing watch asks once ("Also check RPKI signing with the public daily file? Its provider states no
   terms.", Yes / No) and it stays off until then. An install where it is already on keeps it. Cloudflare Radar keeps
   switching on once the user saves their own token.
3. ✓ **TeleGeography cables are opt-in** (v1.2 terms lane, 2026-11-20): never downloaded at start; turning the world
   map's cable or landing layer on downloads both files once (`POST /api/geo/cables/fetch`, 64 MB cap a file, refused
   in offline mode), and wherever cables are drawn (map, Cinema) "Cable data © TeleGeography (submarinecablemap.com)"
   shows on screen. The layer is off by default; installs that already have the files keep them. Drop the layer if
   TeleGeography says no.
4. ✓ **Online basemaps only with the user's own CARTO key** (v1.2 terms lane): the keyless CARTO styles and both Esri
   layers (Satellite, Terrain and their labels) are gone; local stays the default. With `CARTO_API_KEY` set, Dark
   Matter and Positron come back with the key on CARTO's style URL (`?key=`, as CARTO documents) and "© OpenStreetMap
   contributors, © CARTO" on the map itself (CARTO: not behind a click); the CSP lists CARTO only then. CARTO's
   terms read 2026-11-20 (https://carto.com/legal/basemap-terms/): free with a key, 5M tile requests a month
   non-commercial, no server-side proxying or caching. Not tried with a real key: CARTO moved its vector styles to
   the Protomaps schema on 2026-10-21, so Dark Matter's re-toning (`toneDark`, written for the old layer names) may
   no longer apply; the map still shows CARTO's own style.
5. ✓ **Feodo Tracker is `ai_ok = False`**, like every abuse.ch source (ToS s7.3 has no CC0 carve-out): its claims
   stay out of the entity brief, and malware names known only from Feodo are never embedded.
6. ✓ **Bluesky stays, with terms of our own** (v1.2 terms lane, owner's decision 2026-11-20): the reported rule
   ("All services must have a method for deleting content a user has requested to be deleted") is read as met by
   a local, offline-capable install whose user controls and can delete their own data. NOTICE ("Your data and the sources you
   turn on") and the README carry one generic pass-through line and nothing source-specific: you are responsible for
   how you keep, use and share what the sources you turn on send, and for following each source's terms. The stream
   now records each Jetstream delete of a post it stored in the DuckDB table `deletion_requests` (event id, url,
   when the author deleted it) and **does not hide or remove the post**. Deletes made while Night Desk is stopped are
   not seen (no cursor replay). The rule is Bluesky's own wording: item 3 of the "Bluesky Developer
   Guidelines" in Bluesky's docs repository (github.com/bluesky-social/bsky-docs, `docs/support/developer-guidelines.md`,
   read 2026-11-20). The docs site's page now redirects to an empty page and the repository was archived on
   2026-08-18, so whether the guidelines are still current is not known.
7. ✓ **Attribution in the app:** "IP Geolocation by DB-IP" linked on the world map and in Help › About; Help ›
   Sources › Credits names every provider whose terms ask for credit (Spamhaus, ransomware.live linked, RIPE NCC,
   Cloudflare Radar, TeleGeography, CARTO / OpenStreetMap, MISP galaxy and Malpedia, blocklist.de, CINS Army,
   Proofpoint ET, Natural Earth) and carries MITRE's notice, beside the NVD and EPSS lines.
8. ✓ **Files** (v1.2 terms lane): `LICENSE` (PolyForm Noncommercial 1.0.0, verbatim, with "Required Notice:
   Copyright 2026 The Night Desk authors": owner's choice, so no personal name is tracked), `NOTICE` (from the lead's
   draft, with ECharts' NOTICE verbatim from the echarts@5.5.1 package), `web/vendor/glyphs/OFL.txt`; the unused
   vendored echarts-gl is removed.
9. ✓ **Globe images and Tranco** (v1.2 terms lane): the three-globe images are replaced by NASA's public-domain Blue
   Marble (2002), Black Marble (2012) and SRTM topography, from the Wikimedia Commons copies of the NASA originals
   (NASA's record pages now redirect), scaled to the old sizes; source of each in `web/vendor/nasa/SOURCES.md` and
   NOTICE; `night-sky.png` dropped (Cinema's background is plain). `tranco200.json` and the Tranco part of
   `top-domains.txt` are gone: the network demo browses a hand-made list of 58 well-known sites on documentation
   addresses (`popular-sites.json`), and the offline allowlist is the ~170 hand-picked services (online installs still
   download the Tranco top 20k themselves).
10. ✓ **Terms records fixed:** Tor exits CC0 (CC BY 3.0 US is the graphs only), ransomware.live non-commercial (T&C
    s5), DShield "no resale; own-network use, commercial included", the catalog's "In app" column, and a terms
    line with link and read date on every source page.

# Next session: where to pick up (2026-11-20)

Workstreams 2 (personal info and keys), 3 (security review findings C1, M1-M5, L1-L5) and all of 8 (items 1-10
above; 3, 4, 6, 8 and 9 built in the v12-terms lane on 2026-11-20 with the lead's recommended decisions, confirmed by
the owner) are done.

The owner sends the operator emails drafted in the lead's terms review (RIPE NCC, Cloudflare and rpki-client,
TeleGeography, Tranco, IODA, blocklist.de, Proofpoint ET, CINS Army); each answer goes into that source's page. A
"no" from TeleGeography drops the cable layer; a "yes" from Tranco can bring the offline list and the demo's real
sites back.

**Workstream 3 is done (2026-11-21):** the dependency audit, the MapLibre upgrade, the Tranco cap and SECURITY.md;
the known limits are in the [release notes](#known-limits).

**Then:** workstreams 4 (clean code base), 5 (one-line install), 6 (README and video) and 7 (tester feedback), in
the order below. Keyboard-only operation is not a requirement (owner, 2026-11-20): lanes neither build nor test it.

# Order

1. Owner decisions are in (see below).
2. Workstreams 2 and 3 first (they can block release), with 8 in parallel.
3. Workstream 4, then 5 (the installer is easier once the tree is clean and the bind/password rule exists).
4. Workstreams 6 and 7, then the clean export, the release scan, the gate, and the tag.
5. Install test on clean machines, then invite colleagues.

# Owner decisions (2026-11-19)

* Licence: see below. Repo name: `nightdesk` (public), `nightdesk-private` (development). `okf/` ships, without dev- or machine-specific content.
* AI: Apple silicon only for pre-alpha, behind an on/off toggle.
* LAN use: allowed; testers should try other network-log formats.
* Issue triage automation: not part of the public repo.
* Video: exists, a little under a minute.

# Licence (owner, 2026-11-19)

* **Pre-alpha: PolyForm Noncommercial 1.0.0** (source-available, not OSI open source). Personal, research, education
  and other noncommercial use is allowed; commercial use is not. It does not stop noncommercial public hosting, so the
  README also asks testers not to host it publicly without permission.
* **Later: Apache-2.0**, once the project is ready for general use.
* The relicence is only simple while the owner holds all the rights: until then, outside code contributions need a
  short contributor agreement that lets the owner relicense (or the pre-alpha takes feedback through issues only).
* Vendored libraries keep their own licences (MIT, BSD, OFL and others), listed in NOTICE; PolyForm covers Night
  Desk's own code only. The feed terms (several feeds are noncommercial too) are listed there as well.

# Release notes (draft)

Upgrade notes collected for the pre-alpha release notes.

* **Feeds whose terms are unclear or restrictive now start off** (terms review, 2026-11-19): Spamhaus DROP, DShield,
  blocklist.de, Emerging Threats compromised hosts and IODA. An install that already answered "Choose your sources"
  (or was never offered it) keeps what it ran. An install still waiting for that answer starts with these five off,
  even if it had been fetching them under the old default, until the user ticks them in the box or in Sources.
* **The RPKI file is no longer switched on with the first watched network**: Routing watch asks once. An install where
  it is already on keeps it.
* **Feodo Tracker data is kept out of AI features** like the other abuse.ch feeds. On the first start after the
  upgrade, malware names known only from abuse.ch feeds lose their search vectors and cached brief texts written from
  that evidence are dropped (they are written again from the remaining evidence).

## Known limits

* **IPv6 neighbours:** on a local-network install, 50 wrong passwords from one IPv6 /64 block that whole network for
  15 minutes, so a device on the same /64 can lock the other IPv6 devices there out
  ([who can reach it](/architecture/deployment.md#who-can-reach-it)).
* **One password:** there are no user accounts; the password gives full control (SECURITY.md).
* **The AI helper's token has no throttle** for wrong guesses. It is needed only when the helper listens beyond this
  computer, which it does not by default.
* **Paths in a few answers:** the settings answers for the inbox folder, the push listener and the certificate name
  the data folder's path, as their GET routes do.
* **Search by meaning with Docker:** Settings › AI can't install or start the helper from inside the container; it
  runs on the Mac outside it, started by hand from a copy of the source. Chat needs no helper: it can use Ollama or
  LM Studio on the Mac, which the page finds at `host.docker.internal` ([chat connection](/architecture/local-ai.md#chat-connection)).
* **Chat on other servers is tested with Ollama and MLX only:** LM Studio and providers (OpenRouter, OpenAI,
  Anthropic's or Gemini's compatibility endpoints) use the same OpenAI chat requests but were not tried.
* **Size caps that are estimates:** the RPKI file, Cloudflare Radar, RIPEstat, ThreatFox and URLhaus have caps set
  from estimates, not measurements ([size limits](/data/size-limits.md)).
