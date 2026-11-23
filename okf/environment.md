---
type: Reference
title: Environment
description: What is installed, downloaded and started for Night Desk on the development Mac, where its data lives, the vendored web libraries, and how to remove each addition.
tags: [environment, installation, data, removal]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-22T17:27:00Z }
---

A snapshot of the development Mac (macOS 27, Apple silicon) on which Night Desk was built. Versions and sizes
rot; regenerate them (`uv pip list`, `du -sh`) rather than trusting the numbers here. The repo's own
dependencies are pinned in `pyproject.toml` / `uv.lock`.

# Installed software

**Added for Night Desk** (all via Homebrew unless noted; remove with `brew uninstall <name>`):

* **GitHub CLI (`gh`)** — to create and push the repository.
* **gitleaks** — scanning the repo and its history for secrets before a push.
* **Caddy** — to validate and test `deploy/Caddyfile` on the host (TLS via the internal CA + basic auth); the
  deployment itself runs `caddy:2.8.4-alpine` in a container, not this host binary.

**Already installed, used as-is:** Docker Desktop (runs the containers), Homebrew, the DuckDB CLI (optional,
for querying `hub.duckdb` by hand while the app is stopped — DuckDB allows one writer), uv (creates the venv
and runs the app), Python 3.14 (the venv interpreter), Google Chrome (headless, throwaway profile, for
screenshots) and git.

**Python packages** live in `.venv/` (created by `uv sync`; nothing in the system Python). The direct
dependencies (`pyproject.toml`) are fastapi, uvicorn[standard], duckdb, numpy, httpx, websockets, feedparser,
trafilatura, maxminddb, python-multipart, certifi, pytz and cryptography (the upload listener's self-signed
cert). mlx-lm (the AI helper, macOS only) is in the `mlx` dependency group, which uv installs by default; the
Docker image skips it. `uv.lock` pins every transitive version. Remove with
`rm -rf .venv`.

**Not needed:** Go and Node/npm (the backend is Python; the web client has no build step).

# Containers

Docker Compose project `nightdesk` (`ND_PROJECT`; an older install keeps its own project name through its `.env`, so its volumes stay attached; [deployment](/architecture/deployment.md)):

* **Images:** `nightdesk-app` (built locally from the repo `Dockerfile`), `caddy:2.8.4-alpine` (pulled),
  `qdrant/qdrant:v1.20.0` (pulled, used by the Compose `qdrant` service and the standalone `hlta-qdrant`
  container), plus the `python:3.14-slim` and `ghcr.io/astral-sh/uv` build-cache bases.
* **Containers:** `nightdesk-app-1` (port 8787, internal only; runs as `ND_UID`/`ND_GID`) and `nightdesk-caddy-1`,
  which publishes `${HTTPS_PORT}` (default 8443; the installer picks 443 or the first free of 8443–8449) on the
  `ND_BIND` address (`127.0.0.1` by default, `0.0.0.0` for the network with a password), the same port inside the
  container. The `qdrant` service is optional (Compose profile `qdrant`) and only exposes 6333 inside the Compose network.
  The installer keeps its files in `~/.nightdesk` (`NIGHTDESK_HOME`: `app/`, `.env`, `nightdesk-root.crt`), and in LAN
  mode on macOS a launch agent `~/Library/LaunchAgents/local.nightdesk.mdns.plist` announces `nightdesk.local`. The standalone `hlta-qdrant` holds the vector index for host runs on `127.0.0.1:6335` → 6333
  ([local AI](/architecture/local-ai.md#vectors)); it is rebuilt from the lake, so `docker rm -f hlta-qdrant`
  is safe.
* **Volumes:** `nightdesk_lake` (the container's own lake, separate from a host-run lake unless `LAKE_DIR`
  is set), `nightdesk_caddy_data`, `nightdesk_caddy_config` and `nightdesk_qdrant` (the Compose Qdrant service's
  storage).

# Data locations

**Reference data** is downloaded by `osinthub/bootstrap.py` on first start into `<lake>/ref`, so there is one
copy per lake. Delete a file to re-download it next start. The cable files are the exception: they are opt-in and
downloaded once only when the user turns the world map's cable layer on (`POST /api/geo/cables/fetch`, capped at
64 MB a file; never in offline mode), and the map and Cinema then credit TeleGeography on screen.

| File | Source | Licence |
|---|---|---|
| `dbip-city-lite.mmdb`, `dbip-asn-lite.mmdb` | DB-IP IP-to-City / IP-to-ASN Lite, monthly | CC BY 4.0 |
| `countries-110m.geojson` | Natural Earth 1:110m admin-0 countries | Public domain |
| `cable-geo.json`, `landing-point-geo.json` (opt-in) | TeleGeography Submarine Cable Map | CC BY-NC-SA 3.0 (map); TeleGeography says the underlying data is for subscribers, so it is asked about |

**The data lake** (default the app-data folder (`~/Library/Application Support/Night Desk` on macOS, `~/.local/share/nightdesk` on Linux), or `OSINTHUB_LAKE`): `db/` (`hub.duckdb` plus the rebuildable
`vectors.duckdb`), `raw/` (record and event deltas per source), `ref/` (above), `tmp/` (the open stream hour)
and `uploads/`; DuckDB's own folders (`home_directory`, `secret_directory`, `extension_directory`) point to
`db/.duckdb/` instead of `~/.duckdb`, and persistent secrets are off, so the app writes nothing to the home folder (the
folder is only created if DuckDB ever needs it). Layout and policy are in [data architecture](/data/architecture.md). Retention is off by
default, so the lake grows until a limit is set. If the lake or `OSINTHUB_DB` is under an unmounted
`/Volumes/<name>` drive, the app refuses to start rather than create an empty lake on the boot disk.

<a id="vendored-web-libraries"></a>

# Vendored web libraries

The web client loads nothing from a CDN and has no CDN fallback: every library, texture, font and map glyph
is copied into `web/vendor/` at an exact version and served by the app itself, so it renders with no internet
(checked with `tools/shot.py --offline`, which routes every non-loopback request to a dead proxy). Each folder
keeps the package's LICENSE; about 7.8 MB in total.

| Package | Licence | Used by |
|---|---|---|
| gridstack | MIT | Ops deck grid |
| maplibre-gl | BSD-3 | World Map panel |
| echarts | Apache-2.0 | All charts |
| globe.gl (includes three.js and three-globe) | MIT | Cyber Cinema globe; Threat Origins 3D (echarts-gl was removed in v1.2: it needs eval, which the Content-Security-Policy refuses) |
| NASA Blue Marble, Black Marble and topography images (`web/vendor/nasa/`, source and scaling of each in its `SOURCES.md`) | Public domain | Cyber Cinema globe (day, night lights, relief). They replaced three-globe's example textures, whose source was not stated |
| cytoscape | MIT | Entity graph (loaded on demand) |
| @fontsource/inter, @fontsource/jetbrains-mono (5.1.0) | SIL OFL 1.1 | The whole UI (replaces Google Fonts) |
| @fontsource/fraunces 5.3.0: latin 400, 500, 600 and 400 italic woff2 only, 77 KB (81 KB with LICENSE) | SIL OFL 1.1 | The `--serif` masthead and headlines; a page fetches only the faces it shows (18 to 59 KB) |
| MapLibre glyphs (CARTO font server): Montserrat, Open Sans, Noto Sans | SIL OFL 1.1 (`web/vendor/glyphs/OFL.txt`) | World Map cluster counts |

By default the browser makes **no request to any host but the app itself**. What still needs the internet is
opt-in and degrades cleanly: online basemaps (only CARTO's Dark Matter and Positron, and only with the user's own
`CARTO_API_KEY`; the World Map defaults to its offline local basemap, and online ones are disabled under
`OSINTHUB_OFFLINE=1`), the cable layer's one-time download, Bluesky names and avatars in the Social OSINT panel (per-browser
opt-in, never in offline mode), and outbound links in new tabs. To upgrade a library, download the new version
into a new `web/vendor/<package>@<version>/` folder, change its path where it is loaded, and delete the old folder. The
five on-demand scripts are in the `LIBS` table of `web/js/core/libs.js`; `web/index.html` holds only the CSS
links (fonts, GridStack, MapLibre); Cytoscape is loaded by `web/js/views/entities/graph.js` and the globe
textures by `web/js/views/cinema.js`.

# Processes

* The app: `uv run python -m osinthub`. Stop with `kill $(lsof -tiTCP:<port> -sTCP:LISTEN)` and wait for it to
  exit before restarting (DuckDB locks the file). Bound to loopback it needs no password; any other bind refuses to
  start without `OSINTHUB_PASSWORD` ([who can reach it](/architecture/deployment.md#who-can-reach-it)). Behind a reverse
  proxy that does the sign-in, keep the loopback bind and set `OSINTHUB_ALLOWED_HOSTS` to the proxy's name
  ([deployment](/architecture/deployment.md#host-allowlist-dns-rebinding)).
* The AI helper: `uv run python -m osinthub.ai.server` on `127.0.0.1:8790` (about 29 GB of unified memory).
  Stop with `kill $(lsof -tiTCP:8790 -sTCP:LISTEN)` ([local AI](/architecture/local-ai.md#ai-helper)).
* The optional containers (above).

<a id="switches"></a>
**Switches** read once at start (in `osinthub/config.py`; values `1`, `true`, `yes` or `on`):

| Variable | Default | What it does |
|---|---|---|
| `OSINTHUB_SQL_CONSOLE` | off | Turns the SQL console on (`POST /api/sql` and the Explorer page). Off, the API answers 403 and the client hides every way in ([API](/architecture/api.md#sql-console), [web client](/architecture/web-client.md#sql-console)). |
| `OSINTHUB_DEBUG` | off | The one general debug switch: turns the SQL console on too and serves FastAPI's `/docs`, `/redoc` and `/openapi.json` (off otherwise, [CSP](/architecture/deployment.md#content-security-policy)). |
| `OSINTHUB_TRUST_PROXY_AUTH` | off | A reverse proxy in front does the sign-in: the app neither refuses a non-loopback bind without a password nor asks for one. Docker Compose sets it (Caddy). Never without such a proxy. |
| `OSINTHUB_OFFLINE` | off | No outbound connections at all ([offline mode](/architecture/local-ai.md#offline-mode)). |

The test servers (`tests/e2e/server.py`, so `tools/scratch-server.sh`, `tools/gate.sh`, smoke.py and the journeys) start
with `OSINTHUB_SQL_CONSOLE=1`; `ND_SQL_CONSOLE=0` starts one with it off. Unit test lakes (`tests/_lake.py`) start with it
off unless a module passes `OSINTHUB_SQL_CONSOLE="1"`.

<a id="settings"></a>

# Settings: every environment variable

Night Desk takes all its settings from environment variables, read once at start; nothing machine-specific is a code
default (the lake defaults to the platform's app-data folder, the address to loopback). **Where to set them:**

* **Docker Compose** reads `.env` next to `docker-compose.yml` (copy `.env.example`; `.env` is ignored by git) and
  passes on only the variables `docker-compose.yml` names in each service's `environment:`.
* **Native runs** (`uv run python -m osinthub`): **the app does not read `.env` itself.** Export the variables in
  the shell that starts it (`set -a; . ./.env; set +a`), on the command line (`OSINTHUB_LAKE=… uv run …`), or in
  a shell profile; keys belong in `~/.zshenv` rather than `~/.zshrc` so background shells see them too.
* Real values (keys, the lake path on your drive, your LAN host names) live only in `.env`, the shell or a profile,
  never in a tracked file. `.env.example` lists every variable with an empty or generic value, and
  `tests/web/test_repo_hygiene.py` fails when the code reads one it does not list.

| Variable | Default | What it sets | Docker (`.env` name) |
|---|---|---|---|
| `OSINTHUB_LAKE` | the folder chosen in Settings › Data, else the app-data folder (`osinthub/lakeloc.py`) | The data lake folder (when set, Settings cannot change it); refused when under an unmounted `/Volumes/<name>` | fixed `/data`; host folder `LAKE_DIR` |
| `OSINTHUB_DB`, `OSINTHUB_VECTORS_DB` | `<lake>/db/hub.duckdb`, `vectors.duckdb` beside it | The warehouse and the DuckDB vector store | — |
| `OSINTHUB_HOST`, `OSINTHUB_PORT` | `127.0.0.1`, `8787` | Listen address and port | fixed (Caddy in front: `HTTPS_PORT`, `ND_BIND`) |
| `OSINTHUB_ALLOWED_HOSTS` | none (loopback only) | Extra host names the app answers to ([deployment](/architecture/deployment.md#host-allowlist-dns-rebinding)) | from `HLTA_HOSTS` |
| `OSINTHUB_PASSWORD` | none | The app's password (HTTP Basic, any user name; at least 8 characters, whitespace only counts as unset); required for any non-loopback `OSINTHUB_HOST`, checked on every request when set except `GET /api/health` from this machine ([who can reach it](/architecture/deployment.md#who-can-reach-it)) | — (Caddy signs in) |
| `OSINTHUB_TRUST_PROXY_AUTH` | off | A proxy in front does the sign-in (a [switch](#switches)) | fixed `1` |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1,::1` | Proxies whose `X-Forwarded-Proto` and `X-Forwarded-For` uvicorn trusts. **Never `*` on a native LAN bind**: any LAN host could then claim any client address and dodge the sign-in throttle ([who can reach it](/architecture/deployment.md#who-can-reach-it)) | fixed `*` (8787 is not published) |
| `OSINTHUB_OFFLINE`, `OSINTHUB_SQL_CONSOLE`, `OSINTHUB_DEBUG` | off | The [switches](#switches) | same names |
| `AI_URL` | `http://127.0.0.1:8790` | The AI helper | same (default `host.docker.internal`) |
| `AI_TOKEN` | none | The AI helper's Bearer token: the helper requires it when `AI_HOST` is not loopback and checks it whenever set; the app sends it ([local AI](/architecture/local-ai.md#ai-helper)) | same |
| `AI_HELPER` | off | `1`: the helper is expected, so a down helper shows red | — |
| `OSINTHUB_VECTORS` | `auto` | Vector index: `auto`, `qdrant` or `duckdb` | same |
| `QDRANT_URL`, `QDRANT_API_KEY`, `OSINTHUB_QDRANT_PREFIX` | `http://127.0.0.1:6335`, none, none | Qdrant address, key and collection prefix | URL and key |
| `ABUSECH_AUTH_KEY` | none (ThreatFox, URLhaus off) | abuse.ch Auth-Key | same |
| `RANSOMWARELIVE_API_KEY`, `RANSOMWARELIVE_API_URL`, `RANSOMWARELIVE_API_KEY_HEADER` | none (free API), PRO URL, `X-API-KEY` | ransomware.live PRO | same |
| `CARTO_API_KEY` | none (local basemap only) | Your own CARTO basemaps key: the world map then offers CARTO's Dark Matter and Positron, credited on the map; the browser sends the key to CARTO | same |
| `CLOUDFLARE_RADAR_TOKEN` | none (or the token saved in Settings) | Cloudflare Radar for the routing watch | — |
| `OSINTHUB_INBOX` | `<lake>/inbox/zeek` | The watched network-log inbox | — |
| `OSINTHUB_INGEST`, `OSINTHUB_INGEST_HOST`, `OSINTHUB_INGEST_PORT` | Settings | Device upload listener on/off, bind address, port | fixed `0.0.0.0`, `8788`; host port `INGEST_PORT` |
| `OSINTHUB_INGEST_URL` | detected | The address devices are told to use | `INGEST_URL` |
| `OSINTHUB_INGEST_CERT`, `OSINTHUB_INGEST_KEY` | a self-signed pair in the lake | Your own TLS certificate and key files for the listener | — |
| `OSINTHUB_LAKE_HOST`, `OSINTHUB_DOCKER` | none, detected | The host folder behind `/data`; container detection override | from `LAKE_DIR` |
| `OSINTHUB_DISABLE_EXT` | none | Feature packages to skip, comma-separated | — |
| `OSINTHUB_NEWS_NO_VECTORS`, `OSINTHUB_EPSS_ALLOW_SHRINK` | off | News without vectors; accept a much smaller EPSS file once | — |
| `NIGHTDESK_COMMIT` | read from `.git` | The commit shown in Settings › About | — |
| `OSINTHUB_RISLIVE_URL`, `OSINTHUB_RIPESTAT_URL`, `OSINTHUB_RADAR_URL`, `OSINTHUB_RPKI_URL`, `OSINTHUB_RPKI_FALLBACK_URL` | the providers' URLs | Source endpoints, only if a provider moves | — |
| `AI_HOST`, `AI_PORT`, `AI_CHAT_MODEL`, `AI_EMBED_MODEL`, `AI_EMBED_MAX_TOKENS`, `AI_EMBED_BATCH`, `AI_CHAT` | `127.0.0.1`, `8790`, the models in `osinthub/ai/server.py`, `1024`, `32`, `1` | The AI helper process (`AI_CHAT=0`: embeddings only); a non-loopback `AI_HOST` needs `AI_TOKEN` | not in Docker |
| `AI_ALLOWED_HOSTS` | none | Extra Host names the AI helper answers to (loopback and `host.docker.internal` always) | not in Docker |

**The config folder** (`~/.config/nightdesk`, or `$XDG_CONFIG_HOME/nightdesk`; `%APPDATA%\Night Desk` on Windows)
sits outside every lake and holds what Settings › Data › Change… writes: `lake-folder` (the chosen folder),
`lake-move.json` (a move waiting for the next start) and `lake-move-result.json` (the last move's result). In Docker
the app also reads `OSINTHUB_INSTALL_DIR` (the installer's folder, from `NIGHTDESK_HOME`) to show the move command.

Compose-only names (`.env`): `ND_BIND` (who can reach it), `HLTA_AUTH_USER`, `HLTA_AUTH_HASH` (Caddy sign-in,
required with `ND_BIND=0.0.0.0`), `HLTA_HOSTS`, `HTTPS_PORT`, `HTTP_PORT` (not published), `LAKE_DIR`, `ND_UID`,
`ND_GID`, `INGEST_PORT`, `INGEST_URL`. Installer-only: `NIGHTDESK_HOME` (its folder, default `~/.nightdesk`),
`ND_PROJECT` (the Compose project, default `nightdesk`; tests use another).

**Developer and test variables** (never read by the app): `ND_LAKES`, `ND_LAKE_BASE` (scratch lakes of
`tools/scratch-server.sh`, a lake to clone into them), `ND_GATE_OUT`, `ND_E2E_PORTS` and the other `ND_E2E_*`
([testing](/architecture/testing.md)), `ND_BASE`, `ND_ALLOW_WRITES` (`tests/e2e/nd.py`), `ND_SQL_CONSOLE`,
`ND_TEST_SERIAL`, `ND_EVAL_CACHE` (the eval report cache), `ND_SEED_LAKE` (the seed lake `tests/eval/zeek_planted.py`
reads), `ND_LIVE_LAKE` (the live lake `tests/eval/offline_check.py` refuses to use) and `NIGHTDESK_SCAN_PATTERNS`
(below).

<a id="release-scan"></a>

# Release scan

`python3 tools/release_scan.py [--patterns FILE] [--summary]` (standard library only) reads every tracked file
(`git ls-files`), both its name and its text, and exits 1 on:

* this machine's home folder, user name and git identity (read at run time), and anyone's home folder
  (`/Users/<name>`, `/home/<name>`, `C:\Users\<name>`) outside placeholders such as `you` or `<name>`;
* the GitHub account name anywhere except this repo's own URL (read from `git remote get-url origin` or the
  README's `git clone` line);
* key-like strings: GitHub, GitLab (`glpat-` and the other `gl…-` tokens), `sk-`, Slack (`xox…-`, `xapp-`) and AWS
  tokens, Slack and Discord webhook URLs (also with JSON's escaped slashes), PEM and PGP private keys,
  `Bearer`/`Authorization:` values, URLs with a password, any `<name>key|token|secret|password` set to 16+
  characters in code, JSON, YAML, a header, a query string or a command-line flag (`"api_key": "…"`,
  `'Auth-Key': '…'`, `?apikey=…`, `--token …`), and a 15-character Gotify token (`A`, `C` or `P` then 14 random
  characters) set to such a name, unless the whole value is a placeholder. A Gotify token needs a digit or one of
  `. - _`, so the few drawn as letters only are missed (a 15-letter word such as a class name is not a token);
* long random-looking strings that are not a hash named as one on the same line;
* `*.lan`, `*.local`, `*.localdomain`, `*.internal`, `*.home`, `*.home.arpa` and Tailscale `*.ts.net` names and
  `/Volumes/<name>` drives (any case) outside a generic-examples list. A `<name>.home` counts as a host in code
  too, even when it is an attribute (in any case, so an enum member named Home counts as well): guessing which ones are
  attributes hid real host names, so the two code attributes on the tree are in the scan's ALLOW list by file and
  value instead, and a new one gets an ALLOW entry the same way;
* addresses in every file: IPv6 literals that could be a real network, also a prefix written without `::` (three
  or more groups, or two with a `/length`) and the reverse-DNS `….ip6.arpa` form of a /32 or longer; private and
  CGNAT IPv4 (a range named by its base, such as `192.168.0.0/16`, is not one network), also with zero-led or hex
  parts (each reading counts: inet_aton's, where a zero-led part of up to four digits is octal and `0x` is hex, and
  zero padding read as decimal when each padded part has 3 or 4 digits, so `10.08.12.05` stays a version) and in
  reverse-DNS form (`….in-addr.arpa`, a whole address or a /24 zone, flagged when either the reversed or the
  forward reading is private); and hardware MACs in `:`, `-` or Cisco `.` notation. Digits-only groups count as a
  prefix too, so a stepped slice or a ratio of three plain numbers that starts like a global prefix is flagged (rare, and safe: write it otherwise or
  ALLOW it); the one shape skipped is an EXIF date `2023:10:15` with a valid month and day, which also lets a prefix
  written exactly like a date through.
  Files that hold addresses as data on purpose (the backend's and tests' private ranges, vendored libraries) are
  listed in the script with the reason.

Each hit prints `file:line: category:` and the line with every flagged value replaced by `[REDACTED]`, then counts
per category and top-level folder; a hit in a file name is line 0, and that name is printed redacted everywhere.
A file that is not UTF-8 is still scanned (UTF-16 with or without a BOM, otherwise Latin-1) with a warning; a file
with NUL bytes is skipped silently only when its extension is a known binary type. A PNG (found by its signature,
whatever its name) has its text chunks scanned: `tEXt`, `zTXt` and `iTXt` (comments, the software, XMP metadata),
the keyword and an iTXt's language tag and translated keyword as well as the text, and any text after `IEND`. A hit
is shown as `[PNG <chunk> <keyword>]` (the keyword redacted like any value) or `[PNG <chunk> <field>]`, with lines
counted across the chunks. An unreadable file, binary content with no known extension, a PNG text chunk that cannot
be decoded (or expands past 4 MB) or binary data after `IEND` fails the scan as `unscanned`; a tracked symlink is
checked as its target path. PNG `eXIf` chunks and JPEG/WebP metadata are not read. The
address checks cover every tracked file: private IPv4 is allowed only for the demo, documentation and a few listed
textbook values (192.168.1.1, 10.0.0.1 and the like), so a real LAN address fails wherever it is. Deliberate
false positives are in the script's `ALLOW` list and example sets, each with its reason.

A maintainer's own names (drive names, LAN host names, the home network's prefixes and MACs) are patterns in a
**private file outside the repo**, given by `--patterns` or `NIGHTDESK_SCAN_PATTERNS`: one per line, literal text
(case-insensitive) or `re:<regex>`, `#` for comments; a line that is a MAC matches it in any notation, and a
name's stem (without a trailing number) catches its variants too. Without it that check is skipped with a warning, so a public
checkout runs everything else. The unit suite runs the scan (`tests/web/test_repo_hygiene.py`), and also the
private patterns when `NIGHTDESK_SCAN_PATTERNS` is set (skipped otherwise).

# Removing everything

Each step is independent; skip any you want to keep. None touch already-installed software.

1. Stop the server: `kill $(lsof -tiTCP:<port> -sTCP:LISTEN)` and wait.
2. Containers, volumes and images: `docker compose down -v --rmi all`, then `docker builder prune`.
3. Python environment: `rm -rf .venv` (and optionally `uv cache prune`).
4. GitHub CLI: `gh auth logout` then `brew uninstall gh`. Other brew additions: `brew uninstall gitleaks caddy`.
5. The data lake: `rm -rf <lake>` — this permanently deletes all collected history, so back it up first.
