---
type: Playbook
title: Deployment
description: Installing Night Desk with one line (Docker, HTTPS by Caddy), on a home server, or directly with uv, and who can reach it (the password for non-loopback binds, the Content-Security-Policy).
tags: [deployment, docker, caddy, operations]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-22T18:25:00Z }
---

# One-line install (Docker)

```sh
curl -fsSL https://github.com/MrAndrew/nightdesk/releases/latest/download/install.sh | sh      # deploy/install.sh
```

The installer (`deploy/install.sh`, POSIX `sh`, macOS first and Linux too; Windows inside WSL) checks Docker and
Compose, downloads the release into `~/.nightdesk/app` (`NIGHTDESK_HOME`), asks a few questions from the terminal
(each has a default; `--yes` takes them all), writes `~/.nightdesk/.env`, builds the image on this computer, starts
the stack, waits for the app's health check, copies Caddy's root certificate to `~/.nightdesk/nightdesk-root.crt` and
offers to trust it on this computer (macOS: the System keychain; Debian/Ubuntu and Fedora: the system store; one
admin password prompt), then opens the browser.

| Question | Default |
|---|---|
| Where should Night Desk keep its data? | this computer's app-data folder, the same one a native run uses (`~/Library/Application Support/Night Desk`, `~/.local/share/nightdesk`) |
| Who should be able to open it? | **1, only this computer**: `https://nightdesk.localhost[:port]/` (every browser and macOS itself send `*.localhost` to this computer; no DNS). **2** adds the network: [home server](#home-server--other-lan-devices). |
| Trust the certificate on this computer? | yes |

The HTTPS port is 443 when free, else the first free of 8443–8449 (`--port N` chooses). Running the line again
**updates** (new code, same `.env`, same data); `--reconfigure` asks the questions again starting from the current
answers (it keeps the port and the LAN password, and every line of `.env` it does not write itself: the keys and
settings you added, with their comments. It names them, never their values, and asks whether to keep them, default
yes; `--yes` keeps them. `--reset-keys` is `--reconfigure` that removes them instead. It reads its own settings only
in the form it writes them, `NAME='value'`: one you rewrote in another form is named and replaced by the new answer,
never guessed at); `-s -- --uninstall` stops and removes the containers, image, Caddy's
volumes, the launch agent and the trusted certificate, asks before deleting the data folder (default no), and removes
`~/.nightdesk`. Other options: `--data DIR`, `--lan`, `--no-trust`, `--no-open`, `--no-mdns`, `--source DIR|URL`
(a checkout or tarball instead of the release, for testing). Nothing of the local AI is installed
([pre-alpha release plan](/project/pre-alpha-release.md#5-one-line-install-and-run)).

**Testing it without touching a real install:** give it its own Compose project, install folder and data folder, and
skip the trust and the browser (a test run on this machine picks a free port):

```sh
ND_PROJECT=ndtest NIGHTDESK_HOME=$TMPDIR/ndtest sh deploy/install.sh --yes --no-trust --no-open --no-mdns \
  --data "$TMPDIR/ndtest-data" --source .        # --source . installs the committed HEAD of this checkout
ND_PROJECT=ndtest NIGHTDESK_HOME=$TMPDIR/ndtest sh deploy/install.sh --yes --uninstall
```

`tests/app/test_container.py` checks the rules offline (no published app port, every published port on `ND_BIND`,
the two reach rule files, the password rule, the image's user and contents, the installer's shape).

# Docker Compose

> **In Docker, Caddy is the sign-in.** The app's own password check is off in the container (`OSINTHUB_TRUST_PROXY_AUTH=1`, set in `docker-compose.yml`), because Caddy is the only way in: never publish 8787. `docker-compose.yml` only `expose`s it on the internal Compose network; the only ports it publishes are Caddy's HTTPS port and the device-upload listener 8788 (per-sender tokens, off until you enable it), both on the `ND_BIND` address. Keep it that way. If you run the image by hand, without Compose, the app binds `0.0.0.0` inside the container and so refuses to start without `OSINTHUB_PASSWORD` ([who can reach it](#who-can-reach-it)); give it one and publish on loopback only:
>
> ```sh
> docker build -t night-desk .
> docker run --rm -p 127.0.0.1:8787:8787 -e OSINTHUB_PASSWORD -v osint-lake:/data night-desk   # http://127.0.0.1:8787/
> ```
>
> Never `-p 8787:8787` without a password (that binds every interface). The [Host allowlist](#host-allowlist-dns-rebinding) is not a substitute for a password.

By hand, without the installer (this computer only, no password needed):

```sh
docker compose up -d --build
open https://nightdesk.localhost:8443/       # the browser warns once until you trust the certificate (below)
```

For the network by hand, add the password's hash and the reach setting to `.env` first:

```sh
cp .env.example .env
printf 'HLTA_AUTH_HASH=%s\n' "$(docker run --rm caddy:2.8.4-alpine caddy hash-password --plaintext 'your-password' | sed 's/\$/$$/g')" >> .env
printf "ND_BIND=0.0.0.0\nHLTA_HOSTS='nightdesk.local, 192.0.2.10, localhost'\n" >> .env
docker compose up -d --build
```

| Service | Image | Role |
|---|---|---|
| `app` | built from `Dockerfile`: stage 1 builds the `nightdesk` wheel, stage 2 installs it on the locked dependencies (`uv sync --frozen --no-dev --no-default-groups`), runs as the unprivileged user `nightdesk` (Compose: `ND_UID`/`ND_GID`) | Ingest, API, static client, docs and embedded DuckDB. Data in `/data`. |
| `caddy` | `caddy:2.8.4-alpine` | Serves HTTPS on `HTTPS_PORT` at the site root with a certificate from its own local authority (`tls internal`) for the names in `HLTA_HOSTS`, the authority's certificate at `/ca/root.crt`, the reach rule (`deploy/reach-<ND_BIND>.caddy`: none, or basic auth), and proxies to `app:8787` with response buffering off so the live stream works. Config in `deploy/Caddyfile`. The authority lives in the `caddy_data` volume, so the certificate survives restarts. |
| `qdrant` | `qdrant/qdrant:v1.20.0` | Optional (Compose profile `qdrant`: `docker compose --profile qdrant up -d`). Vector index for [semantic search](/architecture/local-ai.md#vectors) with local AI. Derived data: the app rebuilds it from the lake, and uses DuckDB vectors when Qdrant is not running. |

The [local AI helper](/architecture/local-ai.md#ai-helper) is not a container, because MLX needs the Mac's GPU. Run it on the host with `uv run python -m osinthub.ai.server`. The app reaches it at `AI_URL=http://host.docker.internal:8790`. Docker Desktop forwards that name to the host's loopback, and `extra_hosts: host-gateway` provides it on Linux. Without the helper, search falls back to keywords.

DuckDB is a library inside `app`, so there is no separate database container. Its file is `/data/db/hub.duckdb`.

On first start the app downloads about 140 MB of reference data into `/data/ref` (DB-IP City and ASN Lite, country shapes; the cable map only if the user turns that layer on), usually a minute or two (`docker compose logs -f app` shows it), then starts every enabled source; most panels fill within a few minutes. The ATT&CK catalogue, MISP galaxies, the public suffix list and the Tranco list (about 70 MB) follow in the background. The Compose project is `nightdesk` (containers `nightdesk-app-1` and so on, volumes `nightdesk_lake` ...). An install made before the rename keeps its old project name through `ND_PROJECT` in its `.env`, so its containers and volumes stay attached.

**Upgrading a setup from before v1.2** (served at `/cyberintel/`, root in the container): the app now runs unprivileged and is served at the site root. Give the data to the new user once, `docker compose run --rm --user root app chown -R 1000:1000 /data` (or set `ND_UID`/`ND_GID` to the owner of a `LAKE_DIR` folder), and open `https://<name>:<port>/` instead of `/cyberintel/`; `HTTP_PORT` is no longer published.

# Settings

Put overrides in `.env` (see `.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `ND_BIND` | `127.0.0.1` | Who can reach it: `127.0.0.1` = this computer only, no sign-in; `0.0.0.0` = your network too, with the password. The address the HTTPS (and device-upload) ports are published on; Caddy reads `deploy/reach-<ND_BIND>.caddy` and refuses to start on any other value. |
| `HTTPS_PORT` | `8443` (the installer: 443, or the first free of 8443–8449) | Caddy's HTTPS port — the dashboard, the same inside the container and on the host. |
| `HTTP_PORT` | `8080` | Caddy's plain-HTTP port inside the container; not published (the address is always `https://`). |
| `HLTA_HOSTS` | `nightdesk.localhost, localhost` | Name(s)/IP(s) the certificate is issued for, comma- or space-separated; the first is the address the installer prints. Compose also hands the same list to the app as `OSINTHUB_ALLOWED_HOSTS` (see [Host allowlist](#host-allowlist-dns-rebinding)). |
| `HLTA_AUTH_USER` | `nightdeskuser` | Basic-auth user name when `ND_BIND=0.0.0.0`. The installer asks for it (`--yes`: `nightdeskuser`; a re-run keeps the current one): letters, digits, `.`, `_` and `-`, at most 64, and not `import` (a word Caddy reserves). |
| `HLTA_AUTH_HASH` | not set | Basic-auth bcrypt hash, required when `ND_BIND=0.0.0.0` (the installer makes one). By hand: `docker run --rm caddy:2.8.4-alpine caddy hash-password --plaintext '…'` (in `.env`, single-quote the value, or double every `$` in an unquoted one). |
| `LAKE_DIR` | Docker volume `lake` (the installer: this computer's app-data folder) | Host folder for the data lake, e.g. `/Volumes/MyDrive/night-desk`. |
| `ND_UID`, `ND_GID` | `1000` | The user and group the app runs as, so files in `LAKE_DIR` belong to you (the installer sets your own). |
| `ABUSECH_AUTH_KEY` | empty | abuse.ch Auth-Key; turns on ThreatFox and URLhaus ([API keys](#api-keys-for-sources)). |
| `RANSOMWARELIVE_API_KEY` | empty | ransomware.live PRO key; without it the free API is used. |
| `RANSOMWARELIVE_API_URL`, `RANSOMWARELIVE_API_KEY_HEADER` | not passed | Override the PRO endpoint and key header; passed to the app only when set, so the app's defaults apply otherwise. |
| `QDRANT_API_KEY` | empty | API key for the Qdrant service. |
| `QDRANT_URL` | `http://qdrant:6333` | Vector store (outside Docker the default is HLTA's `http://127.0.0.1:6335`). |
| `OSINTHUB_VECTORS` | `auto` | `auto`, `qdrant` or `duckdb` ([vectors](/architecture/local-ai.md#vectors)). |
| `AI_URL` | `http://host.docker.internal:8790` | Local AI helper (`http://127.0.0.1:8790` outside Docker). |
| `AI_EMBED_BATCH` | `32` | How many texts the AI helper embeds per batch (read by the helper, `osinthub/ai/server.py`). |
| `AI_EMBED_MAX_TOKENS` | `1024` | Max tokens per text the AI helper embeds; longer texts are truncated (`osinthub/ai/server.py`). |
| `OSINTHUB_NEWS_NO_VECTORS` | not set | `1` turns off news-article chunk embeddings, so news search stays keyword-only (`osinthub/news/common.py`). |
| `OSINTHUB_RADAR_URL` | Cloudflare Radar BGP API | Test-only: point the Cloudflare Radar source at a fake server (`osinthub/sources/routing_radar.py`). |
| `OSINTHUB_RIPESTAT_URL` | RIPEstat Data API | Test-only: point the RIPEstat source at a fake server (`osinthub/sources/routing_ripestat.py`). |
| `OSINTHUB_OFFLINE` | `0` | `1` stops every outbound fetch; the app serves what it has ([offline mode](/architecture/local-ai.md#offline-mode)). |
| `OSINTHUB_SQL_CONSOLE` | `0` | `1` turns on the SQL console (`POST /api/sql` and the Explorer page); off, the API answers 403 and the client hides it ([SQL console](/architecture/api.md#sql-console)). Set it in `.env`. |
| `OSINTHUB_DEBUG` | `0` | The one general debug switch: `1` turns the SQL console on too and serves FastAPI's `/docs`, `/redoc` and `/openapi.json` (off otherwise: they load scripts from a CDN). |
| `OSINTHUB_TRUST_PROXY_AUTH` | `1` in Compose | The app skips its own password check and its refusal to bind `0.0.0.0` without one, because Caddy in front asks for the password. Only ever set it when a proxy in front does the sign-in ([who can reach it](#who-can-reach-it)). |
| `AI_TOKEN` | empty | The AI helper's Bearer token, when the helper has one (required if it listens beyond loopback); the app sends it ([local AI](/architecture/local-ai.md#ai-helper)). |

Inside the container the app reads `OSINTHUB_LAKE`, `OSINTHUB_DB`, `OSINTHUB_HOST`, `OSINTHUB_PORT`, `OSINTHUB_ALLOWED_HOSTS`, `OSINTHUB_TRUST_PROXY_AUTH`, `AI_TOKEN`, `OSINTHUB_OFFLINE`, `OSINTHUB_SQL_CONSOLE`, `OSINTHUB_DEBUG`, `OSINTHUB_VECTORS`, `OSINTHUB_VECTORS_DB`, `QDRANT_URL`, `QDRANT_API_KEY`, `AI_URL`, the `OSINTHUB_INGEST_*` upload settings and the source keys above. Compose passes every one it sets from `.env`; `tests/app/test_setup.py` checks that each credential the code reads is passed through and listed in `.env.example`.

# Who can reach it

| Bind (`OSINTHUB_HOST`) | Password | What happens |
|---|---|---|
| `127.0.0.1` (default), `localhost`, `::1` | none | This machine only, no sign-in. The usual native run, and a loopback app behind your own reverse proxy that does the sign-in (keep `OSINTHUB_ALLOWED_HOSTS` set to the proxy's name). |
| anything else: `0.0.0.0`, `::`, a LAN address, a host name | none | **Refuses to start**, with one line: set `OSINTHUB_PASSWORD`, or bind 127.0.0.1 and put a reverse proxy that asks for a password in front. Nothing is opened. |
| any | `OSINTHUB_PASSWORD` set | Every request needs it (below). |
| `0.0.0.0` in Docker Compose | `OSINTHUB_TRUST_PROXY_AUTH=1` | No check in the app: Caddy asks for the password and is the only way in. |

**The password** (`osinthub/config.py`, checked in `api.py` `_guard` after the Host check and before the CSRF check):
HTTP Basic, so there is no login page and no cookie: the browser asks once and re-sends it, which also covers the live
stream (`/api/stream`, an `EventSource`) and `curl -u any:password`. Any user name is accepted; the password is compared
as a SHA-256 hash in constant time. Without it, or with a wrong one, every request is **401** with
`WWW-Authenticate: Basic realm="Night Desk"`, the web pages included, except `GET /api/health` from this machine (the
Docker health check, local monitors). Ten **different** wrong passwords from one client within 10 minutes block it for
15 minutes (**429** with `Retry-After` on every attempt while blocked, the right password included). The same wrong
password repeated counts once, so an open tab still polling with an old password never locks its owner out, and a
correct password clears only that same address's earlier failures; a request with no credentials does not count at
all. Counting is per exact address. For IPv6 there is also a looser count per /64 (50 different wrong passwords in 10
minutes block the whole /64 for 15 minutes), because one device can use any address in its /64; a correct password
never clears it, so one device's polling cannot hide another's guesses. The cost: any device on the same IPv6 /64
(on a home network, every IPv6 device) can send 50 wrong passwords and lock out all IPv6 devices there for 15 minutes,
again and again; devices reaching it over IPv4, and this machine itself, keep working. At most 4096 addresses and 1024
networks are tracked (constant time per request). When the table is full the oldest entry that is not blocked is
evicted; only if the 64 oldest are all blocked does the oldest go anyway. So an attacker with more than 4096 IPv4
addresses or 1024 /64s could still guess without limit; on a home LAN that is not available. Blocks are in memory and a
restart clears them. The password must
be at least 8 characters (whitespace only counts as unset). The password is never
logged and never in a response (`/api/settings/about`, `/api/help/diagnostics`, `/api/paths` are tested). When an API
call gets a 401 (the browser's sign-in has gone), the page shows one plain banner: "Sign in again: reload the page."
There is no logout: close the browser, or change the password and restart.

**Plain HTTP on a LAN can be sniffed.** Basic auth sends the password with every request; on a trusted home network
that is the trade-off for no extra setup, but beyond it (shared or guest Wi-Fi, an office, anything routed) put a TLS
reverse proxy in front instead: the Docker Compose stack above, or your own Caddy on the same machine in front of a
loopback app.

```sh
OSINTHUB_HOST=0.0.0.0 OSINTHUB_PASSWORD='a long passphrase' OSINTHUB_ALLOWED_HOSTS=nightdesk.lan,192.0.2.10 \
  uv run python -m osinthub                 # http://nightdesk.lan:8787/ from the LAN, after a password prompt
```

The refusal runs when the app starts (`python -m osinthub`) and again when `osinthub.api` is imported (`uvicorn
osinthub.api:app`, `fastapi run`). A bind given only on the uvicorn command line (`--host 0.0.0.0`) is not in
`OSINTHUB_HOST`, so without a password every request that arrives on a non-loopback address of the machine gets
**503** ("…listening beyond this machine without a password"); over loopback it still works.

**Never set `FORWARDED_ALLOW_IPS=*` on a native LAN bind.** uvicorn then believes any LAN host's `X-Forwarded-For`,
so one device could pose as many clients and dodge the throttle (or pose as loopback for `/api/health`). Keep the
default (`127.0.0.1,::1`, right for a proxy on the same machine). Docker Compose sets `*` only because 8787 is not
published there.

The Host allowlist (`OSINTHUB_ALLOWED_HOSTS`, next section) and the CSRF check stay exactly as strict with or without a
password: browsers re-send cached Basic credentials on cross-site requests, so the `Origin`/`Sec-Fetch-Site` refusal is
what stops another site from using them. The [device upload listener](/data/netlog.md) (port 8788) has its own
per-sender tokens and is not affected; nor is the [AI helper](/architecture/local-ai.md#ai-helper), which has its own
token (`AI_TOKEN`) and Host allowlist.

# Home server / other LAN devices

Answer **2** at the installer's "Who should be able to open it?" (or run it again with `--reconfigure --lan`). It then:

* publishes the HTTPS port on every interface (`ND_BIND=0.0.0.0`), so Caddy reads `deploy/reach-0.0.0.0.caddy` and
  asks for the password on every request except `/ca/root.crt` (the authority's public certificate);
* makes a password (20 letters and digits, printed once; `--reconfigure` keeps it unless you ask for a new one) and
  stores only its bcrypt hash (`HLTA_AUTH_HASH`); it asks for the user name (`HLTA_AUTH_USER`; `--yes` takes
  `nightdeskuser`, a re-run keeps the current one) and prints both at the end;
* issues the certificate for `nightdesk.local`, this computer's own `<name>.local` and `localhost` (`HLTA_HOSTS`), and
  on macOS announces `nightdesk.local` over Bonjour with a small launch agent (`~/Library/LaunchAgents/local.nightdesk.mdns.plist`,
  `dns-sd -P`, removed by `--uninstall`; `--no-mdns` skips it). The announcement carries this Mac's current address,
  so run the install line again if that changes. On Linux, use the computer's own `<name>.local` (Avahi) or a name
  on your router.

**Other devices** trust the certificate once: open `https://nightdesk.local[:port]/ca/root.crt` (the browser warns
the first time; that page needs no password), then install it as a trusted root (macOS: Keychain Access → System →
"Always Trust"; iOS: Settings → General → VPN & Device Management, then Certificate Trust Settings; Android and
Windows have equivalent steps).

Notes:

* Caddy refuses to start with `ND_BIND=0.0.0.0` and no `HLTA_AUTH_HASH`, and with any `ND_BIND` other than
  `127.0.0.1` or `0.0.0.0` (there is no rule file for it): a hand edit can never put the dashboard on the network
  without a password (`docker compose logs caddy` shows the reason).
* Put every name/IP you use in `HLTA_HOSTS`, or the certificate won't match and the browser blocks the connection.
* Binding the app directly to the LAN (`OSINTHUB_HOST=0.0.0.0`, a native run) needs `OSINTHUB_PASSWORD` and has no
  TLS ([who can reach it](#who-can-reach-it)); the container's Caddy is the HTTPS way.
* Put the same names in `OSINTHUB_ALLOWED_HOSTS` when the app runs outside this Compose stack ([Host allowlist](#host-allowlist-dns-rebinding)).

## Host allowlist (DNS rebinding)

The app answers only requests whose `Host` header is a loopback name — `localhost`, `127.0.0.1` or `[::1]`, any port — or a name listed in **`OSINTHUB_ALLOWED_HOSTS`** (comma- or space-separated; ports, schemes and case are ignored). Anything else gets **421** with a message naming the setting. This stops DNS rebinding: a web page you visit can point its own hostname at 127.0.0.1, but the browser still sends that hostname, so it can't read the API or the SQL console. (When `OSINTHUB_HOST` is one specific address rather than `0.0.0.0`, that address is allowed too.)

Reaching the app from another machine also needs a password ([who can reach it](#who-can-reach-it)): an allowed name alone opens nothing, and the 421 message says so. A reverse proxy must forward a Host the app knows. Caddy's `reverse_proxy` passes the browser's Host through unchanged, so:

* **Bundled Compose stack:** nothing to do — `docker-compose.yml` sets `OSINTHUB_ALLOWED_HOSTS` from `HLTA_HOSTS`, the same names the certificate covers.
* **Your own Caddy in front of `uv run python -m osinthub`** (e.g. `https://nightdesk.lan:8443/` → `reverse_proxy 127.0.0.1:8787`): start the app with the proxy's name allowed, or every proxied request is refused with 421:

  ```sh
  OSINTHUB_ALLOWED_HOSTS=nightdesk.lan uv run python -m osinthub
  ```

State-changing requests (POST/PUT/PATCH/DELETE) are also refused (403) when the browser marks them cross-site (`Sec-Fetch-Site: cross-site`/`same-site`) or when their `Origin` (or, without one, `Referer`) is not this same host and port — including `Origin: null`; the scheme must match too. Behind a TLS proxy the app learns the browser's `https` from the proxy's `X-Forwarded-Proto`, which uvicorn trusts only from `FORWARDED_ALLOW_IPS` (default `127.0.0.1,::1`, right for a Caddy on the same machine; `docker-compose.yml` sets `*` because 8787 is reachable only on the internal Compose network). The web client's own writes are same-origin and pass; scripts and `curl` send none of these headers and pass. The [device upload listener](/data/netlog.md) on port 8788 is a separate server with its own per-sender tokens and is not affected.

## Content-Security-Policy

Every response carries a `Content-Security-Policy` (`api.py` `csp()`, built per response), so a missed escape in the
client cannot run a script or send data anywhere unexpected:

`default-src 'self'; script-src 'self' 'sha256-…'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: …;
connect-src 'self' …; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`

* **Scripts** only from this server. The one inline script, `web/index.html`'s stale-code check, is allowed by its
  SHA-256 hash, which the server computes from the file (it stays inline on purpose: it must work when every other
  file is an old cached copy). No `'unsafe-inline'`, no `'unsafe-eval'`, no inline event handlers (`onerror=` and the
  like are refused; the client uses listeners).
* **Styles** allow `'unsafe-inline'`: the views' markup uses `style=` attributes, and gridstack, cytoscape and globe.gl
  add `<style>` elements. Styles cannot run code.
* `data:` images: the favicon and SVG icons. `blob:` images and workers: MapLibre decodes map tiles into images and
  starts its worker from a `blob:` URL.
* **No eval.** echarts-gl compiles code with `new Function`, so it was removed; Threat Origins 3D draws with
  globe.gl (as Cinema). Every panel in **+ Widget** is crawled with a `securitypolicyviolation` listener.
* **External origins, only when not in offline mode** (`OSINTHUB_OFFLINE=1` lists none at all, so the browser cannot
  reach the internet either):

| Origin | Directive | Feature (opt-in) |
|---|---|---|
| `https://public.api.bsky.app` | connect-src | Bluesky names and avatars in the Feeds panel (after the user clicks to load them) |
| `https://cdn.bsky.app` | img-src | the Bluesky avatar images themselves |
| `https://basemaps.cartocdn.com`, `https://*.basemaps.cartocdn.com` | connect-src | World map basemaps Dark Matter and Positron (style, tiles, sprites, glyphs); listed only when the user set their own `CARTO_API_KEY` (`CSP_CARTO`) |

A new feature that loads anything from another origin must add it to `CSP_ONLINE` in `api.py` and to this table.
FastAPI's `/docs`, `/redoc` and `/openapi.json` are off unless `OSINTHUB_DEBUG=1` (they load unpinned scripts from a
CDN); when on, those two pages keep only `frame-ancestors 'none'`.

## Security model and hardening

The app was built loopback-first with no per-user accounts, so **the password (the app's own or Caddy's basic-auth credential) is admin-equivalent**: anyone who has it can use the SQL console and every management action. That is fine for a single trusted user; for several or less-trusted LAN users, use per-user auth at the proxy (or an auth gateway) and add `fail2ban` on the Caddy access log to throttle password guessing.

Hardening already in the code (2026-11-06 security pass, two review rounds): the SQL console is sandboxed by parsing each query with DuckDB's own parser — only safe table functions are allowed **and every base-table name must be a plain identifier**, so a replacement scan (`FROM '/path/x.csv'` or `FROM 'https://…'`) that would read a file or reach the network is rejected — plus an 8s interrupt-timeout and a query-length cap; the news fetcher resolves and refuses non-public addresses (incl. IPv4-mapped / NAT64) on the seed URL, every redirect and every robots.txt hop, and connects to the address it checked (SSRF and DNS rebinding; [news](/data/news.md#fetching)); every source download has a byte cap counted after decoding ([size limits](/data/size-limits.md)); log imports cap per-file and per-bundle decompressed size and reject oversized archives by entry count before parsing the index (decompression / archive-index bombs), spooling on the lake drive; a Host allowlist (DNS rebinding, see above), a CSRF guard (`Sec-Fetch-Site`/`Origin`/`Referer`) and security response headers protect the browser; `/api/upload` keeps the first 200,000 rows and its answer names no absolute path; every request body is capped while it streams in (**413**, counted as it arrives when there is no `Content-Length`, before anything is spooled to disk): 16 MB for JSON and form bodies, 65 MB for `/api/upload` (its 64 MB file cap plus the multipart envelope) and 2 GB per request for `/api/netlog/import` ([import](/data/netlog.md#import)); netlog `limit=0` is capped; errors are generic with detail logged server-side. See `tests/security/test_hardening.py` and the netlog decompression tests.

Documented residuals (accepted for a single-user home app): the single-credential trust boundary above; lake paths in `/api/paths` and `/api/lake` (the UI shows them; `/api/health` carries no paths). The fetcher's DNS-rebinding race is closed: article and robots requests connect to the address that was checked, with the real name in `Host` and SNI ([news fetching](/data/news.md#fetching)).

# Without Docker

```sh
uv run python -m osinthub        # http://127.0.0.1:8787, data in the app-data folder
nightdesk --open                 # the same, as the installed command (`uv tool install .`), opening the browser
OSINTHUB_OFFLINE=1 uv run python -m osinthub   # no outbound fetching
OSINTHUB_ALLOWED_HOSTS=nightdesk.lan uv run python -m osinthub   # also reachable through a proxy as nightdesk.lan
OSINTHUB_HOST=0.0.0.0 OSINTHUB_PASSWORD='…' uv run python -m osinthub   # on the LAN, behind a password (plain HTTP)
nohup uv run python -m osinthub.ai.server > logs/ai-server.log 2>&1 &   # local AI helper, :8790 (one per machine)
```

The default lake is the app-data folder (`~/Library/Application Support/Night Desk` on macOS, `~/.local/share/nightdesk` on Linux), whatever folder the app is started from; set `OSINTHUB_LAKE` to use another folder (a lake on an external drive always needs it). If `OSINTHUB_LAKE` points into `/Volumes/<drive>` and that drive isn't mounted, the app exits at once with a clear message and creates nothing (it never starts an empty lake on the boot disk). Only one process may open the DuckDB file at a time, so stop a running instance before starting another, and don't point Docker's `LAKE_DIR` at a lake a local process is using.

## Moving the data folder

**Settings › Data and retention › Change…** (`osinthub/lakeloc.py`, `POST /api/lake/move`). Where the lake is comes
from, in order: `OSINTHUB_LAKE` (or `nightdesk --lake`), the folder chosen in Settings (the file `lake-folder` in the
config folder, `~/.config/nightdesk`, outside every lake), then the app-data folder.

* **A native run started by its own command** (`nightdesk`, `python -m osinthub`): the page checks the new folder (a
  full path; new or empty; not a system folder, the top of a drive or the home folder; not inside or around the
  current one; on a connected drive; writable; free space for the data plus 10% and 200 MB) and saves the move. The
  app stops its server, closes the database and starts again in place (same process id, so a terminal, `nohup`,
  launchd or `ttl` keeps watching it). Before anything opens the database it copies the lake, checks that every file
  arrived with its size, and only then points `lake-folder` at the new folder; the old folder is never changed or
  deleted. The page waits, reloads, and shows the result once ("Moved to … The old folder … is still there"). If the
  copy fails or is incomplete, the app starts on the old folder and the page says why.
* **Started some other way** (`uvicorn osinthub.api:app`): it cannot restart itself, so the move runs the next time
  it is started with `nightdesk` or `python -m osinthub`.
* **Named by the start command** (`OSINTHUB_LAKE`, `OSINTHUB_DB`, `OSINTHUB_VECTORS_DB` or `--lake`, as for the owner's
  live app): the page says so and offers nothing; the start command wins.
* **Docker:** the folder is the host's `LAKE_DIR`, outside the container, so the page shows the host folder and builds
  the command to run on the host, `sh ~/.nightdesk/app/deploy/install.sh --move-data '<new folder>'`. It stops the
  app, copies the folder (`cp -Rp`), checks the file count, sets `LAKE_DIR` in `.env` and starts the app on the new
  folder; the old folder stays. On a failure it starts the app again on the old folder.

`tests/app/test_lake_move.py` covers the order, the checks, the move (success, a folder filled in the meantime, an
incomplete copy, a start command that names the lake), the API in each setup and the installer's shape.

## The package

The repo builds as the Python package **`nightdesk`** (`uv build`; the module stays `osinthub`). Its one command,
`nightdesk` (`osinthub/__main__.py`), takes `--lake`, `--port`, `--offline`, `--open` (opens the browser once
`/api/health` answers) and `--version`; each option is a shortcut for the `OSINTHUB_*` variable. The wheel carries
the web client and this docs bundle inside the package (`osinthub/web`, `osinthub/okf`, copied at build time by the
`force-include` table in `pyproject.toml`), and `osinthub/config.py` looks there before the repo root, so Help and
the source catalogue work in an installed copy. The build backend (hatchling) is used only to build; the local AI
libraries are a repo-only dependency group, so an installed `nightdesk` never includes them. Install it from a
checkout with `uv tool install .`; the release install line is planned in the
[pre-alpha release plan](/project/pre-alpha-release.md#5-one-line-install-and-run).

# Operations

* **Logs:** `docker compose logs -f app`.
* **Health:** `GET /api/health`; the container also has a Docker health check.
* **Update:** `git pull && docker compose up -d --build`. Data survives in the volume or `LAKE_DIR`.
* **Reset:** `docker compose down -v` deletes the volumes, including all collected data.

# API keys for sources

Keys come only from environment variables, read once at start in `osinthub/config.py`. With Docker, put them in `.env` (see `.env.example`) and run `docker compose up -d`; `docker-compose.yml` passes them to the app container. Without Docker, set them in the service environment (a launchd plist, or the shell) and restart. They are never written to the lake, the database, logs or URLs.

| Variable | Used by | Without it |
|---|---|---|
| `ABUSECH_AUTH_KEY` | [ThreatFox](/sources/current/threatfox.md) and [URLhaus](/sources/current/urlhaus.md): a free abuse.ch Auth-Key from https://auth.abuse.ch/, sent in the `Auth-Key` header | Both stay off, are never fetched, cannot be enabled, and the Sources page says "Needs a free key". SSL Blacklist needs no key. |
| `RANSOMWARELIVE_API_KEY` (+ `_HEADER`, `RANSOMWARELIVE_API_URL`) | [ransomware.live](/sources/current/ransomware_live.md) PRO | The free v2 API is used. |
