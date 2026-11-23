---
type: Guide
title: Start here
description: The hard rules every change must follow, how to run and test Night Desk, where things live, and the architecture in brief.
tags: [guide, onboarding, rules, testing]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-22T18:07:00Z }
---

Night Desk is a local-first cyber-OSINT hub: one Python process serves the API, the ingest scheduler and the
static web client; DuckDB is embedded; the browser client is plain ES modules. Read this page before changing
anything. Details are linked from each point.

# Hard rules

* **No real home-network data, anywhere.** Tests, fixtures and docs use the documentation ranges only
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`), the documented demo home
  (`10.86.24.0/24`, `fd4e:6400:d35c::/48`, `02:4e:44:…` MACs) or invented MACs. **Never write a real network
  prefix** in the repo, not even in a comment to forbid it.
* **No personal info or secrets in tracked files.** No owner name, user name, email, home folder, LAN host name,
  drive name, key, token or password; use generic examples (`nightdesk.lan`, `/Volumes/ExternalDrive`, `~`) and
  environment variables (`.env`, ignored; `.env.example` lists them). `tools/release_scan.py` checks every
  tracked file and runs in the unit suite (`tests/web/test_repo_hygiene.py`): the home folder, user name and git
  identity read at run time, other home folders, the GitHub account outside this repo's URL, key-like strings,
  unlisted `*.lan` and `/Volumes/<name>` names, and in every file MACs, private IPv4 and every global or
  unique-local IPv6 literal (an allowlist; the prefix is never a hash or a denylist entry), in file names too
  ([release scan](/environment.md#release-scan)). Maintainers keep their own names as patterns in a private
  file outside the repo (`NIGHTDESK_SCAN_PATTERNS`).
* **Never test against your own install.** Tests and experiments use scratch ports and scratch lakes
  (`tools/scratch-server.sh`), never the lake of a Night Desk you use, and never port 8787, its default.
* **Offline means zero egress.** `OSINTHUB_OFFLINE=1` must stop every non-loopback connection; each new
  fetch path checks `config.OFFLINE` ([offline mode](/architecture/local-ai.md#offline-mode)). No new
  outbound calls, no CDN, no new Python or JS dependency (web libraries are
  [vendored](/environment.md#vendored-web-libraries)).
* **Terms.** The User-Agent is honest (`config.USER_AGENT`), robots.txt is respected and bot checks are
  never bypassed; a keyed source never fetches without its key; feeds whose terms forbid AI use are kept
  out of every prompt and embedding (the `ai_ok` class attribute of a `Source`, `osinthub/sources/base.py`; the
  user-facing terms table is `osinthub/feed_terms.py`); abuse.ch data (ThreatFox, URLhaus)
  stays out of all AI input and any redistribution; blocklists are never re-served. The terms checklist for
  a public release is in [open issues](/project/open-issues.md#before-the-repo-goes-public).
* **One AI helper.** Models run only in the single AI helper process on `127.0.0.1:8790`
  ([local AI](/architecture/local-ai.md#ai-helper)); never load a model in the app's own process. If the
  helper is down, report it and fall back (semantic search drops to keyword).
* **Names.** The name is **Night Desk**: new code, keys and docs use no older name. Browser storage keys
  start `nd.` (`web/js/core/storage-names.js` moves values a browser saved under the earlier prefix). The
  Compose project is `nightdesk`. What still carries an old name is listed in the README's "About the names".
* **UI.** Plain language a home-lab owner understands in primary text (no internal ids, rule slugs, tier
  letters or file paths; details and tooltips may carry them). Text meets 4.5:1 contrast; red appears only on
  flagged things; every page works at 390 px wide with no sideways page scroll; motion respects
  `prefers-reduced-motion`. No new Python or JS dependency and no CDN: web libraries are vendored.

# How to run

```sh
OSINTHUB_LAKE=<dir> OSINTHUB_PORT=<port> OSINTHUB_OFFLINE=1 uv run python -m osinthub
```

Lake defaults to the platform's app-data folder (`~/Library/Application Support/Night Desk` on macOS); port to
8787; offline keeps all fetching off. The one-line Docker install (`deploy/install.sh`: Compose with Caddy serving
HTTPS) is the deployed form ([deployment](/architecture/deployment.md#one-line-install-docker)).

# How to test

Three tiers; the first is the one that must stay green on every change.

| Tier | Command | Time | What |
|---|---|---|---|
| Unit / API | `uv run --quiet --with pytest pytest -q -p no:cacheprovider tests --ignore=tests/soak --ignore=tests/eval` | ~11 s | Backend behaviour and web lint. Each test module builds its own temp lake with no network and no AI helper; `tests/conftest.py` collects and runs the files in parallel child processes (`ND_TEST_SERIAL=1` to debug) because each module reads the lake and flags once at import. |
| End-to-end | `uv run --with playwright --with pytest pytest -q -p no:cacheprovider tests/e2e` | ~64 s | The browser journeys that are the regression bar every refactor keeps green ([testing](/architecture/testing.md)); one scratch server per run. Not collected by the unit command. |
| Merge gate | `tools/gate.sh <port> <label>` | ~1 min 45 s | Runs the unit suite (~11 s), the E2E journeys (~64 s), then `tests/e2e/smoke.py` and `deeplinks.py` side by side against a scratch server with the demo loaded (~20 s). Port must not be 8787. |
| Lint | `uvx ruff check osinthub tests tools` | ~1 s | Faults only (unused names, loop closures, invisible characters, old syntax), from `[tool.ruff]` in `pyproject.toml`; there is no formatter. Not part of the gate; keep it at zero. |

Manual evals (not part of the suite, run by hand against your own server and the AI helper) live in
`tests/eval/`: the extraction and CVE-search scorers, the Zeek planted-traffic test and the offline check
(`tests/eval/README.md`, with the pass bars). `tests/soak/` is a long stress script.

# Where things live

* `osinthub/` — the backend. Core: `config.py`, `api.py`, `scheduler.py`, `db.py`, `lake.py`, `bus.py`,
  `ext.py` (the [extension registry](/architecture/system.md#extensions)), `vectors.py`, `search.py`,
  `geo.py`, `analytics.py`, `bootstrap.py`, `notify.py`. Feature packages, each plugging in through `ext.py`:
  `ai/`, `news/`, `entities/`, `netlog/`, `notes/`, `routing/`, `watch/`, `help/`, and `sources/` (source
  plugins).
* `web/` — the client: `index.html`, one stylesheet `css/app.css`, and ES modules under `js/{core,panels,views,help}`.
  Every library, font and glyph is vendored in `web/vendor/`.
* `okf/` — this documentation bundle. `tests/` — the suites (`tests/eval/` and `tests/soak/` are manual).
  `Dockerfile` and `docker-compose.yml` sit at the repo root; `deploy/` holds the `Caddyfile`. `tools/` holds
  `gate.sh` (the merge gate), `scratch-server.sh`, `okf_sources.py` (regenerates the source pages; `--check` fails
  when a committed page differs), `shot.py` (screenshots), `release_scan.py` (personal info and secrets in tracked
  files) and `okf_check.py` (checks the OKF bundles).

# Architecture in brief

One `osinthub` process runs the scheduler, the HTTP API, the `/api/stream` live feed and the static client,
with DuckDB embedded ([system](/architecture/system.md)). Batch and stream sources write record and event
deltas to the data lake, which loads into DuckDB; the pipeline publishes live topics to the browser's one
`EventSource`. Feature packages register schema, routers, background tasks and startup hooks through the
extension registry, so a failed feature never takes the app down. The optional AI helper (:8790) and an
optional Qdrant index serve embeddings and vectors; both have offline / DuckDB fallbacks. See
[web client](/architecture/web-client.md), [data architecture](/data/architecture.md),
[HTTP API](/architecture/api.md) and [network logs](/data/netlog.md).

# Contributing

How to propose a change, what a pull request must include and what CI checks are in
[CONTRIBUTING.md](../CONTRIBUTING.md). In short: update the OKF page for what you change (keep each page's
frontmatter; `index.md` carries none), say in the pull request when the change is a decision, and keep `tools/okf_check.py`, the release scan, lint and the tests green. Not in a
current revision: Cases, the [Ask page](/project/ideas/ask-page.md), blocklist export, MISP/STIX import, beaconing
detection.
