---
type: Architecture
title: Testing and the E2E journeys
description: The two test layers (the pytest suite by feature and the end-to-end journeys in tests/e2e), how to run each, how the suite isolates and parallelises its files, the rules for adding a test, and the rule that every refactor keeps the journeys green.
tags: [architecture, testing, e2e, playwright, quality]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T18:00:00Z }
---

# Testing and the E2E journeys

**The rule: every change, and every refactor in particular, keeps the E2E journeys green.** They are the regression
bar: a refactor that needs a journey changed has changed behaviour, and says so.

| Layer | What | Run | Time |
|---|---|---|---|
| Unit / API | `tests/` by feature (pytest; each file in its own process, run side by side; see below) | `uv run --quiet --with pytest pytest -q -p no:cacheprovider tests --ignore=tests/soak --ignore=tests/eval` | ~11 s |
| E2E journeys | `tests/e2e/test_*.py`: real flows through the UI and the API on a scratch server | `uv run --with playwright --with pytest pytest -q -p no:cacheprovider tests/e2e` | ~64 s |
| Merge gate | both, plus `smoke.py` and `deeplinks.py` | `tools/gate.sh PORT LABEL` | ~1 min 45 s (unit ~11 s, E2E ~64 s, smoke + deeplinks ~20 s) |

`pytest tests` does **not** collect `tests/e2e` (no Playwright needed, no browser started): the journeys run only when
`tests/e2e` (or a file in it) is named, or with `ND_E2E=1`. They carry the `e2e` marker.

## The pytest suite

About 670 tests in 54 files, grouped by feature. A file holds the behaviour of one feature and is named after it
(never after the lane or release that wrote it):

| Folder | What it guards | Files (`test_*.py`) |
|---|---|---|
| `security/` | Host 421 and the CSRF route walker (every POST/PUT/PATCH/DELETE in `app.routes` refuses another site, so a new route is covered without a new test), the SQL console sandbox, archive bombs, lake-mount and path checks, offline mode (a socket guard over every source and every GET route) | `http_guards`, `sql_console`, `archives`, `paths`, `offline` |
| `netlog/` | reading logs (`parse`: timestamps, NDJSON/array, gzip, malformed lines, EVE), matching (`matching`: time-aware listings, direction, DNS from home, CNAME/SNI/Host, retro), incidents and counts, devices, own lists, the inbox folder, push uploads, the demo, Search logs filters, "seen on your network", sinkhole logs | `parse`, `matching`, `incidents`, `counts`, `devices`, `device_names`, `lists`, `inbox`, `push`, `push_listener`, `demo`, `demo_removal`, `demo_empty_lake`, `query`, `seen`, `sinkhole`, `netlog_api` |
| `news/` | the news API and EPSS lookup, extraction and trust tiers, stories, the polite fetcher and its SSRF guard, the LLM retry | `news_api`, `articles`, `stories`, `fetcher`, `llm_retry` |
| `entities/` | extraction, ranking (confidence bands, searcher), list/graph parameters, curation (merges, verdicts, hypotheses) | `extract`, `ranking`, `entity_api`, `curation` |
| `sources/` | the feed pipeline, feed parsers, abuse.ch (parsing, alerts, links), vulnerabilities and EPSS | `feeds`, `feed_parsing`, `abusech`, `abusech_alerts`, `abusech_links`, `vulns` |
| `routing/` | the routing watch (validation, detection, data limit, token secrecy) and its sources against fake servers | `routing_watch`, `routing_sources` |
| `app/` | the core API, HTTP (upgrade, gzip), Settings › Sources, retention, setup, search, notes, notifications, Watch, Stack, Help, geo | `core_api`, `http`, `sources_api`, `retention`, `setup`, `search`, `notes`, `notify`, `watch`, `stack`, `help`, `geo` |
| `web/` | eight codebase-wide client rules (phone CSS stays in the phone query, one phone query string, vendored libraries only, `need()` before a library global, every error state has a next step, every shown time through `core/time.js`, Help content resolves, no native dialogs), the computed palette (CIEDE2000, WCAG, red only for flags, one severity map, one entity-type map), repo hygiene (no home folder, no owner drive, IPv6 literals only from an allowlist) | `client_lint`, `palette`, `repo_hygiene` |
| `e2e/` | the journeys (below) | |
| `eval/`, `soak/` | manual benchmarks and soaks, never in CI (`tests/eval/README.md`) | |

### How it runs

* **One process per file** (`tests/conftest.py`). osinthub reads its settings (lake, offline, AI helper) once, at
  import, and modules build their data at import, so files must not share a process. On a plain run each file's one
  child process collects and runs it and reports every test; on a run that selects (`-k`, `-m`, `--deselect`,
  `file::test`), a collect child per file reports its tests, pytest selects, and a run child per file runs just
  those. Either way the summary counts tests, and failures show the child's traceback. A run on one file runs
  in-process as usual.
* **Side by side:** up to `min(8, cpu)` children at a time. `ND_TEST_SERIAL=1` runs them one at a time (debugging).
* **Nothing left behind:** each child's `TMPDIR` is its own temporary folder, deleted when it ends, and
  `tests/_lake.py:make_lake()` deletes its lake when the process exits, so a run (whole suite or one file) leaves
  nothing in the system temp folder.
* `tests/e2e` is never a child: it runs in-process with its own server, only when named.

### Adding a test

1. **Prefer a journey for what a person does** (open, click, see): extend one in `tests/e2e`. A pytest test is for
   behaviour a browser cannot see or cannot pin cheaply: parsing, matching windows, limits, refusals, security guards,
   data integrity across restarts.
2. **Put it in the feature's file** (table above); start a new file only for a new feature, named after it. No lane,
   release or round names in file or test names.
3. **Start the module with the lake**, before anything from osinthub is imported:
   `from _lake import make_lake` then `LAKE = make_lake("name", disable=..., offline=...)`. `_lake` also has
   `client(*routers)`, `ORIGIN`, `ndjson()` and the `conn()`/`dns()` Zeek record builders.
4. **Assert behaviour, not source text.** Never assert a string of a JS, CSS or Python file; a rule that must hold for
   every client file goes in `tests/web/test_client_lint.py` (keep it at about eight rules).
5. **A table, not one test per case**: a list of (input, expected) checked in one test that reports every mismatch
   at once, unless each case needs its own setup.
6. **No fixed waits.** Wait on a condition or an `asyncio.Event` (at most 1 s); shorten the app's own timer with
   `monkeypatch` when the timer is what you wait for; give record files their own second instead of sleeping.
7. **Synthetic data only**: documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32),
   the demo ranges (10.86.24.0/24, fd4e:6400:d35c::/48), `.example` names, invented MACs (`02:00:5e:…`). Never real
   home data, no real names or keys: `web/test_repo_hygiene.py` runs the [release scan](/environment.md#release-scan)
   (`tools/release_scan.py`) over every tracked file, and `web/test_release_scan.py` tests the scan itself with
   invented values built from pieces, so the test file passes its own scan.
8. **Fast and independent**: a file should run in well under 2 s and a new test must pass when run alone
   (`pytest tests/x/test_y.py::test_z`): build shared worlds in module fixtures, not in an earlier test. (Some older
   tests are steps of a chain and pass only after the steps before them: in `sources/test_vulns.py`,
   `netlog/test_lists.py`, `netlog/test_sinkhole.py`, `sources/test_abusech.py`, `app/test_stack.py` and
   `sources/test_abusech_alerts.py`; do not add to them.) A test that pins a known bug is
   `@pytest.mark.xfail(strict=True, reason="BUG: …")`, so the fix turns it red until the mark is removed.

## How the E2E run works

* **One scratch server per run** (`tests/e2e/server.py`, started by the session fixture in `tests/e2e/conftest.py`):
  `OSINTHUB_OFFLINE=1`, the SQL console on (`OSINTHUB_SQL_CONSOLE=1`; `ND_SQL_CONSOLE=0` leaves it off, and
  `test_sqlgate.py` covers the off state by answering `/api/health` as an off server would), the AI helper and Qdrant
  pointed at the discard port, DuckDB vectors, loopback only, a free port
  from `ND_E2E_PORTS` (default `9880-9889`; never 8787), its own process group, under `~/.claude/bin/ttl` when that
  exists. It is stopped and its temporary lake deleted at the end of the run, pass or fail.
* **No real data.** The lake starts empty. `tests/e2e/seed.py` puts the synthetic news in
  `tests/e2e/fixtures/news.json` (invented outlets and CVE, RFC 5737 addresses, `.example` domains) into it as fetched
  articles and runs the app's own pipeline on them (chunks, entity extraction, story clustering), with the checked-in
  ATT&CK/MISP fixture `tests/entities/fixtures/ref` (APT28) as reference data, plus three invented NVD CVEs with
  entity-encoded descriptions (`tests/sources/fixtures/unescape/nvd_cves.json`) loaded through the source's own
  `parse()` for the escaping journey. `e2e-art-1` also stores one technique (T1566.001, already in the
  reference fixture for APT28: an article reporting a catalogue link), and `e2e-art-4` carries a
  stored `extraction` (what the local model returned for it), used in place of the offline pass so its story has
  techniques of all three labels (named, likely, possible) with their sentences. Network data is the built-in demo
  (`POST /api/netlog/demo`) plus a Zeek `conn.log` a journey writes into the inbox folder (192.0.2.10 → 203.0.113.66,
  on a list the journey creates). So it runs anywhere, CI included.
* **One browser per journey**, desktop 1440×900 or phone 390×844 with touch (`isPhone()` true). Waits are on
  conditions (Playwright `expect`), never fixed sleeps, except the offline walk's short settle per view.
* **Every page is watched**: page errors, console errors, 5xx responses and every request to a host other than this
  machine (aborted and recorded). A journey with any of them fails, even if its steps passed.
* **On failure**: a screenshot of each page of the journey and the server log go to `ND_E2E_ARTIFACTS`
  (default `<temp>/nd-e2e-artifacts`). Nothing is written on success.
* Options: `ND_E2E_BASE=http://127.0.0.1:PORT` drives a server you started (the journeys write, so never the live app),
  `ND_E2E_TMP` (where the run folder goes), `ND_E2E_KEEP=1` (keep it), `ND_E2E_HEADED=1`, `ND_E2E_CHANNEL`
  (default `chrome`; falls back to Playwright's Chromium: `uv run --with playwright playwright install chromium`).

## The journeys

Each asserts what a person would notice (text on screen, state after a reload) and what the server then holds.

| File | Journey | Forms |
|---|---|---|
| `test_network.py` | First run: Watch has no network data; loading the demo puts its alert on Watch, kept after a reload, and it opens | desktop, phone |
| | A Zeek log dropped in the inbox folder is scanned (Connect logs › Just files › Scan inbox now) and raises a medium alert; acknowledge it and take it back (Undo on a phone, Reopen on a computer), mark it expected and take that back (Undo / Stop treating as expected) | desktop, phone |
| | Search logs: a field filter, a drag across the timeline zooms the range (filter kept), Zoom out restores it | desktop |
| | Device page: open the demo laptop, rename it, the name survives a reload and is on the server | desktop, phone |
| `test_intel.py` | News: two reports form one story; story → lead article → APT28 from the text (side panel on a computer, its own page on a phone) → back to the story | desktop, phone |
| | Global search from Watch finds the actor, the story and both articles; a result opens; Back returns | desktop, phone |
| | Help desk: open (? / More › Help), close with ×, with Esc (focus returns) or Back; a glossary term found by search | desktop, phone |
| | Entity graph: every link type switched off empties the side panel's link list and shows the empty-state card; Turn all link types on brings the links back (focus lands on the first switch) | desktop, phone |
| `test_ttp_labels.py` | Techniques read from articles: the story groups them as Named in the article, Likely and Possible with the caveat; a click on the quote button shows each one's sentence (hover and focus open nothing) (or say none is kept); the Navigator layer and STIX carry named and likely only, with confidence 85 / 50 and a comment; Copy summary keeps the labels | desktop |
| | Phone story: the Techniques section, a tap on a technique shows its sentence, no sideways scroll | phone |
| | Intel ATT&CK strip: ExampleRAT's techniques are labelled likely and possible; APT28's catalogue technique stays "confirmed" (score 100, "also in 1 article") although e2e-art-1 reports it too | desktop |
| | The same labels in the story's actors table (none on the catalogue link), the entity panel, the article's reported relationships and a technique's own page | desktop |
| | Esc on an open evidence card closes only the card, focus stays on its button, the story stays open | desktop |
| | Esc on a card over the entity side panel closes only the card (focus back on its label, the panel stays); the panel shows "also in 1 article" from the server's count | desktop |
| | The card opens on a click only (not on hover or focus), opens below the app header, and closes on any scroll, a click elsewhere or one Esc (focus stays on the label) | desktop |
| | Phone: a card opened near the bottom of the screen stays fully on screen; it closes on scroll and never covers the header | phone |
| | A technique's own page opened directly (deep link) shows the card on a click | desktop |
| | Phone: the first tap on an ATT&CK strip cell shows the card (no navigation); its link opens the technique's page | phone |
| `test_desk.py` | Settings › Sources: the first-run chooser, then a source turned off and on, saved across a reload | desktop |
| | Inbox folder: a system folder is refused with its reason, another folder is saved (kept after a reload), back to the default | desktop |
| | Routing watch: a documentation AS number is refused, a preset network is watched and removed; offline, nothing is checked | desktop |
| | Notes on a story: write, find in Notes, edit, delete (inline confirm on a computer; a confirm sheet then Undo on a phone) | desktop, phone |
| | Ops: the desktop grid of panels; the phone summary from More, a card full screen and Back | desktop, phone |
| `test_escaping.py` | Provider text that arrived entity-encoded (`&lt;img src=x onerror=…&gt;` in an NVD description) shows as text in the New CVEs row and the event drawer: no element is created and no handler runs | desktop, phone |
| `test_guards.py` | Offline mode: a walk through every view (and Help) makes no request to any other host; Run now fetches nothing. The recorder is checked to catch a request | desktop, phone |
| | Security: a foreign `Host` gets 421; a write with another Origin, Referer or `Sec-Fetch-Site` gets 403, also from a real page on another origin (`localhost` vs `127.0.0.1`), and changes nothing | API + desktop |

Journeys do not depend on each other's order: each sets up what it needs (the `demo` fixture loads the demo when it is
not loaded; the first-run journey removes it first) and uses its own indicators and texts per form.

## The other tools in tests/e2e and tools/

* `tests/e2e/smoke.py OUTDIR`: visits every view and known sub-route at both widths (read from the nav, so new views
  are picked up), screenshots each into OUTDIR, and fails on page/console errors or blocked requests.
* `tests/e2e/deeplinks.py`: every deep link keeps its path through load, a reload, a range change and Back.
* Both use `tests/e2e/nd.py`, a read-only async harness (it aborts writes unless `ND_ALLOW_WRITES=1` on a port that is
  not 8787, and aborts every non-loopback request). Set `ND_BASE=http://127.0.0.1:PORT`.
* `tools/scratch-server.sh NAME PORT [SECONDS]`: a scratch server in the foreground (same settings as the E2E one; lake
  in `$ND_LAKES/NAME`, default `$TMPDIR/nd-lakes`; `ND_LAKE_BASE=/path` clones a lake instead of seeding one). Start it in
  the background, note the PID, `kill PID` stops the whole group.
* `tools/gate.sh PORT LABEL [WORKTREE]` (or the older `gate.sh WORKTREE PORT LABEL`): pytest, the E2E journeys, then
  smoke and deeplinks on a scratch server on PORT with the demo loaded. Prints `pytest exit N`, `E2E exit N`,
  `SMOKE PASS|FAIL`, `RESULT PASS|FAIL`; output in `$ND_GATE_OUT/LABEL` (default `$TMPDIR/nd-gates`).

## Adding or changing a journey

Add a journey only for a flow a person relies on that no journey covers; prefer extending one. Drive the UI the way a
person does (roles and visible text first, a class only where there is no name), assert the outcome on screen and on
the server, and keep it fast: no fixed waits, no reliance on another journey's state. Fixtures stay synthetic
(documentation addresses, `.example` names, the demo ranges): never real home data.
