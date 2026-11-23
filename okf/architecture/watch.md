---
type: Architecture
title: Watch
description: The Watch front page, its deterministic "since you were last here" briefing, the one app-wide last-seen marker shared by Watch, News and the KEV list, and the setup checklist (GET /api/setup/status).
tags: [architecture, watch, frontend, api]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-22T08:00:00Z }
---

# Watch

Watch is the default landing view (`#watch`, first tab). It answers the morning questions in one place: is my network
touching anything bad, does any new exploited bug or news story affect me, and what else happened since I last looked.
Backend: `osinthub/watch/` (an extension package: `marker.py`, `briefing.py`, `setup.py`, `api.py`, `ext.py`). Client:
`web/js/views/watch.js`. Tests: `tests/test_v11_watch.py`. Nothing in it calls a language model.

## Marker
<a id="marker"></a>One "last seen" time for the whole app, server-side (`settings` key `app.last_seen`:
`{last_seen, previous, set_at, history}`).

* It moves **only** when the user says so: **Caught up** on Watch, or **Mark all as read** in News (the same action).
  There is no automatic advance.
* The previous value is kept (plus up to 10 older ones), so Watch can **Show since <previous> again**. That view is
  read-only (`GET /api/watch?since=previous`); `PUT /api/marker {"back": true}` puts the marker itself back.
* Every move returns `undo`, the whole marker as it was just before (`{last_seen, previous, set_at, history}`, all null
  on a first visit). `PUT /api/marker {"restore": <undo>}` puts it back exactly, history included, even to "no marker
  at all" (the old `news.last_seen` follows): the Undo of the phone's **Mark all as seen** (v1.2 mobile).
  `restore` must be exactly that shape (those four keys; times are ISO 8601 strings or null; `history` a list of
  them); anything else is a 400 and the marker is left as it was.
* What Watch shows is capped at **7 days** (`marker.CAP_DAYS`), even when the marker is older; the masthead says so.
  With no marker at all (first visit) Watch shows the last 24 hours.
* Backwards compatible: the v1.0 news-only setting `news.last_seen` (a bare ISO string) is read when `app.last_seen` is
  missing, and every write keeps it in step. `GET/PUT /api/news/marker` are now the same as `/api/marker`.
* Readers: Watch, News ("new since your last visit", `new_since=marker`, the digest default) and the Ops KEV panel
  (a **New** chip and NEW tag for entries added since the marker, by the same rule as Newly exploited).
* A move publishes the live topic `marker` (`{last_seen, previous}`); News and Watch re-read on it.

## Briefing
<a id="briefing"></a>`GET /api/watch` returns sections in this fixed order. Each is `{id, title, count, items (at most
8), link {href, label}, empty}`; `empty` is a plain sentence with `{since}` for the client to fill with the reader's
local time ("Nothing new on your network since Mon 21:40.").

| id | Title | What | Item opens |
|---|---|---|---|
| `network` | Your network | Needs-you incidents ([count rule](/data/netlog.md#the-needs-you-count): untriaged, not expected, high or medium) whose last contact, creation or update is after the window start; `needs_you` (the total, new or not); `logs` from `GET /api/netlog/freshness` (newest record, stale or not). Demo incidents only when there are no real ones (`demo: true`, each item `demo`). | `#network/alerts/<id>` |
| `touches` | Touches you | KEV entries whose CVE your network logs named (a software notice), stories active in the window naming an IP, domain, URL, hash or CVE that an alert (not dismissed) has, and what you follow ([My stack](/architecture/my-stack.md)): new KEV entries for a followed vendor, product, CVE or word (plus, once, the last 30 days of entries for something followed since the marker: `recent_follow`), network incidents involving a followed entity (`type: alert`; still-open ones go to `still_open`, not counted), EPSS jumps of followed CVEs (`type: epss`) and ransomware victims (`type: victim`). `why` is `network` or `follow`; follow items carry `matched` and `matched_names`. | KEV, victim: event drawer; story: `#news/story/<id>`; alert: `#network/alerts/<id>`; EPSS: `#entities/cve:<id>` |
| `kev` | Newly exploited | KEV entries dated after the window start, or first stored after it and dated at most 3 days before; EPSS highest first; vendor, product, name, date added, due date (from CISA's records), ransomware flag. | the KEV event drawer |
| `follow` | News you follow | The watchlist digest (`watchlist_digest`) since the window start. | `#news/story/<id>` |
| `stories` | Big stories | Story clusters active in the window with at least 2 outlets, most outlets first (top 5; `count` is the total). | `#news/story/<id>` |
| `health` | Feed health | **Only when something is wrong:** offline mode (one line), a failing source, a batch source with no good run for 3 intervals (at least 6 h), or a source Watch needs (`cisa_kev`, `epss`) turned off. Sources waiting for a key are never listed. | `#sources` |

Also: `window {since, asked, capped, first_visit, cap_days}`, `marker`, `viewing_previous`, `feeds {enabled, fresh,
offline}` and `total` (items across sections other than health). The same lake gives the same answer (no LLM, no
randomness); every list has a stable order.

## Setup status
<a id="setup-status"></a>`GET /api/setup/status` (also for the Help desk): `{items, done, required, complete,
first_run, has_logs, demo, has_data, dismissed}`. Items, each `{id, title, done, optional, detail, action {label,
href | api+method}}`, from real state. `detail` is plain language and never names a setting; an item that does
(`feeds` while offline mode is on, `abusech` while the key is missing) adds `tech`, the variable's name
(`OSINTHUB_OFFLINE=1`, `ABUSECH_AUTH_KEY`), which Watch and the Help desk show as the detail's hover title:

* `feeds`: feeds running and the first data arrived (events in the lake and a good run).
* `demo`: demo network data loaded (or not needed: real logs are in); action `POST /api/netlog/demo`.
* `logs`: your own network logs imported; link `#network/import`.
* `abusech` (optional): the abuse.ch key is set (ThreatFox and URLhaus can run).
* `watchlist` ("Follow what you run"): you follow at least one thing ([My stack](/architecture/my-stack.md)); `quick` holds the "What do you run?" chips (common home-lab gear not followed yet, each `{vendor, product, label, kev}`), `suggest` the vendors most often in CISA KEV; one click follows. The action opens Settings › What you follow (`#settings/follow`).
* `ai` (optional): the local AI helper answered this run.

`first_run` is true when there are no network logs (real or demo) or no data at all. Watch then shows the checklist at
the top and collapses empty sections to one line. **Hide checklist** stores `PUT /api/setup/dismiss {"dismissed":
true}` (`settings` key `watch.setup_dismissed`); the masthead link **Setup checklist** brings it back.

## API
<a id="api"></a>

| Method | Path | Body / params | Returns |
|---|---|---|---|
| GET | `/api/watch` | `since` (optional: `previous`, or an ISO time; still capped at 7 days) | The briefing above. 400 for a bad time or no previous marker. |
| GET | `/api/marker` | | `{last_seen, previous, set_at, window}` |
| PUT | `/api/marker` | `{}` (Caught up: now), `{"last_seen": ISO}`, `{"back": true}`, or `{"restore": <undo>}` | As GET, plus `undo` (the marker before this move). 400 for a bad or future time, 409 for back with no previous. |
| GET, PUT | `/api/news/marker` | as `/api/marker` | as `/api/marker` (kept for old clients) |
| GET | `/api/setup/status` | | The checklist above |
| PUT | `/api/setup/dismiss` | `{"dismissed": bool}` (default true) | `{dismissed}` |

## Client
`web/js/views/watch.js`: a single column (max 780 px, one column at every width, "Your network" first). Masthead with
the date in serif, "Since Mon 21:40 · 9 h ago", the amber **Caught up** button, and links for the previous window and
the checklist. Network headlines use the Network view's own wording (`net/alert-text.js headline()`), falling back to
the stored title. Severity text is red only for high (flagged), amber for medium. After **Caught up**, when nothing is
new, the page shows a calm "You're caught up." card with the time it was set and the "Show since … again" link, and
the empty sections in one line. Live: the `netlog_alerts`, `events` (from `cisa_kev`) and `marker` topics re-read the
briefing (debounced; a hidden view re-reads when shown), plus every 5 minutes while open.

**Caught up** is offered on a first visit even when nothing is new (and the checklist is showing), so Watch can always
leave "First visit: the last 24 hours". When only demo alerts are open, the Your network count carries the DEMO tag and
is never amber or red. The count says what it counts next to it ("high/medium since 21:40", "high/medium demo in the
last 24 hours") and links the total the Alerts tab shows ("12 new in all", from `GET /api/netlog/alerts/count`
`open`): [which number](/data/netlog.md#which-number). The logs line uses Network's per-source verdict
(`GET /api/netlog/freshness`, the same as "Are my logs current?"): "Your logs cover up to 01:59 (20h ago)." and then
only the sources Network calls stale, each with its own age ("Files you uploaded: stale, nothing newer for 5 days.");
a source Network calls current is never named next to "stale".

A failed load ("Couldn't read the briefing", Try again) retries by itself every 10 s while Watch is open, when the
live stream reconnects and when Watch is shown again, so a server restart never leaves it up.

**Load demo data** from the checklist behaves like Network › Connect logs › Demo data: Your network then opens with the
demo report (planted N of M, the scenarios left out grouped by cause with their fix and a link to Sources or News,
`net/demo.js skippedHtml`), an "Open the top demo alert" button (`#network/alerts/<top_alert>?range=all`) and a link to
every check in Connect logs; the top demo alert in the list is marked and scrolled into view. The report closes with
its × or when the demo is removed; removing from Watch says in the toast which names and rules made for the demo went
with it.

## On a phone
<a id="phone"></a>On a phone (`isPhone()`) Watch is a different page built by `phoneWatch()` in `watch.js`
([phone layout](/architecture/phone.md#per-view)). Its **answer card** (`.watch-m-answer`) is built from the
network endpoints alone (`GET /api/netlog/alerts/count`, `/api/netlog/freshness`,
`/api/netlog/incidents?needs_you=true&limit=3`), so it shows first and on its own even when the briefing or
news endpoints fail, leading with one headline (logs stale / alerts open / nothing needs you / no logs); then
**Touches you**, **Newly exploited** and **Following** from `GET /api/watch`, and an end-of-feed **Mark all as
seen** (which moves the marker and shows an Undo toast; Undo sends `{"restore": undo}`).
