---
type: Architecture
title: Help desk
description: The "?" Help desk - on this page, a live setup and health check, guides, glossary with app-wide definition popovers, shortcuts and commands, data sources and their terms, About with redacted diagnostics and the local docs.
tags: [architecture, frontend, help]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-16T22:00:00Z }
---

# Help desk

The "?" button in the top bar opens the Help desk: a modal side panel on desktop (580 px) and a full sheet on phones.
The button is `aria-haspopup="dialog"` with `aria-expanded` true while the desk is open (`core/help.js` `isHelpOpen()`).
On a phone (a touch screen, `isPhone()`) there is no Shortcuts tab, link or search result, the section tabs are one strip that scrolls sideways with an edge fade, and a tap on a glossary term inside a card that is a link or button opens the term without opening the card or changing the address. It also opens from **Help** in the phone More sheet, the `?` key anywhere (not while typing or over another overlay),
⌘K ("Help: …" and "Guide: …" commands) and any `#help/<section>[/<item>]` link (rewritten on sight, see below). Everything in it works offline: the
content ships with the client, and the live parts read the app's own endpoints.

Client: `web/js/core/help.js` (registry, route, the `?` key, ⌘K commands, popover loader) and `web/js/help/`:
`desk.js` (the panel), content as data modules `pages.js`, `glossary.js`, `guides.js`, `keys.js`, and `status.js`
(the health check), `actions.js` ("Do it" buttons), `terms.js` (definition popovers), `md.js` (the docs renderer).
Backend: `osinthub/help/` (an extension package, `/api/help/*`). CSS: the `lane:help` block in `app.css`, prefix
`.help-`. Tests: `tests/test_v11_help.py`.

## Sections and routes

| Section | Route | What it holds |
|---|---|---|
| On this page | `#help/page[/<page key>]` | For the page Help was opened on: what it is for, what each part means, 1-5 common tasks with a **Do it** button each, related guides and glossary words, "Tour this page", and "Help for another page". A health line on top links to the check. |
| Is everything working? | `#help/status` | A live check, one line per subject, green (working), amber (needs a look) or grey (off, optional or not set up: never a fault), each with what it means and a fix button. |
| Guides | `#help/guides[/<id>]` | 9 task recipes with numbered steps; a step's button does it or goes there. |
| Glossary | `#help/glossary[/<id>]` | 79 plain-language entries (v1.1 finish added Source, Collecting (ingest) and Time zone) (definition, why it matters here, where it appears) with category filters. |
| Shortcuts | `#help/keys` | The real keyboard shortcuts by place, then every ⌘K palette entry (read live from `core/commands.js`), each runnable. |
| Sources | `#help/sources` | Every feed (from the source registry) with what it gives, its terms in plain words, licence, trust tier and whether it is on; the reference datasets with their licences; credits (FIRST EPSS and the others). |
| About | `#help/about` | Version, commit, uptime, data folder and size, feeds, network-log counts, AI helper, system, extensions, browser; **Copy diagnostics**; "Take the tour"; other registered help items; the local docs. |
| Docs | `#help/docs/<okf path>` | One page of `okf/` rendered inside the desk; links between docs stay inside it. |

**On this page** keys come from the hash Help was opened on (`pages.js pageKey()`): `watch`, `network/overview`,
`network/alerts`, `network/alert` (`#network/alerts/<id>`), `network/rules`, `network/hunt`, `network/devices`,
`network/import`, `news`, `news/story` (story or article), `entities`, `entities/page`, `entities/graph`,
`entities/review`, `notes`, `ops`, `cinema`, `explorer`, `settings` and `settings/sources|home|data`.

## Search

One box searches every section at once, as you type, in memory: sections, page help and its tasks, glossary words
(with their other names), guides and their steps, shortcuts, palette commands, sources (once loaded) and doc titles.
Words are folded before matching: stop words dropped ("how do I"), light stemming ("quieting" = "quiet"), a few
spellings joined ("license" = "licence"), prefixes match, and words written apart match written together ("backup"
finds "Back up"). Results with every word rank first, title hits higher; results with at least half the words follow
below them; groups are ordered by their best hit. ↓ moves into the results,
Enter opens the first; a task or command result runs it. When nothing matches it offers the app's own search.

## Route and history

Help is not a route (v1.2). The URL always names the page underneath (`#network/alerts` stays `#network/alerts`), and
the open desk lives in the history entry's state, `{ndHelp: '<section>[/<item>]'}`:

* Opening pushes an entry with the same URL and that state, so Back (or Esc, or the close button) closes the desk,
  with focus back on what opened it, and Forward reopens it. Switching section replaces the state.
* A reload keeps the page and reopens the desk on the same section (`history.state` survives a reload; `core/help.js`
  reads it when it loads, before any view can rewrite the entry).
* A **Do it** that goes somewhere replaces the desk's entry with its target, so Back then returns to the page before
  Help. Any other move to a different page (a link, ⌘K) closes the desk, and focus lands on that page's heading.
* The old `#help/<section>[/<item>]` links (in these docs, glossary links, bookmarks) still work: `core/help.js` sees
  the hash change before the shell or any view and rewrites it to the page it was clicked on plus the desk state. Loaded
  cold, the link opens the desk over the landing page.
* Esc closes one layer: with the desk open over the entity panel, the first Esc closes only the desk.

## Modal behaviour

`role="dialog"`, `aria-modal`, focus starts in the search box (on touch screens and at ≤760 px it starts on the "Help desk" heading instead, so no on-screen keyboard covers the sheet; the `/` hint is hidden there) and is trapped (Tab and Shift+Tab wrap; closed
`<details>` content is skipped), Esc closes (a palette opened on top closes first). Its key handler runs first
(window, capture phase): `/` focuses the help search and single-key page shortcuts (j, k, a, d, Space, ←/→) are kept
from the page behind. The panel slides in; with reduced motion it just appears.

## Actions

A task, step or fix is data (`actions.js`): `{go: '#hash'}`, `{help: 'section/item'}`, `{api, method, then?, done?}`
(for example `POST /api/netlog/demo`), or `{fn}`: `follow` (one-click follow chips for the vendors most often in KEV,
from `GET /api/setup/status`), `first-alert` (the worst new incident, then optionally opens "This is expected…"),
`expect`, `caught-up` (moves the marker, as Caught up), `hunt` (asks for an address, prefilled from the alert Help was
opened on, then runs it in Hunt), `name-device` (opens the rename form on the first unnamed device), `copy-diag`,
`search`, `palette`, `tour` (a view with no tour of its own gets Watch's; "Tour this page" shows only where a tour
exists), `choose-sources`, `reload`, `click`. Loading the demo when it is already loaded opens it instead of failing. While the demo is loaded (`demo_loaded` in the badge's last `GET /api/netlog/alerts/count`), every page's "Load demo
data" task is replaced by **Remove demo data** (opens Connect logs, where the removal shows what goes and what stays):
`shownTasks()` in `actions.js`, applied to `PAGES` by `pages.js`.

**Guides keep your place.** A guide step that goes somewhere marks the step done (kept for the browser tab, with
"Start over"). On a wide screen the guide stays open beside the page it went to (that page then owns the URL, so
closing Help changes no history); on a phone Help closes and the next Help opens back on the guide, once.

## Is everything working?

Built in `status.js` from `live.status()`, `/api/health`, `/api/setup/status` (Watch's checklist), `/api/sources`,
`/api/netlog/freshness`, `/api/netlog/status` and `/api/settings/about`, re-read at most every 30 s; the cache is cleared when the desk opens, after any fix button, and on the live topics
`netlog_alerts`, `source` and `marker` (the open section repaints). Lines: live connection, offline mode, feeds (failing ones named; paused by offline mode is grey),
network logs (none yet grey; stale amber with how long and the limit; devices with a token that never sent), demo
data, matching against the threat lists (green only with active list entries; none loaded is amber, grey in offline
mode), following, the abuse.ch key (optional, grey) and the local AI helper
(running green, expected but down amber, not running grey). An endpoint that fails gives a grey "could not check",
never green.

## Glossary

`glossary.js`: `{id, term, aka, cat, short, why, where: [[label, link]]}`. Any element with `data-term="<id>"` shows
a definition popover (`terms.js`): after a short hover, on keyboard focus (terms get `tabindex="0"` and
`aria-describedby` while it shows), or on one tap or click (a second tap on the term, or a tap elsewhere, closes it); a term inside a clickable card or row (a News story card, an alert row) answers the tap itself, in the capture phase, so the card does not also open; Enter on a focused term opens its entry; Esc hides it; "More in the
glossary ›" links to `#help/glossary/<id>`. Terms are marked with an amber dotted underline. `data-term` is used in
`net/alert-text.js` (What happened), `panels/pulse.js` (Sub-index) and `news/detail.js` (IoCs, ATT&CK,
Relationships), plus the guides. Notes and Copy summary (with "Redact my network") have entries, page help (`notes`, and the alert, entity and story pages) and a step in "Investigate an alert end to end". The test checks that every `data-term` in `web/js` has an entry.

## Shortcuts

`keys.js` lists each shortcut with the file that handles it and a `probe` (a fragment of the handler's code); the test
fails if a probe disappears, so the list cannot drift from the code. The palette list is read live.

## API

<a id="api"></a>`osinthub/help/api.py`, read-only and offline:

| Method | Path | Returns |
|---|---|---|
| GET | `/api/help/sources` | `{sources, reference, offline}`: each source's id, name, provider, category, mode, `enabled`, `unavailable`, `needs_key`, status, `last_ok`, the `feed_terms` row (`gives`, `terms`, `licence`, `terms_url`, `local_default`, `badge`) and `tier`/`tier_words` from `okf/sources/catalog.md`. Unlike `/api/settings/sources-choice` it never decides or saves the first-run state. |
| GET | `/api/help/diagnostics` | `app`, `system`, `lake` (path, sizes per folder), `data`, `feeds`, `network_logs` (counts only: files, rows, devices, demo, newest record, number of home prefixes and upload devices, needs-you), `ai_helper`, `intel`, `extensions`. Every string passes `redact()`. |
| GET | `/api/help/docs` | `{available, docs: [{path, title, description, section}]}` from `okf/` (not the log, references or candidates). |
| GET | `/api/help/docs/{path}` | `{path, title, description, markdown}`; only `.md` files inside `okf/`, anything else 404. |

**Redaction** (`redact()`, mirrored in the client before copying): the configured keys and `key=`/`token:`-style
values, long token-like strings, MAC addresses, IPv4 and IPv6 addresses (validated, so times and versions stay) and
the home folder (as `~`). Diagnostics never include device names, upload-device names or home prefixes, only counts.

## Extension points

* `registerHelp({id, label, run, order?})` still works: items other than the tour and shortcuts are listed under
  About. `setHelpRenderer(fn)` still replaces what "?" does.
* `showShortcuts()` now opens the Shortcuts section.
* Page help: add a key to `PAGES` and to `pageKey()`.
