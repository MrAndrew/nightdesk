---
type: Architecture
title: Notes and Copy summary
description: Notes kept on the server for incidents, entities, stories and articles, the one shared component that mounts them, the Notes list and the Copy-summary builder with its redaction.
tags: [architecture, frontend, notes]
generated: { by: claude-code/claude-opus-4-8, at: 2026-11-18T22:00:00Z }
---

Notes are kept on the Night Desk server (DuckDB table `notes`, package `osinthub/notes/`), so they survive a
browser change and show on every device that opens the app. One shared component, `core/notes.js`, is mounted
with one line wherever an item is shown:

| Where | Item | Mount |
|---|---|---|
| Network → Alerts, incident detail | `incident` (the incident id, its first alert) | `views/net/alerts.js`, before the Questions tabs; Copy summary joins the action row |
| Entity drawer | `entity` (e.g. `actor:apt29`) | `core/entity-panel.js`, above "Open full profile"; Copy summary in the drawer's action row |
| Entity page | `entity` | `views/entities/page.js`, top of the side column; Copy summary in the header actions |
| News story | `story` | `views/news/detail.js`, under the summary; Copy summary in the story actions |
| Article reader | `article` | `views/news/detail.js`, above "Why this is here" |

A note on an incident shows the incident's title **as it reads now**: the server attaches `incident`
(severity, kind, device with the user's current name, indicator, trimmed evidence; `notes.store.incidents_now`)
to every incident note it returns (`GET /api/notes`, the note group of global search), and the Notes list and
search word it with the Network headline (`net/alert-text.js headline()`). Renaming a device or regrouping
never leaves a note with an old title; the stored `title` is only the fallback for an incident that is gone.
Search also matches a note by its incident's current title, and a title match reads "Note on a network
incident" under it.

`mountNotes(host, {kind, item, title, before | at, cls, actions, summary})` lists the item's notes (oldest
first, with created and edited times), adds, edits (Ctrl+Enter saves, Esc cancels) and deletes them (with an
inline confirmation). The text is **markdown-lite**: `**bold**`, `*italic*` or `_italic_`, `` `code` ``, fenced
code blocks, `-` and `1.` lists, `>` quotes, `#` headings (shown bold) and `[text](https://…)` links. The
server renders it (`store.render`): every character is escaped first, only those tags are written, links are
http(s) only and open in a new tab, and bare URLs are **not** linked (a pasted indicator never becomes a
click). The client inserts that `html` field as is.

**Badges.** `notes.js` watches `#views` and puts a small note-count badge on rows of the incidents list, the
story cards and "What's new" rows, article search results and the entity directory (counts from
`GET /api/notes/counts`, refreshed after any change and when the tab comes back into view). The views
themselves are not changed.

**The Notes list.** `#notes` (optionally `#notes/<search>`) lists every note grouped by item, newest change
first, with a search box (notes and item titles) and a filter by kind; each item title links back to it. It is
an ordinary view (`<section data-view="notes">` in `index.html`, title in the shell's `TITLES`) with no
navigation tab: reach it from "All notes ›" in every notes block or from the command palette (⌘K, "All notes";
`notes.js` registers `NOTES_COMMAND` with `core/commands.js`). `openNotes(q)` is exported for other modules.

**Old browser notes.** v1.0 kept article notes in localStorage (`nd.news.notes`, "saved in this
browser"). On the first load after the update, `migrateLegacy()` sends them to `POST /api/notes/import` and then
removes the key. The import skips a note whose kind, item and text are already stored, so a repeat adds nothing;
if the server cannot be reached the key is kept and the move is tried again on the next load.

# Copy summary

**Copy summary** (`core/summary.js`) builds Markdown: title; kind and date; what happened (or what it is, or
the story summary); why it matters; key facts; what to do (incidents); evidence with UTC times (log rows,
reported claims with their dates, or the coverage timeline); sources with links (the threat list's homepage,
reports, articles); and the item's notes. A dialog shows it in a selectable text box with **Copy** (the
clipboard, or the text is selected for Ctrl+C when the browser refuses). **Redact my network** is on by default
and works in three steps:

1. **Structural.** The summary builder wraps every value it knows is home-side in a marker before any text is
   produced: device names, labels, owners and announced names, the device's addresses and MAC, and every
   address in an evidence row (kind `ipq`: the server redacts it when it is in the home network; IPv6 with a
   port is written `[addr]:port`). `POST /api/notes/redact` turns each marker into a placeholder first.
2. **Backstop** over the remaining free text (titles, the user's notes): MACs written with colons, dashes, dots
   or as 12 bare hex digits; reverse-DNS names (`…in-addr.arpa`, `…ip6.arpa`) of home addresses; home IPv4 and
   IPv6 in any form (with `:port`, `[v6]:port`, `::ffff:a.b.c.d`, zero-padded or compressed: every run is parsed
   with `ipaddress` and tested against the effective home prefixes, private and ULA ranges and every address a
   device used); then the user's labels and owners at any length, whole word, any case, longest first, with
   numeric-suffix variants ("Laptop-2"), and the names devices announce (except a few generic words such as
   `localhost`). Over-redaction is preferred: a device called "Router" also turns the word "router" into a
   placeholder.
3. **Placeholders** (`[home IP 1]`, `[MAC 1]`, `[device 1]`) are unforgeable private-use tokens until the end,
   so a later pass never touches them (a device named "mac" cannot corrupt `[MAC 1]`), numbered in reading
   order, the same value always the same number. Outside addresses, the threat itself, stay.

The unredacted view just drops the markers. If redaction fails, Copy stays off until the box is unticked, and
anything the server left marked is shown as `[redacted]`.

| Method | Path | Body / params | Returns |
|---|---|---|---|
| GET | `/api/notes` | `kind`, `item` | `{notes}` of one item, oldest first |
| GET | `/api/notes` | `q`, `kind`, `limit` (≤1000), `offset` | `{total, kinds: {kind: n}, notes}`, newest change first |
| GET | `/api/notes/counts` | `kind` (optional) | `{incident: {id: n}, entity: {...}, story: {...}, article: {...}}` |
| POST | `/api/notes` | `{kind, item, body, title?}` | the note `{id, kind, item, title, body, html, href, created_at, updated_at}` |
| PUT | `/api/notes/{id}` | `{body?, title?}` | the note; 404 when gone |
| DELETE | `/api/notes/{id}` | | `{ok: true}`; 404 when gone |
| POST | `/api/notes/import` | `{notes: [{kind, item, body, title?}]}` (≤5000) | `{imported, skipped, errors}` |
| POST | `/api/notes/redact` | `{text}` | `{text, replaced: {ips, macs, names}}` |

A note is at most 10,000 characters; an empty note is refused (400). Tests: `tests/app/test_notes.py` (and the E2E desk journey, `tests/e2e/test_desk.py`).
