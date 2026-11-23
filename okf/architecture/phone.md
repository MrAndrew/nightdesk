---
type: Architecture
title: Phone layout
description: The v1.2 phone contract (the phone switch, pages and Back, the bottom layer, sheets, swipes, Undo and libraries on demand) and how each view behaves on a phone.
tags: [architecture, frontend, mobile, phone]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T21:00:00Z }
---

v1.2 added a real phone layout. A desktop window of any width keeps the desktop client, including its
narrow-window bottom bar; only a phone gets these pages. Nothing here changes a desktop page.

# What "phone" means

A **phone** is a coarse primary pointer and a screen ≤ 760 px wide or ≤ 500 px tall (`PHONE_MQ` in
`core/mobile.js`; `isPhone()`, `onPhoneChange(cb)` fires on rotation or a split-screen resize). Every phone
CSS rule sits inside that media query, and every JS layout branch asks `isPhone()`. Switching layout
(rotation, split screen) re-routes the current URL in the other layout.

# The contract (shared modules)

* **The page scrolls.** `body` is no longer `overflow: hidden`; the top bar is sticky; every view ends with
  bottom padding for the bottom layer plus the safe area.
* **One bottom layer:** the tab bar (`#m-tabbar`: Watch · Network · News · Intel · More; Ops, Notes, Cinema,
  SQL console, Sources, Settings and Help are in **More**) on root pages, or a pushed page's action bar
  (`#m-actbar`, `page.setActionBar(nodes)`). Both are opaque and sit above everything in the page; `#views` is
  its own stacking context, so a high z-index inside a view cannot cover the bar. A maximised panel lifts the
  page to a layer between the top bar and the bottom layer, with a 44 px **Close** button. While the keyboard
  is up (`body.m-kbd`, from visualViewport) the bottom layer and the drawer step aside.
* **Pages and history** (`core/page.js`, loaded before `main.js`): every entry carries `ndKey` and `ndDepth`
  in `history.state` (pushState/replaceState are wrapped). `depth()` is the number of in-app entries behind
  the current one (0 for a pasted link, a notification or a fresh tab). Scroll is restored per entry after
  Back/Forward once the view re-renders (`afterRender(viewId)`).
* **Back and overlays** (owner decision, 2026-11-15): browser Back and Forward move between **URL pages only**.
  Sheets, maximised panels, the note sheet, dialogs and popovers get **no** history entry; they sit on an
  in-memory overlay stack (`overlayOpened`, `closeOverlay`, `topOverlay`) and close through their own control,
  Esc (one capture-phase handler, top overlay first) or a scrim tap. Moving to another page closes open
  overlays, top first, with no history side effect.
* **‹ Parent:** `page.back(parent)` goes to the parent page and never leaves the app (`history.back()` when
  the entry behind is the parent, else the entry is replaced by the parent). Each route's parent comes from
  `parentOf(hash)`; a view adds a route with `addParentRule(re, parent)`.
* **Sheets** (`core/sheet.js`): `openSheet()`, `confirmSheet()` (instead of `confirm()`), `actionSheet()` (the
  ⋯ menu) and `navigateFromSheet(hash)`. A sheet traps focus, makes the page inert, and closes on ×, Esc, a
  scrim tap or a handle drag. A routed sheet (`#network/alerts/<id>/expected`) is that page, and closing it
  goes to its parent.
* **Swipes** (`core/swipe.js`, `swipeRow`): touch and pen only, never within 24 px of a screen edge, off under
  reduced motion; always a shortcut for a visible ⋯ action. **Undo** (`core/undo.js`) is an opaque toast above
  the bottom layer, announced in `#sr-live`. Phone **notes** use `core/note-sheet.js` (`openNoteSheet`).
* **Libraries on demand** (`core/libs.js`): `index.html` loads none of the five vendor scripts, so a phone's
  first screen fetches no chart, map, grid or globe code. `await need('echarts' | 'maplibre' | 'gridstack' |
  'globe')` injects the vendored script once (echarts-gl was removed: it needs eval, which the
  Content-Security-Policy refuses). `preloadAll()` loads all four; on desktop `js/core/preload.js` (loaded by `index.html`) calls it on idle, so desktop
  views find the libraries ready.
  Fonts are not scripts: `vendor/fonts/fonts.css` declares them and the browser fetches only the faces a page
  shows. The Fraunces serif adds 18 KB (600) to a News or story first screen, 36 KB (500, 600) to an entity
  page and 59 KB (500, 600, 400 italic) to Watch.

# Phone shell

The phone chrome (`core/mshell.js`, `core/status.js`): its parts are created the first time the phone layout
applies and are `[hidden]` otherwise.

* **Top bar** (52 px plus safe area, 44 px sideways): on root pages `[lamp] [view title] [health pill]
  [search]`; on a pushed page (`page.isPushed()`) `[‹ Parent] [title]`. The title and Back label come from
  `page.setPhoneTitle()` or the route. The view header's title and purpose give way to it; the offline banner
  is not shown (the pill and Status sheet carry it).
* **Health pill** (`core/status.js health()`): one state, never an alert count, in priority order **Logs
  stale** → **N source errors** → **Offline** → **Healthy**; its `aria-label` says it in full. A tap opens the
  **Status sheet** (logs, sources, offline mode, demo data, network alerts, and the note about reaching the
  home server only through your own VPN).
* **Tab bar:** Watch · Network · News · Intel · More, each ≥ 72×56. The Network badge is the
  [needs-you count](/data/netlog.md#the-needs-you-count) (none at 0). **More** opens the More sheet (Places:
  Ops, Notes, Cinema, SQL console while it is on; Desk: Sources & health, Settings, Help, Take the tour).
* **Range:** `core/range.js` shows one chip ("24h ▾" or the brushed window) that opens the range sheet; the
  value, `onChange` and `?range=` are unchanged. **Search** (`#search?q=`) is a full-screen page.

# Per view

* **Watch** (`phoneWatch()` in `watch.js`): nothing sticky. An **answer card** built from the network
  endpoints alone (so it shows even when the briefing fails) leads with one headline — logs stale / alerts
  open / nothing needs you / no logs — the top alerts, and **Open alerts** / **Devices** / **Try the demo**.
  Then **Touches you**, **Newly exploited** and **Following** (3 rows each, "All N ›"), and an end-of-feed
  **Mark all as seen** with Undo. A demo line reads "15 demo alerts (made-up) not counted".
* **Network** (`net/m.js`, `m-alerts.js`, `m-devices.js` plus `isPhone()` branches): the view scrolls; its
  header keeps only its tabs (Alerts · Devices · Overview · Logs; Connect logs from Overview). **Alerts** are
  one link plus a 44 px ⋯ (Acknowledge, Dismiss, Reopen, This is expected…, Copy summary, rules); right-swipe
  acknowledges, left dismisses, each with Undo (a left swipe on a high alert opens the ⋯ sheet instead).
  **Select** shows checkboxes and a batch bar. An **alert**, **device**, and **Mark as expected** are pushed
  pages / routed sheets with ‹ Parent and an action bar; questions, evidence and indicator become accordions.
  **Overview** is status cards, **Logs** is a query chip with Edit query, preset cards and raw-JSON rows. A
  removed alert or a failed load says so and never shows the onboarding.
* **News** (`views/news/phone.js`): a single column that shares the desktop view's state and data and follows
  the URL. **Sub-nav** Latest · Most covered · Following; a filter row (Search, range sheet, Filter). **Cards**
  are one link to `#news/story/<id>` with nothing interactive inside (outlets and age, serif headline ≤ 3 lines,
  one summary line measured to whole words, a meta line). **Density** Comfortable or Titles only, chosen in the
  Filter sheet and kept per device (localStorage `nd.news.density`). The list shows 60 cards at a time ("Show 60
  more of N"). It loads the newest 500 stories; when the server has more, the end of the list says so ("The
  newest 500 stories of N…") and the Filter sheet's count reads "Show N+ stories".
  * **Filter sheet:** a full-screen sheet working on a copy of the filters (Show, Has, Trust, Watchlist, Sources,
    Density). Its pinned button reads **Show N stories**, where N is what the list will show (the server's answer
    for the chosen sources, trust and followed name, with Show and Has applied as the list applies them).
    Nothing changes until it is pressed; ×, Esc, a tap outside or Back close it unchanged.
  * A **story** and an **article** are pushed pages with action bars (story: Read lead article, Add note, Share,
    ⋯; article: Open original, Add note, ⋯); the full desktop analysis (IoC table and exports, techniques) stays
    on a computer. Chip hit areas are ≥ 44 px.
* **Intel** (entities): `openEntity()` pushes `#entities/<id>` instead of the side panel, so every chip opens
  the entity page. Directory · Graph · Review is the sticky sub-nav. The entity page is a pushed page with a
  "Jump to" row and plain headed sections; its ⋯ holds Copy value, Same as…, Wrong type…, STIX and Open in
  graph. The graph lists the root's connections, with **Open the graph** showing the canvas full screen
  (overlay, no history entry). **Review** is read-only ("Decide these on a computer").
* **Ops, Cinema, SQL console, Settings, Sources, Notes** — the desk pages reached from More, all root pages:
  * **Ops** (`views/ops-phone.js`): four plain-HTML cards (Needs attention, Newly exploited, Latest news,
    Source health); nothing on the summary loads a chart or map library. Each card's ⤢ links to
    `#ops?panel=<id>`, a pushed page that mounts that registered panel full screen (any id works, so a link
    copied on a computer opens the same panel; on a computer it maximises that panel in the current deck).
  * **Cinema:** a "Last 24 hours" list of placed events with a mini-map per row; **Open the globe** opens
    `#cinema?kiosk` (loads globe.gl, full screen, no autopilot). globe.gl is never fetched before that.
  * **SQL console:** the page scrolls; examples are tappable cards; **Edit query** opens a full-screen sheet;
    results scroll sideways in a fade box. The ⌘↵ hint is hidden on any touch screen.
  * **Settings / Sources:** `#settings` is a grouped list of 52 px rows that push `#settings/<id>` pushed
    pages; the Sources row shows the health split ("N with errors / paused / waiting / on"). Routing watch is
    its own page under Sources. Every text field is 16 px so iOS does not zoom; destructive actions use
    `confirmSheet()`, never `window.confirm()`.
  * **Notes:** each note is one button that opens the note sheet (`core/note-sheet.js`) to edit or delete; its
    `nd:notes-changed` event refreshes the list, badges and any notes block on screen.

# Responsive chrome (not only phones)

Short windows (≤ 560 px tall), narrow headers (761–1180 px), touch tablets (a coarse pointer, 761–1100 px),
browser zoom and notches get a compact-but-full layout rather than a phone one: 44×44 tap targets on coarse
pointers, one-row headers and toolbars that do not wrap, sideways-scrolling tab strips with edge fades, and
`viewport-fit=cover` safe-area insets (`--sai-*`) on the bars and full-height overlays. The desktop 1440 and
phone 390 pixel diffs are the guard for this, so it is not pinned here by pixel. The guided tour has its own
three-card phone variant ([web client](/architecture/web-client.md#guided-tour)).

# For maintainers

Every phone branch is behind `isPhone()` / `onPhoneChange()`; a phone view shares the desktop view's state and
data and follows the URL. Cards and pages navigate with `page.pushPage()`, and each sets `setPhoneTitle()` and
`setActionBar()`, so a tapped page and a deep-linked one look the same. On a phone the desktop side pane, its
`history.state.nw` trail and the single-key shortcuts are not used.
