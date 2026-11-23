---
type: Idea
title: The Ask page and its view-spec
description: A proposed page where the local model answers plain-language questions and renders the answer through a fixed set of trusted components driven by a structured view-spec, not model-written HTML.
tags: [project, idea, frontend, local-ai, draft]
status: draft
generated: { by: claude-code/claude-opus-4-8, at: 2026-11-08T00:00:00Z }
---

# Status

**Draft idea, not built.** This records the agreed approach so it can be picked up as a feature after the
Night Desk look settles. Nothing here ships yet. Related: [Local AI](/architecture/local-ai.md),
[Web client](/architecture/web-client.md).

# What it is

An **AI analysis page** (working name "Ask") where the user types a plain-language question — *"What events
are happening near me?"*, *"Does it look like any of my network logs are leaking data?"* — and the local
model ([MLX helper on `127.0.0.1:8790`](/architecture/local-ai.md)) answers in prose **and** lays out the supporting
datapoints as live app components: a chart, a globe focus, an entity card, a table.

The user framed this as the model "dynamically creating UI." The safe form of that is **generative UI driven
by a view-spec**: the model never emits HTML or JavaScript. It emits a small structured document that names
components from a **fixed whitelist we control**, and the frontend renders them with the same vetted widgets
the rest of the app already uses (ECharts, globe.gl, Cytoscape, the entity drawer, tables).

# Why not model-written HTML / "Open UI"

Open UI (open-ui.org) was considered as the mechanism and **does not fit**. It is a W3C Community Group
standardising *native* browser controls (`<select>`, combobox, popover, accordion) — prose research and HTML
spec drafts, with **no machine-readable schema and nothing about LLMs**. It is not something a model talks to.

Its *useful* contribution here is indirect: its cross-design-system research gives a vetted **vocabulary** of
component names that recur everywhere (Accordion, Tabs, Card, Table, Dialog, Badge, List, Tooltip) and a sense
of each component's anatomy and states. We borrow that vocabulary to name our whitelist; we do not consume
Open UI at runtime.

Letting the model emit raw DOM/HTML is rejected on three grounds, each decisive on its own:

1. **Security** — model-authored markup injected into the page is an XSS vector. A typed spec mapped to a
   closed set of renderers cannot execute anything. This matters doubly for an app that ingests untrusted
   OSINT and network-log text.
2. **Grounded numbers** — the model must not *write* datapoints; it must *fetch* them. Every value on screen
   traces to a backend query, so nothing is hallucinated.
3. **Consistency** — reusing the app's components keeps AI answers inside the Night Desk look and behaviour
   instead of a second, divergent UI.

# Shape

```
question
  → local model (:8790) acts as PLANNER
  → calls read-only backend tools over DuckDB / netlog / geo    ← real datapoints
  → returns { answer, blocks:[ {type, …props, source} … ] }     ← the view-spec
  → frontend renders each block from a fixed component registry
```

## The view-spec

A JSON document. `type` is a **closed enum**; unknown types are dropped, not rendered. Each block carries a
`source` that points back to the query that produced its data, so every block is auditable.

```json
{
  "answer": "3 flows to rare destinations in the last 6h look like possible exfiltration.",
  "blocks": [
    { "type": "stat",  "label": "Suspect flows", "value": 3, "tone": "warn", "source": "q:exfil_scan#1" },
    { "type": "table", "columns": ["host", "dst", "bytes_out", "rarity"],
      "rows_from": "q:exfil_scan#1", "source": "q:exfil_scan#1" },
    { "type": "map_focus", "lat": 47.6, "lng": -122.3, "radius_km": 50, "source": "q:events_near#2" },
    { "type": "note", "text": "None matched a known-good destination list.", "source": "q:exfil_scan#1" }
  ]
}
```

## Component whitelist (initial)

Named after the Open UI convergence vocabulary, mapped to widgets the app already has.

| `type` | Renders as | Backed by |
|---|---|---|
| `stat` | A single KPI tile with optional `tone` (`ok`/`warn`/`bad`) | existing `.kpi` styles |
| `timeseries` | A line/area chart | ECharts |
| `bars` | A bar/category chart | ECharts |
| `table` | A sortable table of query rows | app table styles |
| `map_focus` | Camera/marker on the globe or 2D map | globe.gl / MapLibre |
| `entity_card` | An entity summary card | entity panel |
| `event_list` | Ranked event/dispatch cards | Cinema/News card styles |
| `note` | A short qualifying sentence | plain text |

New component types are added deliberately, with a prop schema each — never opened to arbitrary output.

## The tool layer (read-only)

The model gets datapoints only through a small set of **read-only** functions over existing stores. It cannot
write, act, or reach the network. Each returns rows and a stable id the spec references via `source`.

- `events_near(lat, lng, radius_km, window)` — geolocated events (Cinema already geolocates these).
- `exfil_scan(window)` — heuristics over Zeek `conn` logs: large/rare outbound, beaconing cadence, DNS-volume
  anomalies. Analysis only; the app never scans ([Network view is import-only](/architecture/web-client.md)).
- `entity_lookup(name|id)` — entity/claims attribution record.
- `news_search(query, window)` — semantic search over stored articles ([local-ai.md](/architecture/local-ai.md)).

# Safety boundary (invariants)

- **Local model only** — `127.0.0.1:8790`, no egress, consistent with the app's offline guarantee.
- **Read-only** — the page analyses; it never acts, writes, or scans. Tools are query functions.
- **Grounded** — every block cites a `source` query; the UI can show "based on N rows from <query>".
- **Closed whitelist** — unknown `type` or props are dropped. No HTML/JS from the model ever reaches the DOM.
- **Human-in-the-loop** — output is read by the user; the model proposes a reading, not a verdict to act on.

# First slice (when built)

One vertical path end-to-end, to prove the mechanism before widening it:

1. An **Ask** tab (fits the existing view registry / nav).
2. A **view-spec renderer** with 2–3 component types (`stat`, `table`, `map_focus`).
3. **One real tool** wired through — `exfil_scan` or `events_near` — so a typed question returns a prose
   answer plus a real chart/table/map, with sources.

Then add tools and component types as questions demand them.
