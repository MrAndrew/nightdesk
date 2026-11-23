---
type: DuckDB Table
title: Operational tables
description: source_state, runs, record_hashes, settings and metrics, which track each source's health, every ingest run, what is already stored in the lake, user settings, and time-series measurements.
resource: duckdb:///data/db/hub.duckdb
tags: [data, duckdb, table, operations]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-04T14:00:00Z }
---

# source_state

One row per source, updated as it runs and pushed to browsers on the `source` live topic.

| Column | Type | Description |
|---|---|---|
| `id` | VARCHAR, primary key | Source id. |
| `enabled` | BOOLEAN | User override; null means the source's default. |
| `status` | VARCHAR | `running`, `ok`, `idle`, `error`, `live`, `reconnecting` or `disabled`. |
| `message` | VARCHAR | Last result or error text. |
| `last_run`, `last_ok` | TIMESTAMPTZ | Last attempt and last success. |
| `items_last`, `items_total` | BIGINT | Events in the last run; rows in `events` for this source. |

# runs

One row per batch run.

| Column | Type | Description |
|---|---|---|
| `source` | VARCHAR | Source id. |
| `started`, `finished` | TIMESTAMPTZ | Run window. |
| `ok` | BOOLEAN | Whether it succeeded. |
| `items` | BIGINT | Events loaded. |
| `raw_path` | VARCHAR | The run's `records.ndjson.gz` file, or null when nothing changed. |
| `records_changed`, `records_removed` | BIGINT | Provider records written as new/changed, and list keys written as removed. |
| `events_changed` | BIGINT | Normalised events written as new or changed. |
| `error` | VARCHAR | Error text on failure. Also set on a run that loaded but had a part fail (one dead feed of a multi-feed news source); `ok` stays true and the source's `status` is `error` until a clean run. |

# record_hashes

The provider records currently held for each batch source, used to store only new or changed records ([what the lake stores](/data/architecture.md#what-the-lake-stores)). Replaced as a set after each run.

| Column | Type | Description |
|---|---|---|
| `source`, `key` | VARCHAR, primary key | Source id and record key (CVE id, IP, outage key…). |
| `hash` | VARCHAR | Hash of the record's content. |
| `stored_at` | TIMESTAMPTZ | When this version was written to the lake. |

# settings

User settings as JSON values. Today only `retention`: `{"lake_days": null, "db_days": null}` by default ([retention](/data/architecture.md#retention)).

# metrics

Append-only time series.

| Column | Type | Description |
|---|---|---|
| `ts` | TIMESTAMPTZ | Sample time. |
| `name` | VARCHAR | e.g. `bgp.updates_per_s`, `bgp.announcements_per_s`, `bgp.withdrawals_per_s`, `bluesky.posts_per_s`, `bluesky.cyber_per_min`, `source.<id>.items`, `source.<id>.changed` (events new or changed in the run). |
| `value` | DOUBLE | Sample value. |

BGP metrics are written every 5 seconds and Bluesky metrics every 10, about 69,000 rows a day. That is small, but a candidate for downsampling once retention matters.
