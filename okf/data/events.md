---
type: DuckDB Table
title: events
description: One row per distinct observation from any source, with time, severity, location, network and tags.
resource: duckdb:///data/db/hub.duckdb#events
tags: [data, duckdb, table]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-04T14:00:00Z }
---

# Schema

| Column | Type | Description |
|---|---|---|
| `id` | VARCHAR, primary key | `source:sha1(key)[:16]`; stable across re-sightings. |
| `source` | VARCHAR | Source id, e.g. `cisa_kev` ([sources](/sources/)). |
| `kind` | VARCHAR | What the event is ([event kinds](/data/event-kinds.md)). |
| `category` | VARCHAR | `vuln`, `threat`, `infra`, `news`, `social` or `custom`. |
| `ts` | TIMESTAMPTZ | When it happened, or when it was collected if the source gives no time. |
| `title` | VARCHAR | One-line headline. |
| `summary` | VARCHAR | Longer description, up to about 600 characters. |
| `severity` | DOUBLE | 0 to 1. Source-specific mapping, e.g. CVSS/10 or a fixed value per list. |
| `lat`, `lon` | DOUBLE | From GeoIP, or the country's label point. Null when unknown. |
| `country` | VARCHAR | ISO 3166-1 alpha-2. |
| `city` | VARCHAR | From GeoIP. |
| `ip` | VARCHAR | IPv4/IPv6, or the first host of a prefix. |
| `asn` | VARCHAR | `AS<number>`, from the source or DB-IP ASN Lite. |
| `url` | VARCHAR | Link to the source record. |
| `tags` | VARCHAR[] | Free tags: vendor, malware family, `org:<owner>`, mentioned CVEs and countries. |
| `value` | DOUBLE | Kind-specific number: CVSS score, attack count, outage score, prefixes withdrawn. |
| `raw_path` | VARCHAR | Lake file holding the source data for the event's current version: a run's `records.ndjson.gz` or a stream's hourly file. |
| `ingested_at` | TIMESTAMPTZ | When the event was last seen (every run refreshes it). |
| `content_hash` | VARCHAR | Hash of the event's content without app-stamped timestamps; decides whether a run writes it to the lake. |
| `stored_at` | TIMESTAMPTZ | When this version was last written to the lake. |

# Notes

* Snapshot sources (IP lists, KEV) upsert the same ids on every run, so `ingested_at` moves forward while `id` stays put.
* `ts` for IP lists is the collection time, which is why the activity timeline has a spike when those lists refresh.
* Each row takes about 610 bytes on disk after a checkpoint.

# Examples

```sql
-- malicious IPs by network owner in the last day
SELECT asn, count(*) AS n
FROM events
WHERE category = 'threat' AND ts > now() - INTERVAL 1 DAY
GROUP BY asn ORDER BY n DESC LIMIT 10;
```
