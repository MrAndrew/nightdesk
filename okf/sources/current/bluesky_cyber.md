---
type: Data Source
title: "Bluesky firehose — cyber chatter"
description: "Every public Bluesky post, filtered live for cyber keywords (CVE IDs, ransomware, zero-days, breaches, DDoS, botnets). Posts are tagged with mentioned CVEs and countries."
resource: https://github.com/bluesky-social/jetstream
tags: [social, stream, current]
provider: "Bluesky Jetstream"
mode: stream
cadence: "continuous"
trust_tier: D
auth: "none"
license: "Public posts, Bluesky ToS"
in_app: off by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

Every public Bluesky post, filtered live for cyber keywords (CVE IDs, ransomware, zero-days, breaches, DDoS, botnets). Posts are tagged with mentioned CVEs and countries.

| | |
|---|---|
| Source id | `bluesky_cyber` |
| Provider | Bluesky Jetstream |
| Mode | stream (continuous) |
| Trust tier | D: Unverified or crowd content (social posts, tips); signal only, never ground truth |
| Access | none |
| License | Public posts, Bluesky ToS |
| Status in Night Desk | off by default for new lakes (an unvetted social stream; turn it on in Sources). A lake that already ran it keeps it on (`DEFAULT_OFFS` in osinthub/scheduler.py). |

# Corroboration

Other sources that report the same facts, so agreement raises confidence: Mastodon infosec.exchange, Reddit r/netsec, news wire.

# Terms

Read 2026-11-19 ([terms](https://docs.bsky.app/docs/support/developer-guidelines)): The docs site's guidelines page now redirects to an empty page; the guidelines' source in Bluesky's docs repository ([developer-guidelines.md](https://github.com/bluesky-social/bsky-docs/blob/main/docs/support/developer-guidelines.md), archived by Bluesky on 2026-08-18) says, as item 3, "All services must have a method for deleting content a user has requested to be deleted". The owner's reading (2026-11-20): each Night Desk runs on its user's machine, and that user manages the data (NOTICE, "Your data and the sources you turn on"). The stream records each delete of a post it stored in the `deletion_requests` table and keeps the post; deletes made while Night Desk is stopped are not seen.

Commercial use: ?. Redistribution: no. AI use: contested.

# Text

Post text is stored as plain text: posts copied from web pages or made by feed bots can carry HTML entities (`&amp;`, `&#39;`, `&quot;`) that Bluesky stores as typed. The shared decoder (`osinthub/sources/text.py`) decodes well-formed entities only (`AT&T`, `&foo;` stay as written), before the keyword filter runs, so the stored title, summary, tags and the live `social` messages all see the same text. Line breaks are kept. The DID, the record key and the post link are never decoded. Decoded markup such as `<script>` is text: clients escape it where they show it.

Existing lakes: a stream never sees a post twice, so posts stored before the text was decoded are fixed in DuckDB each time the stream connects (only rows that still hold an entity-like `&...` are looked at), each with a new content hash, so the entity linker extracts its mentions again, once. The lake's hourly event files keep the text as it was stored then.

# Storage

0.4 MB of normalised events per day (measured 2026-11-04), or 0.4 MB/day uncompressed. The full feed is still fetched every run, but only new, changed or removed records are stored, gzipped. That leaves 21.00% of it (0.08 MB/day, measured). DuckDB grows only by new unique events (about 400 per day at 610 bytes per row); repeat sightings update rows in place.

| Kept for | Lake (as built) | DuckDB |
|---|---|---|
| 30 days | 0.00 GB | 0.01 GB |
| 90 days | 0.01 GB | 0.02 GB |
| 1 year | 0.03 GB | 0.09 GB |
| 3 years | 0.09 GB | 0.27 GB |

See [storage estimates](/data/storage-estimates.md) for totals across all sources.
