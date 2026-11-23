---
type: Source Candidates
title: "Candidate sources: Social and community signal"
description: "Candidate community and social channels for early signal."
tags: [sources, candidates, social]
status: draft
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-04T14:00:00Z }
---

# Candidates

Probe = HTTP result fetching the feed with Night Desk's own User-Agent on 2026-11-04 ("key" means it needs a free or paid key and was not fetched). Size per fetch is measured where probed and estimated otherwise. Runs/day is a suggested cadence. Lake/day counts raw plus normalised copies of every fetch; the 1-year columns assume that cadence with no compression. Trust tiers are defined in [trust model](/sources/trust-model.md).

| Source | Provider | Trust | Access | Probe | Size/fetch | Runs/day | Lake/day | Lake 1y | DuckDB 1y | Why add it | Corroborates |
|---|---|---|---|---|---|---|---|---|---|---|---|
| [Mastodon (infosec.exchange)](https://infosec.exchange/) | infosec.exchange | D | free account token (public tag timelines disabled) | 422 without token | 60 KB | 288 | 34.6 MB | 13 GB | 0.07 GB | Where much of the infosec community moved; hashtag timelines (#cve, #threatintel). | Bluesky |
| [Reddit r/netsec](https://www.reddit.com/r/netsec/) | Reddit | D | none (RSS) | 200 | 38 KB | 48 | 3.6 MB | 1.33 GB | 0.00 GB | Curated technical research links. | Hacker News |
| [Hacker News (Algolia API)](https://hn.algolia.com/api) | Y Combinator / Algolia | D | none | 200 | 29 KB | 48 | 2.8 MB | 1.02 GB | 0.00 GB | Early discussion of major vulnerabilities and outages. | Reddit |

Category total if all were added at the suggested cadence: about 41 MB/day in the lake (15 GB/year uncompressed) and 0.2 MB/day in DuckDB.
