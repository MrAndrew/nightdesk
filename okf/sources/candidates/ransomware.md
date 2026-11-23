---
type: Source Candidates
title: "Candidate sources: Ransomware and extortion"
description: "Candidate feeds of ransomware leak-site posts and verified breach disclosures."
tags: [sources, candidates, ransomware]
status: draft
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-04T14:00:00Z }
---

# Candidates

Probe = HTTP result fetching the feed with Night Desk's own User-Agent on 2026-11-04 ("key" means it needs a free or paid key and was not fetched). Size per fetch is measured where probed and estimated otherwise. Runs/day is a suggested cadence. Lake/day counts raw plus normalised copies of every fetch; the 1-year columns assume that cadence with no compression. Trust tiers are defined in [trust model](/sources/trust-model.md).

| Source | Provider | Trust | Access | Probe | Size/fetch | Runs/day | Lake/day | Lake 1y | DuckDB 1y | Why add it | Corroborates |
|---|---|---|---|---|---|---|---|---|---|---|---|
| [RansomLook](https://www.ransomlook.io/) | RansomLook.io (open source, AGPL) | C | none | 200 | 69 KB | 48 | 6.6 MB | 2.42 GB | 0.01 GB | Open API of leak-site posts and group profiles. Live, unlike ransomwatch. Drop-in for the blocked ransomware.live feed. | ransomware.live |
| [ransomware.live PRO API](https://www.ransomware.live/) | ransomware.live | C | paid key | 403/404 (public) | 120 KB | 48 | 11.5 MB | 4.20 GB | 0.01 GB | The richer victim feed, including sector and country, once API access is arranged. | RansomLook |
| [ransomwatch](https://github.com/joshhighet/ransomwatch) | joshhighet | C | none | 200 but stale (last post 2025-06-16) | 2,288 KB | ≤1 | 0.0 MB | 0.00 GB | 0.00 GB | Historical leak-site posts only; no longer updated. Useful once for backfill. | RansomLook |
| [DataBreaches.net](https://databreaches.net/) | DataBreaches.net | C | none | 200 | 15 KB | 12 | 0.4 MB | 0.13 GB | 0.00 GB | Journalist-verified breach and extortion reporting; confirms leak-site claims. | RansomLook, news |
| [HHS OCR breach portal](https://ocrportal.hhs.gov/ocr/breach/) | US Department of Health and Human Services | A | none (form-based export) | 200 | 500 KB | 1 | 1.0 MB | 0.36 GB | 0.00 GB | Legally required US healthcare breach notices; ground truth for healthcare ransomware. | RansomLook |
| [Have I Been Pwned breach list](https://haveibeenpwned.com/API/v3) | Troy Hunt / HIBP | B | none (breach list endpoint) | 200 | 1,130 KB | 1 | 2.3 MB | 0.82 GB | 0.00 GB | Verified data breaches with record counts and data classes. | DataBreaches.net |

Category total if all were added at the suggested cadence: about 22 MB/day in the lake (7.94 GB/year uncompressed) and 0.1 MB/day in DuckDB.
