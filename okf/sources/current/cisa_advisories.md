---
type: Data Source
title: "CISA cybersecurity advisories"
description: "CISA's ICS, ICS medical and IT vulnerability advisories from its machine-readable CSAF 2.0 repository on GitHub, with CVEs, CVSS, vendors and products."
resource: https://github.com/cisagov/CSAF
tags: [news, vuln, batch, current]
provider: "CISA (CSAF repository)"
mode: batch
cadence: "every 2h"
trust_tier: A
auth: "none"
license: "Public domain (US Gov); CISA notification and privacy & use policy (https://www.cisa.gov/notification)"
in_app: on by default
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-19T20:00:00Z }
---

# Summary

CISA's advisories in CSAF 2.0, from `github.com/cisagov/CSAF` (branch `develop`, `csaf_files/{OT,IT,VA}/white/`). cisa.gov answers 403 to non-browser clients and the app never spoofs a User-Agent, so the old RSS feed was replaced by this machine-readable channel. Each advisory links to its cisa.gov page (ICS and ICS medical) or, for IT/VA advisories that have none, to the document on GitHub.

| | |
|---|---|
| Source id | `cisa_advisories` (class in `feeds.py`, CSAF code in `vulns.py`) |
| Event | kind `advisory`, category `news` (Newswire and article pipeline), key = CSAF tracking id (`ICSA-26-307-01`). The source itself is listed under Vulnerabilities on the Sources page |
| Mode | batch, every 2 h, windowed: advisories published or revised in the last 90 days |
| Trust tier | A |
| Access | none; raw.githubusercontent.com, unauthenticated |
| Status | on by default (it was off while it depended on cisa.gov). Older versions saved `enabled=false` for every default-off source at startup; a one-time flip (`scheduler.DEFAULT_FLIPS`) clears that saved flag once |

# Terms

Read 2026-11-19 ([cisagov/CSAF](https://github.com/cisagov/CSAF)): the repository has no LICENSE file; the advisories
are US Government work marked TLP:WHITE. CISA also "republishes CSAFs from vendor partners".

Commercial use: yes. Redistribution: yes. AI use: yes.

# Fetching

CSAF's directory distribution: each folder has `changes.csv` (path, last change, newest first; OT ~4,000 lines, 232 KB). A run fetches the three `changes.csv` files and downloads a document only when it is new in the window or its `changes.csv` time moved. Unchanged documents come from `<lake>/cache/csaf/` (gzipped, pruned when they leave the window). First run: ~190 documents (at most 300 a run, 4 at a time); later runs: 3 requests plus the new or revised advisories (2-3 a day). No GitHub API calls, so no API rate limit is involved.

A document that fails to download keeps its cached revision and the run is marked partly failed; a `changes.csv` that fails skips that folder; all three failing fails the run.

# Parsing and dedup

* One event per tracking id. Some VA advisories are in both `IT/` and `VA/`; the later `current_release_date` (then higher version) wins. Drafts are skipped.
* `ts` = `current_release_date`: a revision ("Update A") is news again. The summary says when it was first published. An update changes the same event (same id), never a second one.
* CVEs from `vulnerabilities[].cve` (validated), CVSS = the highest v4/v3/v2 base score per CVE, severity from it (else `aggregate_severity`); vendors and products from the product tree (`known_affected`/`first_affected`/`last_affected`), products collapsed to their family (vendor prefix, parentheticals, `model ...`/`series ...` suffixes and trailing model codes or years dropped: "MELSEC MX Controller MX-R model MXR300-16" -> "MELSEC MX Controller MX-R", "PowerSYSTEM Center 2024" -> "PowerSYSTEM Center"), at most 8 per CVE.
* Tags: `CISA`, the kind (`ICS advisory`, `ICS medical advisory`, `IT advisory`; never a bare `IT`, which tag readers take for Italy), up to 5 vendors, up to 20 CVEs, the vendor's HQ country code.
* `advisory_cves` table: one row per advisory and CVE (cvss, severity, cwe, vendors, products, title, kind, dates, url), kept after the advisory leaves the window.

# Linking

* **CVEs:** `/api/news/cves` lists the advisories covering each CVE and uses the advisory CVSS when NVD's 72-hour window has none (`cvss_status: "from CISA advisory"`). KEV, NVD and EPSS for the advisory's CVEs show in the event drawer.
* **Entities:** the linker mentions each CVE, vendor and product and adds observed `cve affects product` and `product made-by vendor` claims (as KEV does). Free-text IOC extraction is skipped for advisories.
* **News:** the event drawer lists news stories whose articles mention one of the advisory's CVEs or name its id, leaving out the advisory's own page (queued as an article from its news-category event). Newsroom coverage corroborates the advisory; the advisory remains one event. No news feed in the app carries CISA advisories as items, so there is nothing to collapse.
* **Newswire:** advisories appear as "CISA" with an Advisory tag and their highest CVSS.

Old RSS-era events (keyed by link, from before cisa.gov blocked the client) keep their ids; new events are keyed by tracking id.

# Storage

Measured on the scratch lake: 10 advisories = 23 KB of records (2.3 KB each, gzipped full CSAF document). With 2-3 new or revised advisories a day: ~0.01 MB/day lake, a few rows a day in DuckDB, ~1 MB document cache.
