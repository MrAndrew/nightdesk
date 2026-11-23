---
type: Data Architecture
title: Download and upload size limits
description: The byte cap on every source download, how it counts compressed responses, and the row and byte caps on a file added through the upload form.
tags: [data, sources, upload, security, limits]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-22T12:00:00Z }
---

# Source downloads

Every batch source reads its HTTP responses through `osinthub/sources/caps.py` (`caps.get()`, or
`caps.iter_decoded()` for the routing sources' `routing/net.py` and the article fetcher). The body is read in
chunks and counted **after decoding**: requests ask only for `gzip, deflate`, and the code inflates at most 64 KB
per step, so a gzip bomb (or gzip inside gzip) is stopped at the cap without being inflated whole. Any other
`Content-Encoding` is refused.

**Redirects are followed by hand** (`caps.open_final`): httpx's own redirect handling reads and inflates
every 3xx body before it follows it, so a gzip bomb in a redirect would slip past the cap. Every capped request
is sent with `follow_redirects=False`; a 3xx is closed with its body unread, and the next hop is built the way
httpx would (http and https only; for another origin, meaning another scheme, host or port except the plain
http:80 -> https:443 upgrade, every header that could carry a key is dropped, `Authorization` and `X-API-KEY`
included, keeping only Accept, Accept-Encoding, Accept-Language and User-Agent; POST becomes GET on 301/302/303), at
most 5 hops (`TooManyRedirects` after that). The cap applies to the final body. A source that asked for no
redirects (abuse.ch, EPSS's first request) gets the 3xx itself, unread. This covers the batch sources, the routing
sources and the reference files of [entities](/data/entities.md) (`entities/refdata.py`). Over the cap the download stops with a plain message, for example
"feodotracker.abuse.ch sent more than 1 MB (this source's size limit); stopped the download and stored nothing
from it". The run **fails**: nothing from that response is parsed or stored. A source that reads several feeds or
files in one run (the news feeds, CISA CSAF, RIPEstat) fails the whole run too, rather than storing the others and
leaving a gap unnoticed.

Each cap is about 4x the largest response the source has been measured to send (the per-run raw sizes measured on
2026-11-04 in `tools/okf_sources.py` and the [source pages](/sources/current/index.md)), rounded up, with a **1 MB
floor**: a small list can grow tenfold and 1 MB of memory is harmless. Where the provider decides the size, the cap
follows the largest answer it can send.

| Source | Largest measured response | Cap |
|---|---|---|
| `cisa_kev` | 1.8 MB | 8 MB |
| `nvd_recent` | 3.7 MB average; a full 2,000-result page is ~18 MB (~9 KB a CVE) | 32 MB |
| `feodo_c2` | 2 KB | 1 MB |
| `dshield_top` | 50 KB (500 rows) | 1 MB |
| `tor_exits` | 18 KB | 1 MB |
| `blocklist_de` | 369 KB | 2 MB |
| `cins_army` | 230 KB | 1 MB |
| `et_compromised` | 7 KB | 1 MB |
| `spamhaus_drop` | 108 KB | 2 MB |
| `ransomware_live` | 120 KB | 1 MB |
| `ioda_outages` | 265 KB (two requests) | 2 MB per request |
| `security_news` | 260 KB (four feeds) | 2 MB per feed |
| `cisa_advisories` | `changes.csv` 232 KB; one CSAF document ~20 KB | 2 MB per file |
| `epss` | 2.8 MB gzip file; the CSV inside is ~10 MB | 12 MB download, 64 MB once un-gzipped |
| `threatfox` | ~1 MB (estimate) | 4 MB |
| `urlhaus` | ~400 KB (estimate; 1,000 URLs) | 2 MB |
| `sslbl` | 844 KB | 4 MB |
| `rpki_roas` | ~5 MB compressed, about a million ROAs, ~75 MB decoded (estimate) | 300 MB |
| `cf_radar_bgp` | one page of events (not measured) | 4 MB per page |
| `ripestat` | one answer; a large network's neighbours are a few hundred KB (estimate) | 8 MB per answer |
| `news_therecord`, `news_securityweek`, `news_helpnetsecurity`, `news_cyberscoop`, `news_darkreading`, `news_unit42`, `news_eset` | 5 to 78 KB | 1 MB |
| `news_talos` | 1.0 MB | 5 MB |
| `news_mstic` | 494 KB | 2 MB |
| `news_elastic` | 8.4 MB (the whole blog in one feed) | 34 MB |
| reference files (`ref_attack`, `ref_misp_malpedia`, `ref_misp_actor`, `ref_misp_tool`, `ref_psl`, `ref_tlds`) | 55 MB, 3.8 MB, 1.5 MB, 543 KB, 339 KB, 10 KB (2026-11-05) | 224, 16, 6, 3, 2 and 1 MB |
| Tranco top-sites list (`ref_tranco`, online installs only; only its first 20,000 lines are unpacked) | 9.7 MB zip (2026-11-21) | 40 MB |

A source missing from the table gets 8 MB; a unit test (`tests/sources/test_v12_harden.py`) fails when a batch
source has no entry. The two live streams (RIS Live, Bluesky) are WebSocket messages and keep the websocket
library's 1 MiB per-message limit.

The [article fetcher](/data/news.md#fetching) reads at most 6 MB of an article and 512 KB of a robots.txt, through the
same bounded decoder.

# Uploads

`POST /api/upload` (Settings › Sources › Add your own file):

* **Byte cap 64 MB**, checked while the upload is copied into the lake (413 over it, the partial copy deleted).
  The check runs after Starlette has spooled the whole multipart body to a temporary file, so a larger POST is
  still written to disk once before it is refused (the general request-body cap of the auth lane exempts this
  route). 64 MB
  holds about 1.4 million rows of a typical indicator CSV (`ip,title,severity,country` is ~47 bytes a row) and a
  one-million-line IP list (~14 MB), so a real list meets the row cap, which says what was kept, before the byte cap.
* **Row cap 200,000.** The first 200,000 rows are kept; the rest are counted and left out, and the answer says so
  (`note`: "Kept the first 200,000 of 300,000 rows: one upload holds at most 200,000 rows. Split the file to add the
  rest."), shown under the result and in the toast. Rows past the cap are only counted: the parser still reads them
  (a CSV row from DuckDB, a JSON value decoded, an IP-list line matched) but builds no event for them, so a 63 MB
  file of tiny rows (3 to 5 million rows) takes 2 to 3 s to parse instead of 9 to 12 s (pre-public fix round,
  measured in-process: CSV 11.7 → 2.1 s, NDJSON 9.5 → 2.8 s, IP list 8.5 → 2.1 s, JSON array 9.0 → 2.5 s; the whole
  `/api/upload` on a scratch server, with the 200,000-event load: 13.5 → 3.0 s, 12.0 → 5.1 s, 9.1 → 3.6 s,
  18.1 → 6.0 s).
* **Streaming.** A CSV is read by DuckDB's sniffer and rows come out in batches of 5,000 (`fetchmany`, never
  `fetchall`), through an in-memory DuckDB that may read that one file and nothing else (`allowed_paths`, external
  access off, no extension download, settings locked; 512 MB memory, 2 threads, spilling into its own folder under the
  lake's `tmp/duckdb-upload`, removed afterwards). JSON (`.json`, `.ndjson`, `.jsonl`) is read with the standard
  library's decoder 1 MB at a time: the elements of the top-level array (white space before the `[` is skipped 1 MB at
  a time, however much there is; only white space may follow the `]`), or a sequence of values (one object, NDJSON,
  JSONL, pretty-printed objects), each line parsed once; in a sequence a line that is not valid JSON is skipped. A
  file that cannot be read is refused (400) with the reason as the answer's `detail`, shown in the upload form and the
  toast: an array that is never closed ("… the final ] is missing"), an array that is not valid JSON, an array
  followed by anything but white space, a second array too (`[..][..]`, or NDJSON whose lines are arrays: "This file
  has more after the closing ] of its JSON array. Upload one JSON array of rows, or one JSON object per line
  (NDJSON)."), or a file with no valid value ("This file is not valid JSON."). Each case is linear in the file's size:
  63 MB of `[]` pairs is refused at once, 63 MB of white space after an array reads in 0.1 s, and one array of 33
  million numbers (200,000 kept, the rest counted) in 8 s. An IP list is read line by line. Each row becomes an event
  and is written to the events file straight away, so the parse holds one batch.
  The events then load into DuckDB 20,000 at a time (`upload.load_in_parts`): one 200,000-row insert took ~600 MB
  of memory, 20,000-row parts ~20 MB each.
* **Measured** (scratch server, fresh for each file, 300,000 rows of documentation-range addresses, 200,000 kept):

  | File | Before (v1.2) | Now |
  |---|---|---|
  | CSV, 13.4 MB | 219 → 1,180 MB peak (+961 MB), 1,086 MB after | 210 → 401 MB peak (+191 MB), 394 MB after |
  | JSON array, 27.7 MB | (v1.2 parsed it whole: 537 MB peak in-process, evaluator) | 211 → 398 MB peak (+187 MB), 390 MB after |
  | NDJSON, 27.4 MB | | 212 → 401 MB peak (+189 MB), 387 MB after |

  The parse itself stays flat (+6 MB in-process for the JSON array); what remains is DuckDB loading 200,000 events.
* The answer is `{rows, geolocated, kept, total, file, note?}`; `file` is the copy's place in the lake
  (`uploads/YYYY/MM/DD/HHMMSS-<name>`), never an absolute path.
