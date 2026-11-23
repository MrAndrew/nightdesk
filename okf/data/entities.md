---
type: Data Model
title: Entities and claims
description: The attribution layer - entity, mention and claim tables, reference data (ATT&CK, MISP), IOC and LLM extraction, event linking, confidence scoring, inferred links, user merges and retypes, disagreements and the review queue, and the /api/entities endpoints.
tags: [data, entities, claims, attribution, extraction, duckdb]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-20T03:00:00Z }
---

# Overview

The `osinthub/entities/` package turns what the hub already collects (events, articles, network logs) into **entities** (an IP, a CVE, an actor, a malware family) and **claims** about them ("APT28 uses X-Agent", "this IP hosts QakBot C2"). Every claim keeps its origin, its sources and its evidence, so an analyst can see *why* the hub believes something and how strongly.

Everything runs offline. Reference data is cached in the lake, linking and scoring use only DuckDB, and the LLM step is optional: without the [local AI helper](/architecture/local-ai.md) extraction returns its deterministic part.

| Module | Role |
|---|---|
| `normalize.py` | Entity types, claim origins, ids and name keys, generic-word lists. |
| `refdata.py` | Downloads and loads ATT&CK and MISP galaxies; alias index and technique names. Downloads are capped per file and follow redirects by hand ([size limits](/data/size-limits.md)). |
| `iocs.py` | Deterministic IOC extraction with refanging and precision filters. |
| `extract.py` | `extract(text, url=None, use_llm=True)`: IOCs plus LLM entities, techniques and claims. |
| `techcues.py` | Artefact cues for ATT&CK techniques (works offline). |
| `defender.py` | Finds defender text (hunting, detection and mitigation sections, query code, analyst procedure) that technique extraction skips. |
| `link.py` | Event linking (background), IP-in-prefix claims, reference import. |
| `ingest.py` | `ingest_text(ref_type, ref_id, text, url, source_tier)`, the hook the news package calls per article. |
| `scoring.py` | Claim confidence, user feedback, inferred campaign-to-actor links. |
| `overrides.py` | User identity overrides: "Same as…" merges, "Wrong type…" retypes, "Not the same", duplicate suggestions; Undo. |
| `api.py`, `searcher.py` | `/api/entities/…` and the `entity` type for [semantic search](/architecture/local-ai.md#search). |
| `store.py`, `ext.py` | Tables and batch writes; registration with the [extension registry](/architecture/system.md#extensions). |

# Tables

| Table | Columns | Notes |
|---|---|---|
| `entities` | `id`, `type`, `name`, `aliases[]`, `attrs` JSON, `first_seen`, `last_seen` | `id` = `type:normalised`, e.g. `ip:203.0.113.7`, `cve:cve-2024-3400`, `asn:as13335`, `actor:apt28`, `technique:T1059.001`, `product:ivanti-connect-secure`. Seen times are widened by every mention. |
| `mentions` | `entity_id`, `ref_type`, `ref_id`, `role`, `method`, `confidence`, `ts` | Where an entity appears. `ref_type` is `event`, `article` or another caller's type. `method` is `field`, `tag`, `regex`, `alias`, `llm` or `geoip`. Unique on `(entity_id, ref_type, ref_id, role)`. |
| `claims` | `id`, `subj`, `predicate`, `obj`, `origin`, `sources[]`, `confidence`, `first_seen`, `last_seen`, `evidence` JSON | One row per (subject, predicate, object, origin); `id` = sha1 of those four. Evidence holds up to 25 items with source, tier, quote, URL, reference and time. |
| `entity_linked` | `ref_type`, `ref_id`, `hash`, `linked_at` | Which events have been linked, by content hash, so changed events are relinked and unchanged ones skipped. |
| `entity_dirty` | `id`, `since` | Actors, campaigns, malware and tools touched since the last scoring pass. |
| `entity_vec` | `id`, `h`, `embedded_at` | Which entity texts are in the `entities` vector collection. |
| `entity_overrides` | `id`, `action`, `src`, `dst`, `note`, `created_at`, `snapshot` JSON | The user's identity changes: `merge` (src joined dst), `retype` (src is now dst, the same name under another type), `distinct` (the pair src/dst, sorted, is "not the same"). A merge's snapshot holds what moved, for Undo. See [Overrides](#overrides). |

**No primary keys or indexes, on purpose.** DuckDB's ART indexes can drift out of step with the rows on tables that get UPDATEs and DELETEs. Any later delete of an affected row then fails with "Failed to delete all rows from index. Only deleted 0 out of 473 rows". That error is FATAL and invalidates the whole database until restart, and the corrupt index persists in the file. Instead:

* Uniqueness on each table's key is kept by the writers: one re-entrant lock, one transaction per write, UPDATE for existing keys and an anti-join INSERT for new ones.
* On startup, `store.drop_indexes()` rebuilds any entity table that still has a primary key or an index as a plain table, one row per key. This lets lakes created with the old schema start, and repairs an index that is already corrupt.
* The tables are small (about 33,000 entities, 110,000 mentions and 10,000 claims on the seed), so zone maps and scans keep `/api/entities/{id}` at about 20 ms.
* The `benign_check.py` seeding tool (now in `tests/eval/netlog/`) uses `INSERT OR REPLACE INTO mentions`, which needs a key; it has to switch to a plain insert.

**Types:** ip, prefix, asn, domain, url, hash, cve, product, vendor, malware, actor, campaign, technique, tool, sector, country, org, device.

**Origins:**

| Origin | Meaning | Examples |
|---|---|---|
| `observed` | Seen directly in a data feed | `prefix announced-by asn` (RIS Live), `ip hosts-malware` (Feodo), `cve affects product` (KEV), `ip in-prefix prefix` |
| `reported` | Someone said it, with the source named | ATT&CK and MISP relations; LLM claims from articles, each with a verified quote |
| `inferred` | Computed by the hub: a **hypothesis** | `campaign attributed-to actor` from shared features |
| `user` | An analyst's verdict on a triple, not a claim of its own | Feedback on any claim (see [Verdicts](#verdicts)) |
| `local` | Seen on the user's own network ("Seen on your network") | Reserved for network-log sightings |

Two kinds of link are **hypotheses**, links the hub computed rather than ones a source stated: `inferred` claims, and co-mentions (two entities named in the same article or report; the API's `co-mention` origin, label "Mentioned in the same article", never stored as a claim). The UI labels them "Hypothesis", keeps them out of claim counts, and hides them from Related and the graph until the user turns on "Show hypotheses". Co-mentions are never called "local": that word is reserved for the user's own network data.

# Reference data

Downloaded once into `<lake>/ref/`, with the honest User-Agent, and never again while the files exist. With `OSINTHUB_OFFLINE=1` or no network the cached copies are used; if they are missing, extraction still works with a built-in TLD fallback.

| File | Source | Licence |
|---|---|---|
| `enterprise-attack.json` | MITRE ATT&CK Enterprise STIX 2.1 (attack-stix-data) | ATT&CK terms of use |
| `misp-threat-actor.json`, `misp-malpedia.json`, `misp-tool.json` | MISP galaxy clusters | CC0 / BSD-2 |
| `public_suffix_list.dat`, `tlds-alpha-by-domain.txt` | Public Suffix List, IANA TLD list | MPL 2.0, public |

Loaded on startup (about 0.5 s) into a catalogue of about 6,100 entities: 1,120 actors, 3,970 malware, 430 tools, 57 campaigns and 706 techniques, with 7,950 reported relations.

* **Actors** get every alias: ATT&CK `aliases` and group id, MISP `synonyms` and the names in MISP `name-attribution`. A MISP cluster joins an ATT&CK entity only on an exact canonical name, or when its synonyms hold exactly one ATT&CK id that maps to exactly one entity. Otherwise it stays separate, so Lazarus Group and APT38 are not merged although MISP lists one as a synonym of the other.
* **Malware and tools** get ATT&CK `x_mitre_aliases` and MISP synonyms. Platform suffixes such as "LockBit (Windows)" are folded into one family. Generic synonyms ("RAT", "Agent") are not used as aliases.
* **Techniques** keep their name and their full "Parent: Sub" name, both mapped to the id.
* **Relations:** ATT&CK `uses` (actor or campaign to malware, tool or technique) and `attributed-to` (campaign to actor), MISP threat-actor `uses`, and MISP `country` as `actor attributed-to country`. All are `reported` claims with the source named.

**Alias resolution** (`Catalog.resolve`):

1. Exact match on a lookup key (lowercase letters and digits only, so "APT 28" = "APT-28" = "apt28").
2. Exact match after removing generic edge words ("the Lazarus group", "LockBit ransomware", "Cobalt Strike Beacon").
3. Careful fuzzy matching: difflib ratio ≥ 0.88 on the key, the digits must be identical (APT28 never becomes APT29), the specific part of the name must also match at ≥ 0.88, and the generic words must be the same set. Naming-scheme words (Bear, Panda, Kitten, Spider, Typhoon, Blizzard, Sleet…) count as generic, so "Venomous Bear" and "Fancy Bear" can never meet on "Bear".
4. Canonical names win ties; otherwise the better-documented cluster wins.

# Extraction

`extract(text, url=None, use_llm=True)` returns the contract shape `{iocs, techniques, actors, malware, claims}` plus `campaigns`, `victims`, `sectors`, `countries`, `tools` and `technique_quotes`.

**Deterministic part** (`iocs.py`, always runs):

* **Refanging:** `hxxp`/`hxxps`/`h**p`, `fxp`, `[.]`, `(.)`, `{.}`, `[dot]`, `\.`, `[:]`, `[://]`, `[@]`, zero-width characters and Unicode dashes.
* **IPv4 and IPv6:** public addresses only. Version numbers are rejected:
  * by a cue before them ("version", "v", "build", "KB", "SDK", "firmware", "fixed in", "prior to", "Chrome", "kernel" …);
  * by a cue after them ("and later", "or earlier");
  * when they are part of a longer dotted sequence (OIDs, `10.0.19041.1`);
  * when every octet is ≤ 31 (`8.0.5.2`) and nothing suggests an indicator: no defanging and no IOC section in the text, and no C2, IP, address, connect, server or DNS cue within 80 characters.
* **Domains:** the TLD must be in the cached IANA list. Without defanging, a name is rejected when its TLD or an inner label is a file extension (`invoice.pdf.exe`, `run.ps1`, `README.md`, `update.zip`), when it is mixed-case (`ASP.NET`, `System.Net`), an all-caps abbreviation, a bare public suffix, followed by `(` or `=` (code), or belongs to the report's own site (eTLD+1 via the Public Suffix List), a share link, a CDN or asset host (`cdn.`, `static.`…), a reference site (MITRE, NVD, VirusTotal, detection.fyi…) or a big platform. Anything the author defanged is kept: defanging marks a deliberate indicator.
* **URLs** follow the same host rules; trailing punctuation and unbalanced brackets are trimmed.
* **Hashes:** MD5, SHA-1, SHA-256 as standalone hex runs, not all-letters or all-digits. **CVEs** with any dash.
* **Techniques:** explicit ATT&CK ids present in the catalogue, plus `techcues.py`: about 70 high-precision cues that name a concrete artefact implying one technique on its own (`schtasks` → T1053.005, `rundll32` → T1218.011, `nltest … domain_trusts` → T1482, `vssadmin` → T1490, AnyDesk or ScreenConnect → T1219, rclone → T1567.002). Each hit keeps its sentence as the quote. The cues read the text with [defender text](#defender-text) blanked.
* **Known names:** actors, malware and tools spotted by their reference aliases, case-sensitively, whole-word; ordinary-word aliases ("Covenant", "Agent") are skipped, and single-word aliases need two mentions unless they contain digits or several capitals.

**LLM part** (`use_llm=True` and the helper up): the text is split into ~9,000-character chunks on paragraph breaks with 400 characters of overlap. Each chunk is one `osinthub.ai.client.chat` call with a JSON schema, temperature 0 and thinking off. The prompt asks for names exactly as written, ATT&CK techniques the attackers performed (with their official name and a 5-25 word verbatim quote), and up to 8 claims between named entities, each with a verbatim quote.

* **Quote verification:** each quote is looked up in the source after whitespace normalisation; a loose pass (curly quotes, dashes, case) is allowed only to *locate* the span, and the stored quote is then the exact source text. Claims and techniques whose quote is not found are dropped and counted in `LAST_STATS["dropped_unverified"]`.
* **Techniques** are mapped by official or former name through the catalogue ("Spearphishing Attachment" → T1566.001, "Network Service Scanning" → T1046). A parent name with one of its sub-technique ids gives the sub-technique; the model's id alone is used only for names the catalogue doesn't know, and never for a bare tactic name.
* **Names** go through alias resolution; a name must occur in the text, or the model's value is dropped. Unknown tools stay in `tools` only.
* **Placeholders** ("unknown threat actor", "the attackers", "Chinese hackers", "new backdoor": names made only of generic or descriptive words) are never entities; any created earlier are removed on startup with their mentions and claims.
* **Actors:** a name the model calls an actor stays an `actor` only if it is a known ATT&CK or MISP threat actor, or if the text attributes malicious activity to it (a sentence naming it, or a verified claim with it as subject, uses words like attack, compromise, deploy, exploit or target). Otherwise it goes to `orgs` and is stored as an `org` at confidence 0.3; this catches proxy services and vendors such as Honeygain or Oxylabs. Unit tests: `tests/entities/test_extract.py` (with a small ATT&CK/MISP fixture in `tests/entities/fixtures/ref/`, so they need no lake reference data).
* **Appendix chunks** (mostly hashes, addresses and URLs, or 12+ technique ids) are not sent to the model; the deterministic pass covers them.
* **Procedure-example gate** (`procvec.py`): ATT&CK's 17,636 procedure examples (real report sentences in `uses` relationships, each labelled with a technique) are embedded once into the `techniques` vector collection and `<lake>/cache/procedures.npz`.
  * A technique the model or a cue proposes passes if one of its evidence sentences has at least 4 of its 20 nearest examples at cosine ≥ 0.55 in the technique's family.
  * A sentence proposes a technique when 5 of its 10 nearest examples at cosine ≥ 0.725 agree on one.
  * `calibrate_procvec.py` (a lab script kept in the development repo) set these thresholds on 10% held-out procedure examples, never on the eval: verification TPR 0.60, false accepts 0.17 on hard negatives and 0.002 on random ones; proposal precision 0.905 at 29% coverage.
* **Cache:** answers are cached per chunk in `<lake>/cache/entities-llm/`, keyed by the prompt and the chunk text, so re-ingesting a text or a syndicated copy costs nothing.

With `use_llm=False`, or when the first chunk gets no answer, the deterministic result is returned.

**Measured** with `tests/eval/score_extraction.py` (27 vendor reports, 2026-11-05; the 2026-11-18/19 re-run gave the
same scores, with 603 claims instead of 602, and its saved outputs were re-scored on 2026-11-19 against the
re-adjudicated technique gold). Technique rows are after the [defender text](#defender-text) filter (2026-11-19 full
run of v1.2; the model's per-chunk answers are unchanged by the filter, which only acts after them); the figures
before it are in brackets:

| Metric | Without LLM | With LLM | Bar |
|---|---|---|---|
| IOC precision / recall (full page) | 0.975 / 0.998 | 0.975 / 0.998 | ≥ 0.95 / ≥ 0.90 |
| Technique precision / recall (body, confirmed tier), **described in the body** | 0.915 / 0.376 (0.896) | 0.939 / 0.560 (0.910) | ≥ 0.70 / ≥ 0.50 |
| … recall over the vendor's table entries alone | 0.397 | 0.531 | |
| Technique precision / recall, **vendor table** (the old measure, no bar now) | 0.732 / 0.341 | 0.674 / 0.450 | |
| Reports with all actors and malware found | 0.636 | 0.864 | ≥ 0.85 |
| Claims with a quote not in the text | 0 | 0 of 603 | 0 |

"Described in the body" scores against `gold.techniques_body` in `tests/eval/reports.jsonl`: the vendor's ids that
the body actually describes, plus the techniques the extractor proposed that the body supports and the vendor
table leaves out (164, each with a quote), with ids revoked in ATT&CK v20.1 mapped to their replacements and the 18
Mobile ids scored apart (found 0 times; the extractor emits Enterprise ids only). It is built by
`attack_gold.py` (a lab script kept in the development repo) from a step-1 audit; method, bias and per-vendor numbers are in `tests/eval/README.md`
("ATT&CK re-adjudication"). Read the body numbers with its bias in mind (see [Known limits](#known-limits)): the
additions were taken from the LLM run being scored, the audit was done by a Claude agent, not by the owner, and
the `--no-llm` precision is a lower bound (23 of its predictions were never adjudicated and count as wrong).

**Two technique tiers.** A false technique link hurts attribution more than a missed one, so precision wins:

* **Confirmed** (`techniques`): explicit ids, cue-plus-model agreement, and techniques that pass the procedure-example gate, plus the gate's own proposals. Only these feed claim scoring and inferred links.
* **Suggested** (`suggested_techniques`): every other model technique with a verified quote. `ingest_text` stores each as a `uses` claim whose evidence carries `"suggested": true`. Scoring caps such claims at 0.15, inference ignores them, and the entity API marks them `suggested` so the UI can show them apart.

With the LLM on, the confirmed tier meets both technique bars on the "described in the body" measure and misses both on
the vendor table; the suggested tier is not scored. See [Known limits](#known-limits).

## Defender text

Vendor reports also address defenders: Microsoft posts end with mitigation advice, detection-coverage tables and
"Advanced hunting" KQL queries, and analysts write "To deobfuscate the command line, it's necessary to …". Those
sentences read like procedure examples, so before 2026-11-19 they produced techniques (the audit's category D: 8 of 11
were procedure-example proposals on Microsoft hunting and advice text, 3 were cues on analyst sentences).
`defender.py` finds such text conservatively, and technique extraction skips it:

A wrong drop costs a real technique and a missed drop costs one false positive, so the rules are few and fixed
(owner, 2026-11-19: after two evaluator rounds kept finding edge cases in cleverer rules, keep it simple):

* **Sections** open only on a real heading line (a bare short line or a Markdown heading, never a list item or a
  numbered entry) from a fixed list, and only when a sentence, code or a rule listing follows within its next three
  non-empty lines, so a site menu or table of contents listing "Detections" does not. End-of-report sections (Advanced hunting, Hunting queries, Mitigation and
  protection guidance and other "… guidance" headings, Microsoft Defender XDR detections, Actionable investigation
  methods, YARA / Sigma rules) run to a reset heading (MITRE ATT&CK…, Indicators / IoCs, References, Appendix,
  Summary, Conclusion, Outlook, Key findings, an ATT&CK tactic name) or the end of the text; their sub-headings
  (Immediate actions, Security Copilot, a hunting query's title) do not end them. Other defender headings
  (Detections, Mitigations, Recommendations, Protection and mitigation, Detection and response, Remediation,
  Prevention) end at the next heading (here a lower-case start or a question counts too) whose first line is text:
  not another heading, code or a rule-listing line (an IDS signature name such as `ET POLICY …`, a bare rule-repo
  URL, a short line naming a rule by its id, a YARA comment). "Sigma" / "YARA" sub-headings keep them open.
* **Query code** anywhere: a KQL or SPL block (consecutive lines that must include a table line such as
  `DeviceProcessEvents` or a `| where`-style pipe line; Markdown table rows, which is how trafilatura writes HTML
  tables, never count), a YARA rule (`rule … {` … `condition:` … `}`) and only the YAML block around a Sigma
  `detection:` / `logsource:` line (linear time, also for thousands of rules).
* **Analyst procedure** anywhere: only the shapes the 2026-11-19 audit found: "To deobfuscate …, it's necessary to",
  "… decoded using this / the following CyberChef recipe", "Once deobfuscated, we can see / spot", "deobfuscated and
  refactored for readability". Sentences split at every sentence end (also "。"), so such a sentence never takes the
  next one with it.
* **Not masked, by design:** advice sentences outside a defender section ("Organizations should …", "Use Microsoft
  Defender …" in the narrative) and defender headings not on the lists.

The cues read a copy of the text with these spans blanked (same length and line breaks, so quotes stay verbatim); the
procedure-example gate does not let mostly-defender sentences propose a technique; and a model technique whose only
verified quote lies in defender text is dropped (`LAST_STATS["dropped_defender"]`; `LAST_STATS["defender_chars"]`
counts the blanked characters). Explicit technique ids, IOCs, actor and malware spotting and the model's input are
unchanged, so the per-chunk model cache stays valid. `python -m osinthub.entities.defender FILE --cut MARKER -v`
prints what would be removed and why (it warns when the `--cut` marker is missing). On the 27 eval reports the simplified
rules mask the same characters as the first version, except three "Organizations should" sentences and Microsoft's
"Learn more … Microsoft Defender" footer lines, which are no longer masked; `--no-llm` scores are identical. On the 27 eval bodies the filter removes 28-50% of the five Microsoft bodies
(everything from "Mitigation and protection guidance" or "Actionable investigation methods" to the ATT&CK table), 11%
of the Recorded Future body (its Mitigations section and one "Organizations should" sentence), under 4% of three
DFIR bodies and one ESET body (analyst sentences only) and nothing from the other 17. `--no-llm`, body precision went from 0.896 (249/278) to 0.915
(249/272) with recall unchanged (256/680): six wrong techniques gone, none lost. With the model (full run of v1.2,
2026-11-19) body precision went from 0.910 (386/424) to 0.939 (386/411) with recall unchanged (381/680): 13 wrong
confirmed techniques gone, none lost; Microsoft 0.733 → 0.917, DFIR 0.950 → 0.959, ESET 0.906 → 0.912, Recorded
Future 0.900 → 1.000. One known cost: three body techniques that the audited model run put in the suggested tier
only from a Defender coverage table's "Observed activity" cell (fake-download T1055, cursor-extension T1059 and
T1036) are dropped with that table. Unit tests: `tests/entities/test_v12_attackdefender.py`, including the round-1
evaluator's attacker texts.

## Technique labels

Because both tiers are often wrong, the UI never shows a technique read from article text as a plain fact. The same
three labels (`web/js/core/ttp.js`), most certain first, are used on the News story and article pages (the technique
block, the story's actors table, the article's reported relationships), the phone story's Techniques section, Copy
summary, the entity side panel's reported claims, the Intel entity page (ATT&CK strip and claim rows, also on a
technique's own page), the `attack-technique` glossary term and Help:

| Label | When | Exports |
|---|---|---|
| **Named in the article** | The article text prints the ATT&CK id itself (`T1566.001`); on a stored link, a quote that holds the id | Navigator score 85, comment "Named in the article"; STIX `confidence` 85 |
| **Likely** | The confirmed tier: a mention with role `technique` (cue or model agreement, or the procedure-example gate) | Navigator score 50, comment "Likely — found automatically"; STIX `confidence` 50 and a "can be wrong" description |
| **Possible** | The suggested tier only (role `technique-suggested`, evidence `"suggested": true`) | Left out of the Navigator layer, STIX and MISP, and out of the entity brief; drawn dashed |

The block's header reads "Techniques read from this article" (or "these articles"), with the caveat "Found
automatically from the text. They can be wrong; check the sentence each one came from." and "Click or tap one
to see the sentence it came from." Primary text never uses the tier names (confirmed tier, suggested, procvec). In
relationship lists and claim rows the label is a small button (`ttp-tag`). Clicking or tapping a technique's quote
button or label (the whole chip on a phone), or an ATT&CK strip cell, shows a card with its label, what the label
means, the sentence it was read from, the outlet and links to the technique's page and MITRE. The card is kept simple
on purpose (owner decision 2026-11-19): it never opens on hover or focus, opens inside the visible area below the app
header, and closes on Esc, a second click, a click elsewhere, any scroll, a resize or a page change; it does not follow
a scroll. Esc closes only the card and returns focus to what opened it: the card sits on the app's overlay stack
(`core/page.js`) while shown, so it closes before the entity side panel or the story pane under it. The card's
listeners are installed when `core/ttp.js` loads, so a technique page opened straight from a link works. The sentence is the
one around the printed id for a named technique (a sentence over 400 characters is cut to a window around the id, with
an ellipsis on each cut side, so the id always shows), else the quote ingest keeps on the technique's `uses` claim; a
technique found with no actor or malware named has no claim, so the card says "No sentence was kept for this one".
`GET /api/news/intel` returns this list as `techniques` (read-only; no extraction logic). Story cards in the News stream
show only a neutral count ("4 techniques"), since a card cannot carry the labels.

**Catalogue links win.** A link MITRE's catalogue states (any `ref_type: reference` evidence, such as "APT28 uses
T1566.001"), a feed fact or the analyst's own link is not a guess from an article. Articles that report it too merge
into the same claim row (claims are keyed by subject, predicate, object and origin), so its evidence is mixed and it is
not `authoritative`; the API's `catalogue` flag (on `/api/entities/{id}` claims and `/api/news/intel` claims) marks it.
Such a link keeps "confirmed", solid, with no label and no evidence card, and Navigator score 100; article reports only
add "also in N articles", where N is the API's `article_count` (distinct articles over all of the claim's stored
evidence, not the few items a page fetches). The labels apply only when all of a link's evidence is article extraction.
The entity brief leaves possible links out, and on a technique's page words each link by its own evidence: catalogue
links as facts ("Used by APT28."), links read from articles in a sentence of their own ("Used by ExampleRAT (read
automatically from articles; it can be wrong)."), never mixed in one sentence.

**Speed:** LLM time averaged 228 s per report (107-468 s) for the scorer's two calls (full page and body), with the 27B model shared with other jobs: about 1-2 minutes per 9,000-character chunk. That is acceptable for background ingestion. The mixture-of-experts model `mlx-community/Qwen3.6-35B-A3B-8bit` (already in the Hugging Face cache, about 3B active parameters) would be several times faster for this job; the shared helper's model was not swapped. Appendix chunks are skipped and answers are cached per chunk; the procedure-example check adds a few seconds of embeddings per report.

# Linking

A background task (`link_loop`) runs every 60 s:

1. **Reference import** on first start, or when a reference file changes: catalogue entities and their reported claims.
2. **Events:** every event not yet in `entity_linked`, or whose content hash changed, in batches of 5,000. The first pass backfills the seed history (36,854 events in about 2.5 s).
   * `ip`, `asn` and `country` columns become entities and mentions (not for Spamhaus and RIS Live, whose `ip` is a synthetic first host). Tor exit IPs get `attrs.tor`.
   * KEV and NVD events give CVEs. KEV raw records (replayed from `raw/cisa_kev/*.records.ndjson.gz`) add vendor and product entities, `cve affects product` and `product made-by vendor`, and KEV attributes on the CVE.
   * CISA CSAF advisories (`cisa_advisories`, rows from the `advisory_cves` table) give a mention of each CVE, vendor and product they cover, and observed `cve affects product` and `product made-by vendor` claims (products collapsed to their family, so model numbers and editions are one product; at most 8 per CVE). Their text is not run through IOC extraction, and their tags are not resolved as malware or actor names.
   * EPSS makes no events and no mentions (a score is not a sighting; `purge_epss_events()` removes any an earlier build made, and the linker ignores source `epss`). A CVE entity's page reads EPSS and CISA advisories live (`attrs.epss`, `epss_percentile`, `epss_date`, `epss_since`, `epss_prev`, `epss_status`, `advisories`, and `cvss` from an advisory when NVD has none), so they are never stale.
   * Feodo events give `ip hosts-malware family`, with port and status from the raw record.
   * abuse.ch events (records replayed from `raw/<source>/*.records.ndjson.gz`, cached per file): ThreatFox gives the IOC entity (ip, domain, URL with its domain, or hash) and an observed claim to its family: `hosts-malware` for C2, `delivers` for payload delivery, `indicates` for a sample hash. URLhaus gives URL and domain entities that `deliver` a family, only when one of its tags resolves through the catalogue. The family resolves through ThreatFox's Malpedia id (`win.dridex`, indexed from the MISP Malpedia galaxy's `refs`), then the name and aliases through the catalogue. Unknown ThreatFox families become new malware entities with `attrs.ai_excluded` (never embedded). The family is not mentioned once per IOC (mention counts rank the directory; the claims carry the link), and the same triple from Feodo and ThreatFox is one claim with both sources, so it scores high. Their free-text tags are not resolved as names.
   * SSLBL certificates are indicators, not activity: no entity, mention or claim per certificate. Its events are one summary per family; one that resolves through the catalogue gets `attrs.sslbl_certificates` and `attrs.sslbl_last_listed` and one mention. Unknown names ("Malware distribution", "doxbin.cy") make nothing.
   * Spamhaus DROP and BGP events give prefixes; BGP origin changes give `prefix announced-by asn` for the old and the new origin.
   * Tags: `org:` owners, country codes, and tags that are a known malware or actor name.
   * News and social text: IOCs and known names.
3. **IP in prefix:** each IP inside a known prefix gets `ip in-prefix prefix` (new pairs only).
4. **Scoring** of new or changed claims and, if any actor, campaign, malware or tool changed, re-inference.
5. **Embeddings** of named entities into the `entities` collection, 64 at a time, when the helper is up.

**Text ingest:** `osinthub.entities.ingest_text(ref_type, ref_id, text, url, source_tier)` runs `extract()` and stores mentions for every IOC, actor, malware, campaign, sector, country, victim and technique, and a `reported` claim per verified LLM claim (plus `actor uses technique` with the technique's quote). Evidence carries the publisher, its tier, the URL, the quote and, for articles, the story id. It blocks on the LLM; the news package calls it from a worker.

# Scoring

**Reported and observed confidence.** Evidence items are grouped into independent sources. Items with the same publisher or the same quote (a syndicated copy) are one source, at the best tier among them. Different outlets in one news story cluster count separately. A source is *model-extracted* when all its items came from the LLM (`method: llm`). The band follows explicit rules:

| Band | Value range | When |
|---|---|---|
| high | 0.65-0.97 | Two or more independent tier-A/B sources, or a matching `observed` claim corroborates it |
| moderate | 0.35-0.64 | One curated (not model-extracted) tier-A/B source, two or more tier-C sources, or one model-extracted A/B source plus any other source |
| low | 0.10-0.34 | Anything else: one tier-C/D source, or a single model-extracted article |

Within a band the value rises with the noisy-OR of the tier weights (A=3, B=2, C=1, D=0.5; `p = w / (w + 3)`), so more and better sources still rank higher. The entity API returns the numeric `confidence`, its `band`, and a `why` such as "2 sources: A, B", "1 source: B (model-extracted)" or "…; corroborated by an observed claim".

When the scale changes (`SCORING_VERSION`), every observed and reported claim is rescored and every inferred link recomputed once on startup.

**Authoritative rows.** A claim is `authoritative` (API field) when it is an `observed` feed fact (CISA KEV, NVD, threat lists, routing) or a `reported` claim whose every evidence item is a reference listing (`ref_type: reference`: MITRE ATT&CK, MISP galaxy). The entity page shows "reference" on these rows and no Disagree… action: there is nothing for the analyst to judge.

<a id="verdicts"></a>**Verdicts (user feedback).** `POST /api/entities/claims/{id}/feedback` with `{"verdict": "confirm"|"reject"|"clear", "note"}` records a verdict on the claim's triple (subject, predicate, object). It is stored as one `user` row per triple whose evidence is the verdict history, latest last (at most 25 kept, the newest). `clear` (Undo) deletes that row. A verdict **annotates** the claims of its triple; it is never a claim of its own in any count:

* **Confirm:** the triple's claims rise to at least 0.95; the entity API returns the original row with `verdict: "confirm"` (and `verdict_note`, `verdict_ts`), shown as "You confirmed". No second link appears in Related, the graph or the counts. A confirm whose original claim no longer exists is listed once under `user` ("Your links"). A confirmed hypothesis (inferred link) is no longer a hypothesis: it is listed under `user` and counts there, unless a source also states the same triple, in which case that sourced row (also marked confirmed) is the only row.
* **Reject:** the claims fall to a tenth and stop feeding inference. The triple leaves `claims`, `claim_counts`, `related`, the graph and the directory's claim counts, and is listed once in the entity's `rejected` (shown collapsed as "You disagreed (n)" with Undo). The rejected pair does not come back as a hypothesis either: no `related_hypotheses` entry and no same-article graph edge for it.
* Verdict rows written before v1.1 (the same `user` rows) are read the same way, so old rejects disappear from Related instead of counting twice.

<a id="disagree"></a>**Disagree.** The entity page offers one action on claim rows a person can judge (reported claims and hypotheses; never reference listings or feed facts): **Disagree…**, with a reason: `wrong-link` (not connected like this), `wrong-type` (one end is the wrong kind of thing; the dialog links to both ends' **Wrong type…**), `outdated` (true once, not now) or `other` (the UI requires a note). It posts `{"verdict": "reject", "reason", "note"}`; the reason is stored on the verdict item, returned as `verdict_reason` on the claim (and on `rejected` rows), and the reject semantics above apply unchanged. A reason with any other verdict, or an unknown reason, is a 400. The per-row ✓/✕ buttons are gone; "This one" (a confirm) remains only where sources disagree (Contested on the page, and the Review queue). Confirms made before v1.1 still read "You agreed" with Undo.

The SQL used for counts is `api.COUNTED_SQL`: distinct triples, minus rejected ones (`api.REJECTED_SQL`, the latest verdict per `user` row), minus inferred ones.

**Inferred links (campaign → actor).** Features of an actor or campaign are what claims tie to it (malware, tools, techniques, IPs, domains, URLs, hashes, CVEs) and, at half weight, IOCs and names co-mentioned in the same article. For each campaign and each actor sharing a feature:

* `weight = type weight × IDF × commodity × decay`
  * Type weights: hash 1.6, domain and URL 1.3, IP and malware 1.0, prefix 0.6, CVE 0.5, tool 0.35, technique 0.12, ASN 0.1.
  * IDF = `ln(1 + N / df)`, where df is how many actors and campaigns hold the feature.
  * Commodity: Tor IPs ×0.05, cloud and CDN ASNs ×0.15, common tools (Cobalt Strike, Mimikatz, PsExec, AdFind, rclone, AnyDesk…) ×0.2.
  * Decay `0.5^(gap / half-life)` over the time between the two sightings. Half-lives: IP 30 days, URL 60, domain 120, hash and CVE 365, tool 540, malware 730, technique 1,095.
* Within a type, the k-th feature counts 1/k. Techniques are capped at 1.2 in total and tools at 1.0, so behaviour alone can't make a strong link.
* Score `S` ≥ 1.0 is stored as an `inferred attributed-to` claim with confidence `HYPOTHESIS_CAP × (1 - e^(-S/4))` and up to 8 human-readable reasons ("shared malware TrailBlazer (held by 2 of 256 actors/campaigns, idf 4.9)").
* **Hypotheses rank below sourced claims.** `HYPOTHESIS_CAP` is 0.09, below the 0.10 floor of the low band that any observed or reported claim gets, so a quoted claim from a single tier-D outlet always outranks a computed link for the same pair. The API returns `band: "hypothesis"` (not low, moderate or high) and a one-line `why` naming what the two ends share ("Computed by the hub, not said by any source: both share …"). Sorting by confidence and the graph's node budget therefore put hypotheses last; on the graph, a pair held by both a reported and an inferred claim is one edge, the reported one. A confirmed hypothesis rises to 0.95 like any confirmed claim. Tests: `tests/entities/test_v11_trust.py`.
* On the ATT&CK campaigns with a reported attribution, the reported actor ranks first for 16 of 26.

**Conflicts.** Different attributions are separate claims and are never averaged. The entity page marks `conflict: true` on each sourced `attributed-to` claim when the subject has more than one sourced candidate of the same type. Hypotheses and rejected claims do not make an attribution contested.

**Writers and safety.** Every writer of `claims` (ingest, linking, rescoring, inference, feedback) holds one re-entrant claims lock for its whole read-merge-write. Inference deletes only links that disappeared, never a row it is about to rewrite, and rewrites only links whose confidence changed. `tests/soak/soak_entities.py` runs link passes, ingest, feedback, API reads and frequent checkpoints together on a scratch lake and fails on any write error.

**Incremental.** Upserting a claim clears its confidence; the next pass scores only unscored claims. Touched actors, campaigns, malware and tools go to `entity_dirty`, which triggers re-inference. Inferred claims never mark entities dirty.

# Overrides

<a id="overrides"></a>The same group is often split across entities: `malware:qilin`, `actor:qilin` and `malware:agendacrypt` (aliases Agenda, Qilin) on the test lake; actor and malware rows for Akira, Settra and the Scorpius groups. Two user overrides fix this, and both survive re-extraction.

* **Same as… (merge)** `POST /api/entities/merge {src, dst, note}`: src joins dst. Only named types can be merged (actor, campaign, malware, tool, org, vendor, product, sector, country), never indicators.
  * Mentions move to dst unless dst already has the same `(ref_type, ref_id, role)`, so a report naming both counts once.
  * Claims are re-pointed and their ids recomputed; a claim dst already holds merges with it (sources unioned, evidence joined and capped, verdict histories kept in time order). A link between the two (`actor:qilin uses malware:qilin`) becomes a loop and is dropped. Verdicts move with their claims, so a rejected link stays rejected.
  * dst keeps its name, type and facts; src's name and aliases become dst's aliases; src's facts fill only keys dst lacks; seen times widen. src is deleted (and its vector row, so dst is re-embedded with the new aliases). Moved claims are rescored and links re-inferred at once, so counts, Related and the graph follow.
* **Wrong type… (retype)** `POST /api/entities/retype {id, type, note}`: the entity becomes `type:<same name>`. If that exists the two are merged; otherwise it is created from the old one (name, aliases, facts). Types offered: actor, malware, tool, campaign, org, vendor, product.
* **Surviving re-extraction.** Every merge and retype is a redirect (old id → kept id, chains followed) that every writer in `store.py` applies: `upsert_entities` turns a row for the old id into aliases of the kept one (its facts never overwrite the kept entity's), `rename_entities` skips old ids (a reference import cannot rename the kept entity to the merged name), `add_mentions`, `upsert_claims` (loops dropped) and `mark_dirty` write under the kept id. Reference imports, linking and article ingest therefore never bring a merged duplicate back. `guess_ids` (lookup, and `GET /api/entities/{id}` for an unknown id) resolves through the redirects, and an old entity link opens the kept entity with `redirected_from`.
* **Undo** `POST /api/entities/overrides/{id}/undo`. A merge's snapshot holds src's entity row, its mentions and claims, dst's colliding claims and its aliases, facts and seen times before; Undo removes the rewritten claims, puts both sides' originals back, returns the moved mentions, restores src and dst's aliases and facts (seen times re-widened from dst's remaining mentions), and removes the redirect. For a retype that created its target, anything that reached the target since moves back to the original and the target goes. **Changes since the merge** (`overrides._plan`): the snapshot records what each rewritten claim held right after the merge. A later source, evidence item or verdict on a claim that came only from the merged entity goes back to it on Undo, and so does a verdict row made later on one of its links (a Disagree on "actor:x uses T1190" after merging tool:x into it returns to tool:x). Later additions on a link both entities had can't be split and stay on the kept entity; `GET /api/entities/overrides/{id}/undo-preview` lists them as plain sentences (`stays`) with a count of what goes back (`moved_back`), and the UI shows them and asks before undoing. New mentions on the kept entity stay there. Undo is refused (409) while a later merge or retype touches either entity: undo that one first. A merge whose `src` was already merged away is refused (409) rather than resolved, so a stale page can't merge the wrong entity.
* **Stored ids are read, not rewritten.** Watchlists, story `top_entities` and bookmarks keep the id they were saved with. `overrides.resolve(id)` gives the id an entity lives under now and `overrides.equivalents(id)` every id that means it now (the stored one, the kept one, and the ids merged into it). Readers use them: the News watchlist digest and entity filter (`news/api.py`), the Watch briefing's follow matching (`watch/briefing.py`), `/api/news/entity-brief`, and the entities API's graph, timeline, activity, lookup and detail. Following either name of a merged pair keeps working, `matched` still names the id as followed, and Undo needs no clean-up.
* **Not the same** `POST /api/entities/not-same {a, b}`: an `entity_overrides` row of action `distinct`; the pair is no longer suggested. Undo deletes it.

**Duplicate suggestions** (`overrides.suggestions()`, `GET /api/entities/duplicates`, the entity page's `possible_duplicates`): among actors, campaigns, malware and tools (placeholders skipped), pairs that share a name key (letters and digits; also without generic edge words) or where one lists the other's name as an alias. Keys under 4 characters, generic words and keys shared by more than 4 entities are ignored. Pairs where neither side has a mention are left out (two reference entries split no counts). Each has a `strength`, and the list is ordered by it, then by mentions plus claims:

| Strength | When |
|---|---|
| strong | The same name (`same name`, or `same name under two types`), or one lists the other's name as an alias, same type |
| possible | Similar names: equal only after removing generic words ("Akira" and "Akira Stealer") |
| weak | An actor lists a malware or tool name as an alias (MISP often lists a group's tools as synonyms) |

The better-documented side is suggested as the keeper (`a`). On the test lake: 160 pairs, Qilin's two first among its own.

**Review queue** (`GET /api/entities/review`, the Entities tab's **Review** sub-tab, `#entities/review`): likely duplicates (keep either one, or "Not the same"); contested attributions (a subject with two or more sourced `attributed-to` candidates of one type, not all reference listings, none confirmed by you; "This one" or "Disagree…"); claims you disagreed with (reason, note, date, Undo); and your identity changes (Undo). The tab shows no count: it is a place to work through, not another number that needs you.

# Search

The `entity` searcher registers with `osinthub.search`. It runs BM25 over name, aliases and (for named types) description, with the entities a query names first, in tiers: the id, a whole name, a whole alias, a name or alias without its generic words (`lazarus` finds *Lazarus Group*, `gamaredon` *Gamaredon Group*), then up to five names or aliases that start with the query's words (`volt` finds *Volt Typhoon*), and aliases equal to one word of a longer query; most-mentioned first within a tier, and the name-like tiers only for named types (not IOCs). A query made only of stop words or generic words (`the`, `group`, `team`, `operation`, `apt`) gets no tiers, the prefix tier needs a first word of at least 4 letters that is not generic (`win` does not prefix-match *Win.Tool…*), and a name reduced to a generic word (*The Group*) has no stripped form. The rest is fused with vector hits from the `entities` collection (embeddings of "type: name. aka aliases. description"). Without embeddings it answers from keywords.

# API

| Method | Path | Parameters | Returns |
|---|---|---|---|
| GET | `/api/entities` | `type` (comma list), `q` (contains-text on name or id, `%` and `_` literal; or a whole alias), `since_hours` (by `last_seen`; fractions count, 0 is empty), `sort` (`mentions`, `last_seen`, `name`, `claims`), `limit` (≤2000), `offset` | `{counts: {type: n}, total, items: [{id, type, name, aliases, alias_count, first_seen, last_seen, mentions, claims, description}]}` |
| GET | `/api/entities/status` | | Table counts, claims by origin, reference files present, last task pass. |
| GET | `/api/entities/lookup` | `values` (comma list of IPs, prefixes, domains, URLs, hashes, CVEs, ASNs, technique ids or names) | `{results: [{value, found, entity}]}`; names resolve through aliases. |
| GET | `/api/entities/graph` | `id`, `depth` (1-2), `limit`, `min_confidence` (0-1, default 0; outside that range, NaN or infinite is a 422; drops claims below it; links with no confidence, such as `mentioned-with`, always pass, as in the graph view's slider), `collapse_over` (0-100000, default 15; outside that range is a 422) | `{root, nodes: [{id, type, name, root}], edges: [{id, source, target, predicate, origin, hypothesis, verdict, confidence, band, sources, first_seen, last_seen, specificity}]}` (seen times only on dated claims; `verdict` only when the user confirmed the triple). One edge per triple: the best-sourced claim stands for it (observed, reported, local, user, inferred); rejected triples are left out; `hypothesis` is true for inferred links (unless confirmed, `band: "hypothesis"`) and co-mentions. Hypotheses are queried after sourced claims, so they never crowd them out of `limit`. `specificity` (0-1) is the inference weight of the edge's feature end: the IDF over actors and campaigns sharing it, normalised, times the commodity discount, so a UI can mute commodity tools and CDN addresses from data. More than `collapse_over` IPs on one edge type become one `ip-group` node per ASN with `count` and `members`; the group edge's `confidence` is the best member confidence, or null when no member has one (co-mentions), so it passes a confidence floor exactly as its members would. Sparse nodes get `mentioned-with` edges from co-mentions (id `mentioned-with:<root>\|<other>`, origin `co-mention`, `hypothesis: true`, no confidence). `limit` (0-1000) caps the entity nodes: the root is always first and always present (`limit=0` returns the root alone), then nodes in the order their links were found (hop by hop, highest confidence first); an ASN bubble counts as one node and stands where its first member IP was found, so `nodes` never holds more than `max(limit, 1)` entries. Every edge has a non-null unique `id`, and both its `source` and `target` are in `nodes`. 404 `unknown entity` for an id not in the table. |
| GET | `/api/entities/timeline` | `ids` (lanes) or `type` (default `campaign`) and `limit`, `station_types` | Metro map: `{lanes: [{id, name, type, start, end, stations: [{id, name, type, ts, how, shared, specificity}]}], shared: [{id, name, type, lanes, specificity}]}`. `specificity` is defined as for graph edges. |
| GET | `/api/entities/activity` | `ids` (comma list, ≤300; optional: none or empty returns `{weeks, items: {}}`, not a 422), `weeks` (4-104, default 26) | `{weeks, items: {id: {spark: [n per week, oldest first], confidence, band, origins: {origin: n}}}}`; confidence is the strongest non-inferred claim; `origins` leaves out verdict rows and rejected links. Used by the directory, which skips the call for an empty page. |
| GET | `/api/entities/techniques` | | `{items: [{id, attack_id, title, tactics}]}` for the ATT&CK strip. |
| POST | `/api/entities/claims/{id}/feedback` | body `{verdict: confirm\|reject\|clear, note, reason}` (`reason` only with reject: `wrong-link`, `wrong-type`, `outdated`, `other`) | `{verdict, claims}`: the triple's claims after rescoring. `clear` withdraws the verdict (Undo). See [Verdicts](#verdicts) and [Disagree](#disagree). |
| GET | `/api/entities/duplicates` | `id` (optional: pairs with this entity), `limit` (≤500) | `{total, items: [{id, a, b, reasons, strength, tier, weight}]}`; `a`/`b` are `{id, type, name, mentions, claims, aliases}`, `a` the suggested keeper. See [Overrides](#overrides). |
| POST | `/api/entities/merge` | body `{src, dst, note}` | `{id, action, src, dst, src_name, dst_name, src_type, dst_type, dst_created, mentions_moved, claims_moved}`. 400 for the same id or an indicator type, 404 for a missing entity, 409 when `src` was already merged away (`dst` is resolved). |
| POST | `/api/entities/retype` | body `{id, type, note}` | As merge; `dst` is the new id, `dst_created` whether it was made. |
| POST | `/api/entities/not-same` | body `{a, b, note}` | `{id, action: "distinct", src, dst}` (idempotent). |
| GET | `/api/entities/overrides` | `limit` | `{items: [{id, action, src, dst, src_name, dst_name, note, ts}]}`, newest first. |
| GET | `/api/entities/overrides/{id}/undo-preview` | | `{id, action, src_name, dst_name, moved_back, stays: [sentence]}`: what Undo does with changes made since the merge. |
| POST | `/api/entities/overrides/{id}/undo` | | `{undone, action, src, dst, moved_back, stays}`; 404 unknown, 409 when a later merge touches the same entities. |
| GET | `/api/entities/review` | `limit` | `{counts: {duplicates, disagreed, contested}, duplicates, disagreed: [{id, subj, predicate, obj, subj_name, obj_name, reason, note, ts}], contested: [{subj, subj_name, type, candidates: [{id, obj, name, confidence, band, sources, authoritative, quote}]}], changes}`. `disagreed[].id` is the verdict row; posting `clear` to it is Undo. |
| GET | `/api/entities/{id}` | `evidence` (items per claim, ≤25), `bucket` (`hour`, `day`, `week`, `month`) | The entity with `listed_by` (for ip, domain, url and hash: the threat lists holding it now or before, as in story IoCs),  `aliases`, `attrs`, `first_seen`, `last_seen`, `mentions`, `timeline` (`[{t, source, n}]` per source), `sources`, `claims` grouped by origin (`observed`, `reported`, `user`, `inferred`, `local`; each with `other`, `other_name`, `direction`, `band`, `why`, `evidence`, `conflict`, `authoritative`, `catalogue` (some evidence is a reference listing, even when articles report the link too), `article_count` (distinct articles in all of its evidence), `hypothesis`, `verdict`, `verdict_note`, `verdict_ts`, `verdict_reason`; verdict rows are folded into the claim they judge and rejected triples are left out), `claim_counts` (the same groups), `rejected` (one row per rejected triple, for "You disagreed" and Undo), `conflicting_attribution`, `related` (entities a counted claim links to: `{id, how: "claim", n, type, name}`, n = distinct triples), `related_hypotheses` (entities named in the same texts, `how: "mentioned-with"`, or linked only by an inferred claim, `how: "inferred"`; not in `related`) and recent `refs`, `merged_here` (overrides that merged or retyped an entity into this one, with ids for Undo), `possible_duplicates` (as in `/duplicates`, up to 6) and, when the id was merged or retyped away, `redirected_from`. An unknown id is retried as a lookup value. |

# On a phone
<a id="phone"></a>Intel on a phone (`isPhone()`): entity chips push `#entities/<id>` instead of opening the
side panel, the entity page is a pushed page, the graph lists the root's connections with a full-screen
**Open the graph** overlay, and Review is read-only ("Decide these on a computer"). Full contract:
[phone layout](/architecture/phone.md#per-view). Desktop is unchanged.

# Known limits

* **The technique gold is partly built from this extractor's own proposals.** Since 2026-11-19 the bars apply to the
  "described in the body" measure ([Extraction](#extraction)). Its additions only cover techniques the extractor
  proposed in the one audited LLM run, so a technique the body supports that neither the vendor nor the extractor
  named is still invisible: the body recall (0.560) is an upper bound for such techniques, and the recall over the
  vendor's table entries alone (0.531) is the measure without that lift, just above the bar. Precision is judged per
  prediction; a later extractor's new proposals count as wrong until they are adjudicated (the scorer prints the
  count). The adjudication was done by a Claude agent reading the text, not by the owner; 28 additions, 58 described
  table ids and 25 "not in the body" exclusions are marked unsure. Microsoft posts were the weak spot (body precision
  0.733): 8 of their 12 remaining wrong techniques were procedure-example proposals on hunting queries, KQL and
  "Verify Microsoft Defender…" advice. Since 2026-11-19 that text is skipped ([defender text](#defender-text)), and
  Microsoft's body precision with the model is 0.917.
* **Defender text is masked by a few fixed rules only.** A defender heading placed before attacker narrative hides
  that narrative until the section ends (an end-of-report section runs to a reset heading or the end), and advice
  outside a defender section, or under a defender heading not on the lists, is still read.
* **Technique scores against the vendor table (before 2026-11-19).** The vendor table missed the bars. Each approach
  was scored once on `tests/eval/score_extraction.py` (body, appendix stripped; vendor table); nothing was tuned on
  the eval:

| Approach | Precision (vendor table) | Recall (vendor table) |
|---|---|---|
| Artefact cues only (no LLM) | 0.716 | 0.341 |
| Model techniques alone | 0.561 | 0.614 |
| Model plus an LLM self-check | 0.579 | 0.584 |
| Procedure-example gate (**confirmed tier, current**) | 0.653 | 0.450 |
| Score fusion (`techscore.py`, unused) | 0.417 | 0.637 |

  * **Why the fusion failed:** a logistic model over six signals (the model's verified technique, neighbour agreement, top similarity, sentence support, ATT&CK-derived keywords and cues) was fitted on 30 pseudo-reports from held-out ATT&CK groups and software. On the other 30 it reached precision 0.79 and recall 0.64 at threshold 0.40. It did not transfer, because pseudo-reports hold only procedure sentences; a real report has hundreds of background sentences, on which neighbour support also fires.
  * **Next step:** calibrate on realistic pseudo-reports that mix procedure examples with background sentences from the news corpus.
* LLM extraction is slow on the shared 27B model; see [Extraction](#extraction).
* Inferred links exist only for campaigns; actor-to-actor overlap is not computed.
* `device` entities are reserved for the network-log package.
