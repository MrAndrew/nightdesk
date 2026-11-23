# HLTA gold eval sets

These gold sets were written independently of the builders. **Builders must not edit `reports.jsonl`, `cve_queries.jsonl` or the scorers.** The exceptions so far are the owner-approved ATT&CK re-adjudication of 2026-11-19 ([below](#attck-re-adjudication-2026-11-19)), which added fields to `reports.jsonl` through `attack_gold.py` (a lab script kept in the development repo) and left every existing gold value unchanged, and `--save-outputs` in `score_extraction.py` (fix round 3, owner-approved), which only writes files and changes no score.

## Pass bars

Each measured test ships with a fixed bar. Gold data is written by someone other than the builder, who must not edit it.

| Test | Pass bar |
|---|---|
| **Extraction** (`score_extraction.py`, ~25 vendor reports with published IOC and ATT&CK appendices) | IOCs on the full page (ip, domain, url, sha256/sha1/md5, cve): precision ≥ 0.95, recall ≥ 0.90. ATT&CK techniques on the **body without the appendix**: precision ≥ 0.70, recall ≥ 0.50, applied since 2026-11-19 to the **"described in the body"** measure (the vendor-table measure is still printed, without a bar). The report's named actor and malware are found, after alias normalisation, in ≥ 85% of reports. **Zero** LLM claims whose evidence quote is missing from the source text. |
| **CVE semantic search** (`score_cve_search.py`, ≥ 40 paraphrased CVE questions) | recall@5 ≥ 0.90, and the right CVE ranks first ≥ 0.70 of the time. |
| **Zeek planted traffic** (`zeek_planted.py`) | 100% of planted active-C2 contacts raise a high or medium alert; 0 high or medium alerts on decoys (contacts before listing, inbound scanners, Tor, benign traffic); 1M conn lines import in < 60 s. |
| **Offline** (`offline_check.py`) | With `OSINTHUB_OFFLINE=1` and a dead proxy, every new API answers; semantic search, entity pages, log import, matching and alerts all work; nothing hangs. |

| File | What it is |
|---|---|
| `reports.jsonl` | 27 public vendor threat reports with gold IOCs, ATT&CK techniques (the vendor table plus the 2026-11-19 body re-adjudication), actors and malware |
| `score_extraction.py` | Scores `osinthub.entities.extract.extract` against `reports.jsonl` |
| `cve_queries.jsonl` | 45 paraphrased questions, each answered by exactly one CVE in the seed data |
| `score_cve_search.py` | Scores `GET /api/search/semantic?types=cve&k=5` |
| `evalfetch.py` | Polite fetcher and HTML-to-text converter shared by the scorers (stdlib plus certifi) |
| `cache/` | Raw HTML and extracted text, one pair per report. It is gitignored and never committed, because it is third-party text. Set `ND_EVAL_CACHE=<dir>` to keep it elsewhere, so it survives the removal of a worktree (the lead keeps a copy in `~/Projects/nd-wt/tools/eval-cache/`). |
| `attack_gold.py` (lab script, development repo only) | Rebuilds the re-adjudicated technique fields in `reports.jsonl` from the audit's `items.jsonl` (stdlib only, offline) |

## Running

```sh
# Extraction (offline once cache/ exists)
uv run python tests/eval/score_extraction.py --fetch      # first time: build cache/
uv run python tests/eval/score_extraction.py              # full run, LLM on
uv run python tests/eval/score_extraction.py --no-llm     # regex/dictionary path only
uv run python tests/eval/score_extraction.py -v --only eset-webworm --json /tmp/x.json
ND_EVAL_CACHE=~/Projects/nd-wt/tools/eval-cache uv run python tests/eval/score_extraction.py   # cache kept outside the worktree

# Score saved extract() outputs (DIR/<report id>.json = {"full": {"out": ...}, "body": {"out": ...}}),
# without the extractor or the model; the claims check runs only if the cache is present
python3 tests/eval/score_extraction.py --from-outputs DIR -v

# Save every extract() output while scoring (same format, one file per report as soon as it is scored, plus each
# call's seconds, error and extract.LAST_STATS; "body" is left out when the report has no body marker), so a long
# model run can be re-scored later with --from-outputs. Not combinable with --from-outputs.
uv run python tests/eval/score_extraction.py --save-outputs DIR

# CVE semantic search, against your own server on your own port
uv run python tests/eval/score_cve_search.py --base http://127.0.0.1:<port> -v
```

Each scorer prints `PASS` or `FAIL` and exits with 0 on a pass and 1 on a fail. It exits with 2 when the setup is broken: the import fails, the server cannot be reached, or the cache is empty.

## Extraction set: sources

All reports were fetched on 2026-11-04 with the User-Agent `hlta-eval/0.1 (home lab threat analysis; research)`. robots.txt was checked first, there was a 4-second delay between requests to the same site, and nothing was retried around a block.

| Vendor | Reports | Years |
|---|---|---|
| The DFIR Report | 9 | 2021, 2022 ×2, 2023 ×2, 2024 ×2, 2025 ×2 |
| ESET WeLiveSecurity | 12 | 2021, 2022, 2023, 2026 ×9 |
| Microsoft Threat Intelligence | 5 | 2026 |
| Recorded Future (Insikt Group) | 1 | 2026 |

That gives 20 reports from 2024–2026 and 7 from earlier years.

### Sites skipped, and why

| Site | Why it was skipped |
|---|---|
| Check Point Research | HTTP 202 with an AWS WAF challenge (a bot check) |
| Sekoia, CISA, HarfangLab | HTTP 403 to an honest client (robots.txt itself returns 403 for CISA and Sekoia; HarfangLab feed 403) |
| Securelist | Connection refused |
| Unit 42 | The pages are reachable, but the sampled reports publish IOCs and no ATT&CK technique IDs. It is out of scope for a test that needs both. |
| Cisco Talos | Most posts keep IOCs in GitHub rather than on the page, or have no ATT&CK IDs |
| Proofpoint | No reachable feed was found, and the posts have no ATT&CK tables |
| Recorded Future market-overview posts | No IOC appendix |

## Labelling method

All values are **refanged and lowercased**. Labels come only from each report itself.

- **`body_end_marker`**: a string that occurs exactly once and starts the IOC/ATT&CK appendix. The DFIR Report uses `Indicators\n\nAtomic` or `IOCs\n\nFiles`, ESET uses `\nIoCs\n`, Microsoft uses its "MITRE ATT&CK techniques observed" heading, and Recorded Future uses "Appendix A". Techniques, actors, malware and the body claims are scored on `text[:marker]`.
- **IOCs**: the gold IOC list is built from four sources.
  - Every ip, domain and url in the report's own IOC section.
  - Every defanged indicator (`[.]`, `hxxp`) anywhere in the text.
  - Every sha256, sha1 and md5 hex string and every CVE id anywhere in the text.
  - Infrastructure the body names explicitly. Examples are the DFIR Nitrogen C2 IP table, the Lunar Spider C2 resolutions, the domains in the Microsoft hunting queries, and threat-actor source IPs.
  
  Each list was then reviewed by hand. AV detection names such as `WinGo/HackTool.Proxy.AE`, version strings such as `2.5.0.67` and broken IPv6 fragments were removed.
- **`neutral`**: some values are neither rewarded nor penalised. They are:
  - legitimate services the report names, such as `ipinfo.io`, `webhook.site`, `file.io`, DDNS-provider domains and VPN exit IPs
  - loopback addresses that the report defanged
  - JA3/JA3S, imphash and public-key MD5 digests, which have the md5 format but are not file hashes
  - git commit hashes inside reference URLs
  
  A predicted domain or IP that is the host of a gold URL is also neutral.
- **Deliberately not neutral**: reference links in the detection sections (github.com/SigmaHQ, the DFIR YARA repo, learn.microsoft.com, schemas.microsoft.com), private, `0.0.0.0` and netmask addresses, and version numbers. An extractor that reports these as IOCs loses precision, because the brief scores IOCs on the full page.
- **Techniques** (`gold.techniques`, the "vendor table"): every `T####(.###)` ID printed in the report, which in practice means its ATT&CK table or list. A prediction counts as correct if it equals a gold ID or is its parent or child. Sibling sub-techniques do not count. The model has to infer techniques from the prose, because the body contains almost no IDs. This list is unchanged, so older numbers stay reproducible; see the next section for the measure the bars now use.
- **Actors and malware**: only the actors and families the report itself names as the subject. These come from the title, summary or key points, with aliases taken from the report or from well-known vendor naming (APT28/Sednit/BlueDelta/Fancy Bear, and so on). Microsoft posts that name no actor or family have empty lists and are left out of the hit rate. Names are compared case- and punctuation-insensitively, with generic suffixes such as "ransomware", "loader" and "backdoor" stripped. A name can be found in either the actors or the malware output. A report counts as a hit only if **all** of its gold names are found.
- **Claims**: each `quote` must appear in the text that was passed to `extract`, after normalising whitespace, case, curly quotes and dashes. An empty quote counts as missing.

### ATT&CK re-adjudication (2026-11-19)

An audit of the LLM run (2026-11-18/19) found that the vendor table misjudges an extractor that reads the body: 104
of its 147 confirmed-tier "false positives" are described in the body but missing from the table, 63 table ids are
never described in the body, 13 table ids are revoked in ATT&CK Enterprise v20.1 and 18 are Mobile ATT&CK ids
(the extractor emits Enterprise ids only). `attack_gold.py` (a lab script kept in the development repo) turns the audit's classified items into these
fields of `gold`, next to the untouched `techniques`:

| Field | What it holds |
|---|---|
| `techniques_body` | The techniques the body describes: the table ids the audit run matched (not re-read) or the audit found described (F), the Mobile ids (`"mobile": true`, scored apart), and the **B additions**: techniques the extractor proposed (either tier) that the body supports and the table omits, each with `"by": "audit-2026-11-19"`, the tier, and one short verbatim quote, checked against the cached body. `"unsure": true` marks the audit's judgement calls. |
| `techniques_not_in_body` | Table ids no body sentence describes (G), with `unsure`. |
| `techniques_rejected` | Proposals the audit judged wrong: A truly wrong, C sibling sub-technique, D a defender, analyst or hypothetical sentence, E other (near-misses, group background). |
| `revoked` | Revoked table id → its v20.1 replacement (for example `T1574.002` → `T1574.001`, `T1070.001` → `T1685.005`), mapped on both sides when scoring. |

The scorer prints both measures. **"Described in the body"** (bars apply): precision and recall against
`techniques_body` with revoked ids mapped and Mobile ids left out, plus the recall over the table entries alone, the
Mobile ids found, how many matches and misses rest on unsure entries, and how many predictions were **never
adjudicated** (neither in the body gold nor rejected; they count as wrong). **"Vendor table"**: as before, no bar.

**Bias, stated plainly.**
- The B additions only cover techniques the extractor itself proposed in the one audited LLM run. A technique the
  body supports that neither the vendor nor the extractor named is still invisible, so the body recall is an upper
  bound for such techniques; the recall over the table entries alone has no such lift. Precision is judged per
  prediction, so it is not inflated this way, but a prediction that was never adjudicated counts as wrong until
  someone adjudicates it (the scorer prints how many).
- The audited LLM run built part of the gold it is scored on; a later extractor version is judged on the same
  gold, and its new proposals start as "never adjudicated".
- The adjudication was done by a Claude agent reading the body text (no model used), not by the owner. Its
  judgement calls are marked `unsure`: 28 B additions, 58 F table entries and 25 G exclusions.
- Table ids the audit run matched were not re-read; they are taken as described in the body.

**Baseline** (2026-11-19, `--from-outputs` on the audit's saved outputs, confirmed tier, body only):

| Run | Body precision | Body recall | Recall, table entries only | Never adjudicated | Vendor table P / R |
|---|---|---|---|---|---|
| LLM on | **0.910** (386/424) | **0.560** (381/680) | 0.531 (274/516) | 0 | 0.653 / 0.450 |
| `--no-llm` | **0.896** (249/278) | **0.376** (256/680) | 0.397 (205/516) | 23 | 0.716 / 0.341 |
| LLM on, after the defender-text filter (v1.2 full run, 2026-11-19) | **0.939** (386/411) | **0.560** (381/680) | 0.531 (274/516) | 0 | 0.674 / 0.450 |
| `--no-llm`, after the defender-text filter | **0.915** (249/272) | **0.376** (256/680) | 0.397 (205/516) | 21 | 0.732 / 0.341 |

| Vendor (reports) | LLM body P / R | `--no-llm` body P / R | LLM vendor table P / R |
|---|---|---|---|
| DFIR (9) | 0.950 / 0.639 | 0.922 / 0.528 | 0.736 / 0.594 |
| ESET (12) | 0.906 / 0.491 | 0.881 / 0.231 | 0.570 / 0.311 |
| Microsoft (5) | 0.733 / 0.486 | 0.769 / 0.284 | 0.533 / 0.441 |
| Recorded Future (1) | 0.900 / 0.529 | 0.833 / 0.294 | 0.600 / 0.429 |

After the defender-text filter, with the LLM: DFIR 0.959 / 0.639, ESET 0.912 / 0.491, Microsoft 0.917 / 0.486,
Recorded Future 1.000 / 0.529 (body P / R). That run needs the procedure-example index in the lake
(`<lake>/cache/procedures.npz`, built by `osinthub.entities.procvec.build()` with the AI helper up); without it the
model's techniques are never verified and the confirmed tier equals the `--no-llm` result.

The Mobile ids are found 0 of 18 times in both runs. With the LLM on the run passes both technique bars; it is the
run the additions were taken from (see the bias notes). Against the audit's own re-read measures: precision is
0.910, not 0.899 ("B counted correct"), because the 5 predictions of a revoked id's replacement now match (DFIR 3,
ESET 2); recall over the table entries alone is 0.531, against 0.533 for "findable and emittable"; the body recall
(0.560) is above the audit's 0.503 because the denominator adds the 164 B additions (104 of them confirmed-tier
predictions, found by construction; 3 of the 60 suggested-tier ones matched through a parent or child) and drops the
18 Mobile ids, and two table ids collapse into one where a revoked id maps onto an id already in the table. The
`--no-llm` precision is a lower bound: its 23 never-adjudicated predictions (proposed only by the regex path) count
as wrong; counted correct it would be at most 0.978.

For calibration, a naive regex baseline scores IOC precision 0.88 and recall 1.00. Almost all of its false positives are reference URLs and benign hosts.

## CVE search set: method

- **Source**: the seed DB `$ND_SEED_LAKE/db/hub.duckdb` (the seed lake), read from a copy. It holds 3,448 CVEs: 1,768 from CISA KEV and 1,681 from NVD-recent.
- **Selection**: each answer was checked for uniqueness with keyword searches over all CVE and KEV titles and summaries. Ambiguous candidates were dropped:
  - the two Cleo upload CVEs
  - the two SysAid XXE CVEs
  - the two MSDT CVEs
  - LSA spoofing, which also matches PetitPotam
  - the two LoadMaster command injections
  - the three vCenter DCERPC overflows
- **Wording**: the questions are written the way a home user would ask. Distinctive phrases from the summaries are avoided.
- **Mix**: 18 name the vendor, 21 give only the product type and bug class, and 6 are vague but still uniquely answerable.
- **Scoring**: the scorer reads the CVE id from each hit's `id`, then `title`, then `url`, and never from the snippet. The bars are recall@5 ≥ 0.90 and top-1 ≥ 0.70.

## Zeek planted-traffic test

`tests/eval/zeek_planted.py` generates synthetic Zeek JSON logs (conn, dns, ssl, http, ntp, dhcp) for an invented home network on documentation prefixes (`192.0.2.0/24`, `2001:db8:1::/48`, invented MACs). It plants contacts with real threat indicators from the seed lake, imports the files into a running HLTA server and scores the alerts.

* **Indicators:** listing intervals come from the seed lake's record delta files: first `put` to `del`.
* **Positives (37 with the default seed):** must raise a high or medium alert whose `evidence.uids` contains the planted uid.
  * 28 contacts to Feodo C2 IPs inside their listing interval. These cover the listed port, HTTP POST, odd ports, long sessions, DNS answer then connect, failed outbound attempts, a beacon series, and one contact 4 minutes after listing.
  * 9 contacts inside active Spamhaus DROP netblocks.
* **Decoys (141 named, plus about 30,000 benign connections):** must raise no high or medium alert.
  * Contacts with the same C2s before they were listed.
  * Inbound S0/REJ connections from DShield and blocklist.de attackers.
  * Outbound connections to Tor exits.
  * Near-miss neighbouring addresses.
  * Benign traffic to IPs that appear in no seed list.
* **Performance:** `--perf` adds 1,000,000 conn lines, which must import in under 60 s.
* **Ground truth:** written to `<dir>/manifest.json`.

```sh
uv run python tests/eval/zeek_planted.py --base http://127.0.0.1:<port> [--perf] [--seed N]
uv run python tests/eval/zeek_planted.py --out-dir <dir>   # write files only
```

Critic-written adversarial cases live in `tests/eval/critic/`.

## Recorded netlog results

From the network-log build rounds (2026-11-05), kept here because the netlog page now only points to these
tools: the planted-traffic test found 37/37 planted positives with 0 high or medium alerts on decoys (1M conn
lines in about 8.6 s, also passing with seeds 1-3); the critic's adversarial cases (`critic/netlog_adversarial.py`)
passed 51/51 and round 2 (`critic/netlog_r2.py`) 100/100, with every latency case at p95 under 500 ms on 1.6M rows;
`netlog/benign_check.py` gave 0 high or medium alerts.
