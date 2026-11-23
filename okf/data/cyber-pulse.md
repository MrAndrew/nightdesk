---
type: Metric
title: Cyber Pulse index
description: A 0-100 composite score of current cyber pressure, from five sub-indices, with a 24-hour change.
resource: http://127.0.0.1:8787/api/pulse
tags: [metric, analytics]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-12T22:40:00Z }
---

# Definition

Each sub-index is 0-100. Counts are put on a log scale with `100 · ln(1+x) / ln(1+full)`, where `full` is the count that maps to roughly 100.

| Sub-index | Weight | Inputs | Full scale |
|---|---|---|---|
| Exploitation | 0.25 | 60% new KEV entries in 7 days (full = 20) + 40% CVEs with CVSS ≥ 9 in 24h (full = 60) | |
| Ransomware | 0.25 | Ransomware victims in 24h | 60 |
| Connectivity | 0.20 | Sum of outage severities in 24h | 40 |
| Routing | 0.15 | 50% withdrawal rate over the last 15 min vs the 24h average (50 = normal) + 50% BGP origin changes and withdrawal bursts in the last hour (full = 300). The churn half is used only when both rates were measured; otherwise the origin changes and bursts alone (never a made-up neutral 50) | |
| Chatter | 0.15 | Cyber posts in the last hour | 400 |

# Honest about missing data

A score from missing data reads as "all clear", so the Pulse only scores inputs that are **current**:

| Sub-index | Its feeds | Current when |
|---|---|---|
| Exploitation | `cisa_kev`, `nvd_recent` | a successful run within 3 × the feed's interval (at least 3 h) |
| Ransomware | `ransomware_live` | as above |
| Connectivity | `ioda_outages` | as above |
| Routing | `ris_live` (stream) | events or `bgp.*` rate metrics within the last 15 min |
| Chatter | `bluesky_cyber` (stream) | events or `bluesky.*` metrics within the last 15 min |

Each sub-index carries a `status`: `current`, `stale` (its feed delivered before but not recently), `waiting` (its feed has never delivered) or `off` (turned off or needs a key), plus `last_data`. Only current sub-indices have a `value` and `change_24h`; the others are `null` and the UI shows "stale", "no data yet" or "feed off", never 0.0.

The composite is the weighted mean of the current sub-indices, weights re-normalised among them, and only when at least **3 of 5** are current. The response's `state`:

| state | When | Shown |
|---|---|---|
| `ok` | all 5 current | the score and level |
| `partial` | 3 or 4 current | the score and level, with "n of 5 inputs" |
| `warming` | fewer than 3 current, none stale (a fresh install) | "Warming up — n of 5 inputs in", no score |
| `stale` | fewer than 3 current, some stale (feeds stopped, offline mode) | "Stale — n of 5 inputs current", no score |
| `off` | fewer than 3 current, the rest turned off | "Too few feeds on", no score |

`score`, `level` and `change_24h` are `null` unless the state is `ok` or `partial`. The top-bar chip then reads "PULSE — · warming up" (or "stale") with a grey dot; The level colours run neutral to amber to red (v1.2): LOW muted grey, GUARDED sand, ELEVATED amber, HIGH orange, SEVERE red; the sub-index bars use the same continuous ramp, so only a real alarm turns red. The 24-hour change compares with the same calculation shifted back 24 hours. Tests: `tests/test_v11_states_pulse.py`.

| Score | Level |
|---|---|
| < 25 | LOW |
| 25-45 | GUARDED |
| 45-65 | ELEVATED |
| 65-80 | HIGH |
| ≥ 80 | SEVERE |

# Caveats

* Scales are fixed heuristics, not fitted to history. Recalibrate once a few months of data exist.
* IP-list feeds stamp events at collection time, so they are not used in the index.

Computed in `osinthub/analytics.py`.
