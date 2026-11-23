---
type: Architecture
title: My stack (what you follow)
description: The one followed list (vendors and products you run, entities, words), how it is matched against KEV, CVEs, EPSS, news, network incidents and ransomware victims, its false-positive guards, and where it shows in the app.
tags: [architecture, watch, news, entities, frontend, api]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-11T01:00:00Z }
---

# My stack

A home-lab owner's question is "does this affect me?". My stack is the list that answers it: the products the user
runs, plus the groups, malware, CVEs and words they care about. One list, matched across the whole app, with no
language model anywhere. Backend: `osinthub/stack.py` (router registered from `osinthub/watch/ext.py`). Client:
`web/js/core/stack.js` (shared state and Follow buttons) and `web/js/views/settings/watchlist.js` (Settings › What you
follow). Tests: `tests/test_v11_stack.py`.

## The list
<a id="list"></a>`settings` key `news.watchlist` (the v1.0 News watchlist, extended):

```json
{"entities": ["malware:qakbot", "cve:cve-2026-19868"], "keywords": ["ExampleGate"],
 "stack": [{"vendor": "SonicWall", "product": ""}, {"vendor": "Synology", "product": "DSM"}]}
```

* `stack`: vendors and products. Free text is split on a known vendor ("Synology DSM" → Synology / DSM; vendors known
  from KEV, vendor entities and the home-lab list); otherwise the whole text is one name. Kept once per normalised
  vendor and product.
* `entities`: entity ids, stored as followed and always read through the user's merges
  ([overrides](/data/entities.md#overrides)): `overrides.equivalents()` when matching, `overrides.resolve()` when
  deciding whether an id is already followed. Following the kept id of a merged pair adds nothing; unfollowing either
  id removes the follow.
* `keywords`: words, de-duplicated ignoring case.

`settings` key `stack.followed_at` remembers when each item was followed, for the one-time look-back on Watch.

A `matched` key names what matched: `stack:<label>`, the entity id as followed, or `keyword:<word>`. Responses carry
display names next to keys (`names`, `matched_names`).

## Matching
<a id="matching"></a>Names are normalised to lower-case ASCII word tokens; vendor names lose trailing corporate words
(Inc, Corp, Networks, Systems, Software, Technologies, …), so "Palo Alto Networks" = "Palo Alto" and "Cisco Systems,
Inc." = "Cisco". Spacing may differ ("Sonic OS" = "SonicOS") and a product may carry a model number ("SMA" finds
"SMA1000 Appliances").

| Against | How |
|---|---|
| CISA KEV entries | Vendor and product fields (`tags[0..1]`), plus CPE 2.3 strings where a record carries them (`cpe:2.3:o:synology:diskstation_manager:…` → Synology / diskstation manager). A vendor-only item matches the vendor; a distinctive single name ("UniFi", "OpenSSH") also matches a product. Followed CVE ids match exactly; vendor/product entities match like stack items; words match whole words in the CVE, vendor, product and name. |
| News stories | The digest (`/api/news/watchlist/digest`): entity mentions and `top_entities`, keywords in title/dek/text, and stack items as whole words (vendor and product both, or a distinctive product alone). |
| Network incidents | Open (new or acknowledged) incidents whose indicator or observed value is a followed address, domain, URL, hash or CVE; whose feed names a followed malware family or one of its aliases (`evidence.indicator.meta.malware`, e.g. a Feodo QakBot C2); whose title names something followed; or whose indicator is a KEV CVE of a followed product. |
| EPSS | Followed CVEs, and KEV CVEs of followed products, whose probability changed since the marker by at least 5 points or crossed 10%. |
| Ransomware victims | `ransomware_live` posts ("<group> claims <victim>"): the victim name against followed vendors, organisations and words; the group against followed actors and malware. |

**False-positive guards.** Names of three letters or fewer ("HP", "SMA", "DSM") and everyday words ("Progress",
"Arm", "Apple", "Edge", …) match a vendor field exactly, or a headline as written (case-sensitive), never a body. A short
product needs its vendor. Whole words only ("SonicWall" never matches "SonicWallet"). Victim matching reads only the
victim's name, so a group called "Barracuda" never makes Barracuda Networks a victim.

## Where it shows

* **Watch › Touches you**: new KEV entries, network incidents, EPSS jumps and ransomware victims that match, each with
  "You follow …". Right after following something, its KEV entries from the last 30 days show once (until Caught up).
  Still-open matching incidents are listed apart and not counted. See [Watch](/architecture/watch.md#briefing).
* **Watch › News you follow**: the digest since the marker.
* **Watch setup checklist**: "Follow what you run" with "What do you run?" chips (common home-lab gear with its KEV
  count, then KEV's busiest vendors).
* **Exploited Vulns (KEV) list**: "You follow SonicWall" on matching rows, a "You follow" filter chip, and a
  "Follow <vendor>" button on the others.
* **Story header**: "You follow …" and Follow buttons for the vendors, products, groups and malware it is about.
* **Entity drawer and entity page**: one Follow/Following button (not for countries, sectors, prefixes, techniques).
* **News rail watchlist**: lists every followed item, suggests products as you type, and edits the same list.
* **Settings › What you follow** (`#settings/follow`): the chips, a picker (KEV, CISA advisories, NVD vendors, home-lab
  gear, entities, or any word) and the list grouped as products, other things and words, with KEV counts.

Every Follow button is rendered by `followButton()` in `web/js/core/stack.js`; one document-level handler toggles it,
and a `nd:stack` window event (detail: the new list) lets views refresh.

## API
<a id="api"></a>

| Endpoint | Purpose |
|---|---|
| `GET /api/stack[?counts=true]` | The list with `names`, `equivalents`, `count` and, with counts, `kev_counts` (key → KEV entries matched). |
| `PUT /api/stack` | Replace the list; fields left out keep their value. |
| `POST /api/stack/follow` | `{entity}`, `{keyword}`, `{vendor, product}` or `{text}`. Returns the list, `added`, `already` (the existing key when nothing was added) and, for products, `kev`. |
| `POST /api/stack/unfollow` | `{key}` as in `matched`, or `{entity}` (any id of a merged pair), `{keyword}`, `{vendor, product}`. |
| `GET /api/stack/suggest?q=&limit=` | Vendors and products to follow: `{vendor, product, label, kev, from}` (`homelab`, `kev`, `advisory`, `nvd`). |
| `GET /api/stack/quick?limit=` | "What do you run?" chips: home-lab gear not followed yet, with KEV counts. |
| `GET /api/stack/kev` | Every KEV CVE that touches the list → `[{key, name}]` (the KEV list uses it). |
| `POST /api/stack/match` | Which followed items each record touches: `{items: [{key, vendor?, product?, cve?, text?, title?, cpe?, entities?}]}`. |
| `GET /api/stack/matches?since=` | Everything that touches the list since `since` (default: the marker window): `kev`, `network`, `epss`, `victims`. |

The old `/api/news/watchlist` endpoints keep working on the same list ([News](/data/news.md#watchlists)).
