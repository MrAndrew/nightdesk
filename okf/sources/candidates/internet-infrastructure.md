---
type: Source Candidates
title: "Candidate sources: Internet infrastructure, routing and outages"
description: "Candidate feeds for routing, outages, DDoS and reference data about networks."
tags: [sources, candidates, internet-infrastructure]
status: draft
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-04T14:00:00Z }
---

# Candidates

Probe = HTTP result fetching the feed with Night Desk's own User-Agent on 2026-11-04 ("key" means it needs a free or paid key and was not fetched). Size per fetch is measured where probed and estimated otherwise. Runs/day is a suggested cadence. Lake/day counts raw plus normalised copies of every fetch; the 1-year columns assume that cadence with no compression. Trust tiers are defined in [trust model](/sources/trust-model.md).

| Source | Provider | Trust | Access | Probe | Size/fetch | Runs/day | Lake/day | Lake 1y | DuckDB 1y | Why add it | Corroborates |
|---|---|---|---|---|---|---|---|---|---|---|---|
| [Cloudflare Radar API](https://radar.cloudflare.com/) | Cloudflare | B | free API token | key (400 without) | 300 KB | 96 | 57.6 MB | 21 GB | 0.04 GB | Outages, DDoS attack trends (L3/L7), BGP hijacks and route leaks, traffic anomalies by country/ASN. The main missing DDoS source. | IODA, RIS Live |
| [IODA raw signals](https://ioda.inetintel.cc.gatech.edu/) | Georgia Tech IODA | B | none | 200 | 13 KB | 96 | 2.5 MB | 0.91 GB | 0.00 GB | The underlying BGP, active-probe and telescope time series for each country; chartable context for outage events. | IODA outages |
| [GRIP BGP hijack detection](https://grip.inetintel.cc.gatech.edu/) | Georgia Tech INET | B | restricted (403 to automated clients) | 403 | 200 KB | 24 | 9.6 MB | 3.50 GB | 0.01 GB | Classified hijack/leak events with confidence; would corroborate our own origin-change detector. | RIS Live, Cloudflare Radar |
| [RIPEstat Data API](https://stat.ripe.net/docs/data_api) | RIPE NCC | A | none | 200 | 5 KB | 2000 | 20.0 MB | 7.30 GB | 0.00 GB | On-demand routing history, visibility and RIR data for any prefix/ASN; enrichment for BGP events. | RIS Live |
| [RIPE Atlas](https://atlas.ripe.net/) | RIPE NCC | A | none for public results | not probed | 500 KB | 24 | 24.0 MB | 8.76 GB | 0.02 GB | Latency/reachability measurements from 12k+ probes; confirms outages independently of BGP. | IODA |
| [RouteViews](https://www.routeviews.org/) | University of Oregon | A | none | not probed | 200,000 KB | 4 | 0.0 MB | 0.00 GB | 0.00 GB | Second independent BGP collector network (MRT dumps); corroborates RIS. | RIS Live |
| [PeeringDB](https://www.peeringdb.com/) | PeeringDB | B | none | 200 | 30,000 KB | ≤1 | 8.4 MB | 3.07 GB | 0.00 GB | Who operates each ASN, IXPs and facilities; reference data for naming networks. | CAIDA AS Rank |
| [CAIDA AS Rank](https://asrank.caida.org/) | CAIDA (UC San Diego) | A | none | 200 | 1 KB | 500 | 1.0 MB | 0.36 GB | 0.00 GB | ASN size, rank and relationships; lets the map weight impact by network size. | PeeringDB |
| [RIR delegation files](https://ftp.arin.net/pub/stats/) | ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC | A | none | 200 | 60,000 KB | ≤1 | 16.8 MB | 6.13 GB | 0.00 GB | Which country/registry each block and ASN is delegated to; ground truth for 'whose network'. | DB-IP |
| [Tor Onionoo](https://metrics.torproject.org/onionoo.html) | The Tor Project | A | none | 200 | 15,000 KB | 1 | 30.0 MB | 11 GB | 0.01 GB | Full relay details (flags, bandwidth, families), beyond the exit list. | Tor exits |
| [Certificate Transparency (crt.sh / CT logs)](https://crt.sh/) | Sectigo crt.sh, Google CT log list | A | none | crt.sh timeout; log list 200 | 65 KB | 1 | 0.1 MB | 0.05 GB | 0.00 GB | New certificates for watched domains (phishing look-alikes). Query per watched domain, not as a firehose. | CertStream (down) |

Category total if all were added at the suggested cadence: about 170 MB/day in the lake (62 GB/year uncompressed) and 0.2 MB/day in DuckDB.

# Sizing notes

* **RouteViews**: full update dumps are large; keep only derived events.
