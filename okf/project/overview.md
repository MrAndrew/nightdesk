---
type: Project Overview
title: Night Desk project overview
description: Night Desk is a self-hosted cyber OSINT hub that collects public threat and internet-health data and makes it easy to explore on maps, globes and charts.
tags: [project, scope]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-22T18:07:00Z }
---

# Purpose

Night Desk is the analysis desk for the sensor you already run. It reads the logs a home network's Zeek or Suricata sensor already writes (directly, or from Security Onion, OPNsense or pfSense; it also imports Pi-hole and AdGuard Home DNS logs with their filter verdicts, `osinthub/netlog/sinkhole.py`) and answers "what touched my network, and was it bad at the time?":

* every connection is checked against the threat lists as they were at that moment, from the history the app keeps of every list;
* old logs are re-checked when a list changes, so a later listing still raises an alert;
* indicators that researchers publish in the news are matched against the network too, when the article clearly presents them as indicators;
* every alert carries an evidence chain written so anyone can follow it.

Around that it collects open-source intelligence about cyberspace and shows how it is trending: exploited vulnerabilities, new CVEs, attacking and botnet infrastructure, hijacked address space, internet outages, routing changes, security news and social chatter. It runs on one machine or a home server with no cloud services, no accounts and no telemetry.

# Audience

A home-lab owner, or one analyst, who already runs a network sensor and wants its logs judged against public threat data, with the evidence and the raw data kept locally. Not multi-user: there is one sign-in.

# Scope

* **In scope:** public, free sources (batch and live streams); local storage in a data lake plus DuckDB; a localhost web client with dashboards, a 3D globe, analytics and a SQL workbench; network-log alerts; opt-in local webhook notifications (`osinthub/notify.py`, [notifications](/architecture/notifications.md)); Docker deployment.
* **Out of scope for now:** paid data sources, and the non-cyber domains the reference tool also covers (conflict, aviation, maritime, markets).
* **Non-goals (decided):** multi-user accounts and roles; a TAXII or MISP server or other sharing platform (exports to STIX, MISP JSON and CSV cover sharing); a cloud relay; active scanning or packet capture. For remote or multi-person access, put it behind your own reverse proxy and single sign-on.

# Stack

Python 3.14 (FastAPI, uvicorn, httpx, websockets) for ingest, API and static hosting; DuckDB for storage and queries; plain ES-module JavaScript with MapLibre GL, globe.gl and ECharts in the browser; Caddy as the reverse proxy in Docker. See [system architecture](/architecture/system.md).

# Quality bar

The UI was first built and judged against a reference OSINT tool (Sitdeck) in a blind builder/critic loop; that
version is tagged `v1.0` in git.
