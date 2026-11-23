---
type: Architecture
title: Notifications
description: The opt-in webhook (ntfy, Gotify, Home Assistant, Discord-compatible, plain JSON) for a new needs-you incident, a log sender going quiet and a daily summary; destination checks with DNS-rebinding defence, offline behaviour, delivery with retries and the delivery log.
tags: [architecture, notifications, netlog, watch, api, privacy]
generated: { by: claude-code/claude-opus-5-5, at: 2026-11-11T00:30:00Z }
---

# Notifications

Night Desk can post a short message to one webhook when something needs the owner. It is **off by default** and sends
nothing until it is turned on in **Settings › Notifications** (`#settings/notifications`). Backend:
`osinthub/notify.py` (registers itself as the `notify` extension from `osinthub/api.py`). Client:
`web/js/views/settings/notifications.js`. Tests: `tests/test_v11_notify.py` (a local test HTTP server on 127.0.0.1;
nothing leaves the machine). Decision record: v1.1 plan, review items M8/T12 and challenge §1 row 6.

## What a message holds

A **title**, a **severity** and a **link** back to Night Desk (plus a one-line message repeating the title). The text is
built from fixed phrases in `notify.py`, never by a language model:

* "High alert: a device contacted a known command-and-control server", one phrase per kind of incident
  (`notify.phrase`, from the incident kind of [incidents](/data/netlog.md#incidents-and-expected-traffic)).
* No IP addresses, MACs, hostnames, indicators, list entries or log lines, ever.
* Device names (or the log sender's name) only with **Include device names** ticked: "… (Living room TV)".
* Alerts from abuse.ch lists (ThreatFox, URLhaus, SSLBL) get the generic wording ("an address on a threat list"):
  nothing derived from abuse.ch data goes out.
* The link is `<Links open at>/#network/alerts/<incident id>`. The form fills in the address the browser is using. When
  that is a loopback address (127.0.0.1, localhost, ::1) it warns plainly that a phone can't open it and suggests
  `http://<computer name>.local:<port>` and this computer's LAN address (`link_hint` in `GET /api/notify`; found
  with a UDP socket's route lookup, which sends nothing). When Night Desk only listens on loopback it says a phone also
  needs a way in (a reverse proxy or `OSINTHUB_HOST`). Send test reports the exact link it sent.

## Triggers

Checked after every `netlog_alerts` bus message (a matching run, new devices, a sender going quiet) and every 60 s.

| Trigger | When | Rules |
|---|---|---|
| Alert | A **needs-you** incident (untriaged, not hidden by an expected-traffic rule, not demo data) at or above the minimum severity: **high** (default) or **high and medium**. | One message per incident, whatever its number of per-day alerts (an incident across UTC midnight is one). Again only when its severity rises ("— now high"). Incidents already open when notifications are turned on, or when the minimum or the sender option changes, are taken as known and not sent. |
| Log sender quiet | The `sensor_silent` alert of [push ingest](/data/netlog.md) is open (medium, high after a day). | On by default when notifications are on, whatever the minimum. Once per outage; again when it turns high. |
| Daily summary | Once a day at the chosen local time (sent up to 6 h late if Night Desk was not running). | Counts under fixed section names from the [Watch briefing](watch.md#briefing) since the last summary: alerts that need you (high, medium), newly exploited vulnerabilities, touches your network or what you follow, news you follow, big stories, feed problems; and a link to `#watch`. **No item text at all**: headlines, titles, product names and CVE ids can carry an address, a domain, a hash or what your network touched. Demo-derived items are never counted. |

The ledger table `notify_seen (alert_id, incident, srank, notified_at)` records every alert of every incident that was
sent or taken as known, so a regrouped incident (a late import joining two) is not sent twice.

**Quiet hours** (optional, this computer's clock, may cross midnight) hold alert and sender messages in the setting
`notify.held`; they go out when quiet hours end, folded into one "N alerts came in during quiet hours" message when
there are more than three. The summary is not held.

## Formats

| Preset | Address | Request (docs) |
|---|---|---|
| ntfy | `http://ntfy.lan/<topic>` | JSON to the server root: `{topic, title, message, priority 4/3/2, tags, click}` ([publish as JSON](https://docs.ntfy.sh/publish/#publish-as-json)). Basic auth from `user:pass@` in the address. |
| Gotify | `http://gotify.lan/message?token=<app token>` | `{title, message, priority 8/5/3/1, extras: {client::display, client::notification.click.url}}` ([push messages](https://gotify.net/docs/pushmsg), [extras](https://gotify.net/docs/msgextras)). `/message` is added if missing. |
| Home Assistant | `http://homeassistant.local:8123/api/webhook/<id>` | `{title, message, severity, link, trigger, time}`, read as `trigger.json.*` in the automation ([webhook trigger](https://www.home-assistant.io/docs/automation/trigger/#webhook-trigger)). |
| Discord-compatible | `…/api/webhooks/<id>/<token>` | `{username, allowed_mentions: {parse: []}, embeds: [{title, description, url, color}]}` ([execute webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)). |
| Plain JSON | any | `{app, trigger, title, message, severity, link, time}`. |

## Destinations and egress

* **Local by default.** Allowed without asking: loopback, private (10/8, 172.16/12, 192.168/16), link-local,
  100.64/10 (Tailscale, CGNAT), IPv6 `::1`, `fe80::/10`, `fc00::/7`, and names that are single-label, `localhost`, or
  end in `.lan`, `.local`, `.home.arpa`, `.internal`, `.localdomain`, `.home`.
  Tailscale and CGNAT (100.64/10) and IPv4 link-local count as local because home labs use them; the cloud metadata
  address 169.254.169.254 (and `fd00:ec2::254`) is never a destination. Old numeric spellings (`2130706433`,
  `0x7f000001`, `0177.0.0.1`) are read as the address they mean at save time too. IPv6 link-local addresses lose
  their scope id when pinned, so give such a host by name.
* **Anything else** needs **Send to an internet service**; ticking it shows a plain warning of what leaves the machine.
* **At send time** the host is resolved again and **every** address checked; the request then goes to that checked
  address (Host header and TLS name kept, `sni_hostname`). A local-looking name that now resolves to the internet is
  refused ("blocked"): no DNS-rebinding bypass. Redirects are not followed; proxy variables are ignored.
* **Offline** (`OSINTHUB_OFFLINE=1`): anything not local is not sent and is logged as **held: offline** (an internet
  name is not even looked up). Local destinations still work.
* **Secrets.** The saved address can hold a token, so the API returns only `url_masked` (`http://gotify.lan/…`) and the
  host; the delivery log and Night Desk's own log lines name the host only; httpx's request log lines for these
  requests are dropped.

## Delivery

A queue capped at 50 (the oldest is dropped and logged when full), sent by one background task. Each message gets up to
three tries, 10 s timeout each, 2 s then 10 s apart; network errors, 429 and 5xx are retried, other answers are not.
The last 20 outcomes (time, trigger, title, host, status `sent | failed | held | blocked | dropped`, short detail) are
kept in the setting `notify.log` and shown in Settings. An incident is marked as notified when its message is queued, so a message lost to a restart or to three failed tries is not sent again later (the delivery log shows the failure). Matching and ingest never call into this module; a failure here
is logged and the next check runs as usual.

Settings keys: `notify.config`, `notify.log`, `notify.held`, `notify.digest_last`. API: [`/api/notify`](api.md) (`/test` and `/digest` also return the `link` they sent).
