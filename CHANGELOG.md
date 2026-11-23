# Changelog

What changes for you in each release of Night Desk. The newest release is first.

## 0.1.0-prealpha (2026-11-22)

The first public release. It's a pre-alpha: it works and has rough edges, and your feedback shapes what comes next
([open an issue](README.md#feedback-and-problems)).

### Your network

- **Import your sensor's logs:** Zeek and Suricata (or Security Onion, OPNsense or pfSense doing that job), plus
  Pi-hole and AdGuard Home DNS logs. Drag files in, drop them into a watched folder, or let your sensor push them to
  a separate, token-protected upload port. **Connect logs** walks you through each setup.
- **Checked against the threat lists as they were at that moment.** A contact on Tuesday is judged by Tuesday's
  lists, and when a list adds an address later, the logs you already imported are checked again.
- **Alerts you can follow:** a plain headline, "What to do", "Why this severity" and a "why it fired" chain for each
  alert. Alerts are grouped into incidents across days. "This is expected" rules hide traffic you know about, and a
  dismissed alert stays dismissed when you change a setting and change it back.
- **Devices** are recognised by MAC address or behaviour. You can rename, type, merge and annotate them, and
  new-device alerts start after a learning period.
- **Search logs:** filters on any field, including address ranges (they match DNS answers too), pivots, and a
  timeline you can drag to zoom.
- **Demo data:** sample logs on the Network page show alerts and their evidence before you import anything.

### The wider picture

- **Threat feeds:** exploited vulnerabilities (CISA KEV with EPSS scores), new CVEs, attacking and botnet
  infrastructure, internet outages and routing changes. Sources whose terms are unclear or non-commercial start off,
  and each one's terms are shown beside it.
- **News:** security research and news grouped into stories, with indicators and ATT&CK techniques picked out of the
  articles and checked against your logs.
- **Intel:** actors, malware, campaigns and tools, linked by evidence with its source and confidence, in a graph you
  can explore. Indicators export as CSV or STIX 2.1.
- **Watch,** the front page: what changed since you last looked, starting with your network, with a setup checklist
  on first run. **Follow what you run** puts news and exploited bugs about your own devices first.
- **Routing watch:** alerts for the networks (ASNs and prefixes) you choose, covering unexpected origins, RPKI-invalid
  routes, hijacks and leaks.
- **Dashboards, a world map and Cinema,** a lean-back 3D globe that tours notable events.
- **SQL console:** a read-only SQL workbench over all the data. It's off unless you start Night Desk with it turned on.

### Around the app

- **Runs on one machine you own.** No account, no cloud and no telemetry. Offline mode makes no connections beyond
  your own network, and everything already collected keeps working.
- **Install in one line:** Docker with HTTPS, reachable from this computer only or from your network with a user
  name you choose and a password it makes for you. Running the line again updates it and keeps your settings and
  data; `--reconfigure` asks the questions again and keeps the keys you added (`--reset-keys` removes them). Or run
  it without Docker using `uv` (see the README).
- **Works on a phone:** a real phone layout with a bottom tab bar, sheets and swipes, not just a narrow desktop page.
- **Help is built in:** help for the page you're on, a live "Is everything working?" check, a glossary, a guided
  tour, and **Copy diagnostics** for bug reports with your addresses and names removed.
- **Notifications (optional):** a webhook to ntfy, Gotify, Home Assistant, a Discord-compatible service or plain
  JSON when an alert needs you, when a log sender goes quiet, and a daily summary.
- **AI (optional, turned on in the app):** search by meaning, and chat that writes story summaries and entity briefs.
  Chat runs on the built-in helper (Apple silicon), Ollama, LM Studio or any OpenAI-compatible server. Nothing AI
  comes with the install.

### Known limits

- **One password, no user accounts:** whoever has it can do everything.
- **IPv6 neighbours:** when you run it without Docker and with your own password, 50 different wrong passwords in 10
  minutes from one IPv6 /64 block that whole /64 for 15 minutes. (The Docker install's sign-in is Caddy's, with a
  long random password the installer makes.)
- **Search by meaning in Docker:** Settings › AI can't start the helper inside the container. It runs on the Mac
  outside it, started by hand. Chat can use Ollama or LM Studio on the Mac directly.
- **Chat servers:** only Ollama and the built-in MLX helper were tested. LM Studio and hosted providers use the
  same requests but weren't tried.
- **Size caps:** the caps for the RPKI file, Cloudflare Radar, RIPEstat, ThreatFox and URLhaus are estimates, not
  measurements.
- **URLhaus:** a burst of more than 1,000 new URLs in an hour can be missed.
- **Platforms:** the one-line install has been tested on macOS so far; Linux should work too, and Windows runs it
  inside WSL.
