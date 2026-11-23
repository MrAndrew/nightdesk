---
type: Plan
title: Distribution plans
description: The three ways Night Desk could be distributed - a macOS app, a single Docker package and a public GCP website - with the decisions the critic rounds settled and where the full plans live.
tags: [project, distribution, plan]
status: draft
generated: { by: claude-code/claude-opus-4-8, at: 2026-11-18T22:00:00Z }
---

# Status

**Plans only. Nothing here has been built, bought or signed up for.** Written 2026-11-09 to 2026-11-15 by
planner agents and approved by independent critics (security, operations/cost, product/legal) over several
rounds. Prices and terms were checked then and change; re-verify before acting. The plans predate parts of
v1.1/v1.2 (for example a planned `osinthub/auth` module and `OSINTHUB_AUTH`/`OSINTHUB_PROFILE` that do not
exist).

The full, round-by-round plans (3,459 lines across seven pages: macOS, Docker, GCP and their source lists)
were removed from the bundle on 2026-11-18 to keep it readable. **The last commit that holds them in full is
`57e2258` on branch `v1.2`** (they were first written in `21a3351`; the Docker plan was last revised in
`9c524b0`). Recover one with `git show 57e2258:okf/project/distribution/<file>.md` (`macos.md`, `docker.md`,
`gcp.md` and their `-sources.md` lists).

# The three options

| Option | Audience | Shape | Order |
|---|---|---|---|
| **macOS app** | the owner, then testers | A signed, notarized DMG: a small native Swift menu-bar app supervises a relocatable CPython server; the UI is the default browser (v0.0) then a WKWebView on the same loopback URL. Apple silicon, macOS 14+, Sparkle updates, Keychain secrets. | — |
| **Single Docker package** | home servers, NAS and small trusted LANs | One image `nightdesk` plus a short `compose.yaml` with opt-in profiles (Caddy proxy, Qdrant, Ollama AI, ingest). Data in `/data`, `db/` its own volume. | **first** |
| **Public GCP website** | the public, read-only | "Publish through a gatekeeper": an ingest VM writes signed snapshots every 5 minutes; a separate promoter re-validates and KMS-signs them; served read-only through a global HTTPS load balancer + CDN, Cloudflare recommended in front. | then |

Recommended order: Docker first, then a read-only public site. The macOS app is a parallel track for the
owner's own daily use.

# Decisions the rounds settled

**Shared across tracks.**

* **One repo licence** covers every track, and there is none yet: it must be chosen before any public push.
* **Auth modes** are shared: `none` (dev/CLI on loopback), `app` (the Mac app) and `login` (Docker). The
  public GCP profile has **no admin plane on the internet** at all.
* **Feed terms** come from one per-source metadata table ([feed terms](/project/open-issues.md#before-the-repo-goes-public),
  `osinthub/feed_terms.py`), with two policies on it: Docker's `local_default` (on / ask) and GCP's
  `public_policy`. Only verified, clearly permissive feeds are on by default; non-commercial or unclear ones
  are listed unticked with their terms. A release gate fails while any row is unverified. **Silence never
  upgrades a policy.**
* **Supply chain:** multi-arch images, semver tags, cosign signatures, an SBOM, a Trivy gate, CI actions
  pinned by SHA, no `pull_request_target`.
* **Backups:** `CHECKPOINT` + `COPY FROM DATABASE`; a mandatory file-copy snapshot on any app, schema or
  DuckDB version change; downgrades refused before DuckDB opens the file.
* **Security fixes the plans assumed** were made as ordinary bug fixes and are only kept green by regression
  tests: the Host-header/DNS-rebinding allowlist and Origin check, zero non-local browser egress by default,
  the `/api/health` path-disclosure fix, and Spamhaus DROP fetched once a day.

**macOS.** Native Swift shell supervising a direct-child Python server; a per-install random path prefix with
a path-scoped cookie so other loopback servers never receive the session; AI models never bundled and off by
default; data under Application Support or any folder tracked by volume UUID; login Keychain for secrets;
Developer ID-signed and notarized (not the App Store); hardened runtime, not sandboxed in v1; the SQL
console's parser allowlist stays the primary control; SSRF IP-pinning before any non-owner release.

**Docker.** One self-complete image with login built in (one-time setup token, argon2id hashes, server-side
sessions, CSRF token), built-in HTTPS from a name-constrained local CA, a refusal to accept password logins
over plain HTTP from the LAN, and `127.0.0.1` in every quick start. No AI inside the image ("bring an
OpenAI-compatible endpoint"). Images on GHCR with a Docker Hub mirror for NAS discoverability. Honest
estimate: about 10-14 weeks to a public 1.0, most of it product changes, not packaging; a 3-4 week cut line
exists for "only my own server".

**GCP.** The public image has no netlog, uploads, SQL console, admin login or management routes, and starts
with an empty lake; the browser verifies a KMS-signed manifest and every file hash; snapshots are re-signed
every 5 minutes with a sequence number and 30-minute expiry so an old one cannot be replayed. Cloudflare,
recommended in front, is a trust root (Pages for the app, the CDN for signed data, WAF rules allowing only
known GET/HEAD paths) because Google's bucket-edge policies are allow/deny only with no rate limiting; a
GCP-only posture stays possible with a stated worst case. Accounts come only if a value gate proves demand;
multi-tenant is never offered.

# Shared prerequisites before any public release

Choose a repo licence (there is none yet), remove the third-party Sitdeck screenshots (done, 2026-11-18),
resolve the Tranco list's licence, settle per-feed default policy, and finish the
[terms checklist](/project/open-issues.md#before-the-repo-goes-public).
