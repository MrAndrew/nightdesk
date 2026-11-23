"""Feed terms and the first-run "Choose your sources" step.

One row per source: what it gives (plain language), its terms in one line, a link to them, and its default for a
local install (`on` or `ask`) under the policy in okf/project/distribution.md, "Feed terms" (terms first read
2026-11-09, re-read 2026-11-19 for the pre-alpha terms review): `on` only for verified-permissive or syndication
terms; everything non-commercial, unclear, unstated, research-only or key-gated is `ask` and starts unticked on the
first-run screen. An `ask` source is also off in code (`Source.default_enabled = False`), so nothing fetches it before
the user agrees (tests/sources/test_v12_feeds.py holds every source to this).

The step is offered once, on a brand-new lake (see `state()`); "Apply" or "Keep" ends it for good. Applying turns
each listed source on or off through the scheduler (the same path as the Sources toggles). Nothing here fetches.
Reference: okf/architecture/web-client.md#settings
"""
from __future__ import annotations

import datetime as dt

from . import db

CHOICE_KEY = "settings.sources_choice"
NEW_LAKE_DAYS = 7   # a lake whose first feed run is younger than this, and with no choice made, is "new"

PERSONAL = "personal use"   # badge for non-commercial / research-only terms

# id -> gives, terms (one line), licence, url, local_default, badge
TERMS: dict[str, dict] = {
    "cisa_kev": dict(gives="Vulnerabilities attackers are exploiting right now, from CISA.",
                     terms="Public domain (CC0). No CISA endorsement implied.", licence="CC0 1.0",
                     url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog", default="on"),
    "nvd_recent": dict(gives="Newly published CVEs with their severity scores.",
                       terms="US Government data. This product uses the NVD API but is not endorsed or certified by the NVD.",
                       licence="US Government work", url="https://nvd.nist.gov/developers/terms-of-use", default="on"),
    "epss": dict(gives="How likely each CVE is to be exploited in the next 30 days (FIRST EPSS).",
                 terms="Free to use with credit to FIRST.", licence="Free with attribution",
                 url="https://www.first.org/epss/", default="on"),
    "cisa_advisories": dict(gives="CISA security advisories and the CVEs they cover.",
                            terms="US Government work, read from CISA's public CSAF repository.",
                            licence="US Government work", url="https://github.com/cisagov/CSAF", default="on"),
    "feodo_c2": dict(gives="Botnet command servers (Emotet, QakBot and others) to check your logs against.",
                     terms="abuse.ch: Feodo data is CC0; no high-volume harvesting and no AI use, so it is kept out of AI features. Credit abuse.ch.", licence="CC0",
                     url="https://abuse.ch/terms-of-use/", default="on"),
    "sslbl": dict(gives="TLS certificates used by malware servers.",
                  terms="abuse.ch terms of use; credit abuse.ch.", licence="CC0",
                  url="https://abuse.ch/terms-of-use/", default="on"),
    "tor_exits": dict(gives="Tor exit relays, so Tor traffic is labelled as such.",
                      terms="Tor Metrics data is CC0. Credit the Tor Project.", licence="CC0",
                      url="https://metrics.torproject.org/", default="on"),
    "security_news": dict(gives="Headlines and summaries from about a dozen security news sites, linked to the originals.",
                          terms="Each outlet's public RSS feed, used as intended: headline, summary and a link.",
                          licence="Publisher copyright (syndication)", url="", default="on"),
    "spamhaus_drop": dict(gives="Hijacked address blocks that should never send you traffic.",
                          terms="Free to use under Spamhaus' terms; no licence granted and the right can be revoked. Credit The Spamhaus Project. Fetched at most once a day.",
                          licence="Conditional free use", url="https://www.spamhaus.org/blocklists/drop-fair-use-policy/", default="ask"),
    "dshield_top": dict(gives="The internet's busiest scanners this week, from SANS ISC.",
                        terms="CC BY-NC-SA 4.0: fine for protecting your own network, commercial included; no resale.",
                        licence="CC BY-NC-SA 4.0", url="https://isc.sans.edu/api/", default="ask", badge=PERSONAL),
    "blocklist_de": dict(gives="Addresses caught attacking servers (SSH, mail, web logins).",
                         terms="No formal licence; free unless you download in large volume.", licence="Unclear",
                         url="https://www.blocklist.de/en/terms.html", default="ask"),
    "cins_army": dict(gives="Addresses with a poor reputation, from the CINS Army list.",
                      terms="\"Parse and use in any way you see fit\"; no formal licence.", licence="Informal",
                      url="https://cinsscore.com/", default="ask"),
    "et_compromised": dict(gives="Hosts Proofpoint believes are compromised.",
                           terms="No licence stated; copyright Proofpoint.", licence="Unclear",
                           url="https://rules.emergingthreats.net/", default="ask"),
    "ioda_outages": dict(gives="Internet outages by country and network (Georgia Tech IODA).",
                         terms="No terms page found; cite IODA, Georgia Tech.", licence="Unclear",
                         url="https://ioda.inetintel.cc.gatech.edu/", default="ask"),
    "ris_live": dict(gives="Live routing updates (BGP) from RIPE NCC for the networks in Routing watch only.",
                     terms="RIPE NCC data terms: research and network operations, no commercial use.",
                     licence="Research / non-commercial", url="https://www.ripe.net/manage-ips-and-asns/db/support/documentation/terms",
                     default="ask", badge=PERSONAL),
    # Routing watch (okf/project/routing-watch.md): none of these runs until the user adds a network to watch.
    # `ask`: no terms are stated, and silence never upgrades a policy. It can be ticked here before any network is
    # watched (waits_for_watch: Apply saves the answer either way), and its Routing watch toggle works before the
    # first network too. Nothing switches it on by itself: when a network is watched and no choice is saved, Routing
    # watch asks once (osinthub/routing/api.py ASK_FIRST) and saves the answer.
    "rpki_roas": dict(gives="Whether the networks you watch are signed with RPKI, from a public daily file checked on this computer.",
                      terms="No terms stated by the publishers (Cloudflare, rpki-client). Downloaded at most once a day, and only when it changed.",
                      licence="No terms stated", url="https://rpki.cloudflare.com/", default="ask"),
    "cf_radar_bgp": dict(gives="Suspected hijacks and route leaks involving the networks you watch, from Cloudflare Radar. Needs your own free token.",
                         terms="CC BY-NC 4.0: non-commercial use, credit Cloudflare Radar. Each user supplies their own API token.",
                         licence="CC BY-NC 4.0", url="https://developers.cloudflare.com/radar/", default="ask", badge=PERSONAL),
    "ripestat": dict(gives="Who announces each watched network, how widely it is seen and its upstreams, from RIPEstat. RIPE sees which networks you look up.",
                     terms="RIPEstat terms: for analysis, monitoring and research; no redistribution or commercial use without RIPE NCC's written permission. Fewer than 1,000 lookups a day.",
                     licence="RIPEstat terms", url="https://www.ripe.net/about-us/legal/ripestat-service-terms-and-conditions",
                     default="ask", badge=PERSONAL),
    "bluesky_cyber": dict(gives="Live posts from the security community on Bluesky.",
                          terms="Bluesky developer guidelines.",
                          licence="Platform terms", url="https://docs.bsky.app/docs/support/developer-guidelines",
                          default="ask"),
    "ransomware_live": dict(gives="Victims named on ransomware leak sites.",
                            terms="Non-commercial use with attribution and a link back; commercial use needs written approval.",
                            licence="Non-commercial", url="https://www.ransomware.live/t&c", default="ask", badge=PERSONAL),
    "threatfox": dict(gives="Fresh malware servers and indicators from ThreatFox. Needs the free abuse.ch key.",
                      terms="abuse.ch terms of use; needs a personal key.", licence="abuse.ch terms",
                      url="https://abuse.ch/terms-of-use/", default="ask"),
    "urlhaus": dict(gives="Links that serve malware, from URLhaus. Needs the free abuse.ch key.",
                    terms="abuse.ch terms of use; needs a personal key.", licence="abuse.ch terms",
                    url="https://abuse.ch/terms-of-use/", default="ask"),
}


# A security-news outlet's own feed (news_<outlet>): the syndication rule, on by default.
NEWS_OUTLET = dict(gives="Headlines and summaries from this outlet, linked to the original articles.",
                   terms="The outlet's public RSS feed, used as intended: headline, summary and a link.",
                   licence="Publisher copyright (syndication)", url="", default="on")


def row(sid: str) -> dict:
    t = TERMS.get(sid) or (NEWS_OUTLET if sid.startswith("news_") else {})
    return {"gives": t.get("gives", ""), "terms": t.get("terms", "Terms not reviewed yet."), "licence": t.get("licence", ""),
            "terms_url": t.get("url", ""), "local_default": t.get("default", "ask"), "badge": t.get("badge")}


def waits_for_watch(src) -> bool:
    """A Routing watch source that cannot run only because no network is watched yet (no key missing): the user can
    still say yes or no to it now, and the answer is saved for when the first network is added."""
    try:
        from .routing import watchlist
        return src.unavailable() == watchlist.WAITING
    except Exception:
        return False


def _is_new_lake() -> bool:
    """No choice made yet, no source toggled by hand, and the first feed run is recent (or there is none)."""
    try:
        if db.query("SELECT count(*) AS n FROM source_state WHERE enabled IS NOT NULL")[0]["n"]:
            return False
        first = db.query("SELECT min(started) AS t FROM runs")[0]["t"]
    except Exception:
        return False
    if first is None:
        return True
    if first.tzinfo is None:
        first = first.replace(tzinfo=dt.UTC)
    return dt.datetime.now(dt.UTC) - first < dt.timedelta(days=NEW_LAKE_DAYS)


def peek() -> str:
    """state() without saving a decision: the saved state, else what state() would decide now."""
    s = db.get_setting(CHOICE_KEY, None)
    if isinstance(s, dict) and s.get("state") in ("pending", "done", "not_needed"):
        return s["state"]
    return "pending" if _is_new_lake() else "not_needed"


def state() -> str:
    """'pending' (offer the step), 'done' (applied or kept) or 'not_needed' (an existing lake). Decided once and
    saved, so a lake that was new when first asked stays pending until the user answers."""
    s = db.get_setting(CHOICE_KEY, None)
    if isinstance(s, dict) and s.get("state") in ("pending", "done", "not_needed"):
        return s["state"]
    st = "pending" if _is_new_lake() else "not_needed"
    db.set_setting(CHOICE_KEY, {"state": st, "at": dt.datetime.now(dt.UTC).isoformat()})
    return st


def mark_done(how: str) -> None:
    db.set_setting(CHOICE_KEY, {"state": "done", "how": how, "at": dt.datetime.now(dt.UTC).isoformat()})
