"""Research and news feeds added for the News tab. Docs: okf/data/news.md, okf/sources/current/news_*.md

Each outlet is its own batch source so fetch health, cadence and trust tier are tracked per feed.
They reuse the RSS source from osinthub/sources/feeds.py (records() hook, record deltas, events).
Every feed was probed with the app's own User-Agent on 2026-11-04 and its robots.txt allows the
feed and article pages. Feeds that failed the probe are listed in SKIPPED and not registered.
"""
from __future__ import annotations

import re

from ..sources.feeds import SecurityNews, _RssSource
from ..sources.registry import register

# Trust tier per outlet label (okf/sources/trust-model.md). Also covers the labels used by the
# existing security_news source so articles from every feed get a tier.
# Graded with okf/sources/trust-model.md:
#   A  CERTs and agencies; a vendor's own research about its own products (raised per article below)
#   B  newsrooms with original reporting and named sources; vendor threat-research teams
#   C  outlets that mostly rewrite others' research or run vendor press releases; corroborate first
OUTLET_TIER: dict[str, str] = {
    "BleepingComputer": "B", "Krebs on Security": "B", "SANS ISC": "B", "CISA": "A",
    "The Hacker News": "C",   # mostly rewrites of vendor research, plus sponsored webinars and "expert insights"
}
# Outlet label -> "newsroom" (reporting) or "research" (primary vendor research with IOCs).
OUTLET_ROLE: dict[str, str] = {
    "BleepingComputer": "newsroom", "The Hacker News": "newsroom", "Krebs on Security": "newsroom",
    "SANS ISC": "research", "CISA": "research",
}


class _NewsFeed(_RssSource):
    """One outlet's RSS feed. `label` is the outlet name stored on events and articles."""

    label: str = ""
    url: str = ""
    trust_tier: str = "B"
    role: str = "newsroom"
    category = "news"
    kind_name, sev = "news", 0.3

    @property
    def feeds(self):  # type: ignore[override]
        return [(self.label, self.url)]

    def describe(self) -> dict:
        d = super().describe()
        d["trust_tier"] = self.trust_tier
        d["role"] = self.role
        return d


def _feed(sid, label, url, homepage, provider, description, tier="B", role="newsroom", interval=1200):
    cls = type(f"News_{sid}", (_NewsFeed,), dict(
        id=sid, name=label, label=label, url=url, homepage=homepage, provider=provider,
        description=description, trust_tier=tier, role=role, interval=interval,
        license="Publisher copyright; headlines and links only, articles fetched for local reading",
    ))
    OUTLET_TIER[label] = tier
    OUTLET_ROLE[label] = role
    return register(cls)


RESEARCH = 7200   # research feeds: 12 runs a day, as suggested in the candidates doc

_feed("news_therecord", "The Record", "https://therecord.media/feed", "https://therecord.media/",
      "Recorded Future News", "Cyber newsroom of Recorded Future: incidents, policy and nation-state reporting with named sources.")
_feed("news_securityweek", "SecurityWeek", "https://www.securityweek.com/feed/", "https://www.securityweek.com/",
      "SecurityWeek", "Broad vulnerability, incident and industry coverage.")
_feed("news_helpnetsecurity", "Help Net Security", "https://www.helpnetsecurity.com/feed/", "https://www.helpnetsecurity.com/",
      "Help Net Security", "Daily vulnerability, product security and research news; many items are vendor product announcements.",
      tier="C")
_feed("news_cyberscoop", "CyberScoop", "https://cyberscoop.com/feed/", "https://cyberscoop.com/",
      "Scoop News Group", "Policy, government and nation-state reporting.")
_feed("news_darkreading", "Dark Reading", "https://www.darkreading.com/rss.xml", "https://www.darkreading.com/",
      "Informa TechTarget", "Industry news and analysis.")
_feed("news_talos", "Cisco Talos", "https://blog.talosintelligence.com/rss/", "https://blog.talosintelligence.com/",
      "Cisco Talos", "Primary threat research from Cisco Talos, usually with IOCs.", role="research", interval=RESEARCH)
_feed("news_unit42", "Unit 42", "https://unit42.paloaltonetworks.com/feed/", "https://unit42.paloaltonetworks.com/",
      "Palo Alto Networks", "Primary threat research from Palo Alto Networks Unit 42, usually with IOCs.", role="research", interval=RESEARCH)
_feed("news_mstic", "Microsoft Threat Intelligence",
      "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/",
      "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/",
      "Microsoft", "Actor tracking (Storm-xxxx, Typhoon, Blizzard) and campaign reports.", role="research", interval=RESEARCH)
_feed("news_eset", "ESET Research", "https://www.welivesecurity.com/en/rss/feed/", "https://www.welivesecurity.com/en/eset-research/",
      "ESET (WeLiveSecurity)", "ESET's WeLiveSecurity blog: APT and malware research plus security news.", role="research", interval=RESEARCH)
_feed("news_elastic", "Elastic Security Labs", "https://www.elastic.co/security-labs/rss/feed.xml", "https://www.elastic.co/security-labs/",
      "Elastic", "Malware and detection research from Elastic Security Labs. Its list of articles is large (8 MB), so it is read every 6 hours.",
      role="research", interval=6 * 3600)

# Probed 2026-11-04 with the honest User-Agent and not added.
SKIPPED = {
    "Securelist (Kaspersky)": "https://securelist.com/feed/ refused the TCP connection (connection refused) from this network",
    "Google Threat Intelligence Group": "no working RSS path found; the documented feed URL returns 404",
    "MSRC blog": "the old RSS path now returns an HTML page with no entries",
    "Check Point Research": "feed and articles answer 202 with an AWS WAF challenge (x-amzn-waf-action: challenge)",
    "SentinelLabs": "feed works but article pages return 429 'Vercel Security Checkpoint' (bot check)",
    "Sophos X-Ops": "feed timed out (30 s) on every probe",
    "CISA advisories": "403 to non-browser clients; source cisa_advisories reads CISA's CSAF repository on GitHub instead",
}


# A research team writing about a security problem in its own company's products is the primary
# authority on it (trust model: "vendor PSIRTs for their own products"). The publisher's name alone
# ("ESET researchers uncover ...") is not a product, and using a product as a tool ("with Elastic
# Defend") is not the subject.
OWNED_PRODUCTS = {
    "Cisco Talos": ["cisco ios", "ios xe", "ios xr", "nx-os", "cisco asa", "adaptive security appliance", "cisco ftd",
                    "firepower", "webex", "meraki", "sd-wan", "catalyst center", "catalyst sd-wan", "nexus switch",
                    "nexus dashboard", "identity services engine", "cisco ise", "anyconnect", "secure client",
                    "secure firewall", "duo security", "cisco duo", "unified communications manager", "cisco smart licensing"],
    "Unit 42": ["pan-os", "globalprotect", "prisma cloud", "prisma access", "prisma sd-wan", "cortex xdr", "cortex xsoar",
                "cortex xsiam", "expedition", "palo alto networks firewall", "next-generation firewall"],
    "Microsoft Threat Intelligence": ["exchange online", "exchange server", "exchange", "sharepoint", "windows", "azure",
                                      "entra", "microsoft 365", "office 365", "office", "outlook", "teams", "defender",
                                      "edge", "iis", "onedrive", "intune", "copilot", "active directory"],
    "ESET Research": ["eset endpoint", "eset nod32", "eset smart security", "eset internet security", "eset protect",
                      "eset inspect", "eset server security", "eset mail security"],
    "Elastic Security Labs": ["elasticsearch", "kibana", "logstash", "elastic agent", "elastic defend", "elastic endpoint",
                              "beats", "elastic cloud", "fleet server"],
}
PUBLISHER_VENDOR = {"Cisco Talos": "cisco", "Unit 42": "palo alto", "Microsoft Threat Intelligence": "microsoft",
                    "ESET Research": "eset", "Elastic Security Labs": "elastic"}
OWN_PRODUCTS = {k: "|".join(re.escape(p) for p in sorted(v, key=len, reverse=True)) for k, v in OWNED_PRODUCTS.items()}
_PROBLEM = (r"cve-\d{4}-\d+|vulnerabilit\w*|flaws?|bugs?|exploit\w*|zero-day|0-day|advisory|compromis\w*|breach\w*|"
            r"backdoor\w*|activity on|attacks? (on|against)|targets?|targeting|targeted|intrusions?|hijack\w*|"
            r"bypass\w*|rce|remote code execution|patch\w*|outage|misconfigur\w*|exposed|leak\w*")
_THREAT = re.compile(r"\b(" + _PROBLEM + r"|malware|ransomware|stealer|botnet|apt|threat (report|actor|brief)|campaign|"
                     r"operation|disrupt\w*|takedown|phishing|espionage|actor|backdoor|trojan|infostealer|loader|rat|"
                     r"attacks?|uncover\w*|discover\w*|researchers)\b", re.I)
_TOOL_USE = r"\b(with|using|via|in|into|to|from|leaving|on top of|inside)\s+(the\s+)?({prod})\b"


# In the lead, only vulnerability-class terms count: leads routinely name the publisher's products as
# the channel or the team ("used Microsoft Teams messages", "Microsoft Defender Experts observed").
_VULN = (r"cve-\d{4}-\d+|vulnerabilit\w*|flaws?|bugs?|exploit\w*|zero-day|0-day|security update|patch(ed|es)?|"
         r"bypass\w*|rce|remote code execution|misconfigur\w*")
_TEAM_NAMES = r"\b(defender experts|defender for endpoint research|microsoft threat intelligence|talos|unit 42|eset research|elastic security labs)\b"



def own_product_problem(label: str | None, title: str | None, lead: str | None = None,
                        cve_vendors: set[str] | None = None) -> bool:
    """The article is about a security problem in the publisher's own product:

    * an owned product family (not the publisher's name) sits within six words of a problem term in
      the headline or the lead's first two sentences, and isn't used as a tool ("with Elastic Defend");
    * or a CVE the headline or lead names belongs to the publisher (`cve_vendors`, from KEV/NVD).
    """
    rx = OWN_PRODUCTS.get(label or "")
    if not rx or not (title or lead):
        return False
    vendor = PUBLISHER_VENDOR.get(label or "")
    if cve_vendors and vendor and any(vendor in v.lower() for v in cve_vendors):
        return True
    def hit(text: str, terms: str) -> bool:
        text = re.sub(_TEAM_NAMES, " ", re.sub(_TOOL_USE.format(prod=rx), " ", text))
        near = rf"\b({rx})\b(\W+\w+){{0,6}}?\W+({terms})\b|\b({terms})\b(\W+\w+){{0,6}}?\W+({rx})\b"
        return bool(re.search(near, text))
    first = " ".join(re.split(r"(?<=[.!?])\s+", (lead or "").strip())[:2]).lower()
    return hit((title or "").lower(), _PROBLEM) or hit(first, _VULN)


def vendor_promo(label: str | None, title: str | None) -> str | None:
    """A research blog post about its own products, or the publisher itself, with no threat in the
    headline is product marketing."""
    rx = OWN_PRODUCTS.get(label or "")
    vendor = PUBLISHER_VENDOR.get(label or "")
    if not rx or not title:
        return None
    if re.search(rf"\b({rx}|{re.escape(vendor or '~')})\b", title, re.I) and not _THREAT.search(title):
        return f"{label} post about its own products"
    return None


def tier_for(label: str | None, source_id: str | None = None, title: str | None = None, lead: str | None = None,
             cve_vendors: set[str] | None = None) -> str:
    """Trust tier for one article: the outlet's tier, raised to A for a vendor's research on a
    security problem in its own products."""
    if own_product_problem(label, title, lead, cve_vendors):
        return "A"
    if label and label in OUTLET_TIER:
        return OUTLET_TIER[label]
    return "B" if source_id in (SecurityNews.id,) else "C"


def tier_reason(label: str | None, source_id: str | None = None, title: str | None = None, lead: str | None = None,
                cve_vendors: set[str] | None = None) -> str:
    t = tier_for(label, source_id, title, lead, cve_vendors)
    if t == "A" and label in OWN_PRODUCTS:
        return f"{label} on a security problem in its own company's products"
    return {"A": "agency or CERT", "B": "newsroom with original reporting, or vendor threat research",
            "C": "mostly rewrites or vendor announcements; corroborate"}.get(t, "")


def role_for(label: str | None) -> str:
    return OUTLET_ROLE.get(label or "", "newsroom")
