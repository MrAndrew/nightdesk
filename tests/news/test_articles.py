"""Articles: what the extractor keeps from a page (boilerplate lines, link lists, language, author, sponsored), and
which trust tier a story gets (A only for a vendor's research on a security problem in its own products).

    uv run --with pytest pytest tests/news/test_articles.py -q
"""
from __future__ import annotations

from _lake import make_lake
LAKE = make_lake("articles")

from osinthub.news import extract as X  # noqa: E402
from osinthub.news.sources import tier_for, vendor_promo  # noqa: E402

BODY = " ".join(f"Researchers found that the attackers used method number {i} to reach the servers of the victim." for i in range(30))


def page(body_html, head="", lang="en"):
    return (f'<html lang="{lang}"><head><title>Story title</title>{head}</head><body><article><h1>Story title</h1>'
            f"{body_html}</article></body></html>")


fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


def test_extraction_rules():
    html = page(f"<p>{BODY}</p><p>Related: <a href='/x'>Another story about something</a></p>"
                f"<p>{BODY}</p><ul><li><a href='/a'>Promo one</a></li><li><a href='/b'>Promo two</a></li><li><a href='/c'>Promo three</a></li></ul>"
                "<p>Subscribe to our newsletter</p>",
                head='<script type="application/ld+json">{"@type":"NewsArticle","author":{"@type":"Person","name":"Jane Writer"}}</script>')
    ex = X.extract(html, "https://www.securityweek.com/story/")
    check("'Related:' line dropped", "Related:" not in ex["text"], ex["text"][-300:])
    check("link list dropped", "Promo two" not in ex["text"])
    check("newsletter line dropped", "newsletter" not in ex["text"].lower())
    check("body kept", ex["text"].count("Researchers found") >= 50)
    check("author from JSON-LD", ex["author"] == "Jane Writer", ex["author"])

    it = " ".join(["Gli attacchi informatici contro le aziende italiane sono aumentati e non sono stati ancora identificati i responsabili, "
                   "secondo gli esperti della sicurezza che hanno analizzato la situazione per il governo."] * 8)
    ex = X.extract(page(f"<p>{it}</p>", lang="en"), "https://www.darkreading.com/x-italian")
    check("language from text, not the html lang attribute", ex["lang"] == "it", ex["lang"])

    ex = X.extract(page(f"<p>Sponsored by ExampleCorp</p><p>{BODY}</p>", head='<meta name="author" content="Sponsored by ExampleCorp">'),
                   "https://www.bleepingcomputer.com/news/security/x/")
    check("sponsored post detected", bool(ex["sponsored"]), ex["sponsored"])
    ex = X.extract(page(f"<p>{BODY}</p>", head='<meta name="author" content="Unit">'), "https://krebsonsecurity.com/2026/11/x/")
    check("bad byline rejected, site default used", ex["author"] == "Brian Krebs", ex["author"])
    ex = X.extract(page(f"<p>{BODY}</p>"), "https://unit42.paloaltonetworks.com/x/")
    check("no sponsored flag on normal article", ex["sponsored"] is None, ex["sponsored"])
    print("ALL PASS" if not fails else f"{len(fails)} FAILED")
    assert not fails, f"{len(fails)} failed: {fails}"


# ---------------------------------------------------------------- trust tiers
CASES = [
    ("ESET Research", "ESET researchers uncover new backdoor used by Gamaredon",
     "ESET researchers have discovered a backdoor that Gamaredon deploys against Ukrainian government targets.", None, "B"),
    ("Elastic Security Labs", "Elastic Security Labs discovers attacks on exposed Jupyter servers",
     "Elastic Security Labs observed attackers exploiting misconfigured Jupyter notebooks to deploy miners.", None, "B"),
    ("Microsoft Threat Intelligence", "Token theft campaign targets Exchange Online tenants",
     "Microsoft observed a threat actor abusing OAuth applications to read mail in Exchange Online.", None, "A"),
    ("Unit 42", "Misconfigurations in Prisma Cloud deployments exposed secrets",
     "Unit 42 found that misconfigured Prisma Cloud integrations exposed API keys.", None, "A"),
    ("Unit 42", "Threat brief: attackers target GlobalProtect portals",
     "We are tracking exploitation attempts against GlobalProtect gateways.", None, "A"),
    ("Unit 42", "Active Exploitation of May 2026 PAN-OS CVE-2026-0257", "", None, "A"),
    ("Cisco Talos", "Microsoft Patch Tuesday for October 2026 — Snort rules and prominent vulnerabilities",
     "Microsoft released its monthly security update on Tuesday, disclosing 1,400 vulnerabilities.", None, "B"),
    ("Elastic Security Labs", "From 88 lines to 1: Detecting DLL hijacking with Elastic Defend",
     "DLL hijacking is a common technique; here is how to detect it with Elastic Defend.", None, "B"),
    ("Microsoft Threat Intelligence", "Phishing Abuses RMM Tools for Persistent Access",
     "In July 2026, Microsoft Defender Experts observed phishing campaigns targeting organizations across multiple industries.", None, "B"),
    ("Microsoft Threat Intelligence", "From help desk impersonation to AD CS abuse",
     "Microsoft Threat Intelligence investigated two intrusions in which threat actors used Microsoft Teams messages to impersonate IT staff.", None, "B"),
    ("Cisco Talos", "UAT-1234 exploits a zero-day", "The actor exploited CVE-2026-5555 in edge devices.", {"Cisco IOS XE"}, "A"),
]


def test_tiers():
    for label, title, lead, vendors, want in CASES:
        assert tier_for(label, None, title, lead, vendors) == want, (label, title)
    assert vendor_promo("Elastic Security Labs", "Elastic Workflows GA: automation where your security data already lives")
