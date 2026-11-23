"""Main-text extraction from article HTML (trafilatura), plus bot-check and paywall detection."""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit

import trafilatura

_MDLINK = re.compile(r"\[([^\]]*)\]\((?:[^()\s]|\([^()]*\))+\)")
_LANG = re.compile(r"<html[^>]*\slang=[\"']?([A-Za-z]{2})", re.I)
_CANON = re.compile(r"<link[^>]+rel=[\"']canonical[\"'][^>]*>", re.I)
_HREF = re.compile(r"href=[\"']([^\"']+)[\"']", re.I)

# Markers of an interstitial bot check. These pages are never worked around: the article is
# marked blocked with the reason.
BOT_MARKERS = [
    (re.compile(r"<title>\s*Just a moment\.\.\.\s*</title>", re.I), "bot check (Cloudflare challenge)"),
    (re.compile(r"cf-chl-|challenge-platform/h/", re.I), "bot check (Cloudflare challenge)"),
    (re.compile(r"<title>\s*Attention Required!", re.I), "bot check (Cloudflare block)"),
    (re.compile(r"Enable JavaScript and cookies to continue", re.I), "bot check (JavaScript challenge)"),
    (re.compile(r"_Incapsula_Resource|Request unsuccessful\. Incapsula", re.I), "bot check (Imperva)"),
    (re.compile(r"px-captcha|perimeterx", re.I), "bot check (PerimeterX)"),
    (re.compile(r"datadome", re.I), "bot check (DataDome)"),
    (re.compile(r"<title>\s*Vercel Security Checkpoint", re.I), "bot check (Vercel Security Checkpoint)"),
    (re.compile(r"<title>[^<]*(Access Denied|Are you a robot|Verify you are human)", re.I), "bot check"),
]
_PAYWALL_LD = re.compile(r'"isAccessibleForFree"\s*:\s*"?(false|False)"?')
_PAYWALL_TXT = re.compile(r"(subscribe to (continue|read)|this article is for (subscribers|members) only|"
                          r"already a subscriber\? (log|sign) in|to continue reading,? (please )?(subscribe|log in|sign in))", re.I)


def detect_block(html: str, text_len: int) -> str | None:
    head = html[:200_000]
    for rx, why in BOT_MARKERS:
        if rx.search(head):
            # 'datadome' and similar also appear in normal pages that load the script; only treat
            # them as a block when the page has no real article text.
            if text_len < 400:
                return why
    if _PAYWALL_LD.search(head) and text_len < 1500:
        return "paywall (isAccessibleForFree=false)"
    if text_len < 600 and _PAYWALL_TXT.search(head):
        return "paywall (subscriber-only text)"
    return None


# ---------------------------------------------------------------- boilerplate cleanup
# Generic rules first, then a few per-site ones. A line is judged on its own text and on how much of
# it is link text (from trafilatura's markdown links, before they are flattened).
_JUNK_WORDS = re.compile(r"(cookie|newsletter|subscribe|related (posts|articles|stories|reading)|you may also like|read more|"
                         r"share this|advertis|all rights reserved|sign up|follow us|recommended|trending|popular (posts|stories)|"
                         r"leave a (reply|comment)|about the author|tags:|filed under|webinar|register now|download (the|our)|"
                         r"sponsored|how helpful was this content|learn more about|explore (more|our)|contact (us|sales)|"
                         r"free trial|request a demo|diary archives?)", re.I)
_JUNK_START = re.compile(r"^\s*(related( (posts|articles|stories|content|reading))?\s*[:\-–—]|read more|also read|see also|more from|"
                         r"sponsored|webinar\b|register now|download|subscribe|sign up|follow us|tags?\s*:|filed under|about the author|"
                         r"recommended|trending|popular|recent (posts|articles)|share( this)?\b|learn more\b|explore\b|blog$|"
                         r"the post .* appeared first on|(©|copyright) \d{4}|privacy policy|terms of (use|service)|"
                         r"diary archives?|how helpful was this content|advertisement)", re.I)
# A heading after which the rest of the page is navigation, promotion or archives.
_TAIL_START = re.compile(r"^\s*(related (posts|articles|stories|content)|you may also like|more from (the )?|recent (posts|articles)|"
                         r"popular (posts|stories)|diary archives?|about the author|learn more\b|explore (more|related)|"
                         r"(read|see) (more|also)|further reading on our blog|more (resources|reading))\b.{0,60}$", re.I)
# Per-site rules: (host suffix, line pattern to drop).
_SITE_LINES = [
    ("bleepingcomputer.com", re.compile(r"^\s*(sponsored|advertisement|related articles?:?|.*\b(webinar|whitepaper|free trial|"
                                        r"download (the|our)|learn more)\b.{0,80}|.*\b(free|\d+-day)\b.{0,80}\b(scan|trial|demo|assessment)\b.{0,120})\s*$", re.I)),
    ("securityweek.com", re.compile(r"^\s*(related|read more|also read)\s*:.*$", re.I)),
    ("isc.sans.edu", re.compile(r"^\s*(diary archives?|\d+ comment\(s\)|keywords?:.*|--\s*$|johannes b\. ullrich.*twitter.*|.*\|\s*pgp key|[A-Z][\w .'-]{2,40} \(@\w+\)|[\w.-]+\.(com|org|net|be|nl|io)/?)\s*$", re.I)),
    ("elastic.co", re.compile(r"^\s*(the release and timing of any features or functionality described.*|"
                              r"in this blog post, we may have used or referred to third party generative ai tools.*)$", re.I)),
    ("microsoft.com", re.compile(r"^\s*(learn more|related posts?|more (resources|information)|microsoft (defender|security) "
                                 r"(blog|xdr|experts).{0,80}|to (hear|learn) .{0,120}(podcast|follow us).*)\s*$", re.I)),
    ("paloaltonetworks.com", re.compile(r"^\s*(.*\bunit 42 (managed|incident response|threat intelligence|retainer)\b.*|"
                                         r"if you think you may have been compromised.*|additional resources:?)\s*$", re.I)),
]


# Calls to action from inline adverts ("Start your free email security scan.").
_CTA = re.compile(r"^\s*(start|get|try|book|request|schedule|claim|download|watch|join|register)\s+(your|a|the|our|it|now|today)\b"
                  r".{0,60}(free|demo|trial|scan|now|today|webinar|guide|report|assessment)\b.{0,30}[.!]?\s*$", re.I)
_TAIL_PROMO = re.compile(r"(\bis an? (senior |staff |contributing )?(reporter|journalist|editor|writer|correspondent|contributor)\b|"
                         r"\blearn more about\b|\bis available in\b.{0,60}\blearn more\b)", re.I)
# Footer navigation: short pipe-separated items in the last part of the page ("Xameco | PGP Key").
_NAV = re.compile(r"^\s*[^|]{1,30}(\s\|\s[^|]{1,30}){1,}\s*$")


def _link_share(line: str) -> float:
    """Share of the line's visible characters that are link text."""
    links = _MDLINK.findall(line)
    vis = _MDLINK.sub(lambda m: m.group(1), line).strip()
    return (sum(len(x) for x in links) / len(vis)) if vis else 0.0


def _is_junk(line: str, host: str) -> bool:
    vis = _MDLINK.sub(lambda m: m.group(1), line).strip(" -•*|\t")
    if not vis:
        return False
    if len(vis) < 200 and _JUNK_START.match(vis):
        return True
    if len(vis) < 80 and _JUNK_WORDS.search(vis):
        return True
    if len(vis) < 120 and _CTA.match(vis):
        return True
    for suffix, rx in _SITE_LINES:
        if host.endswith(suffix) and len(vis) < 600 and rx.match(vis):
            return True
    return False


def _clean_text(t: str, host: str = "") -> str:
    lines = (t or "").split("\n")
    n = len(lines)
    keep: list[str] = []
    for i, l in enumerate(lines):
        vis = _MDLINK.sub(lambda m: m.group(1), l).strip(" -•*|\t")
        # Everything after a "related / archives / more from" heading in the last third is furniture.
        if i > n * 0.6 and len(vis) < 80 and _TAIL_START.match(vis):
            break
        if _is_junk(l, host):
            continue
        if i > n * 0.8 and len(vis) < 80 and _NAV.match(vis):
            continue
        # Author bios and product plugs at the end of the page.
        if i > n * 0.8 and len(vis) < 400 and _TAIL_PROMO.search(vis):
            continue
        keep.append(l)
    # Link lists: two or more consecutive short lines that are mostly link text.
    out: list[str] = []
    i = 0
    while i < len(keep):
        j = i
        while j < len(keep) and len(keep[j]) < 300 and _link_share(keep[j]) >= 0.7:
            j += 1
        if j - i >= 2:
            i = j
            continue
        out.append(keep[i])
        i += 1
    t = _MDLINK.sub(lambda m: m.group(1), "\n".join(out))
    t = re.sub(r"[ \t]+\n", "\n", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()


# ---------------------------------------------------------------- language
_STOP = {
    "en": "the and of to in is that for with on are was as by this it from be have has which or not an",
    "fr": "le la les des et du un une est que pour dans sur par pas avec qui sont au aux ce cette",
    "it": "il la di che e per un una non sono del della con nel alla gli le dei come più anche",
    "es": "el la de que y en los las un una por con para es del se no al más como",
    "de": "der die und das ist nicht ein eine zu den mit von sich auf für dem des auch im",
    "pt": "o a de que e do da em um uma para com não os as dos das por mais",
}
_STOPSETS = {k: set(v.split()) for k, v in _STOP.items()}


def detect_lang(text: str) -> str | None:
    """Stop-word vote over the first 400 words; None when the text is too short to tell."""
    words = re.findall(r"[a-zà-ÿ]+", (text or "").lower())[:400]
    if len(words) < 30:
        return None
    scores = {k: sum(1 for w in words if w in s) for k, s in _STOPSETS.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] >= 5 else None


# ---------------------------------------------------------------- authors and sponsored posts
_META = r'<meta[^>]+(?:property|name)=["\']{0}["\'][^>]*content=["\']([^"\']*)|<meta[^>]+content=["\']([^"\']*)["\'][^>]*(?:property|name)=["\']{0}["\']'
_BAD_AUTHOR = re.compile(r"^(unit|admin|staff|editor|team|guest|by|the|news|blog|\W*)$", re.I)
# Single-author sites whose pages carry no machine-readable byline.
SITE_AUTHOR = {"krebsonsecurity.com": "Brian Krebs"}


def _meta(html: str, name: str) -> str | None:
    m = re.search(_META.format(re.escape(name)), html[:300_000], re.I)
    return (m.group(1) or m.group(2)).strip() if m else None


def _ld_objects(html: str):
    for m in re.finditer(r'<script[^>]+application/ld\+json[^>]*>(.*?)</script>', html[:500_000], re.S | re.I):
        try:
            data = json.loads(m.group(1))
        except Exception:
            continue
        stack = [data]
        while stack:
            d = stack.pop()
            if isinstance(d, list):
                stack.extend(d)
            elif isinstance(d, dict):
                yield d
                stack.extend(v for v in d.values() if isinstance(v, (dict, list)))


def ld_author(html: str) -> str | None:
    for d in _ld_objects(html):
        a = d.get("author")
        if not a:
            continue
        names = []
        for x in a if isinstance(a, list) else [a]:
            n = x.get("name") if isinstance(x, dict) else x
            if isinstance(n, str) and n.strip():
                names.append(n.strip())
        if names:
            return ", ".join(dict.fromkeys(names))
    return None


def pick_author(html: str, host: str, trafilatura_author: str | None) -> str | None:
    for cand in (ld_author(html), _meta(html, "author"), _meta(html, "article:author"), _meta(html, "parsely-author"),
                 trafilatura_author):
        if cand and not cand.startswith("http") and not _BAD_AUTHOR.match(cand) and len(cand) < 120:
            import html as _h
            return _h.unescape(cand)
    for suffix, name in SITE_AUTHOR.items():
        if host.endswith(suffix):
            return name
    return None


_SPONSORED = re.compile(r"\b(sponsored (by|content|post)|partner content|paid content|this (article|post) is sponsored|"
                        r"sponsored and written by|brought to you by)\b", re.I)


_HTML_SPONSOR = re.compile(r">\s*Sponsored (and written )?by\b", re.I)
PROMO_BYLINES = {"industry news": "press release (byline 'Industry News')", "press release": "press release",
                 "sponsored": "sponsored byline", "partner content": "partner content", "advertorial": "advertorial"}


def detect_sponsored(html: str, title: str | None, author: str | None, text: str) -> str | None:
    """Return why an article is sponsored or promotional, else None."""
    if author and author.strip().lower() in PROMO_BYLINES:
        return PROMO_BYLINES[author.strip().lower()]
    m = _HTML_SPONSOR.search(html[:600_000])
    if m:
        return "page says 'Sponsored by'"
    sec = (_meta(html, "article:section") or "").lower()
    if sec in ("sponsored", "sponsored content", "partner content", "webinar", "webinars"):
        return f"section: {sec}"
    if author and _SPONSORED.search(author):
        return f"byline: {author}"
    if title and re.match(r"^\s*(\[?webinar\]?\s*[:\-–]|sponsored\s*[:\-–]|\[sponsored\])", title, re.I):
        return "title marks it as a webinar or sponsored post"
    head, tail = text[:400], text[-500:]
    m = _SPONSORED.search(head) or _SPONSORED.search(tail)
    if m:
        return f"text: {m.group(0)}"
    return None


def _dedupe_title(text: str, title: str | None) -> str:
    """trafilatura sometimes repeats the headline as the first line; drop it so chunks start with body."""
    if title:
        first, _, rest = text.partition("\n")
        if first.strip().lower() == title.strip().lower() and rest.strip():
            return rest.strip()
    return text


def extract(html: str, url: str) -> dict:
    """Return {title, author, date, lang, text, links, canonical_url, description, sitename, sponsored}."""
    doc = trafilatura.bare_extraction(html, url=url, with_metadata=True, include_links=True,
                                      include_comments=False, include_tables=True, favor_precision=True,
                                      deduplicate=True)
    out = {"title": None, "author": None, "date": None, "lang": None, "text": "", "links": [],
           "canonical_url": None, "description": None, "sitename": None, "sponsored": None}
    m = _LANG.search(html[:5000])
    out["lang"] = m.group(1).lower() if m else None
    c = _CANON.search(html[:300_000])
    if c:
        h = _HREF.search(c.group(0))
        if h:
            out["canonical_url"] = urljoin(url, h.group(1))
    if doc is None:
        return out
    host = (urlsplit(url).hostname or "").lower()
    out["title"] = doc.title
    out["author"] = pick_author(html, host, doc.author)
    out["date"] = doc.date
    out["description"] = doc.description
    out["sitename"] = doc.sitename
    out["text"] = _dedupe_title(_clean_text(doc.text or "", host), doc.title)
    # Language from the text itself (Dark Reading serves French and Italian articles under lang="en").
    out["lang"] = detect_lang(out["text"]) or out["lang"] or doc.language
    out["sponsored"] = detect_sponsored(html, doc.title, out["author"], out["text"])
    links, seen = [], set()
    if doc.body is not None:
        for r in doc.body.iter("ref"):
            t = r.get("target")
            if not t or t.startswith(("#", "mailto:", "javascript:")):
                continue
            t = urljoin(url, t)
            if t in seen:
                continue
            seen.add(t)
            links.append(t)
    out["links"] = links[:300]
    out["external_links"] = [l for l in links if (urlsplit(l).hostname or "").lower().removeprefix("www.") != host.removeprefix("www.")]
    return out


def jsonld_dates(html: str) -> str | None:
    """datePublished from JSON-LD, used when the feed gave no date."""
    for m in re.finditer(r'<script[^>]+application/ld\+json[^>]*>(.*?)</script>', html[:400_000], re.S | re.I):
        try:
            data = json.loads(m.group(1))
        except Exception:
            continue
        stack = [data]
        while stack:
            d = stack.pop()
            if isinstance(d, list):
                stack.extend(d)
            elif isinstance(d, dict):
                if "datePublished" in d:
                    return str(d["datePublished"])
                stack.extend(v for v in d.values() if isinstance(v, (dict, list)))
    return None
