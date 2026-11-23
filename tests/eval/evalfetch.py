"""Polite fetching and HTML-to-text for the HLTA eval sets (stdlib only).

- Honest User-Agent, robots.txt respected, per-host delay.
- Never retries around a block: a 401/403/429/challenge page is recorded as a
  refusal and the site is skipped.
- Cache lives in tests/eval/cache/ (gitignored, third-party text), or in the
  directory named by ND_EVAL_CACHE (so a copy outside the worktree survives
  worktree removal).
"""
from __future__ import annotations

import gzip
import html
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
import zlib
from html.parser import HTMLParser
from pathlib import Path

USER_AGENT = "hlta-eval/0.1 (home lab threat analysis; research)"
HERE = Path(__file__).resolve().parent
CACHE = Path(os.environ["ND_EVAL_CACHE"]).expanduser() if os.environ.get("ND_EVAL_CACHE") else HERE / "cache"
DELAY_S = 4.0

try:  # system Python on macOS often lacks a CA store; certifi is a project dep
    import certifi
    _SSL = ssl.create_default_context(cafile=certifi.where())
except ImportError:  # pragma: no cover
    _SSL = ssl.create_default_context()

_last: dict[str, float] = {}
_robots: dict[str, urllib.robotparser.RobotFileParser | None] = {}


class Refused(Exception):
    """The site refused an automated client (robots, 401/403/429, bot check)."""


def _raw_get(url: str, timeout: float = 30.0) -> tuple[int, bytes, str]:
    host = urllib.parse.urlsplit(url).netloc
    wait = _last.get(host, 0) + DELAY_S - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
            body = r.read()
            enc = r.headers.get("Content-Encoding", "")
            ctype = r.headers.get("Content-Type", "")
            status = r.status
    except urllib.error.HTTPError as e:
        _last[host] = time.monotonic()
        return e.code, b"", ""
    finally:
        _last[host] = time.monotonic()
    if enc == "gzip":
        body = gzip.decompress(body)
    elif enc == "deflate":
        body = zlib.decompress(body)
    return status, body, ctype


def allowed(url: str) -> bool:
    parts = urllib.parse.urlsplit(url)
    root = f"{parts.scheme}://{parts.netloc}"
    if root not in _robots:
        rp = urllib.robotparser.RobotFileParser()
        try:
            status, body, _ = _raw_get(root + "/robots.txt")
        except Exception:
            status, body = 0, b""
        if status in (401, 403):
            _robots[root] = None  # treat as disallow-all, per RFC 9309 guidance
        elif status == 200:
            rp.parse(body.decode("utf-8", "replace").splitlines())
            _robots[root] = rp
        else:
            rp.parse([])  # 404 etc: no restrictions
            _robots[root] = rp
    rp = _robots[root]
    return bool(rp and rp.can_fetch(USER_AGENT, url))


_CHALLENGE = re.compile(r"cf-chl|challenge-platform|Just a moment\.\.\.|captcha|Attention Required", re.I)


def fetch(url: str) -> str:
    """Fetch a page politely. Raises Refused if robots or the site says no."""
    if not allowed(url):
        raise Refused(f"robots.txt disallows {url}")
    status, body, ctype = _raw_get(url)
    if status in (202, 401, 403, 429, 503):  # 202 = AWS WAF challenge
        raise Refused(f"HTTP {status} for {url}")
    if status != 200:
        raise RuntimeError(f"HTTP {status} for {url}")
    m = re.search(r"charset=([\w-]+)", ctype or "")
    text = body.decode(m.group(1) if m else "utf-8", "replace")
    if _CHALLENGE.search(text[:5000]) and len(text) < 50000:
        raise Refused(f"bot check page at {url}")
    return text


# ---------------------------------------------------------------- HTML -> text

_BLOCK = {"p", "div", "br", "li", "ul", "ol", "tr", "table", "h1", "h2", "h3", "h4", "h5",
          "h6", "pre", "section", "article", "blockquote", "figure", "figcaption", "dt",
          "dd", "hr", "header", "footer", "main", "tbody", "thead"}
_SKIP = {"script", "style", "noscript", "svg", "template", "iframe", "form", "button", "select"}
_CHROME = {"nav", "aside", "header", "footer"}


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP or tag in _CHROME:
            self.skip += 1
        elif tag in ("td", "th"):
            self.out.append(" \t ")
        elif tag in _BLOCK:
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag in _SKIP or tag in _CHROME:
            self.skip = max(0, self.skip - 1)
        elif tag in _BLOCK:
            self.out.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)


def _main_html(doc: str) -> str:
    """Return the article body if the page marks one up, else <body>."""
    for pat in (r"<article\b[^>]*>(.*)</article>", r"<body\b[^>]*>(.*)</body>"):
        m = re.search(pat, doc, re.S | re.I)
        if m and len(re.sub(r"<[^>]+>", "", m.group(1))) > 8000:
            return m.group(1)
    return doc


def html_to_text(doc: str) -> str:
    p = _Text()
    p.feed(_main_html(doc))
    t = html.unescape("".join(p.out)).replace("\xa0", " ").replace("\u200b", "")
    t = re.sub(r"[ \t\r\f\v]+", " ", t)
    t = re.sub(r" *\n *", "\n", t)
    return re.sub(r"\n{3,}", "\n\n", t).strip()


def cache_paths(rid: str) -> tuple[Path, Path]:
    return CACHE / f"{rid}.html", CACHE / f"{rid}.txt"


def fetch_to_cache(rid: str, url: str, force: bool = False) -> Path:
    hp, tp = cache_paths(rid)
    if tp.exists() and not force:
        return tp
    CACHE.mkdir(parents=True, exist_ok=True)
    doc = fetch(url)
    hp.write_text(doc, encoding="utf-8")
    tp.write_text(html_to_text(doc), encoding="utf-8")
    return tp
