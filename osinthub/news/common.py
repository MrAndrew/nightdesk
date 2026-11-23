"""Shared helpers for the news package: offline flag, guarded access to the other packages."""
from __future__ import annotations

import hashlib
import logging
import os
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .. import config, db
from .schema import SCHEMA

log = logging.getLogger("osinthub.news")

_TRACKING = re.compile(r"^(utm_|fbclid$|gclid$|mc_|ref$|ref_src$|cmpid$|_hs)")


def offline() -> bool:
    return bool(config.OFFLINE)


def norm_url(url: str) -> str:
    """Normalise a URL for identity: lower host, no fragment, no tracking params, no trailing slash."""
    try:
        p = urlsplit(url.strip())
    except ValueError:
        return url.strip()
    q = urlencode([(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not _TRACKING.match(k)])
    path = p.path.rstrip("/") or "/"
    host = (p.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return urlunsplit(("https" if p.scheme in ("http", "https") else p.scheme, host, path, q, ""))


_SANS_SUFFIX = re.compile(r",?\s*\((Mon|Tue|Wed|Thu|Fri|Sat|Sun), [A-Z][a-z]{2} \d{1,2}(st|nd|rd|th)\)\s*$")


def clean_title(t: str | None) -> str | None:
    """Feed titles: unescape HTML entities (Dark Reading sends '&amp;') and drop SANS ISC's '(Sat, Oct 31st)' suffix."""
    if not t:
        return t
    import html
    t = html.unescape(html.unescape(t)).strip()
    return _SANS_SUFFIX.sub("", t).strip()


# Columns to reset when an article gets new text: entities are extracted again from scratch, with a fresh
# set of LLM retries and ingest-failure backoff (pipeline.ingest_entities_pending), even if the old text gave up.
ENTITIES_RESET = dict(entities_at=None, entities_llm_missed=None, entities_llm_tries=None,
                      entities_fails=None, entities_failed_at=None)


def article_id(url: str) -> str:
    return hashlib.sha1(norm_url(url).encode()).hexdigest()[:16]


def domain_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


_schema_done = False


def ensure_schema() -> None:
    """Create the news tables. ext.register also passes SCHEMA; this keeps scripts and tests working."""
    global _schema_done
    if not _schema_done:
        for stmt in [s for s in SCHEMA.split(";") if s.strip()]:
            db.execute(stmt)
        _schema_done = True


# ---- guarded access to modules other builders own -----------------------------------------
def ai_client():
    try:
        from ..ai import client  # type: ignore
        return client
    except Exception:
        return None


def vectors():
    if os.environ.get("OSINTHUB_NEWS_NO_VECTORS") == "1":
        return None
    try:
        from .. import vectors as v  # type: ignore
        return v
    except Exception:
        return None


def entities():
    try:
        from .. import entities as e  # type: ignore
        return e if hasattr(e, "ingest_text") else None
    except Exception:
        return None


def embed(texts: list[str], kind: str = "document") -> list[list[float]] | None:
    c = ai_client()
    if c is None or not texts:
        return None
    try:
        return c.embed(texts, kind=kind)
    except Exception as e:
        log.debug("embed failed: %s", e)
        return None


def chat(messages: list[dict], max_tokens: int = 300, timeout: float = 120.0) -> str | None:
    c = ai_client()
    if c is None:
        return None
    try:
        return c.chat(messages, max_tokens=max_tokens, timeout=timeout)
    except Exception as e:
        log.debug("chat failed: %s", e)
        return None
