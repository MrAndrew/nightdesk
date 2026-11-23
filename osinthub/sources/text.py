"""Plain text from provider text that is still HTML-entity-encoded ('&amp;', '&#39;', '&quot;').

Shared by every source whose display text can carry entities: the news feeds (feeds._RssSource), NVD descriptions
(feeds.NvdRecent), Bluesky posts (streams.BlueskyCyber) and ransomware.live victims (feeds.RansomwareLive). Only
display text is decoded, never keys, URLs, hashes or indicators. Text is escaped again wherever the client shows it,
so decoding cannot inject markup. Docs: okf/data/architecture.md (pipeline, Parse).
"""
from __future__ import annotations

import html
import re

# Only well-formed references are decoded: a named entity needs its ';' ('&amp;' yes; 'Q&notes', '&copy law',
# '&pound5' stay as written), a numeric one may lack it ('&#xd', '&#39': '&#' plus digits is never ordinary text).
_ENTITY = re.compile(r"&(?:[A-Za-z][A-Za-z0-9]{1,31};|#[0-9]{1,7};?|#[xX][0-9a-fA-F]{1,6};?)")
_SEMI = re.compile(r"(&#(?:[0-9]{1,7}|[xX][0-9a-fA-F]{1,6}))(?:&#[xX]0*3[bB];|&#0*59;)")  # '&#39&#x3b;' is '&#39;'
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")  # \r too (SANS &#xd)
_WS = re.compile(r"\s+")


def unentity(s: str | None) -> str:
    """Plain text from text that is still entity-encoded: feedparser decodes one level, but some feeds
    (Dark Reading's '&amp;amp;') encode twice, and SANS ISC summaries carry '&#xd' and '&#x5b;'. Text is
    escaped again where it is shown, so decoding here cannot inject markup. Decoded until nothing is left to decode
    (one SANS summary carries '&#x26;#39&#x26;#x3b;', three levels), so the result is a fixed point: unentity() of it
    changes nothing, and a stored row that parse() wrote is never decoded again by fix_encoded_events(). Every step
    that changes the text shortens it, so this ends; the cap of 50 levels is only a guard. An unknown name ('&foo;')
    stays as it is."""
    s = s or ""
    for _ in range(50):
        if "&" not in s:
            break
        d = _ENTITY.sub(lambda m: html.unescape(m.group(0) if m.group(0).endswith(";") else m.group(0) + ";"),
                        _SEMI.sub(r"\1;", s))
        if d == s:
            break
        s = d
    return _CTRL.sub(" ", s)


def fix_encoded_events(source_id: str, squash: bool = True) -> int:
    """Decode titles and summaries of this source's events stored before parse() decoded them. Batch sources store
    only changed events, and a provider's window moves on, so an item that is no longer fetched is never re-parsed;
    a stream never sees a post twice. Only the DuckDB copy is touched (the lake files keep what was fetched), and only
    rows that still hold an entity-like '&...' ('&#X27;' too). A fixed row gets the content hash parse() would give
    it today (base.stored_content_hash), so the entity linker relinks it once and its mentions are re-extracted, and a
    later run that parses the same item does not count it as changed. `squash` strips the title and collapses
    whitespace in the summary, as the news feeds' parse does; the other sources pass False and get unentity() alone,
    exactly what their parse() gives, so a row parse() writes again is never rewritten on the next run. Idempotent
    and cheap once nothing is left to fix. Returns the number of rows changed."""
    from .. import db
    from .base import now, stored_content_hash
    pat = "'&(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*)'"
    try:
        rows = db.query(f"""SELECT * EXCLUDE (raw_path, ingested_at) FROM events WHERE source = ?
                            AND (regexp_matches(title, {pat}) OR regexp_matches(coalesce(summary, ''), {pat}))""",
                        [source_id])
    except Exception:  # no events table yet (fresh lake)
        return 0
    n = 0
    for r in rows:
        # only rows the decoder actually changes: the SQL pre-filter also matches plain 'AT&T' or 'R&D', and
        # re-squashing such a row (a summary parse() cut at 500 characters) would differ from what parse() stored,
        # so every poll would rewrite it and count it as changed (fix round 3 evaluation)
        if unentity(r["title"]) == (r["title"] or "") and unentity(r["summary"]) == (r["summary"] or ""):
            continue
        if squash:
            title = unentity(r["title"]).strip()
            summary = _WS.sub(" ", unentity(r["summary"])).strip() if r["summary"] is not None else None
        else:
            title = unentity(r["title"])
            summary = unentity(r["summary"]) if r["summary"] is not None else None
        if (title, summary) != (r["title"], r["summary"]):
            h = stored_content_hash({**r, "title": title, "summary": summary}, r.get("stored_at") or now())
            db.execute("UPDATE events SET title = ?, summary = ?, content_hash = ? WHERE id = ?",
                       [title, summary, h, r["id"]])
            n += 1
    return n
