"""Entities and claims: the attribution layer linking events, articles and network logs.

Public hook for other packages: ``ingest_text(ref_type, ref_id, text, url, source_tier)``.
Docs: okf/data/entities.md
"""


def ingest_text(ref_type, ref_id, text, url=None, source_tier="C", **kw):
    """Extract entities and claims from a text and store them (blocking; call from a thread)."""
    from .ingest import ingest_text as _ingest
    return _ingest(ref_type, ref_id, text, url, source_tier, **kw)
