"""Small helpers shared by the HTTP API modules (osinthub/api.py and the feature routers).

Entity-id resolution lives here, not in entities/, so it still works (falling back to the id) when the entities
package is disabled.
"""
from __future__ import annotations

import datetime as dt
from typing import Any


def like_escape(s: str) -> str:
    """Escape % _ and \\ in user text so they match literally in a LIKE/ILIKE pattern (use with ESCAPE '\\')."""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def like(s: str) -> str:
    """A contains-text LIKE/ILIKE pattern for user text, with % _ and \\ matched literally (use with ESCAPE '\\')."""
    return "%" + like_escape(s) + "%"


def csv_list(v: str | None) -> list[str]:
    """A comma-separated query value as a list of non-empty, trimmed items."""
    return [x.strip() for x in v.split(",") if x.strip()] if v else []


def jsonable(v: Any) -> Any:
    """Deep-convert datetimes and dates to ISO strings inside dicts, lists and tuples; everything else unchanged."""
    if isinstance(v, dict):
        return {k: jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [jsonable(x) for x in v]
    if isinstance(v, (dt.datetime, dt.date)):
        return v.isoformat()
    return v


def entity_equivalents(eid: str) -> list[str]:
    """Entity ids equivalent to `eid` under the user's merges, or [eid] when the entities package is off."""
    try:
        from .entities import overrides
        return overrides.equivalents(eid) or [eid]
    except Exception:
        return [eid]


def entity_resolve(eid: str) -> str:
    """The canonical entity id for `eid` under the user's merges, or `eid` when the entities package is off."""
    try:
        from .entities import overrides
        return overrides.resolve(eid)
    except Exception:
        return eid
