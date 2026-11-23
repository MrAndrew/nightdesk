"""Registers notes (table and /api/notes routes) with the extension registry. Docs: okf/architecture/notes.md"""
from __future__ import annotations

from .. import ext
from .api import router
from .store import SCHEMA

ext.register("notes", schema_sql=SCHEMA, router=router)
