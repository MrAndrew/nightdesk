"""Registers the Help desk API (/api/help/*) with the extension registry. Docs: okf/architecture/help.md"""
from __future__ import annotations

from .. import ext
from .api import router

ext.register("help", router=router)
