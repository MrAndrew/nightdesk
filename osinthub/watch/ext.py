"""Registers the Watch package (briefing, marker, setup status) with the extension registry, and the followed list
it reads (My stack, osinthub/stack.py, /api/stack). Docs: okf/architecture/watch.md, okf/architecture/my-stack.md"""
from __future__ import annotations

from .. import ext
from ..stack import router as stack_router
from .api import router

ext.register("watch", router=router)
ext.register("stack", router=stack_router)
