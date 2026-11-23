from __future__ import annotations

from .base import Source

SOURCES: dict[str, Source] = {}


def register(cls):
    inst = cls()
    SOURCES[inst.id] = inst
    return cls
