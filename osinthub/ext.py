"""Extension registry. Feature packages (ai, news, entities, netlog, ...) plug in here.

A package ``osinthub/<pkg>/`` with an ``ext.py`` module is discovered automatically. That
module calls ``register()`` at import time::

    from osinthub import ext
    ext.register("news", schema_sql=SCHEMA, router=router, tasks=(poll_feeds,), on_start=warm_cache)

* ``schema_sql``: SQL run on the main DuckDB connection at connect time (use IF NOT EXISTS).
* ``router``: a FastAPI ``APIRouter``; include its own prefix (``/api/news``).
* ``tasks``: async callables taking no arguments, started after the scheduler. A task that
  returns is done; one that raises is logged and restarted with backoff.
* ``on_start``: a sync (run in a worker thread) or async callable run once at startup.

Every step is isolated: an extension that fails to import, whose schema fails, or whose
hook raises is logged and recorded in ``status()``; the app keeps running without it.
Architecture: okf/architecture/system.md#extensions
"""
from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
import os
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from collections.abc import Callable

log = logging.getLogger("osinthub.ext")


@dataclass
class Extension:
    name: str
    schema_sql: str | None = None
    router: Any = None
    tasks: tuple = ()
    on_start: Callable | None = None
    on_stop: Callable | None = None
    module: str | None = None
    errors: list[str] = field(default_factory=list)


EXTENSIONS: dict[str, Extension] = {}
FAILED: dict[str, str] = {}  # module -> error, for imports that failed
_loaded = False
_current_module: str | None = None
_tasks: list[asyncio.Task] = []


def register(name: str, schema_sql: str | None = None, router: Any = None, tasks=(), on_start: Callable | None = None,
             on_stop: Callable | None = None) -> Extension:
    """Register (or replace) an extension. Called from a package's ext module at import time."""
    e = Extension(name, schema_sql, router, tuple(tasks or ()), on_start, on_stop, module=_current_module)
    EXTENSIONS[name] = e
    return e


def discover() -> list[str]:
    root = Path(__file__).resolve().parent
    return sorted(f"osinthub.{p.parent.name}.ext" for p in root.glob("*/ext.py") if not p.parent.name.startswith(("_", ".")))


def load_all() -> dict[str, Extension]:
    """Import every package's ext module once. Failures are logged, never raised."""
    global _loaded, _current_module
    if _loaded:
        return EXTENSIONS
    _loaded = True
    # OSINTHUB_DISABLE_EXT=entities,news skips those packages (a safety switch for a misbehaving feature).
    disabled = {x.strip() for x in os.environ.get("OSINTHUB_DISABLE_EXT", "").split(",") if x.strip()}
    for mod in discover():
        if any(mod == f"osinthub.{d}.ext" or mod.startswith(f"osinthub.{d}.") for d in disabled):
            FAILED[mod] = "disabled by OSINTHUB_DISABLE_EXT"
            log.warning("extension %s disabled by OSINTHUB_DISABLE_EXT", mod)
            continue
        _current_module = mod
        before = dict(EXTENSIONS)
        try:
            importlib.import_module(mod)
        except Exception as e:
            # Roll back anything the module registered before it raised: a half-imported
            # extension must not have its schema, router or tasks used.
            EXTENSIONS.clear()
            EXTENSIONS.update(before)
            FAILED[mod] = f"{type(e).__name__}: {e}"[:500]
            log.error("extension %s failed to import; continuing without it\n%s", mod, traceback.format_exc())
        finally:
            _current_module = None
    if EXTENSIONS:
        log.info("extensions loaded: %s", ", ".join(EXTENSIONS))
    return EXTENSIONS


def apply_schema(conn) -> None:
    for e in EXTENSIONS.values():
        if not e.schema_sql:
            continue
        try:
            conn.execute(e.schema_sql)
        except Exception as ex:
            msg = f"schema: {type(ex).__name__}: {ex}"[:500]
            e.errors.append(msg)
            log.error("extension %s %s", e.name, msg)


def include_routers(app) -> None:
    for e in EXTENSIONS.values():
        if e.router is None:
            continue
        try:
            app.include_router(e.router)
        except Exception as ex:
            msg = f"router: {type(ex).__name__}: {ex}"[:500]
            e.errors.append(msg)
            log.error("extension %s %s", e.name, msg)


async def _supervise(e: Extension, fn: Callable) -> None:
    name = getattr(fn, "__name__", "task")
    backoff = 5
    while True:
        t0 = time.monotonic()
        try:
            await fn()
            return
        except asyncio.CancelledError:
            raise
        except Exception as ex:
            msg = f"task {name}: {type(ex).__name__}: {ex}"[:500]
            e.errors = (e.errors + [msg])[-10:]
            log.error("extension %s %s; restarting in %ds\n%s", e.name, msg, backoff, traceback.format_exc())
        if time.monotonic() - t0 > 300:
            backoff = 5  # it ran for a while; treat the next failure as fresh
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 600)


async def start() -> None:
    """Run on_start hooks, then start background tasks. Call from the app lifespan."""
    for e in EXTENSIONS.values():
        if e.on_start is None:
            continue
        try:
            if inspect.iscoroutinefunction(e.on_start):
                await e.on_start()
            else:  # sync hooks run in a thread so they can't stall the event loop
                res = await asyncio.to_thread(e.on_start)
                if inspect.isawaitable(res):
                    await res
        except Exception as ex:
            msg = f"on_start: {type(ex).__name__}: {ex}"[:500]
            e.errors.append(msg)
            log.error("extension %s %s\n%s", e.name, msg, traceback.format_exc())
    for e in EXTENSIONS.values():
        for fn in e.tasks:
            _tasks.append(asyncio.create_task(_supervise(e, fn), name=f"ext:{e.name}:{getattr(fn, '__name__', 'task')}"))


async def stop() -> None:
    for t in _tasks:
        t.cancel()
    _tasks.clear()
    # on_stop hooks run as the app shuts down (sync ones in a worker thread); one that fails is logged, never fatal
    for e in list(EXTENSIONS.values()):
        if e.on_stop is None:
            continue
        try:
            r = await asyncio.to_thread(e.on_stop) if not asyncio.iscoroutinefunction(e.on_stop) else await e.on_stop()
            if asyncio.iscoroutine(r):
                await r
        except Exception as ex:
            log.warning("extension %s: on_stop failed: %s", e.name, ex)


def status() -> dict:
    return {
        "extensions": [{"name": e.name, "module": e.module, "schema": bool(e.schema_sql), "router": e.router is not None,
                        "tasks": [getattr(f, "__name__", "task") for f in e.tasks], "on_start": e.on_start is not None,
                        "errors": e.errors} for e in EXTENSIONS.values()],
        "failed_imports": FAILED,
    }
