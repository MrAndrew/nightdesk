"""Registers the local-AI pieces with the app: the embedding pipeline and its status API."""
from __future__ import annotations

import asyncio
import logging
import threading

from fastapi import APIRouter, Body, HTTPException

from .. import config, ext, vectors
from . import chatconn, client, indexer, setup

log = logging.getLogger("osinthub.ai")

router = APIRouter(prefix="/api/ai", tags=["ai"])


@router.get("/status")
def status():
    """AI helper health, vector backend and collection counts, and indexing progress."""
    try:
        vec = vectors.status()
    except Exception as e:
        vec = {"error": f"{type(e).__name__}: {e}"}
    return {"helper": {**client.status(), "health": client.health()}, "vectors": vec,
            "index": indexer.status(), "offline": config.OFFLINE}


@router.post("/reindex")
async def reindex():
    """Run an indexing pass now (embeds whatever is new or changed)."""
    return await asyncio.to_thread(indexer.sync_all)


# ------------------------------------------------------------------ Settings › AI (osinthub/ai/setup.py)
@router.get("/setup")
def setup_status():
    """What turning AI on would take here: the machine, both models (size, memory, already downloaded), the libraries,
    the saved choice, the download in progress and the helper."""
    return setup.status()


@router.post("/setup/plan")
def setup_plan(body: dict = Body(...)):
    """What these models would download and whether it fits ({models: ["search", "chat"]})."""
    models = [m for m in body.get("models") or [] if m in setup.MODELS]
    return {**setup.plan(models, _text(body.get("chat_repo"))), "why_not": setup.why_not()}


@router.post("/setup", status_code=202)
def setup_start(body: dict = Body(...)):
    """Turn AI on with these models: install the libraries and download what is missing, then start the helper."""
    try:
        return setup.start(list(body.get("models") or []), _text(body.get("chat_repo")))
    except ValueError as e:
        raise HTTPException(409, str(e))


@router.delete("/setup/job")
def setup_cancel():
    """Stop a download in progress (what is already downloaded stays, and the next try picks up from there)."""
    setup.cancel()
    return setup.job()


@router.post("/setup/off")
def setup_off(body: dict = Body(default={})):
    """Turn AI off: stop the helper and forget the choice; delete_models / delete_libs also delete those files."""
    return setup.turn_off(bool(body.get("delete_models")), bool(body.get("delete_libs")))


def _text(v) -> str | None:
    return v.strip() if isinstance(v, str) and v.strip() else None


# ------------------------------------------------------------------ Settings › AI › Chat (osinthub/ai/chatconn.py)
# POST throughout, also for the read-only ones: each makes the server contact an address, so they pass the same
# cross-site guard as every other change.
@router.post("/chat/discover")
def chat_discover():
    """What is on this computer: Ollama and LM Studio on their usual ports, and the built-in helper's MLX models."""
    return chatconn.discover()


@router.post("/chat/models")
def chat_models(body: dict = Body(...)):
    """The chat models a server offers ({via, url, key?}; without a key the saved one for that host is used)."""
    return chatconn.list_models(str(body.get("via") or "other"), str(body.get("url") or ""), _key(body))


@router.post("/chat/test")
def chat_test(body: dict = Body(...)):
    """Send one short chat to a server before saving it ({via, url, model, key?})."""
    return chatconn.test(str(body.get("via") or "other"), str(body.get("url") or ""), str(body.get("model") or ""),
                         _key(body))


@router.post("/chat")
def chat_save(body: dict = Body(...)):
    """Use another server for chat ({via, url, model, key?}). No key keeps the saved one for the same host; "" removes it."""
    try:
        return chatconn.save(str(body.get("via") or ""), str(body.get("url") or ""), str(body.get("model") or ""),
                             _key(body))
    except ValueError as e:
        raise HTTPException(409, str(e))


@router.post("/chat/off")
def chat_off():
    """No chat: story summaries and entity briefs stop being written; a saved API key is deleted."""
    return chatconn.turn_off()


def _key(body: dict) -> str | None:
    k = body.get("key")
    return k if isinstance(k, str) else None


def _start_helper_if_on() -> None:
    """At start: a helper the user turned on in Settings is started again (in the background; the app never waits)."""
    if setup.enabled():
        threading.Thread(target=lambda: log.info("AI helper: %s", setup.start_helper()), name="ai-helper-start",
                         daemon=True).start()


def _stop_helper_unless_restarting() -> None:
    """At shutdown: the helper this app started stops with it, except for a restart in place (the new start reuses it)."""
    from .. import lakeloc
    if not lakeloc.restart_requested.is_set():
        setup.stop_at_exit()


ext.register("ai", router=router, tasks=(indexer.index_loop,), on_start=_start_helper_if_on,
             on_stop=_stop_helper_unless_restarting)
