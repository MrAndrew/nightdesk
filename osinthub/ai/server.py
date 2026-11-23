"""Local AI helper: one process that holds the chat and embedding models and serves an
OpenAI-compatible API on 127.0.0.1:8790.

    uv run python -m osinthub.ai.server

Endpoints
* ``GET  /health``               loaded models, state, embedding dimension
* ``GET  /v1/models``            OpenAI model list
* ``POST /v1/embeddings``        ``{"input": str | [str], "kind": "document"|"query", "instruction": str?}``
* ``POST /v1/chat/completions``  OpenAI chat; extras: ``response_format`` (``json_object`` or
  ``json_schema``), ``enable_thinking`` / ``chat_template_kwargs.enable_thinking`` (default off)

Only one instance should run on a machine: the 27B chat model alone needs ~28 GB.
Architecture: okf/architecture/local-ai.md
"""
from __future__ import annotations

import os

os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import glob
import json
import logging
import re
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

if _libs := os.environ.get("OSINTHUB_AI_LIBS"):   # the AI libraries Settings › AI installed (osinthub/ai/setup.py)
    import sys
    sys.path.append(_libs)                          # after the app's own packages, so those always win

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from .. import httpguard   # the app's request guards, without loading the app or its configuration
from .jsonout import check as _check, extract as _extract_json, with_hint as _with_hint

log = logging.getLogger("osinthub.ai.server")

HOST = os.environ.get("AI_HOST", "127.0.0.1")
PORT = int(os.environ.get("AI_PORT", "8790"))
# Bearer token. Required when AI_HOST is not loopback (main() refuses to start without it); checked whenever set.
# The app sends it from its own AI_TOKEN. okf/architecture/local-ai.md#ai-helper
TOKEN = (os.environ.get("AI_TOKEN") or "").strip() or None
# DNS-rebinding defence, as in the app: only these Host names are served. host.docker.internal is how the app in
# Docker reaches the helper on the host; AI_ALLOWED_HOSTS adds more (comma- or space-separated).
ALLOWED_HOSTS = set(httpguard.LOOPBACK_NAMES) | {"host.docker.internal"} | httpguard.host_list(
    os.environ.get("AI_ALLOWED_HOSTS", ""))
if httpguard.host_name(HOST) not in ("", "0.0.0.0", "::"):
    ALLOWED_HOSTS.add(httpguard.host_name(HOST))
CHAT_MODEL = os.environ.get("AI_CHAT_MODEL", "mlx-community/Qwen3.8-27B-8bit")
EMBED_MODEL = os.environ.get("AI_EMBED_MODEL", "Qwen/Qwen3-Embedding-0.6B")
EMBED_MAX_TOKENS = int(os.environ.get("AI_EMBED_MAX_TOKENS", "1024"))
EMBED_BATCH = int(os.environ.get("AI_EMBED_BATCH", "32"))
# Set AI_CHAT=0 to run embeddings only (e.g. on a smaller machine).
LOAD_CHAT = os.environ.get("AI_CHAT", "1") not in ("0", "false", "no")

QUERY_INSTRUCTION = "Given a web search query, retrieve relevant passages that answer the query"

_state: dict[str, Any] = {"chat": {"id": CHAT_MODEL, "loaded": False, "error": None},
                          "embed": {"id": EMBED_MODEL, "loaded": False, "error": None, "dim": None},
                          "started": time.time()}
_chat_lock = threading.Lock()    # one generation at a time
_embed_lock = threading.Lock()   # one embedding batch at a time (separate so search stays fast during generation)
_chat = None   # (model, tokenizer)
_embed = None  # (model, tokenizer)


def _snapshot(repo: str) -> Path:
    """The cached snapshot folder for a repo id (or a local path), without any network call."""
    if Path(repo).is_dir():
        return Path(repo)
    from huggingface_hub.constants import HF_HUB_CACHE
    base = Path(HF_HUB_CACHE) / ("models--" + repo.replace("/", "--"))
    ref = base / "refs" / "main"
    if ref.exists():
        snap = base / "snapshots" / ref.read_text().strip()
        if (snap / "config.json").exists():
            return snap
    snaps = sorted((base / "snapshots").glob("*/config.json"), key=lambda p: p.stat().st_mtime)
    if not snaps:
        raise FileNotFoundError(f"{repo} is not in the Hugging Face cache ({base})")
    return snaps[-1].parent


# ------------------------------------------------------------------ embeddings
def _load_embed() -> None:
    global _embed
    import mlx.core as mx
    from mlx_lm.models import qwen3
    from transformers import AutoTokenizer

    path = _snapshot(EMBED_MODEL)
    cfg = json.loads((path / "config.json").read_text())
    args = qwen3.ModelArgs.from_dict(cfg)
    model = qwen3.Qwen3Model(args)  # the bare transformer: final hidden states, no LM head
    weights = {}
    for f in glob.glob(str(path / "*.safetensors")):
        weights.update(mx.load(f))
    weights = {k.removeprefix("model."): v for k, v in weights.items() if not k.startswith("lm_head")}
    model.load_weights(list(weights.items()))
    model.eval()
    mx.eval(model.parameters())
    tok = AutoTokenizer.from_pretrained(str(path))
    _embed = (model, tok)
    _state["embed"].update(loaded=True, dim=args.hidden_size)
    log.info("embedding model %s loaded (dim %d)", EMBED_MODEL, args.hidden_size)


def embed_texts(texts: list[str], kind: str = "document", instruction: str | None = None) -> list[list[float]]:
    """Last-token pooled, L2-normalised Qwen3 embeddings. Queries get the instruction prefix."""
    import mlx.core as mx
    if _embed is None:
        raise RuntimeError("embedding model not loaded")
    model, tok = _embed
    if kind == "query":
        texts = [f"Instruct: {instruction or QUERY_INSTRUCTION}\nQuery:{t}" for t in texts]
    eos = tok.convert_tokens_to_ids("<|endoftext|>")
    ids = []
    for t in texts:
        x = tok(t or " ", add_special_tokens=False, truncation=True, max_length=EMBED_MAX_TOKENS - 1)["input_ids"]
        ids.append(x + [eos])  # Qwen3-Embedding pools the hidden state of the trailing <|endoftext|>
    out: list[list[float] | None] = [None] * len(ids)
    order = sorted(range(len(ids)), key=lambda i: len(ids[i]))  # batch similar lengths together
    with _embed_lock:
        i = 0
        while i < len(order):
            # Keep batches to ~16k tokens so long documents don't blow up memory.
            longest = len(ids[order[min(i + EMBED_BATCH, len(order)) - 1]])
            n = max(1, min(EMBED_BATCH, 16384 // max(longest, 1)))
            chunk = order[i:i + n]
            i += n
            width = max(len(ids[j]) for j in chunk)
            # Right padding is safe with a causal model: positions before the pad never see it.
            batch = mx.array([ids[j] + [eos] * (width - len(ids[j])) for j in chunk])
            h = model(batch)  # (B, L, D), already through the final norm
            last = mx.array([len(ids[j]) - 1 for j in chunk])
            v = h[mx.arange(len(chunk)), last].astype(mx.float32)
            v = v / mx.maximum(mx.linalg.norm(v, axis=-1, keepdims=True), 1e-12)
            mx.eval(v)
            for j, row in zip(chunk, v.tolist()):
                out[j] = row
    return out  # type: ignore[return-value]


# ------------------------------------------------------------------ chat
def _load_chat() -> None:
    global _chat
    from mlx_lm import load
    model, tok = load(str(_snapshot(CHAT_MODEL)))
    _chat = (model, tok)
    _state["chat"]["loaded"] = True
    log.info("chat model %s loaded", CHAT_MODEL)


THINK_RE = re.compile(r"^\s*<think>(.*?)</think>\s*", re.S)


def _generate(messages: list[dict], max_tokens: int, temperature: float, top_p: float,
              enable_thinking: bool) -> tuple[str, str | None, int, int, str]:
    from mlx_lm import stream_generate
    from mlx_lm.sample_utils import make_sampler
    if _chat is None:
        raise RuntimeError("chat model not loaded")
    model, tok = _chat
    prompt = tok.apply_chat_template(messages, add_generation_prompt=True, tokenize=False,
                                     enable_thinking=enable_thinking)
    prompt_ids = tok.encode(prompt, add_special_tokens=False)
    sampler = make_sampler(temp=temperature, top_p=top_p if temperature > 0 else 0.0)
    text, finish, n_out = "", "length", 0
    with _chat_lock:
        for r in stream_generate(model, tok, prompt_ids, max_tokens=max_tokens, sampler=sampler):
            text += r.text
            n_out = r.generation_tokens
            if r.finish_reason:
                finish = "stop" if r.finish_reason == "stop" else "length"
    reasoning = None
    if enable_thinking:
        # The template opens <think> itself, so the output usually starts inside it.
        if "</think>" in text:
            head, _, text = text.partition("</think>")
            reasoning = head.replace("<think>", "").strip()
    else:
        m = THINK_RE.match(text)
        if m:
            text = text[m.end():]
    return text.strip(), reasoning, len(prompt_ids), n_out, finish


# ------------------------------------------------------------------ app
@asynccontextmanager
async def _lifespan(app):
    # Load in the background so /health answers at once and the embedder is usable
    # while the much larger chat model is still loading.
    threading.Thread(target=_load_all, name="model-loader", daemon=True).start()
    yield


app = FastAPI(title="HLTA local AI helper", lifespan=_lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def _guard(request, call_next):
    """Host allowlist (421), cross-site writes (403) and the token (401), the same rules as the app's _guard."""
    host = request.headers.get("host", "")
    if httpguard.host_name(host) not in ALLOWED_HOSTS:
        return JSONResponse({"detail": f"host {host[:100]!r} is not allowed: the AI helper answers only localhost, "
                                       "127.0.0.1, [::1], host.docker.internal and the names in AI_ALLOWED_HOSTS"},
                            status_code=421)
    if (why := httpguard.cross_site(request.method, request.headers, request.url.scheme)) is not None:
        return JSONResponse({"detail": why}, status_code=403)
    if TOKEN and not httpguard.bearer_ok(request.headers.get("authorization"), TOKEN):
        return JSONResponse({"detail": "missing or wrong token (AI_TOKEN)"}, status_code=401,
                            headers={"WWW-Authenticate": "Bearer"})
    return await call_next(request)


def bind_problem(host: str | None = None, token: str | None = None) -> str | None:
    """Why the helper must not start on this address (one line), or None: beyond loopback it needs AI_TOKEN."""
    return httpguard.bind_problem(HOST if host is None else host, secret=bool(TOKEN if token is None else token),
                                  secret_var="AI_TOKEN", host_var="AI_HOST", proxy_hint=False)


@app.get("/health")
def health():
    ok = _state["embed"]["loaded"] and (_state["chat"]["loaded"] or not LOAD_CHAT)
    return {"ok": ok, "models": {"chat": _state["chat"] if LOAD_CHAT else None, "embed": _state["embed"]},
            "uptime_s": round(time.time() - _state["started"]), "query_instruction": QUERY_INSTRUCTION}


@app.get("/v1/models")
def models():
    data = [{"id": EMBED_MODEL, "object": "model", "owned_by": "local", "ready": _state["embed"]["loaded"]}]
    if LOAD_CHAT:
        data.append({"id": CHAT_MODEL, "object": "model", "owned_by": "local", "ready": _state["chat"]["loaded"]})
    return {"object": "list", "data": data}


@app.post("/v1/embeddings")
def embeddings(body: dict):
    if not _state["embed"]["loaded"]:
        raise HTTPException(503, "embedding model loading" if not _state["embed"]["error"] else _state["embed"]["error"])
    inp = body.get("input")
    texts = [inp] if isinstance(inp, str) else list(inp or [])
    if not all(isinstance(t, str) for t in texts):
        raise HTTPException(400, "input must be a string or a list of strings")
    if len(texts) > 2048:
        raise HTTPException(400, "at most 2048 inputs per request")
    kind = body.get("kind") or body.get("input_type") or "document"
    t0 = time.time()
    vecs = embed_texts(texts, "query" if kind == "query" else "document", body.get("instruction"))
    log.info("embedded %d %s texts in %.2fs", len(texts), kind, time.time() - t0)
    return {"object": "list", "model": EMBED_MODEL,
            "data": [{"object": "embedding", "index": i, "embedding": v} for i, v in enumerate(vecs)],
            "usage": {"prompt_tokens": 0, "total_tokens": 0}}


@app.post("/v1/chat/completions")
def chat_completions(body: dict):
    if not LOAD_CHAT or not _state["chat"]["loaded"]:
        raise HTTPException(503, "chat model not loaded" if not _state["chat"]["error"] else _state["chat"]["error"])
    if body.get("stream"):
        raise HTTPException(400, "streaming is not supported")
    messages = [{"role": m["role"], "content": m.get("content") or ""} for m in body.get("messages") or []]
    if not messages:
        raise HTTPException(400, "messages required")
    max_tokens = max(1, min(8192, int(body.get("max_tokens") or body.get("max_completion_tokens") or 1024)))
    temperature = float(body.get("temperature", 0.0) or 0.0)
    top_p = float(body.get("top_p", 0.95) or 0.95)
    think = body.get("enable_thinking")
    if think is None:
        think = (body.get("chat_template_kwargs") or {}).get("enable_thinking", False)
    rf = body.get("response_format") or {}
    schema = None
    json_mode = rf.get("type") in ("json_object", "json_schema")
    if rf.get("type") == "json_schema":
        schema = (rf.get("json_schema") or {}).get("schema") or rf.get("schema")
    if json_mode:
        think = False  # structured output is extraction work; skip the reasoning tokens
        messages = _with_hint(messages, schema)

    t0 = time.time()
    text, reasoning, p_tok, c_tok, finish = _generate(messages, max_tokens, temperature, top_p, bool(think))
    if json_mode:
        # No constrained decoding in mlx-lm: validate, and give the model one chance to fix it.
        for attempt in range(2):
            try:
                obj = _extract_json(text)
                errs = _check(obj, schema) if schema else []
                if not errs:
                    text = json.dumps(obj, ensure_ascii=False)
                    break
                problem = "; ".join(errs[:10])
            except ValueError as e:
                problem = str(e)
            if attempt == 1:
                log.warning("JSON output still invalid after retry: %s", problem)
                break
            fix = messages + [{"role": "assistant", "content": text},
                              {"role": "user", "content": f"That was not valid: {problem}. Reply with the corrected JSON only."}]
            text, _, p2, c2, finish = _generate(fix, max_tokens, 0.0, 0.0, False)
            p_tok += p2
            c_tok += c2
    log.info("chat: %d prompt + %d completion tokens in %.1fs (thinking=%s, json=%s)",
             p_tok, c_tok, time.time() - t0, bool(think), json_mode)
    msg: dict[str, Any] = {"role": "assistant", "content": text}
    if reasoning:
        msg["reasoning_content"] = reasoning
    return JSONResponse({
        "id": f"chatcmpl-{uuid.uuid4().hex[:24]}", "object": "chat.completion", "created": int(time.time()),
        "model": CHAT_MODEL,
        "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
        "usage": {"prompt_tokens": p_tok, "completion_tokens": c_tok, "total_tokens": p_tok + c_tok},
    })


def _load_all() -> None:
    for name, fn in (("embed", _load_embed), ("chat", _load_chat)):
        if name == "chat" and not LOAD_CHAT:
            continue
        try:
            t0 = time.time()
            fn()
            log.info("%s ready in %.1fs", name, time.time() - t0)
        except Exception as e:  # keep serving whatever did load
            log.exception("could not load %s model", name)
            _state[name]["error"] = f"{type(e).__name__}: {e}"[:300]


def main() -> None:
    import uvicorn
    if (problem := bind_problem()) is not None:
        raise SystemExit(f"osinthub.ai.server: {problem}")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning", workers=1)


if __name__ == "__main__":
    main()
