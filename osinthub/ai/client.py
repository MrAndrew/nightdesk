"""Client for the local AI helper (osinthub/ai/server.py) and, for chat, any other OpenAI-compatible server the user
chose in Settings (osinthub/ai/chatconn.py: Ollama, LM Studio, another address). Never loads a model in-process.

Both calls return None quickly when their server is down: the connect timeout is short, and after a failure that
server is treated as down for ``DOWN_FOR`` seconds without retrying. Embeddings always go to the helper; chat goes
to the helper unless another server is chosen, and that server has its own down state.
Architecture: okf/architecture/local-ai.md
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from typing import Any

import httpx

from .. import config
from . import jsonout

log = logging.getLogger("osinthub.ai.client")

DOWN_FOR = 30.0
CONNECT_TIMEOUT = 0.5
QUERY_TIMEOUT = 2.5  # a search waits at most this long for its query embedding
EMBED_BATCH = 128

_down_until = 0.0
_last_error: str | None = None
_ever_up = False   # the helper answered at least once during this server run
_lock = threading.Lock()
_http: httpx.Client | None = None


def _client() -> httpx.Client:
    global _http
    if _http is None:
        # trust_env=False: the helper is local, so HTTP(S)_PROXY must never apply to it.
        # The helper's token when one is set (AI_TOKEN): a helper beyond loopback requires it.
        auth = {"Authorization": f"Bearer {config.AI_TOKEN}"} if config.AI_TOKEN else {}
        _http = httpx.Client(base_url=config.AI_URL, trust_env=False, headers=auth,
                             timeout=httpx.Timeout(120.0, connect=CONNECT_TIMEOUT))
    return _http


def _mark_down(err: str, seconds: float = DOWN_FOR) -> None:
    global _down_until, _last_error
    with _lock:
        if time.monotonic() >= _down_until:
            log.warning("AI helper at %s unavailable (%s); retrying in %.0fs", config.AI_URL, err, seconds)
        _down_until = time.monotonic() + seconds
        _last_error = err


def _post(path: str, body: dict, timeout: float, down_on_timeout: bool = True) -> dict | None:
    global _last_error
    if time.monotonic() < _down_until:
        return None
    try:
        r = _client().post(path, json=body, timeout=httpx.Timeout(timeout, connect=CONNECT_TIMEOUT))
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.RemoteProtocolError, httpx.ReadError) as e:
        _mark_down(f"{type(e).__name__}: {e}")
        return None
    except httpx.TimeoutException as e:
        if down_on_timeout:  # a hung helper: stop waiting on it for a while
            _mark_down(f"{type(e).__name__} on {path} after {timeout:.0f}s: {e}")
        else:  # a chat waiting behind other generations is busy, not hung; embeddings still work
            log.warning("AI helper %s timed out after %.0fs (busy)", path, timeout)
        return None
    except httpx.HTTPError as e:  # broken connection: treat as down
        _mark_down(f"{type(e).__name__} on {path}: {e}")
        return None
    if r.status_code == 503:  # model still loading
        _mark_down(f"503 {r.text[:120]}", 5.0)
        return None
    if r.status_code >= 400:
        log.warning("AI helper %s -> %d %s", path, r.status_code, r.text[:200])
        return None
    global _ever_up
    _last_error = None
    _ever_up = True
    return r.json()


def mark_up() -> None:
    """Forget an earlier failure (the app has just started the helper)."""
    global _down_until
    _down_until = 0.0


def helper_down() -> bool:
    return time.monotonic() < _down_until


def is_down() -> bool:
    """Chat can't answer right now (its server failed recently). Callers use it to skip chat work."""
    ext = _external()
    return ext.down() if ext is not None else helper_down()


def health(timeout: float = 1.0) -> dict | None:
    """The helper's /health, or None if unreachable. Does not respect the down cache."""
    global _ever_up
    try:
        r = _client().get("/health", timeout=httpx.Timeout(timeout, connect=CONNECT_TIMEOUT))
        if r.status_code == 200:
            _ever_up = True
            return r.json()
        return None
    except httpx.HTTPError:
        return None


def _turned_on() -> bool:
    from . import setup
    return setup.enabled()


def status() -> dict:
    """configured: the user said the helper is expected (AI_HELPER=1|on|required). AI_URL alone does not count:
    docker-compose always sets it. ever_up: the helper answered at least once during this server run. Neither:
    the optional helper is simply not running, which is not an error."""
    return {"url": config.AI_URL, "down": helper_down(), "last_error": _last_error,
            "configured": os.environ.get("AI_HELPER", "").strip().lower() in ("1", "on", "yes", "true", "required")
            or _turned_on(),
            "ever_up": _ever_up,
            "retry_in_s": max(0.0, round(_down_until - time.monotonic(), 1)),
            "chat": chat_status()}


def embed(texts: list[str], kind: str = "document", instruction: str | None = None,
          timeout: float | None = None) -> list[list[float]] | None:
    """Embed texts (1024-d, L2-normalised). kind="query" adds the retrieval instruction.

    Returns one vector per text, or None if the helper is unavailable or any batch fails.
    """
    if not texts:
        return []
    if timeout is None:
        timeout = QUERY_TIMEOUT if kind == "query" else 60.0
    out: list[list[float]] = []
    for i in range(0, len(texts), EMBED_BATCH):
        body: dict[str, Any] = {"input": texts[i:i + EMBED_BATCH], "kind": kind}
        if instruction:
            body["instruction"] = instruction
        res = _post("/v1/embeddings", body, timeout)
        if res is None:
            return None
        out.extend(d["embedding"] for d in sorted(res["data"], key=lambda d: d["index"]))
    return out


def chat(messages: list[dict], json_schema: dict | None = None, max_tokens: int = 1024,
         temperature: float = 0.0, think: bool = False, timeout: float = 300.0) -> str | None:
    """One chat completion; returns the assistant text or None.

    ``json_schema`` asks for a JSON reply validated against that schema (one repair retry: in the helper, or here for
    another server); the returned string is then JSON. Thinking is off unless ``think``.
    """
    ext = _external()
    if ext is not None:
        return ext.chat(messages, json_schema, max_tokens, temperature, think, timeout)
    body: dict[str, Any] = {"messages": messages, "max_tokens": max_tokens, "temperature": temperature,
                            "chat_template_kwargs": {"enable_thinking": bool(think)}}
    if json_schema is not None:
        body["response_format"] = {"type": "json_schema", "json_schema": {"name": "out", "schema": json_schema}}
    res = _post("/v1/chat/completions", body, timeout, down_on_timeout=False)
    if res is None:
        return None
    try:
        return res["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return None


# ------------------------------------------------------------------ chat on another server (osinthub/ai/chatconn.py)
_THINK = re.compile(r"^\s*<think>.*?</think>\s*", re.S)


def openai_body(via: str, model: str, messages: list[dict], max_tokens: int, temperature: float,
                think: bool) -> dict:
    """A plain OpenAI chat request. Thinking off: Ollama takes reasoning_effort "none" (tested with Ollama 0.40);
    other servers get no extra field, since a strict one rejects fields it does not know."""
    body: dict[str, Any] = {"model": model, "messages": messages, "max_tokens": max_tokens,
                            "temperature": temperature, "stream": False}
    if via == "ollama" and not think:
        body["reasoning_effort"] = "none"
    return body


def reply_text(res: Any) -> str | None:
    """The assistant text of an OpenAI chat reply (a leading <think> block removed), or None if it isn't one."""
    try:
        text = res["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return None
    if isinstance(text, list):      # content parts
        text = "".join(p.get("text", "") for p in text if isinstance(p, dict))
    if not isinstance(text, str):
        return None
    return _THINK.sub("", text).strip()


# response_format kinds to try, best first; a server that rejects one (400) gets the next, remembered per connection
_RF = ("json_schema", "json_object", None)


class _External:
    def __init__(self, conn: dict):
        self.via, self.url, self.model, self.is_local = conn["via"], conn["url"], conn["model"], conn["is_local"]
        headers = {"Authorization": f"Bearer {conn['key']}"} if conn.get("key") else {}
        # on this computer or network: no proxy and a short connect timeout; on the internet: proxies apply
        self.http = httpx.Client(base_url=self.url, headers=headers, trust_env=not self.is_local, follow_redirects=False,
                                 timeout=httpx.Timeout(120.0, connect=CONNECT_TIMEOUT if self.is_local else 5.0))
        self.down_until = 0.0
        self.last_error: str | None = None
        self.ever_up = False
        self.rf = 0

    def down(self) -> bool:
        return time.monotonic() < self.down_until

    def _mark_down(self, err: str, seconds: float = DOWN_FOR) -> None:
        if not self.down():
            log.warning("chat server %s unavailable (%s); retrying in %.0fs", self.url, err, seconds)
        self.down_until = time.monotonic() + seconds
        self.last_error = err

    def _send(self, body: dict, timeout: float) -> httpx.Response | None:
        if self.down():
            return None
        try:
            r = self.http.post("/chat/completions", json=body, timeout=httpx.Timeout(
                timeout, connect=CONNECT_TIMEOUT if self.is_local else 5.0))
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.RemoteProtocolError, httpx.ReadError) as e:
            self._mark_down(f"{type(e).__name__}: {e}")
            return None
        except httpx.TimeoutException as e:     # busy, not gone: as for the helper, chat is not marked down
            log.warning("chat server %s timed out after %.0fs: %s", self.url, timeout, e)
            return None
        except httpx.HTTPError as e:
            self._mark_down(f"{type(e).__name__}: {e}")
            return None
        if r.status_code in (401, 403):
            self._mark_down(f"{r.status_code}: the server refused the API key", 300.0)
            return None
        if r.status_code in (429, 503):
            self._mark_down(f"{r.status_code} {r.text[:120]}", 30.0)
            return None
        return r

    def _once(self, messages: list[dict], schema: dict | None, json_mode: bool, max_tokens: int,
              temperature: float, think: bool, timeout: float) -> str | None:
        body = openai_body(self.via, self.model, messages, max_tokens, temperature, think)
        while True:
            kind = _RF[self.rf] if json_mode else None
            if kind == "json_schema":
                body["response_format"] = {"type": "json_schema",
                                           "json_schema": {"name": "out", "schema": schema or {"type": "object"}}}
            elif kind == "json_object":
                body["response_format"] = {"type": "json_object"}
            else:
                body.pop("response_format", None)
            r = self._send(body, timeout)
            if r is None:
                return None
            if r.status_code == 400 and kind is not None and self.rf < len(_RF) - 1:
                log.info("chat server %s rejected response_format %s; trying %s", self.url, kind, _RF[self.rf + 1])
                self.rf += 1
                continue
            if r.status_code >= 400:
                log.warning("chat server %s -> %d %s", self.url, r.status_code, r.text[:200])
                self.last_error = f"{r.status_code} {r.text[:160]}"
                return None
            try:
                text = reply_text(r.json())
            except ValueError:
                text = None
            if text is None:
                self.last_error = "the reply was not in the OpenAI chat format"
                return None
            self.ever_up, self.last_error = True, None
            return text

    def chat(self, messages: list[dict], schema: dict | None, max_tokens: int, temperature: float, think: bool,
             timeout: float) -> str | None:
        msgs = [{"role": m["role"], "content": m.get("content") or ""} for m in messages]
        json_mode = schema is not None
        if json_mode:
            msgs = jsonout.with_hint(msgs, schema)
            think = False
        text = self._once(msgs, schema, json_mode, max_tokens, temperature, think, timeout)
        if text is None or not json_mode:
            return text
        obj, problem = jsonout.problem(text, schema)
        if problem is None:
            return json.dumps(obj, ensure_ascii=False)
        # as the helper does: one chance to fix it
        fix = msgs + [{"role": "assistant", "content": text},
                      {"role": "user", "content": f"That was not valid: {problem}. Reply with the corrected JSON only."}]
        text = self._once(fix, schema, json_mode, max_tokens, 0.0, False, timeout)
        if text is None:
            return None
        obj, problem = jsonout.problem(text, schema)
        if problem is not None:
            log.warning("chat server %s: JSON still invalid after a retry: %s", self.url, problem)
            return None
        return json.dumps(obj, ensure_ascii=False)


_ext: _External | None = None
_ext_key: tuple | None = None


def _external() -> _External | None:
    """The chosen other server for chat, or None for the helper. Rebuilt when the choice changes."""
    global _ext, _ext_key
    from . import chatconn
    try:
        conn = chatconn.external()
    except Exception as e:   # a broken saved choice must not break chat callers
        log.warning("chat connection: %s", e)
        conn = None
    key = None if conn is None else (conn["via"], conn["url"], conn["model"], conn.get("key"), chatconn.version())
    with _lock:
        if key != _ext_key:
            if _ext is not None:
                _ext.http.close()
            _ext, _ext_key = (_External(conn) if conn else None), key
        return _ext


def chat_status() -> dict:
    """Where chat goes and how it is doing (no key)."""
    from . import chatconn
    try:
        via = chatconn.via()
    except Exception:
        via = None
    ext = _external()
    if ext is not None:
        return {"via": ext.via, "model": ext.model, "url": ext.url, "is_local": ext.is_local, "down": ext.down(),
                "ever_up": ext.ever_up, "last_error": ext.last_error}
    return {"via": via, "model": None, "url": config.AI_URL, "is_local": True, "down": helper_down(),
            "ever_up": _ever_up, "last_error": _last_error}
