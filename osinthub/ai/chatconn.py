"""Where chat goes (Settings › AI › Chat): the built-in helper, or another OpenAI-compatible server.

Chat writes story summaries, entity briefs and the names picked out of articles. It can run on
* the built-in helper (osinthub/ai/server.py, MLX on this Mac; setup.py downloads and starts it), or
* any server that speaks the OpenAI chat format: Ollama and LM Studio on this computer (found by asking their usual
  ports), or another address (another machine, or a provider such as OpenRouter) with an optional API key.
Search by meaning always uses the built-in helper's search model: its vectors fill the search index, so it stays
local and fixed.

The choice is saved with the rest of the AI choice in <config>/ai/ai.json as {"chat": {"via", "url", "model"}}; the
API key in <config>/ai/chat-key.json (owner-only), tied to the host it was entered for, so changing the address never
sends an old key to a new host, and never returned to the browser. Offline mode allows only addresses on this
computer or the local network.
okf/architecture/local-ai.md#chat-connection
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import logging
import os
import socket
import threading
import time
from urllib.parse import urlsplit, urlunsplit

import httpx

from .. import config

log = logging.getLogger("osinthub.ai.chatconn")

EXTERNAL = ("ollama", "lmstudio", "other")
VIA = ("builtin", *EXTERNAL)
PRESETS = {"ollama": {"label": "Ollama", "port": 11434}, "lmstudio": {"label": "LM Studio", "port": 1234}}
PROBE_TIMEOUT = 1.0
TEST_TIMEOUT = 180.0          # a test may have to load a large model from disk first
_LOCAL_NAMES = ("localhost", "host.docker.internal")
_LOCAL_SUFFIXES = (".local", ".lan", ".home.arpa", ".internal", ".localdomain", ".localhost")


# ------------------------------------------------------------------ addresses
def _in_docker() -> bool:
    from ..netlog.ingest import in_docker
    return in_docker()


def _this_computer() -> str:
    """How the app reaches a server on the same computer (from inside Docker that is the Mac itself)."""
    return "host.docker.internal" if _in_docker() else "127.0.0.1"


def preset_url(via: str) -> str:
    return f"http://{_this_computer()}:{PRESETS[via]['port']}/v1"


def normalise(url: str) -> str:
    """A base URL for the OpenAI API: scheme, host, port and path, without '/chat/completions' or a trailing '/'.
    An address with no path gets '/v1'. Raises ValueError with a plain message."""
    u = (url or "").strip()
    if not u:
        raise ValueError("Enter the server's address.")
    if "://" not in u:
        host = u.split("/")[0].split(":")[0].strip("[]")
        u = ("http://" if _host_is_local(host) else "https://") + u
    p = urlsplit(u)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("The address must start with http:// or https:// and name a server.")
    if p.username or p.password:
        raise ValueError("Put the API key in its own field, not in the address.")
    if p.query or p.fragment:
        raise ValueError("The address should not have a '?' or '#' part.")
    try:
        _ = p.port
    except ValueError:
        raise ValueError("The port in the address is not a number.") from None
    path = p.path.rstrip("/")
    for tail in ("/chat/completions", "/models"):
        if path.endswith(tail):
            path = path[: -len(tail)].rstrip("/")
    return urlunsplit((p.scheme, p.netloc.lower(), path or "/v1", "", ""))


def host_of(url: str) -> str:
    p = urlsplit(url)
    return f"{(p.hostname or '').lower()}:{p.port or (443 if p.scheme == 'https' else 80)}"


_LOCAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                  "fc00::/7")]
_local_cache: dict[str, tuple[float, bool]] = {}


def _ip_local(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    # Python's is_private also covers the documentation ranges, so the local networks are named one by one
    return a.is_loopback or a.is_link_local or any(a in n for n in _LOCAL_NETS)


def _host_is_local(host: str) -> bool:
    """On this computer or the local network: loopback, private and link-local addresses, local names, or a name
    that resolves only to such addresses."""
    h = (host or "").lower().strip("[]").rstrip(".")
    if not h:
        return False
    if h in _LOCAL_NAMES or h.endswith(_LOCAL_SUFFIXES):
        return True
    try:
        ipaddress.ip_address(h.split("%")[0])
        return _ip_local(h)
    except ValueError:
        pass
    hit = _local_cache.get(h)
    if hit and time.monotonic() - hit[0] < 300:
        return hit[1]
    try:
        ips = {ai[4][0] for ai in socket.getaddrinfo(h, None)}
        local = bool(ips) and all(_ip_local(ip) for ip in ips)
    except (OSError, UnicodeError):
        local = False
    _local_cache[h] = (time.monotonic(), local)
    return local


def is_local(url: str) -> bool:
    return _host_is_local(urlsplit(url).hostname or "")


# ------------------------------------------------------------------ the saved choice and key
def _setup():
    from . import setup
    return setup


def _key_file():
    return _setup().ai_dir() / "chat-key.json"


def _saved_key() -> dict:
    try:
        d = json.loads(_key_file().read_text())
        return d if isinstance(d, dict) and d.get("key") else {}
    except (OSError, ValueError):
        return {}


def key_for(url: str) -> str | None:
    """The saved API key, only for the host it was entered for."""
    k = _saved_key()
    return k["key"] if k and k.get("host") == host_of(url) else None


def _write_key(url: str, key: str | None) -> None:
    f = _key_file()
    if not key:
        f.unlink(missing_ok=True)
        return
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({"host": host_of(url), "key": key}, fh)
    os.chmod(tmp, 0o600)
    tmp.replace(f)


_version = 0          # bumped on every change, so the client rebuilds its connection
_lock = threading.Lock()


def version() -> int:
    return _version


def saved() -> dict:
    """{"via", "url", "model"} as saved; via None when chat was never set up or turned off here."""
    c = _setup().saved().get("chat")
    if isinstance(c, dict) and c.get("via") in VIA:
        return {"via": c["via"], "url": c.get("url"), "model": c.get("model")}
    return {"via": None, "url": None, "model": None}


def via() -> str | None:
    """Where chat goes now: a saved choice, else 'builtin' when the built-in chat model is turned on."""
    s = saved()
    if s["via"]:
        return s["via"]
    return "builtin" if "chat" in _setup().chosen_models() else None


def external() -> dict | None:
    """The connection the client uses for chat, or None for the built-in helper (AI_URL):
    {"via", "url", "model", "key", "is_local"}. Offline mode drops one that is not local."""
    s = saved()
    if s["via"] not in EXTERNAL or not s["url"] or not s["model"]:
        return None
    local = is_local(s["url"])
    if config.OFFLINE and not local:
        return None
    return {**s, "key": key_for(s["url"]), "is_local": local}


def describe() -> dict:
    """What Settings shows (never the key itself)."""
    s, v = saved(), via()
    out = {"via": v, "url": s["url"], "model": s["model"], "has_key": False, "is_local": None,
           "blocked_offline": False, "presets": {k: {"label": p["label"], "url": preset_url(k)} for k, p in PRESETS.items()}}
    if v in EXTERNAL and s["url"]:
        out["has_key"] = key_for(s["url"]) is not None
        out["is_local"] = is_local(s["url"])
        out["blocked_offline"] = bool(config.OFFLINE and not out["is_local"])
    if v == "builtin":
        out["model"] = _setup().repo("chat")
    return out


def save(via_: str, url: str, model: str, key: str | None = None) -> dict:
    """Use another server for chat. key: a new key; None keeps the saved one when the host is the same; "" removes it.
    Raises ValueError with a plain message."""
    global _version
    if via_ not in EXTERNAL:
        raise ValueError("Choose Ollama, LM Studio or another address.")
    url = normalise(url)
    model = (model or "").strip()
    if not model or len(model) > 300:
        raise ValueError("Choose a model.")
    if config.OFFLINE and not is_local(url):
        raise ValueError("Offline mode is on, so chat can only use a server on this computer or the local network.")
    if key is not None and len(key) > 4096:
        raise ValueError("That API key is too long.")
    with _lock:
        was_builtin = via() == "builtin"
        keep = key_for(url) if key is None else key.strip()
        _write_key(url, keep or None)
        _setup()._save(chat={"via": via_, "url": url, "model": model})
        _version += 1
    if was_builtin:
        _setup().drop_builtin_chat()   # free the built-in chat model's memory
    log.info("chat now uses %s (%s, model %s)", via_, host_of(url), model)
    return describe()


def use_builtin() -> None:
    """Chat goes to the built-in helper (setup.py has just turned its chat model on)."""
    global _version
    with _lock:
        _setup()._save(chat={"via": "builtin", "url": None, "model": None})
        _version += 1


def turn_off() -> dict:
    """No chat. A built-in chat model is unloaded (the helper keeps running for search); a saved key is deleted."""
    global _version
    with _lock:
        was_builtin = via() == "builtin"
        _write_key("", None)
        _setup()._save(chat={"via": None, "url": None, "model": None})
        _version += 1
    if was_builtin:
        _setup().drop_builtin_chat()
    return describe()


# ------------------------------------------------------------------ finding servers and models
def _http(url: str, key: str | None, timeout: float) -> httpx.Client:
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    # a server on this computer or network is reached directly; HTTP(S)_PROXY applies only to the internet
    return httpx.Client(headers=headers, timeout=httpx.Timeout(timeout, connect=min(timeout, 5.0)),
                        trust_env=not is_local(url), follow_redirects=False)


def _plain_error(e: Exception | None, r: httpx.Response | None, url: str) -> str:
    where = host_of(url)
    if r is not None:
        msg = ""
        try:
            j = r.json()
            err = j.get("error") if isinstance(j, dict) else None
            msg = (err.get("message") if isinstance(err, dict) else err) or j.get("message") or ""
        except ValueError:
            msg = r.text[:120]
        msg = str(msg).strip()[:200]
        if r.status_code in (401, 403):
            return f"{where} refused the request ({r.status_code}): check the API key." + (f" It said: {msg}" if msg else "")
        if r.status_code == 404:
            return f"{where} has no such address or model (404)." + (f" It said: {msg}" if msg else "")
        return f"{where} answered {r.status_code}." + (f" It said: {msg}" if msg else "")
    if isinstance(e, httpx.ConnectError):
        return f"Nothing answers at {where}."
    if isinstance(e, httpx.TimeoutException):
        return f"{where} did not answer in time."
    return f"{where}: {type(e).__name__}: {str(e)[:160]}"


def list_models(via_: str, url: str, key: str | None = None, timeout: float = 5.0) -> dict:
    """The chat models a server offers: {"ok", "url", "models": [{"id", "size"}], "error"}."""
    try:
        url = normalise(url)
    except ValueError as e:
        return {"ok": False, "url": url, "models": [], "error": str(e)}
    if config.OFFLINE and not is_local(url):
        return {"ok": False, "url": url, "models": [], "error": "Offline mode is on: only local servers can be used."}
    if key is None:
        key = key_for(url)
    try:
        with _http(url, key, timeout) as h:
            if via_ == "ollama":
                root = url[: -len("/v1")] if url.endswith("/v1") else url
                r = h.get(root + "/api/tags")
                if r.status_code == 200:
                    ms = []
                    for m in r.json().get("models") or []:
                        caps = m.get("capabilities")
                        if caps is not None and "completion" not in caps:
                            continue      # an embedding-only model
                        ms.append({"id": m.get("name") or m.get("model"), "size": m.get("size")})
                    return {"ok": True, "url": url, "models": sorted(ms, key=lambda m: m["id"] or ""), "error": None}
            r = h.get(url + "/models")
            if r.status_code != 200:
                return {"ok": False, "url": url, "models": [], "error": _plain_error(None, r, url)}
            data = r.json().get("data") or []
            ms = [{"id": m.get("id"), "size": None} for m in data if isinstance(m, dict) and m.get("id")
                  and "embed" not in str(m.get("id")).lower()]
            return {"ok": True, "url": url, "models": sorted(ms, key=lambda m: m["id"]), "error": None}
    except (httpx.HTTPError, ValueError) as e:
        return {"ok": False, "url": url, "models": [], "error": _plain_error(e, None, url)}


def discover() -> dict:
    """Ask Ollama and LM Studio on their usual ports what they have, and list the MLX chat models in the Hugging
    Face cache for the built-in helper. Quick: one second per server, asked side by side."""
    out: dict = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futs = {k: pool.submit(list_models, k, preset_url(k), None, PROBE_TIMEOUT) for k in PRESETS}
        for k, f in futs.items():
            r = f.result()
            out[k] = {"label": PRESETS[k]["label"], "url": r["url"], "running": r["ok"], "models": r["models"],
                      "error": r["error"]}
    out["builtin"] = {"label": "Built-in (this Mac)", "models": _setup().mlx_chat_models(),
                      "why_not": _setup().why_not()}
    return out


def test(via_: str, url: str, model: str, key: str | None = None) -> dict:
    """Send one short chat. {"ok", "seconds", "reply", "error"}."""
    from . import client
    try:
        url = normalise(url)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    if config.OFFLINE and not is_local(url):
        return {"ok": False, "error": "Offline mode is on: only local servers can be used."}
    if key is None:
        key = key_for(url)
    body = client.openai_body(via_, model, [{"role": "user", "content": "Reply with the single word: ready"}],
                              max_tokens=400, temperature=0.0, think=False)
    t0 = time.monotonic()
    try:
        with _http(url, key, TEST_TIMEOUT) as h:
            r = h.post(url + "/chat/completions", json=body)
    except httpx.HTTPError as e:
        return {"ok": False, "error": _plain_error(e, None, url)}
    secs = round(time.monotonic() - t0, 1)
    if r.status_code != 200:
        return {"ok": False, "seconds": secs, "error": _plain_error(None, r, url)}
    try:
        text = client.reply_text(r.json())
    except ValueError:
        text = None
    if text is None:
        return {"ok": False, "seconds": secs, "error": f"{host_of(url)} answered, but not in the OpenAI chat format."}
    return {"ok": True, "seconds": secs, "reply": text[:80], "error": None}
