"""Turning local AI on from the app (Settings › AI).

Nothing here runs until the user turns AI on: the install brings no AI libraries and no models. Turning it on
1. installs the AI libraries (MLX, pinned to uv.lock) into Night Desk's own folder, unless they are importable
   already (a source checkout has them);
2. downloads the models the user ticked into the Hugging Face cache (osinthub/ai/fetch.py, its own process);
3. starts the helper (osinthub/ai/server.py) on this computer only, and stops it again when the app stops.
Turning it off stops the helper; deleting the models and libraries is a separate choice, and only what Night Desk
downloaded itself is ever deleted.

The chat model is one choice among several (osinthub/ai/chatconn.py): the recommended download, any MLX chat model
already in the Hugging Face cache, or another OpenAI-compatible server instead of the built-in helper.

The choice is kept per machine in <config>/ai/ai.json (the models and libraries are per machine too), never in
the data folder. Apple silicon only, native runs only (in Docker the helper runs on the Mac outside the container).
okf/architecture/local-ai.md#turning-ai-on
"""
from __future__ import annotations

import atexit
import importlib.util
import json
import logging
import os
import platform
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from .. import config, lakeloc

log = logging.getLogger("osinthub.ai.setup")

AI_LIBS = ["mlx-lm==0.32.2"]     # the version in uv.lock (tests/ai/test_ai_setup.py keeps them equal)
GB = 1_000_000_000
GIB = 1 << 30
CHAT_MIN_MEMORY = 48 * GIB       # the 28 GB chat model plus macOS, the app and a browser
LIBS_SIZE = 1 * GB               # about 600 MB installed; asked for with headroom

MODELS: dict[str, dict] = {
    "search": {"repo": os.environ.get("AI_EMBED_MODEL", "Qwen/Qwen3-Embedding-0.6B"), "size": int(1.2 * GB),
               "memory": 2 * GB, "label": "Search model",
               "what": "Search by meaning: finds stories, CVEs and events by what they are about, not only by their words."},
    "chat": {"repo": os.environ.get("AI_CHAT_MODEL", "mlx-community/Qwen3.8-27B-8bit"), "size": 28 * GB,
             "memory": 30 * GB, "label": "Chat model",
             "what": "Story summaries and entity briefs, written on this Mac."},
}


def repo(m: str) -> str:
    """The model behind 'search' or 'chat': for chat, the MLX model chosen in Settings, else the recommended one."""
    if m == "chat" and (r := saved().get("chat_repo")):
        return str(r)
    return MODELS[m]["repo"]


def chat_memory_needed(repo_id: str, size: int | None) -> int:
    """Memory a Mac needs to run this chat model next to macOS, the app and a browser."""
    if repo_id == MODELS["chat"]["repo"] or not size:
        return CHAT_MIN_MEMORY
    return int(size * 1.2) + 12 * GIB


# ------------------------------------------------------------------ where things go
def ai_dir() -> Path:
    return lakeloc.config_dir() / "ai"


def libs_dir() -> Path:
    return ai_dir() / "libs"


def _state_file() -> Path:
    return ai_dir() / "ai.json"


def helper_log() -> Path:
    return ai_dir() / "helper.log"


def hf_cache() -> Path:
    """The Hugging Face model cache, found the way huggingface_hub finds it (without importing it)."""
    if v := os.environ.get("HF_HUB_CACHE"):
        return Path(v)
    if v := os.environ.get("HF_HOME"):
        return Path(v) / "hub"
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "huggingface" / "hub"


def _model_dir(repo: str) -> Path:
    return hf_cache() / ("models--" + repo.replace("/", "--"))


def model_present(repo: str) -> bool:
    """The model is fully in the cache: a snapshot with its config and no download left half done."""
    d = _model_dir(repo)
    if not any((d / "snapshots").glob("*/config.json")):
        return False
    return not any((d / "blobs").glob("*.incomplete"))


def _snapshot_size(d: Path) -> int:
    total = 0
    for f in d.rglob("*"):
        try:
            if f.is_file():
                total += f.stat().st_size     # snapshot files link to the shared blobs
        except OSError:
            pass
    return total


def mlx_chat_models() -> list[dict]:
    """Chat models the built-in helper can run: the recommended one (downloaded or not) and every MLX language model
    already in the Hugging Face cache. [{repo, size, present, recommended, memory_needed, enough_memory}]"""
    mem = memory() or 0
    out: dict[str, dict] = {}
    rec = MODELS["chat"]["repo"]
    root = hf_cache()
    try:
        dirs = sorted(root.glob("models--*"))
    except OSError:
        dirs = []
    for d in dirs:
        repo_id = d.name[len("models--"):].replace("--", "/", 1)
        if repo_id == MODELS["search"]["repo"] or not model_present(repo_id):
            continue
        snaps = sorted((d / "snapshots").glob("*/config.json"), key=lambda f: f.stat().st_mtime)
        try:
            cfg = json.loads(snaps[-1].read_text())
        except (OSError, ValueError, IndexError):
            continue
        archs = " ".join(cfg.get("architectures") or [])
        mlx = "quantization" in cfg or "mlx" in repo_id.lower()
        if not mlx or not ("CausalLM" in archs or "ConditionalGeneration" in archs) or not any(
                snaps[-1].parent.glob("*.safetensors")):
            continue
        size = _snapshot_size(snaps[-1].parent)
        out[repo_id] = {"repo": repo_id, "size": size, "present": True, "recommended": repo_id == rec}
    if rec not in out:
        out[rec] = {"repo": rec, "size": MODELS["chat"]["size"], "present": False, "recommended": True}
    for m in out.values():
        m["memory_needed"] = chat_memory_needed(m["repo"], m["size"])
        m["enough_memory"] = mem >= m["memory_needed"]
    return sorted(out.values(), key=lambda m: (not m["recommended"], m["repo"].lower()))


# ------------------------------------------------------------------ the machine
def _in_docker() -> bool:
    from ..netlog.ingest import in_docker
    return in_docker()


def apple_silicon() -> bool:
    return sys.platform == "darwin" and platform.machine() == "arm64"


def memory() -> int | None:
    try:
        if sys.platform == "darwin":
            return int(subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, timeout=5).stdout)
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _free(path: Path) -> int | None:
    p = path
    while not p.exists() and p != p.parent:
        p = p.parent
    try:
        return shutil.disk_usage(p).free
    except OSError:
        return None


def libs_where() -> str | None:
    """'app' when the app's own environment has MLX (a source checkout), 'libs' when Night Desk installed it, else None."""
    if importlib.util.find_spec("mlx_lm") is not None:
        return "app"
    if (libs_dir() / "mlx_lm").is_dir():
        return "libs"
    return None


def _loopback_url() -> tuple[str, int] | None:
    u = urlsplit(config.AI_URL)
    if u.hostname in ("127.0.0.1", "localhost", "::1"):
        return u.hostname, u.port or 8790
    return None


# ------------------------------------------------------------------ the saved choice
def saved() -> dict:
    try:
        d = json.loads(_state_file().read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(**kw) -> None:
    d = {**saved(), **kw}
    f = _state_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=1))
    tmp.replace(f)


def enabled() -> bool:
    return bool(saved().get("enabled"))


def chosen_models() -> list[str]:
    return [m for m in saved().get("models") or [] if m in MODELS]


# ------------------------------------------------------------------ the download job
_lock = threading.Lock()
_job: dict = {"running": False, "step": None, "done": 0, "total": 0, "error": None, "finished": None, "models": []}
_proc: subprocess.Popen | None = None
_cancel = threading.Event()


def _uv() -> str | None:
    for c in (shutil.which("uv"), Path.home() / ".local" / "bin" / "uv", Path.home() / ".cargo" / "bin" / "uv"):
        if c and Path(c).is_file():
            return str(c)
    return None


def why_not() -> str | None:
    """Why the built-in AI (the helper: search by meaning, and the built-in chat model) can't be turned on from this
    page here (one plain sentence), or None. Chat on another server does not depend on it."""
    if _in_docker():
        return ("Night Desk is running in Docker. The built-in AI runs on the Mac itself, outside the container, so "
                "it can't be turned on from here.")
    if not apple_silicon():
        return "The built-in AI needs a Mac with Apple silicon (M1 or later). Everything else works without it."
    if _loopback_url() is None:
        return f"The AI helper is set to another computer ({config.AI_URL}), so it is not started from here."
    return None


def _chat_choice(chat_repo: str | None) -> dict | None:
    """The chat model entry for this repo (None: not one the built-in helper can run here)."""
    want = chat_repo or repo("chat")
    return next((m for m in mlx_chat_models() if m["repo"] == want), None)


def plan(models: list[str], chat_repo: str | None = None) -> dict:
    """What turning on these models would download, and whether it fits: {download, need, free, problem}."""
    repos = {m: (chat_repo or repo("chat")) if m == "chat" else repo(m) for m in models}
    todo = [m for m in models if not model_present(repos[m])]
    need = sum(MODELS[m]["size"] for m in todo) + (LIBS_SIZE if libs_where() is None else 0)
    pick = _chat_choice(chat_repo) if "chat" in models else None
    free = _free(hf_cache())
    problem = None
    if not models:
        problem = "Choose at least one model."
    elif "chat" in models and "search" not in models:
        problem = "The chat model works together with the search model, so choose both."
    elif "chat" in models and pick is None:
        problem = "That chat model is not one the built-in helper can run (an MLX model in the Hugging Face cache)."
    elif "chat" in models and not pick["enough_memory"]:
        problem = f"That chat model needs a Mac with at least {round(pick['memory_needed'] / GIB)} GB of memory."
    elif need and config.OFFLINE:
        problem = "Offline mode is on, so nothing can be downloaded. Restart Night Desk with offline mode turned off first."
    elif need and libs_where() is None and _uv() is None:
        problem = "Installing the AI libraries needs uv (https://docs.astral.sh/uv/), which is not on this Mac."
    elif need and free is not None and free < need * 1.1:
        problem = f"Not enough free disk space: this needs about {need / GB:.1f} GB and {free / GB:.1f} GB is free."
    return {"download": todo, "libs": libs_where() is None, "need": need, "free": free, "problem": problem}


def start(models: list[str], chat_repo: str | None = None) -> dict:
    """Start turning AI on with these models (in the background). Raises ValueError with a plain message."""
    models = [m for m in dict.fromkeys(models) if m in MODELS]
    if (why := why_not()) is not None:
        raise ValueError(why)
    chat_repo = (chat_repo or repo("chat")) if "chat" in models else None
    p = plan(models, chat_repo)
    if p["problem"]:
        raise ValueError(p["problem"])
    with _lock:
        if _job["running"]:
            raise ValueError("AI is already being set up.")
        _cancel.clear()
        _job.update(running=True, step="starting", done=0, total=0, error=None, finished=None, models=models)
    threading.Thread(target=_run, args=(models, chat_repo), name="ai-setup", daemon=True).start()
    return job()


def cancel() -> None:
    _cancel.set()
    if _proc is not None and _proc.poll() is None:
        _proc.terminate()


def job() -> dict:
    return dict(_job)


def _env(libs: bool) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH",)}
    if libs:
        env["OSINTHUB_AI_LIBS"] = str(libs_dir())
    return env


def _step(cmd: list[str], env: dict, step: str, progress: bool) -> None:
    """Run one step as its own process; raise RuntimeError with its last message when it fails or is cancelled."""
    global _proc
    _job.update(step=step, done=0, total=0)
    last = ""
    _proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             stdin=subprocess.DEVNULL)
    try:
        for line in _proc.stdout:
            line = line.strip()
            if not line:
                continue
            last = line
            if progress:
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if "total" in d:
                    _job.update(total=int(d.get("total") or 0), done=int(d.get("done") or 0))
                if d.get("error"):
                    last = d["error"]
        _proc.wait()
    finally:
        rc, _proc = _proc.returncode, None
    if _cancel.is_set():
        raise RuntimeError("Stopped.")
    if rc != 0:
        raise RuntimeError(last[:300] or f"{step} failed")


def _run(models: list[str], chat_repo: str | None = None) -> None:
    try:
        if libs_where() is None:
            tmp = libs_dir().with_name("libs.part")
            shutil.rmtree(tmp, ignore_errors=True)
            tmp.parent.mkdir(parents=True, exist_ok=True)
            _step([_uv() or "uv", "pip", "install", "--quiet", "--python", sys.executable, "--target", str(tmp), *AI_LIBS],
                  _env(False), "libs", progress=False)
            shutil.rmtree(libs_dir(), ignore_errors=True)
            tmp.replace(libs_dir())
        for m in models:
            r = chat_repo if m == "chat" else repo(m)
            if not model_present(r):
                _step([sys.executable, "-m", "osinthub.ai.fetch", r], _env(libs_where() == "libs"), m, progress=True)
                if not model_present(r):
                    raise RuntimeError(f"The {MODELS[m]['label'].lower()} did not download completely.")
                _save(downloaded=sorted({*(saved().get("downloaded") or []), r}))   # only these are ever deleted
        from . import chatconn
        # the list is always written, so a model that was already here never counts as one Night Desk downloaded
        _save(downloaded=list(saved().get("downloaded") or []))
        _save(enabled=True, models=models, at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
              chat_repo=chat_repo if "chat" in models else saved().get("chat_repo"))
        if "chat" in models:
            chatconn.use_builtin()
        elif chatconn.saved()["via"] == "builtin":
            chatconn.turn_off()
        _job.update(step="starting the helper", done=0, total=0)
        restart_helper()
        _job.update(step="done")
    except Exception as e:
        log.warning("AI setup stopped: %s", e)
        _job.update(error=str(e)[:300] or type(e).__name__)
    finally:
        _job.update(running=False, finished=time.time())


# ------------------------------------------------------------------ the helper process
_helper: subprocess.Popen | None = None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _is_our_helper(pid: int) -> bool:
    """The pid is still a helper process (not a reused number): its command line runs osinthub.ai.server."""
    try:
        cmd = subprocess.run(["ps", "-o", "command=", "-p", str(pid)], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return "osinthub.ai.server" in cmd


def helper_running() -> dict:
    """{up, ours, pid}: up = something answers at AI_URL; ours = it is the helper this app started."""
    from . import client
    pid = saved().get("helper_pid")
    ours = bool(pid) and _pid_alive(int(pid)) and _is_our_helper(int(pid))
    return {"up": client.health(timeout=0.5) is not None, "ours": ours, "pid": int(pid) if ours else None}


def start_helper() -> str:
    """Start the helper for the saved models unless one already answers. Returns what happened, in a few words."""
    global _helper
    from . import client
    if why_not() is not None or not enabled():
        return "not started"
    if client.health(timeout=0.5) is not None:
        if helper_running()["ours"]:
            _save(helper_owner=os.getpid())   # a helper an earlier run started: this run stops it when it exits
        return "already running"
    models = chosen_models()
    where = libs_where()
    if where is None or not all(model_present(repo(m)) for m in models) or "search" not in models:
        return "not ready"
    host, port = _loopback_url()
    env = _env(where == "libs")
    env.update(AI_HOST=host, AI_PORT=str(port), AI_CHAT="1" if "chat" in models else "0", HF_HUB_OFFLINE="1",
               AI_EMBED_MODEL=repo("search"), AI_CHAT_MODEL=repo("chat"))
    helper_log().parent.mkdir(parents=True, exist_ok=True)
    with open(helper_log(), "ab") as out:
        _helper = subprocess.Popen([sys.executable, "-m", "osinthub.ai.server"], env=env, stdout=out,
                                   stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
    _save(helper_pid=_helper.pid, helper_owner=os.getpid())   # a restart in place keeps the app's pid
    client.mark_up()
    log.info("AI helper started (pid %s, %s)", _helper.pid, ", ".join(models))
    return "started"


def stop_helper() -> bool:
    """Stop the helper this app started (also one an earlier run of the app started). True if one was stopped."""
    global _helper
    pid = saved().get("helper_pid")
    stopped = False
    if pid and _pid_alive(int(pid)) and _is_our_helper(int(pid)):
        try:
            os.killpg(int(pid), signal.SIGTERM)
        except OSError:
            os.kill(int(pid), signal.SIGTERM)
        for _ in range(50):
            if not _pid_alive(int(pid)):
                break
            time.sleep(0.1)
        stopped = True
    if _helper is not None:
        try:
            _helper.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
    _helper = None
    if pid:
        _save(helper_pid=None, helper_owner=None)
    return stopped


def restart_helper() -> str:
    """Start the helper again so it loads the saved models (only a helper this app started is restarted)."""
    if helper_running()["ours"]:
        stop_helper()
    return start_helper()


def drop_builtin_chat() -> None:
    """Chat moved off the built-in helper: forget its chat model and restart the helper with search only, in the
    background, so its memory is freed."""
    if "chat" not in chosen_models():
        return
    _save(models=[m for m in chosen_models() if m != "chat"])
    if helper_running()["ours"]:
        threading.Thread(target=lambda: log.info("AI helper: %s", restart_helper()), name="ai-helper-restart",
                         daemon=True).start()


def _delete_model(repo: str) -> bool:
    """Delete a model the way huggingface_hub does (its shared files too, unless another model uses them). Without
    the library (the AI libraries were deleted earlier) only the model's own folder goes."""
    where = libs_where()
    if where is not None:
        try:
            r = subprocess.run([sys.executable, "-m", "osinthub.ai.fetch", "--delete", repo], env=_env(where == "libs"),
                               capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
            if r.returncode == 0:
                return True
            log.warning("deleting %s: %s", repo, (r.stdout or r.stderr).strip()[-300:])
        except (OSError, subprocess.SubprocessError) as e:
            log.warning("deleting %s: %s", repo, e)
    shutil.rmtree(_model_dir(repo), ignore_errors=True)
    return not _model_dir(repo).exists()


def turn_off(delete_models: bool = False, delete_libs: bool = False) -> dict:
    """Stop the helper and the download, forget the choice; optionally delete what was downloaded."""
    cancel()
    stopped = stop_helper()
    from . import chatconn
    if chatconn.saved()["via"] == "builtin" or (chatconn.saved()["via"] is None and "chat" in chosen_models()):
        chatconn.turn_off()      # chat on another server stays as it is
    st = saved()
    # Only models Night Desk downloaded are deleted: never one that was in the cache before (another app's, or one
    # picked from the cache). An older choice without that list counts the recommended models as downloaded.
    mine = st.get("downloaded")
    mine = list(mine) if isinstance(mine, list) else [MODELS[m]["repo"] for m in (st.get("models") or MODELS)
                                                      if m in MODELS]
    _save(enabled=False, models=[])
    deleted = []
    if delete_models:
        for r in mine:
            if _model_dir(r).is_dir() and _delete_model(r):
                deleted.append(r)
        _save(downloaded=[r for r in mine if _model_dir(r).is_dir()])
    if delete_libs and libs_dir().is_dir():
        shutil.rmtree(libs_dir(), ignore_errors=True)
        deleted.append("AI libraries")
    return {"stopped": stopped, "deleted": deleted}


def stop_at_exit() -> None:
    # only the app that started the helper stops it (another Night Desk on this machine may be using it)
    if saved().get("helper_pid") and saved().get("helper_owner") == os.getpid():
        stop_helper()


atexit.register(stop_at_exit)   # a backup: __main__ calls it as soon as the server stops


# ------------------------------------------------------------------ what Settings shows
def status() -> dict:
    mem = memory()
    from . import chatconn, client
    models = {}
    for k, m in MODELS.items():
        r = repo(k)
        models[k] = {"label": m["label"], "what": m["what"], "repo": r, "size": m["size"],
                     "memory": m["memory"], "present": model_present(r), "folder": str(_model_dir(r))}
    models["chat"]["enough_memory"] = (mem or 0) >= chat_memory_needed(repo("chat"), None)
    mine = saved().get("downloaded")
    deletable = [r for r in (mine if isinstance(mine, list) else [repo(m) for m in chosen_models()])
                 if _model_dir(r).is_dir()]
    return {"why_not": why_not(), "docker": _in_docker(), "apple_silicon": apple_silicon(), "offline": config.OFFLINE,
            "memory": mem, "chat_min_memory": CHAT_MIN_MEMORY, "free": _free(hf_cache()), "cache": str(hf_cache()),
            "libs": {"where": libs_where(), "folder": str(libs_dir()), "size": LIBS_SIZE, "uv": _uv() is not None},
            "models": models, "enabled": enabled(), "chosen": chosen_models(), "job": job(),
            "helper": helper_running(), "log": str(helper_log()), "chat": chatconn.describe(),
            "helper_chat": client.chat_status(),
            "deletable": [{"repo": r, "size": _snapshot_size(_model_dir(r))} for r in deletable]}
