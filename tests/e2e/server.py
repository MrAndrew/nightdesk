"""A throwaway Night Desk server for the E2E journeys, smoke.py, deeplinks.py and tools/gate.sh.

Offline (OSINTHUB_OFFLINE=1), AI helper and Qdrant pointed at the discard port, DuckDB vectors, its own scratch lake,
loopback only, the SQL console on (OSINTHUB_SQL_CONSOLE=1; ND_SQL_CONSOLE=0 leaves it off). A new lake is seeded with the synthetic news fixture (seed.py); `--from DIR` clones an existing lake
instead (APFS clone where the disk supports it). Never port 8787 (the owner's live app).

    python tests/e2e/server.py --port 9880 --lake /tmp/nd-lake [--from DIR] [--ttl 7200]

runs the server in the foreground until it is stopped or the time limit ends. The server runs in its own process
group, under ~/.claude/bin/ttl when that exists (a backstop that kills the whole group); stop() kills the group.
"""
from __future__ import annotations

import argparse
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TTL = Path.home() / ".claude" / "bin" / "ttl"
LIVE_PORT = 8787


def env_for(lake: Path, port: int) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("OSINTHUB_")}
    env.update(OSINTHUB_LAKE=str(lake), OSINTHUB_PORT=str(port), OSINTHUB_HOST="127.0.0.1", OSINTHUB_OFFLINE="1",
               OSINTHUB_VECTORS="duckdb", OSINTHUB_NEWS_NO_VECTORS="1", AI_URL="http://127.0.0.1:9",
               QDRANT_URL="http://127.0.0.1:9", PYTHONUNBUFFERED="1",
               XDG_CONFIG_HOME=str(lake) + ".config",   # never the machine's own Night Desk settings (AI, lake folder)
               HF_HUB_CACHE=str(lake) + ".hf",          # an empty model cache, whatever this machine has downloaded
               # the journeys, smoke.py and deeplinks.py drive the SQL console, so it is on here (the app's default is
               # off); ND_SQL_CONSOLE=0 starts a scratch server with it off
               OSINTHUB_SQL_CONSOLE=os.environ.get("ND_SQL_CONSOLE", "1"))
    env.pop("OSINTHUB_INBOX", None)
    env.pop("ABUSECH_AUTH_KEY", None)
    return env


def port_free(port: int) -> bool:
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def pick_port(spec: str | None = None) -> int:
    """The first free port of ND_E2E_PORTS ("9880-9889" by default, or "9885", or "0" for any free port)."""
    spec = spec or os.environ.get("ND_E2E_PORTS", "9880-9889")
    if spec == "0":
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]
    lo, _, hi = spec.partition("-")
    for p in range(int(lo), int(hi or lo) + 1):
        if p != LIVE_PORT and port_free(p):
            return p
    raise RuntimeError(f"no free port in {spec}")


def prepare_lake(lake: Path, base: Path | None = None) -> None:
    """A fresh lake: a clone of `base`, or empty and seeded with the synthetic news fixture."""
    if lake.exists():
        shutil.rmtree(lake)
    if base:
        lake.parent.mkdir(parents=True, exist_ok=True)
        if subprocess.run(["cp", "-cR", str(base), str(lake)], capture_output=True).returncode != 0:
            shutil.copytree(base, lake)
        return
    lake.mkdir(parents=True)
    r = subprocess.run([sys.executable, str(ROOT / "tests" / "e2e" / "seed.py")], cwd=ROOT, env=env_for(lake, 9),
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"seeding the scratch lake failed:\n{r.stdout}\n{r.stderr}")


def command(ttl: int) -> list[str]:
    cmd = [sys.executable, "-m", "osinthub"]
    return [str(TTL), str(ttl), *cmd] if TTL.exists() and os.access(TTL, os.X_OK) else cmd


def start(lake: Path, port: int, log_path: Path, ttl: int = 1800) -> subprocess.Popen:
    if port == LIVE_PORT:
        raise ValueError("refusing port 8787 (the owner's live app)")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(log_path, "ab")
    return subprocess.Popen(command(ttl), cwd=ROOT, env=env_for(lake, port), stdout=fh, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, start_new_session=True)


def wait_healthy(base: str, proc: subprocess.Popen | None = None, timeout: float = 90) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if proc is not None and proc.poll() is not None:
            raise RuntimeError(f"the scratch server exited early (code {proc.returncode})")
        try:
            with urllib.request.urlopen(base + "/api/health", timeout=2) as r:
                if r.status == 200:
                    return
        except OSError:
            pass
        time.sleep(0.25)
    raise RuntimeError(f"the scratch server at {base} did not become healthy in {timeout:.0f} s")


def stop(proc: subprocess.Popen, port: int | None = None) -> None:
    """TERM the server's process group (ttl and the python under it), then KILL; wait for the port to free."""
    for sig, wait in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            break
        try:
            proc.wait(timeout=wait)
            break
        except subprocess.TimeoutExpired:
            continue
    try:   # stragglers in the group once the leader is gone
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    if port:
        end = time.time() + 10
        while time.time() < end and not port_free(port):
            time.sleep(0.2)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--lake", type=Path, required=True, help="scratch lake folder (recreated)")
    ap.add_argument("--from", dest="base", type=Path, default=os.environ.get("ND_LAKE_BASE") or None,
                    help="clone this lake instead of seeding an empty one (env ND_LAKE_BASE)")
    ap.add_argument("--ttl", type=int, default=7200, help="hard time limit in seconds (with ~/.claude/bin/ttl)")
    a = ap.parse_args()
    if a.port == LIVE_PORT:
        raise SystemExit("refusing port 8787 (the owner's live app)")
    prepare_lake(a.lake, a.base)
    os.chdir(ROOT)
    cmd = command(a.ttl)
    os.execvpe(cmd[0], cmd, env_for(a.lake, a.port))


if __name__ == "__main__":
    main()
