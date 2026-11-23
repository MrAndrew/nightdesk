"""Start Night Desk: `nightdesk` (the installed command) or `python -m osinthub` (a checkout).

Options are shortcuts for the OSINTHUB_* environment variables (see .env.example); they are applied before the app's
configuration is read.
"""
import argparse
import logging
import os
import sys

import uvicorn


def _args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="nightdesk", description="Night Desk: a local cyber OSINT hub.")
    p.add_argument("--lake", metavar="DIR", help="data folder (OSINTHUB_LAKE; default: this computer's app-data folder)")
    p.add_argument("--port", type=int, metavar="N", help="port (OSINTHUB_PORT; default 8787)")
    p.add_argument("--offline", action="store_true", help="fetch nothing from the internet (OSINTHUB_OFFLINE=1)")
    p.add_argument("--open", action="store_true", help="open the dashboard in the browser once it is up")
    p.add_argument("--version", action="store_true", help="print the version and exit")
    return p.parse_args(argv)


def _version() -> str:
    from importlib.metadata import PackageNotFoundError, version
    try:
        return version("nightdesk")
    except PackageNotFoundError:
        return "0.0.0 (source checkout)"


def _open_when_up(url: str) -> None:
    """Open the browser once /api/health answers (a background thread; gives up after a minute)."""
    import threading
    import time
    import urllib.request
    import webbrowser

    def wait():
        for _ in range(120):
            try:
                with urllib.request.urlopen(url + "api/health", timeout=1) as r:
                    if r.status == 200:
                        webbrowser.open(url)
                        return
            except Exception:
                pass
            time.sleep(0.5)
    threading.Thread(target=wait, daemon=True, name="open-browser").start()


def main(argv: list[str] | None = None) -> None:
    """Start the app; `argv` are command-line options (none when called from code)."""
    a = _args(argv or [])
    if a.version:
        print(f"nightdesk {_version()}")
        return
    if a.lake:
        os.environ["OSINTHUB_LAKE"] = os.path.abspath(os.path.expanduser(a.lake))
    if a.port:
        os.environ["OSINTHUB_PORT"] = str(a.port)
    if a.offline:
        os.environ["OSINTHUB_OFFLINE"] = "1"

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # A data-folder move asked for in Settings runs now, before anything opens the database (osinthub/lakeloc.py).
    from . import lakeloc
    lakeloc.run_pending_move()

    from . import config

    # A bind beyond this machine without a password would be an open admin API on the network: refuse, one line.
    if (problem := config.bind_problem()) is not None:
        raise SystemExit(f"osinthub: {problem}")
    log = logging.getLogger("osinthub")
    if config.TRUST_PROXY_AUTH:
        log.warning("OSINTHUB_TRUST_PROXY_AUTH is on: no sign-in here; the reverse proxy in front must ask for one")
    elif config.PASSWORD:
        log.info("sign-in on: every request needs the password (HTTP Basic, any user name)")
    host = "127.0.0.1" if config.HOST in ("0.0.0.0", "::", "") else config.HOST
    url = f"http://{'[' + host + ']' if ':' in host else host}:{config.PORT}/"
    log.info("Night Desk on %s (data in %s)", url, config.LAKE)
    if a.open:
        _open_when_up(url)
    # A Server object rather than uvicorn.run, so Settings can stop it to restart (lakeloc.schedule_restart) without a
    # signal: uvicorn re-raises a captured SIGTERM after shutdown, which would end the process before it starts again.
    server = uvicorn.Server(uvicorn.Config("osinthub.api:app", host=config.HOST, port=config.PORT, log_level="info",
                                           # Open live-stream (SSE) tabs would otherwise hold shutdown open.
                                           timeout_graceful_shutdown=5))
    lakeloc.SERVER = server
    server.run()
    if lakeloc.restart_requested.is_set():
        _restart(argv or [], log)


def _restart(argv: list[str], log: logging.Logger) -> None:
    """Start this process again in place (same process id, so whatever started it, a terminal, nohup, launchd or a
    time limit, keeps watching it). The database is closed first and no open file is handed on."""
    log.warning("restarting Night Desk")
    try:
        from . import db
        db.close()
    except Exception:
        pass
    logging.shutdown()
    sys.stdout.flush(); sys.stderr.flush()
    os.closerange(3, 65536)
    os.execv(sys.executable, [sys.executable, "-m", "osinthub", *argv])


def cli() -> None:
    """The `nightdesk` command."""
    main(sys.argv[1:])


if __name__ == "__main__":
    cli()
