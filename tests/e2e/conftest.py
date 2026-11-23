"""E2E journeys: one scratch Night Desk server per run, one browser per journey. Docs: okf/architecture/testing.md

    uv run --with playwright --with pytest pytest tests/e2e -q

* Off by default: a run that does not name tests/e2e (e.g. `pytest tests`) skips collecting it entirely, so the
  unit/integration suite needs no Playwright and stays fast. Naming tests/e2e (or setting ND_E2E=1) turns it on.
* The journeys run in this process (the root conftest's one-process-per-file isolation exists for modules that import
  osinthub; these talk to a server over HTTP), so a run boots exactly one server: offline, a temporary lake seeded
  with the synthetic news fixture (seed.py), a free port from ND_E2E_PORTS (default 9880-9889). It is stopped and the
  lake deleted at the end, pass or fail. ND_E2E_BASE=http://127.0.0.1:PORT drives a server you started instead
  (never :8787: journeys write).
* Every page records page errors, console errors, 5xx responses and every request to a host that is not this machine
  (aborted); a journey fails if any of them is non-empty. A failing journey saves a screenshot of each of its pages
  (and the server log) to ND_E2E_ARTIFACTS (default: <temp>/nd-e2e-artifacts).
* Browser: Google Chrome when installed (channel "chrome"), else Playwright's Chromium
  (`uv run --with playwright playwright install chromium`). ND_E2E_HEADED=1 shows it.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

DESKTOP = {"viewport": {"width": 1440, "height": 900}}
PHONE = {"viewport": {"width": 390, "height": 844}, "has_touch": True, "is_mobile": True, "device_scale_factor": 2}
LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}


def _enabled(config) -> bool:
    if os.environ.get("ND_E2E") == "1":
        return True
    for a in config.args:
        p = Path(a.split("::")[0]).resolve()
        if p == HERE or HERE in p.parents:
            return True
    return False


def pytest_configure(config):
    config.addinivalue_line("markers", "e2e: an end-to-end journey (tests/e2e; runs only when tests/e2e is named)")


def pytest_ignore_collect(collection_path, config):
    p = Path(collection_path).resolve()
    if (p == HERE or HERE in p.parents) and p.suffix == ".py" and not _enabled(config):
        return True
    return None


@pytest.hookimpl(tryfirst=True)
def pytest_pycollect_makemodule(module_path, parent):
    if HERE in Path(module_path).resolve().parents:
        return pytest.Module.from_parent(parent, path=module_path)   # in process: one server for the whole run
    return None


def pytest_collection_modifyitems(config, items):
    for it in items:
        if HERE in Path(str(it.fspath)).resolve().parents:
            it.add_marker(pytest.mark.e2e)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    rep = yield
    setattr(item, f"rep_{rep.when}", rep)
    return rep


# ------------------------------------------------------------------------------------------------ the server
class ND:
    """The server under test: its base URL, lake, and a small JSON API client (writes carry this app's Origin)."""

    def __init__(self, base: str, lake: Path | None, run_dir: Path):
        self.base, self.lake, self.run_dir = base.rstrip("/"), lake, run_dir
        self.port = int(urllib.parse.urlsplit(self.base).port or 80)

    def url(self, hash_: str = "") -> str:
        return f"{self.base}/{hash_}"

    def call(self, method: str, path: str, body=None, params=None, headers=None, form: dict | None = None):
        url = self.base + path + ("?" + urllib.parse.urlencode(params) if params else "")
        h = {"Origin": self.base, **(headers or {})}
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                raw, status = r.read(), r.status
        except urllib.error.HTTPError as e:
            raw, status = e.read(), e.code
        try:
            out = json.loads(raw or b"null")
        except ValueError:
            out = raw.decode("utf-8", "replace")
        if status >= 400:
            raise AssertionError(f"{method} {path} -> {status}: {str(out)[:300]}")
        return out

    def get(self, path, **params):
        return self.call("GET", path, params=params or None)

    def post(self, path, body=None, **kw):
        return self.call("POST", path, body=body, **kw)

    def put(self, path, body=None):
        return self.call("PUT", path, body=body)

    def delete(self, path):
        return self.call("DELETE", path)

    def wait_for(self, fn, timeout=15.0, what="condition"):
        end = time.time() + timeout
        while True:
            v = fn()
            if v:
                return v
            if time.time() > end:
                raise AssertionError(f"timed out after {timeout:.0f} s waiting for {what}")
            time.sleep(0.2)


@pytest.fixture(scope="session")
def run_dir():
    d = Path(tempfile.mkdtemp(prefix="nd-e2e-", dir=os.environ.get("ND_E2E_TMP") or None))
    yield d
    if os.environ.get("ND_E2E_KEEP") != "1":
        shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope="session")
def artifacts() -> Path:
    return Path(os.environ.get("ND_E2E_ARTIFACTS") or Path(tempfile.gettempdir()) / "nd-e2e-artifacts")


@pytest.fixture(scope="session")
def nd(run_dir, artifacts, request):
    import server

    ext = os.environ.get("ND_E2E_BASE")
    if ext:
        if ext.rstrip("/").endswith(":8787"):
            pytest.exit("ND_E2E_BASE must not be the live app on :8787 (the journeys write)", returncode=2)
        yield ND(ext, Path(os.environ["ND_E2E_LAKE"]) if os.environ.get("ND_E2E_LAKE") else None, run_dir)
        return
    lake = run_dir / "lake"
    server.prepare_lake(lake)
    port = server.pick_port()
    log = run_dir / "server.log"
    proc = server.start(lake, port, log, ttl=int(os.environ.get("ND_E2E_TTL", "1200")))
    base = f"http://127.0.0.1:{port}"
    try:
        try:
            server.wait_healthy(base, proc)
        except RuntimeError as e:
            tail = log.read_text(errors="replace")[-3000:] if log.exists() else ""
            pytest.exit(f"{e}\n--- server log ---\n{tail}", returncode=3)
        yield ND(base, lake, run_dir)
    finally:
        server.stop(proc, port)
        if request.session.testsfailed and log.exists():
            artifacts.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(log, artifacts / "server.log")
        if not server.port_free(port):
            print(f"\nWARNING: port {port} still listening after stopping the scratch server (pid {proc.pid})",
                  file=sys.stderr)


@pytest.fixture(scope="session")
def demo(nd):
    """The built-in demo network data, loaded (journeys that need it call this; loading twice is refused)."""
    if not (nd.get("/api/netlog/demo") or {}).get("loaded"):
        nd.post("/api/netlog/demo")
    return nd


# ------------------------------------------------------------------------------------------------ browsers
@pytest.fixture(scope="session")
def pw():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.exit("the E2E journeys need Playwright: uv run --with playwright --with pytest pytest tests/e2e",
                    returncode=4)
    p = sync_playwright().start()
    yield p
    p.stop()


def _launch(pw):
    headless = os.environ.get("ND_E2E_HEADED") != "1"
    want = os.environ.get("ND_E2E_CHANNEL", "chrome")
    try:
        return pw.chromium.launch(channel=want or None, headless=headless)
    except Exception:
        return pw.chromium.launch(headless=headless)   # Playwright's own Chromium


class Pages:
    """One browser per journey; ui(form) opens a page in it with the error and egress recorders on."""

    def __init__(self, pw, nd):
        self.pw, self.nd, self.browser, self.pages = pw, nd, None, []

    def __call__(self, form: str = "desktop", *, tour_done: bool = True, base: str | None = None):
        if self.browser is None:
            self.browser = _launch(self.pw)
        ctx = self.browser.new_context(**(PHONE if form == "phone" else DESKTOP), base_url=base or self.nd.base,
                                       service_workers="block")
        ctx.set_default_timeout(10_000)
        if tour_done:
            ctx.add_init_script("try{localStorage.setItem('nd.tour.done','1')}catch(e){}")
        log = {"page_errors": [], "console_errors": [], "server_errors": [], "egress": []}

        def guard(route, request):
            u = urllib.parse.urlsplit(request.url)
            if u.scheme in ("data", "blob") or (u.hostname or "") in LOOPBACK:
                return route.continue_()
            log["egress"].append(f"{request.method} {request.url[:200]}")
            return route.abort()
        ctx.route("**/*", guard)
        page = ctx.new_page()
        page.on("console", lambda m: m.type == "error" and log["console_errors"].append(m.text[:300]))
        page.on("pageerror", lambda e: log["page_errors"].append(str(e)[:400]))
        page.on("response", lambda r: r.status >= 500 and log["server_errors"].append(f"{r.status} {r.url[:200]}"))
        page.on("websocket", lambda ws: (urllib.parse.urlsplit(ws.url).hostname or "") not in LOOPBACK
                and log["egress"].append(f"WS {ws.url[:200]}"))
        page.nd_log = log
        page.nd_form = form
        self.pages.append(page)
        return page

    def problems(self) -> list[str]:
        out = []
        for i, p in enumerate(self.pages):
            for k, v in p.nd_log.items():
                if v:
                    out.append(f"page {i} ({p.nd_form}) {k}: {v[:6]}")
        return out


@pytest.fixture
def ui(pw, nd, request, artifacts):
    pages = Pages(pw, nd)
    yield pages
    failed = getattr(request.node, "rep_call", None) is not None and request.node.rep_call.failed
    try:
        if failed:
            artifacts.mkdir(parents=True, exist_ok=True)
            for i, p in enumerate(pages.pages):
                name = "".join(c if c.isalnum() or c in "-_." else "_" for c in request.node.name)
                try:
                    p.screenshot(path=str(artifacts / f"{name}-{i}.png"), full_page=False)
                except Exception:
                    pass
        bad = pages.problems()
    finally:
        if pages.browser:
            pages.browser.close()
    if bad and failed:
        print("pages logged problems:\n" + "\n".join(bad), file=sys.stderr)
    if bad and not failed:
        pytest.fail("the journey passed but its pages logged problems:\n" + "\n".join(bad), pytrace=False)
