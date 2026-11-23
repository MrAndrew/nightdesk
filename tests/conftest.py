"""Every test file runs in its own Python process, with normal per-test selection and results. Docs:
okf/architecture/testing.md

Each test module sets OSINTHUB_LAKE (a fresh temporary lake, see tests/_lake.py), OSINTHUB_OFFLINE and AI_URL before
it imports osinthub, and osinthub reads them once, at import (and modules do their data setup at import). In one shared
process the first module to import osinthub would decide the lake and the flags for all of them.

So when a run covers more than one test file, the parent process never imports a test module. It starts one child
`pytest` per file, up to min(8, cpu) at a time (ND_TEST_SERIAL=1: one at a time, for debugging):

* a plain run (no -k, -m, --deselect or `file::test` ids): the child runs the whole file and reports both its tests
  (ids, markers, keywords) and each outcome; the parent builds proxy items that pass, fail (with the child's
  traceback) or skip as their test did, so the summary counts tests, not files;
* a run that selects: a `--collect-only` child per file reports its tests, the parent selects exactly as in a plain
  run (`-k`, `-m`, node ids, `::Class::test`; selecting nothing exits 5), then one child per file runs just the
  selected tests.

Each child gets its own TMPDIR inside a TemporaryDirectory, so every temp lake a module makes is deleted when the
child ends: a run leaves nothing in the system temp folder. A run on a single file runs in-process as usual.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

import pytest

CHILD = "OSINTHUB_TEST_CHILD"          # set in a child process
REPORT = "OSINTHUB_TEST_REPORT"        # child: write {"tests": [...], "outcomes": {...}} here (JSON)
SELECT = "OSINTHUB_TEST_SELECT"        # child: run only the test ids listed in this file (JSON list)
TIMEOUT = 1800
HERE = Path(__file__).resolve().parent


# ---------------------------------------------------------------- child side
def _tail(nodeid: str) -> str:
    return nodeid.split("::", 1)[1] if "::" in nodeid else nodeid


if os.environ.get(CHILD) == "1":
    _tests: list[dict] = []
    _outcomes: dict[str, dict] = {}

    def pytest_collection_modifyitems(session, config, items):
        sel = os.environ.get(SELECT)
        if sel:
            want = set(json.loads(Path(sel).read_text()))
            items[:] = [i for i in items if _tail(i.nodeid) in want]

    def pytest_collection_finish(session):
        _tests[:] = [{"id": _tail(i.nodeid), "markers": [m.name for m in i.iter_markers()],
                      "keywords": [k for k in i.keywords if isinstance(k, str)]} for i in session.items]

    def pytest_runtest_logreport(report):
        o = _outcomes.setdefault(_tail(report.nodeid), {"outcome": "passed", "longrepr": "", "sections": ""})
        if report.failed:
            o["outcome"] = "error" if report.when != "call" and o["outcome"] != "failed" else "failed"
            o["longrepr"] += f"[{report.when}]\n{report.longreprtext}\n"
        elif report.skipped and o["outcome"] == "passed":
            o["outcome"] = "xfailed" if hasattr(report, "wasxfail") else "skipped"
            lr = report.longrepr
            o["longrepr"] = (report.wasxfail if hasattr(report, "wasxfail") else
                             f"{lr[2]} ({Path(lr[0]).name}:{lr[1]})" if isinstance(lr, tuple) and len(lr) == 3 else str(lr))
        elif report.passed and hasattr(report, "wasxfail") and report.when == "call":
            o["outcome"] = "xpassed"
            o["longrepr"] = report.wasxfail
        if report.failed:
            o["sections"] += "".join(f"\n--- {name} ---\n{text}" for name, text in report.sections)

    def _write_report():
        if os.environ.get(REPORT):
            Path(os.environ[REPORT]).write_text(json.dumps({"tests": _tests, "outcomes": _outcomes}))


# ---------------------------------------------------------------- parent side
def _isolate(config) -> bool:
    if os.environ.get(CHILD) == "1":
        return False
    files = {Path(a.split("::")[0]).resolve() for a in config.args}
    return not (len(files) == 1 and next(iter(files)).is_file())


def _whole(config) -> bool:
    """True when nothing narrows the run: each file's one child then collects and runs it in one go."""
    o = config.option
    return not (o.collectonly or o.keyword or o.markexpr or getattr(o, "deselect", None) or getattr(o, "lf", False)
                or any("::" in a for a in config.args))


_pool: ThreadPoolExecutor | None = None
_jobs: dict[Path, Future] = {}


def _submit(config, path: Path, args: list[str], select: list[str] | None = None) -> Future:
    global _pool
    if _pool is None:
        width = 1 if os.environ.get("ND_TEST_SERIAL") == "1" else min(8, os.cpu_count() or 1)
        _pool = ThreadPoolExecutor(max_workers=width, thread_name_prefix="test-child")
    return _pool.submit(_child, path, config.rootpath, args, select)


def _child(path: Path, rootpath: Path, args: list[str], select: list[str] | None = None):
    """Run pytest on one file in a fresh process. Returns (returncode, output, report JSON or None)."""
    with tempfile.TemporaryDirectory(prefix="osinthub-test-child-", ignore_cleanup_errors=True) as d:
        env = {**os.environ, CHILD: "1", REPORT: str(Path(d) / "report.json"), "TMPDIR": d}
        if select is not None:
            Path(d, "select.json").write_text(json.dumps(select))
            env[SELECT] = str(Path(d) / "select.json")
        cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *args, str(path)]
        p = subprocess.run(cmd, cwd=rootpath, env=env, capture_output=True, text=True, timeout=TIMEOUT)
        rp = Path(env[REPORT])
        return p.returncode, p.stdout + p.stderr, (json.loads(rp.read_text()) if rp.exists() else None)


def _ignored(config, p: Path) -> bool:
    if p.name.startswith((".", "_")) or p.name == "__pycache__" or p == HERE / "e2e":
        return True       # tests/e2e runs in-process (its own conftest), never in a child
    ign = [Path(x).resolve() for x in (config.getoption("ignore") or [])]
    return any(p == i or i in p.parents for i in ign)


@pytest.hookimpl(tryfirst=True)
def pytest_collection(session):
    """Start every file's first child now, so they run side by side while pytest walks the tree."""
    config = session.config
    if not _isolate(config):
        return
    args = [] if _whole(config) else ["--collect-only"]
    for a in config.args:
        root = Path(a.split("::")[0]).resolve()
        found = [root] if root.is_file() else sorted(root.rglob("test_*.py")) if root.is_dir() else []
        for f in found:
            if f not in _jobs and not any(_ignored(config, q) for q in [f, *f.parents] if HERE in q.parents):
                _jobs[f] = _submit(config, f, args)


def pytest_sessionfinish(session):
    if os.environ.get(CHILD) == "1":
        _write_report()
    elif _pool is not None:
        _pool.shutdown(wait=True, cancel_futures=True)


def pytest_pycollect_makemodule(module_path, parent):
    if _isolate(parent.config):
        return IsolatedFile.from_parent(parent, path=module_path)
    return None


@pytest.hookimpl(tryfirst=True)
def pytest_runtestloop(session):
    """A selecting run: start the run children of every file that has selected tests, side by side."""
    if session.config.option.collectonly or not _isolate(session.config) or _whole(session.config):
        return None
    by_file: dict[IsolatedFile, list[str]] = {}
    for i in session.items:
        if isinstance(i, ProxyItem):
            by_file.setdefault(i.file, []).append(i.test["id"])
    for f, ids in by_file.items():
        f.run_job = _submit(session.config, f.path, [], select=ids)
    return None


class ChildFailed(Exception):
    pass


class IsolatedFile(pytest.File):
    """A test file whose tests are collected and run in a child process."""

    results: dict | None = None
    run_output: str = ""
    run_job: Future | None = None

    def collect(self):
        whole = _whole(self.config)
        job = _jobs.pop(self.path, None) or _submit(self.config, self.path, [] if whole else ["--collect-only"])
        rc, out, rep = job.result()
        if rc not in (0, 1, 5) or rep is None or (rc == 1 and not whole):
            raise self.CollectError(f"collecting {self.path} in its own process failed (exit {rc}):\n{out}")
        if whole:
            self.results, self.run_output = rep["outcomes"], out
        groups: dict[str, ProxyGroup] = {}
        for t in rep["tests"]:
            parts = t["id"].split("::")
            parent = self
            for i, part in enumerate(parts[:-1]):         # unittest / class-based tests: File::Class::test
                k = "::".join(parts[: i + 1])
                if k not in groups:
                    groups[k] = ProxyGroup.from_parent(parent, name=part)
                    if parent is not self:
                        parent.groups[k] = groups[k]
                parent = groups[k]
            if parent is self:
                yield ProxyItem.from_parent(self, name=parts[-1], test=t)
            else:
                parent.tests.append(t)
        for g in groups.values():
            if g.parent is self:
                yield g

    def run_selected(self, session):
        """Wait for this file's run child (started by pytest_runtestloop, or one now)."""
        if self.results is not None:
            return
        if self.run_job is None:
            mine = [i.test["id"] for i in session.items if isinstance(i, ProxyItem) and i.file is self]
            self.run_job = _submit(self.config, self.path, [], select=mine)
        rc, out, res = self.run_job.result()
        self.results, self.run_output = (res or {}).get("outcomes", {}), out


class ProxyGroup(pytest.Collector):
    """A class of tests (unittest.TestCase or a test class) inside an isolated file."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.tests: list[dict] = []
        self.groups: dict[str, ProxyGroup] = {}

    def collect(self):
        yield from self.groups.values()
        for t in self.tests:
            yield ProxyItem.from_parent(self, name=t["id"].split("::")[-1], test=t)


class ProxyItem(pytest.Item):
    def __init__(self, *a, test: dict, **k):
        super().__init__(*a, **k)
        self.test = test
        known = {ln.split(":")[0].split("(")[0].strip() for ln in self.config.getini("markers")}
        for m in test["markers"]:
            if m in ("skip", "skipif", "xfail"):
                continue        # the child already applied them (with their conditions); here, bare, skipif would always skip
            if m not in known:  # registered in the child (or built in there); tell the parent about it too
                self.config.addinivalue_line("markers", m)
            self.add_marker(m)
        self.extra_keyword_matches.update(test["keywords"])

    @property
    def file(self) -> IsolatedFile:
        n = self.parent
        while not isinstance(n, IsolatedFile):
            n = n.parent
        return n

    def setup(self):
        f = self.file
        f.run_selected(self.session)
        self.result = f.results.get(self.test["id"])
        if self.result is None:
            raise ChildFailed(f"no result for {self.test['id']}: the child process for {f.path.name} did not report it\n"
                              f"{f.run_output}")
        if self.result["outcome"] == "error":   # failed in setup/teardown in the child: an error here too
            raise ChildFailed(self.result["longrepr"] + self.result["sections"])

    def runtest(self):
        r = self.result
        if r["outcome"] == "skipped":
            pytest.skip(r["longrepr"] or "skipped in the child process")
        if r["outcome"] == "xfailed":
            pytest.xfail(r["longrepr"] or "expected failure (in the child process)")
        if r["outcome"] == "xpassed":
            return      # a non-strict xfail that passed: a pass, as in a single-file run (a strict one fails in the child)
        if r["outcome"] == "failed":
            raise ChildFailed(r["longrepr"] + r["sections"])

    def repr_failure(self, excinfo):
        if isinstance(excinfo.value, ChildFailed):
            return f"(ran in its own process)\n{excinfo.value}"
        return super().repr_failure(excinfo)

    def reportinfo(self):
        # line 0, not None: pytest's report for a test skipped while it runs needs a line number
        return self.file.path, 0, self.test["id"].replace("::", ".")
