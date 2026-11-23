"""The `nightdesk` package: what the wheel must carry and how an installed copy finds its files (no build, no network).

The full check (build the wheel, `uv tool install` it, run it on a scratch port) needs the network for its
dependencies, so it is a manual step: okf/architecture/deployment.md#the-package.

    uv run --with pytest pytest tests/app/test_package.py -q
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PY = tomllib.loads((ROOT / "pyproject.toml").read_text())


def test_package_name_command_and_build_backend():
    assert PY["project"]["name"] == "nightdesk"
    assert PY["project"]["scripts"] == {"nightdesk": "osinthub.__main__:cli", "nightdesk-redact": "osinthub.redact:cli"}
    assert PY["build-system"]["build-backend"] == "hatchling.build"
    assert all("==" in r for r in PY["build-system"]["requires"]), "pin the build backend"


def test_wheel_carries_the_web_client_and_the_docs():
    wheel = PY["tool"]["hatch"]["build"]["targets"]["wheel"]
    assert wheel["packages"] == ["osinthub"]
    assert wheel["force-include"] == {"web": "osinthub/web", "okf": "osinthub/okf"}
    assert set(PY["project"]["license-files"]) == {"LICENSE", "NOTICE"}


def test_local_ai_is_never_an_install_dependency():
    deps = " ".join(PY["project"]["dependencies"]).lower()
    assert "mlx" not in deps and "torch" not in deps and "transformers" not in deps
    assert "optional-dependencies" not in PY["project"] or not any(
        "mlx" in " ".join(v) for v in PY["project"]["optional-dependencies"].values())


def _paths(fake_installed: Path | None = None) -> list[str]:
    """config's RES/WEB_DIR/DOCS_DIR in a fresh interpreter, optionally for a copy of the package laid out like a wheel."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("OSINTHUB_")}
    env["OSINTHUB_LAKE"] = str((fake_installed or ROOT) / "_lake_unused")
    env["PYTHONPATH"] = str(fake_installed or ROOT)
    code = "from osinthub import config; print(config.RES); print(config.WEB_DIR); print(config.DOCS_DIR)"
    r = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60,
                       cwd=fake_installed or ROOT)
    assert r.returncode == 0, r.stderr
    return r.stdout.splitlines()


def test_a_checkout_uses_the_repo_root():
    assert _paths() == [str(ROOT), str(ROOT / "web"), str(ROOT / "okf")]


def test_an_installed_copy_uses_the_files_inside_the_package(tmp_path):
    site = tmp_path / "site-packages"
    pkg = site / "osinthub"
    shutil.copytree(ROOT / "osinthub", pkg, ignore=shutil.ignore_patterns("__pycache__"))
    (pkg / "web").mkdir()
    (pkg / "web" / "index.html").write_text("<!doctype html>")
    (pkg / "okf").mkdir()
    res, web, docs = _paths(site)
    assert Path(res).resolve() == pkg.resolve()
    assert Path(web).resolve() == (pkg / "web").resolve() and Path(docs).resolve() == (pkg / "okf").resolve()


def test_version_option_prints_and_starts_nothing(capsys):
    from osinthub import __main__ as m
    m.main(["--version"])
    assert capsys.readouterr().out.startswith("nightdesk ")
