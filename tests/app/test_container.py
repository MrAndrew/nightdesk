"""The container setup's safety rules, read from the files (no Docker needed): who can reach the dashboard, the
password rule for the network, the image's user and contents, and the installer's shape.

The real check (install into a scratch folder under a test Compose project, open the page through Caddy) needs Docker
and the network, so it is a manual step: okf/architecture/deployment.md#one-line-install.

    uv run --with pytest pytest tests/app/test_container.py -q
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = (ROOT / "docker-compose.yml").read_text()
CADDY = (ROOT / "deploy" / "Caddyfile").read_text()
DOCKERFILE = (ROOT / "Dockerfile").read_text()
INSTALL = ROOT / "deploy" / "install.sh"


def _code(text: str) -> str:
    """Drop comment lines, so a rule mentioned in a comment does not count as the rule."""
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def test_the_app_port_is_never_published():
    assert not re.search(r"^\s*-\s*\"?[^#\n]*8787:", _code(COMPOSE), re.M)


def test_every_published_port_is_on_the_reach_address_default_this_computer():
    ports = re.findall(r'^\s*-\s*"([^"]+:\d+[^"]*)"', _code(COMPOSE), re.M)
    assert ports, "no published ports found"
    for p in ports:
        assert p.startswith("${ND_BIND:-127.0.0.1}:"), p


def test_caddy_reads_the_rule_file_named_after_the_reach_address():
    assert "import /etc/caddy/reach-{$ND_BIND:127.0.0.1}.caddy" in CADDY
    rules = sorted(p.name for p in (ROOT / "deploy").glob("reach-*.caddy"))
    assert rules == ["reach-0.0.0.0.caddy", "reach-127.0.0.1.caddy"], "any other address must have no rule file"
    for r in rules:
        assert f"./deploy/{r}:/etc/caddy/{r}:ro" in COMPOSE


def test_the_network_rule_asks_for_the_password_and_this_computer_does_not():
    lan = _code((ROOT / "deploy" / "reach-0.0.0.0.caddy").read_text())
    local = _code((ROOT / "deploy" / "reach-127.0.0.1.caddy").read_text())
    assert "basic_auth @signin" in lan and "{$HLTA_AUTH_HASH}" in lan
    assert "@signin not path /ca/root.crt" in lan     # only the public certificate is open
    assert local.strip() == ""


def test_https_with_the_local_authority_and_the_app_trusts_the_proxy_only_inside_compose():
    assert "tls internal" in CADDY and "reverse_proxy app:8787" in CADDY
    assert 'OSINTHUB_TRUST_PROXY_AUTH: "1"' in COMPOSE
    assert "OSINTHUB_ALLOWED_HOSTS: ${HLTA_HOSTS:-nightdesk.localhost, localhost}" in COMPOSE
    assert "{$HLTA_HOSTS:nightdesk.localhost, localhost}" in CADDY


def test_qdrant_is_optional():
    block = COMPOSE.split("\n  qdrant:\n", 1)[1].split("\nvolumes:", 1)[0]
    assert 'profiles: ["qdrant"]' in block
    assert "depends_on:\n      - qdrant" not in COMPOSE


def test_image_installs_the_package_and_runs_unprivileged():
    assert "uv build --wheel" in DOCKERFILE and "uv pip install --python /app/.venv --no-deps" in DOCKERFILE
    assert "--no-default-groups" in DOCKERFILE           # never the Mac AI libraries
    assert re.search(r"^USER nightdesk$", DOCKERFILE, re.M)
    assert 'CMD ["nightdesk"]' in DOCKERFILE
    assert 'user: "${ND_UID:-1000}:${ND_GID:-1000}"' in COMPOSE
    ignore = [l.strip() for l in (ROOT / ".dockerignore").read_text().splitlines() if l.strip() and not l.startswith("#")]
    assert ignore[0] == "*", ".dockerignore starts by leaving everything out, then allows only what the image needs"
    for need in ("!osinthub/", "!web/", "!okf/", "!uv.lock", "!pyproject.toml"):
        assert need in ignore


def test_installer_shape():
    text = INSTALL.read_text()
    assert text.startswith("#!/bin/sh\n") and "set -eu" in text
    assert "</dev/tty" in text                           # questions come from the terminal, not the piped script
    assert "--yes" in text and "--uninstall" in text
    assert "ND_BIND='$BIND'" in text and "BIND=127.0.0.1" in text and "LAN=0" in text  # this computer by default
    for shell in ("sh", "dash", "bash"):
        if shutil.which(shell):
            r = subprocess.run([shell, "-n", str(INSTALL)], capture_output=True, text=True)
            assert r.returncode == 0, f"{shell}: {r.stderr}"


@pytest.mark.parametrize("name", ["deploy/install.sh"])
def test_installer_is_executable(name):
    assert (ROOT / name).stat().st_mode & 0o111
