"""The installer's settings step (deploy/install.sh, "3. settings"), run for real in a POSIX shell against a scratch
install folder: a re-run with --reconfigure keeps the keys and settings the user added to .env unless they ask to
reset them (--reset-keys, or answering no). No Docker: the step only writes .env when the reach is this computer.

    uv run --with pytest pytest tests/app/test_install_env.py -q
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / "deploy" / "install.sh").read_text()
SH = shutil.which("sh") or "/bin/sh"
DASH = shutil.which("dash")          # Debian and Ubuntu's /bin/sh: the strictest shell the installer meets


def _func(name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{[^\n]*\}}\n", SRC, re.M)          # one line: name() { ...; }
    if not m:                                                          # or a block ending in a line "}"
        m = re.search(rf"^{name}\(\) \{{.*?^\}}\n", SRC, re.S | re.M)
    assert m, name
    return m.group(0)


def _settings_step() -> str:
    m = re.search(r'^if \[ ! -f "\$ENVF" \] \|\| \[ "\$RECONF" = 1 \]; then\n.*?^fi\n', SRC, re.S | re.M)
    assert m
    return m.group(0)


MANAGED = re.search(r'^MANAGED=".*"$', SRC, re.M).group(0)
KEY = "invented-key-0123456789abcdef"               # invented values only


def run(home: Path, *, reconf: int, reset: int = 0, answer: str | None = None, sh: str = SH, lan: int = 0) -> subprocess.CompletedProcess:
    """The settings step with these flags; `answer` replaces the terminal's answer to every question."""
    ask = (f'ask() {{ printf "%s\\n" "{answer}"; }}\n' if answer is not None else _func("ask"))
    script = "\n".join([
        "set -eu",
        f"HOME_DIR='{home}'", 'ENVF="$HOME_DIR/.env"', 'APP="$HOME_DIR/app"', "PROJECT=nightdesk", "OS=Darwin", "TTY=''",
        f"YES=0 LAN={lan} PORT='' DATA='{home}/data' RECONF={reconf} RESET_KEYS={reset}",
        "docker() { printf '%s\\n' '$2a$14$invented.hash'; }",      # the password hash, without Docker
        re.search(r"^ENV_LINE=.*$", SRC, re.M).group(0),
        _func("say"), _func("step"), _func("die"), _func("getenv"), ask, _func("yes_no"),
        "port_free() { return 0; }", f"default_data() {{ printf '%s\\n' '{home}/data'; }}",
        MANAGED, _func("odd_settings"), _func("own_lines"), _func("own_settings"),
        _settings_step(),
    ])
    return subprocess.run([sh, "-c", script], capture_output=True, text=True, timeout=30)


def env_lines(home: Path) -> list[str]:
    return (home / ".env").read_text().splitlines()


@pytest.fixture
def home(tmp_path: Path) -> Path:
    h = tmp_path / "nd"
    h.mkdir()
    r = run(h, reconf=0)                                  # a first install writes the installer's own settings
    assert r.returncode == 0, r.stderr
    with (h / ".env").open("a") as f:                     # what the README tells a user to do
        f.write("\n# my abuse.ch key\nABUSECH_AUTH_KEY='" + KEY + "'\nCARTO_API_KEY='a=b c'\n")
    return h


def test_a_first_install_has_no_own_section(tmp_path):
    h = tmp_path / "fresh"
    h.mkdir()
    assert run(h, reconf=0).returncode == 0
    text = (h / ".env").read_text()
    assert "LAKE_DIR=" in text and "Your own settings" not in text


def test_reconfigure_keeps_the_users_keys_as_written(home):
    r = run(home, reconf=1)
    assert r.returncode == 0, r.stderr
    lines = env_lines(home)
    assert f"ABUSECH_AUTH_KEY='{KEY}'" in lines and "CARTO_API_KEY='a=b c'" in lines and "# my abuse.ch key" in lines
    assert sum(ln.startswith("LAKE_DIR=") for ln in lines) == 1          # the installer's settings, once each
    assert "ABUSECH_AUTH_KEY, CARTO_API_KEY" in r.stdout + r.stderr       # it names what it keeps ...
    assert KEY not in r.stdout + r.stderr                                 # ... and never prints a value


def test_reconfigure_twice_does_not_pile_up(home):
    assert run(home, reconf=1).returncode == 0
    first = env_lines(home)
    assert run(home, reconf=1).returncode == 0
    second = env_lines(home)
    assert [ln for ln in first if not ln.startswith("# Written")] == [ln for ln in second if not ln.startswith("# Written")]
    assert sum("Your own settings" in ln for ln in second) == 1 and sum(ln.startswith("ABUSECH_AUTH_KEY=") for ln in second) == 1


def test_reset_keys_removes_them(home):
    r = run(home, reconf=1, reset=1)
    assert r.returncode == 0, r.stderr
    text = (home / ".env").read_text()
    assert "ABUSECH_AUTH_KEY" not in text and "CARTO_API_KEY" not in text and "Your own settings" not in text
    assert "LAKE_DIR=" in text and "--reset-keys" in r.stdout + r.stderr


def test_answering_no_removes_them_and_yes_keeps_them(home):
    assert run(home, reconf=1, answer="n").returncode == 0
    assert "ABUSECH_AUTH_KEY" not in (home / ".env").read_text()
    with (home / ".env").open("a") as f:
        f.write("ABUSECH_AUTH_KEY='" + KEY + "'\n")
    assert run(home, reconf=1, answer="y").returncode == 0
    assert f"ABUSECH_AUTH_KEY='{KEY}'" in env_lines(home)


def test_a_plain_rerun_leaves_the_file_alone(home):
    before = (home / ".env").read_text()
    assert run(home, reconf=0).returncode == 0
    assert (home / ".env").read_text() == before


def test_the_flag_is_documented():
    assert "--reset-keys) RECONF=1 RESET_KEYS=1" in SRC
    head = SRC.split("set -eu", 1)[0]
    assert "--reset-keys" in head                         # --help prints the header


@pytest.mark.skipif(not DASH, reason="dash is not installed")
def test_keep_and_reset_work_in_dash(home):
    assert run(home, reconf=1, sh=DASH).returncode == 0
    assert f"ABUSECH_AUTH_KEY='{KEY}'" in env_lines(home)
    r = run(home, reconf=1, reset=1, sh=DASH)
    assert r.returncode == 0, r.stderr
    assert "ABUSECH_AUTH_KEY" not in (home / ".env").read_text()


def test_export_and_indented_lines_are_named_and_asked_about(home):
    with (home / ".env").open("a") as f:
        f.write("export EXPORTED_KEY='e1'\n  INDENTED_KEY=i2\nABUSECH_AUTH_KEY='" + KEY + "'\n")   # a duplicate too
    r = run(home, reconf=1)
    out = r.stdout + r.stderr
    assert r.returncode == 0, r.stderr
    assert "ABUSECH_AUTH_KEY, CARTO_API_KEY, EXPORTED_KEY, INDENTED_KEY." in out   # each named once
    lines = env_lines(home)
    assert "export EXPORTED_KEY='e1'" in lines and "  INDENTED_KEY=i2" in lines
    r = run(home, reconf=1, answer="n")
    text = (home / ".env").read_text()
    assert r.returncode == 0 and "EXPORTED_KEY" not in text and "INDENTED_KEY" not in text


def test_a_managed_name_in_another_form_is_named_and_replaced_never_read(home):
    with (home / ".env").open("a") as f:
        f.write("export HTTPS_PORT=9443\n  LAKE_DIR='/elsewhere'\n")
    r = run(home, reconf=1)
    out = r.stdout + r.stderr
    assert r.returncode == 0, r.stderr
    lines = env_lines(home)
    assert sum("HTTPS_PORT" in ln for ln in lines) == 1 and sum("LAKE_DIR" in ln for ln in lines) == 1
    assert "HTTPS_PORT='443'" in lines and f"LAKE_DIR='{home}/data'" in lines   # the installer's own answers
    assert "HTTPS_PORT, LAKE_DIR in .env isn't written the installer's way" in out
    assert "9443" not in out and "/elsewhere" not in out                      # named, never shown


def test_unquoted_values_are_never_misread_or_rewritten(home):
    """Compose reads these as 9443 and $2a$..., the installer would not: it must not copy them in its own form."""
    text = (home / ".env").read_text().replace("HTTPS_PORT='443'", "HTTPS_PORT=9443 # my port")
    (home / ".env").write_text(text + "HLTA_AUTH_HASH=$$2a$$14$$invented.hash.value\n")
    r = run(home, reconf=0)                                   # a plain re-run leaves the file alone and says so
    assert r.returncode == 0 and (home / ".env").read_text() == text + "HLTA_AUTH_HASH=$$2a$$14$$invented.hash.value\n"
    assert "HTTPS_PORT, HLTA_AUTH_HASH in .env" in r.stderr and "--reconfigure" in r.stderr
    r = run(home, reconf=1)
    assert r.returncode == 0, r.stderr
    new = (home / ".env").read_text()
    assert "9443" not in new and "my port" not in new and "$$" not in new and "invented.hash" not in new
    assert "HTTPS_PORT='443'" in new.splitlines() and f"ABUSECH_AUTH_KEY='{KEY}'" in new.splitlines()


def test_a_quoted_setting_with_a_quoted_comment_is_named_not_misread(home):
    text = (home / ".env").read_text().replace("HTTPS_PORT='443'", "HTTPS_PORT='9443' # was '443'")
    (home / ".env").write_text(text)
    r = run(home, reconf=1)
    assert r.returncode == 0, r.stderr
    assert "HTTPS_PORT in .env isn't written the installer's way" in r.stderr and "9443" not in r.stderr
    new = (home / ".env").read_text()
    assert "HTTPS_PORT='443'" in new.splitlines() and "9443" not in new and "# was" not in new


def test_crlf_settings_are_read_as_current_answers(home):
    text = (home / ".env").read_text().replace("HTTPS_PORT='443'", "HTTPS_PORT='9443'")
    (home / ".env").write_text(text.replace("\n", "\r\n"))
    r = run(home, reconf=1)
    assert r.returncode == 0, r.stderr
    lines = env_lines(home)
    assert "HTTPS_PORT='9443'" in lines and "isn't written" not in r.stderr
    assert not any(ln.endswith("\r") for ln in lines) and f"ABUSECH_AUTH_KEY='{KEY}'" in lines


def test_the_rewritten_file_is_owner_only(home):
    (home / ".env").chmod(0o644)
    assert run(home, reconf=1).returncode == 0
    assert (home / ".env").stat().st_mode & 0o777 == 0o600


COMPOSE = (ROOT / "docker-compose.yml").read_text()
CADDY_LAN = (ROOT / "deploy" / "reach-0.0.0.0.caddy").read_text()


def test_the_default_sign_in_user_is_nightdeskuser_everywhere():
    assert "${HLTA_AUTH_USER:-nightdeskuser}" in COMPOSE and "{$HLTA_AUTH_USER:nightdeskuser}" in CADDY_LAN
    assert "HLTA_AUTH_USER=nightdeskuser" in (ROOT / ".env.example").read_text()
    assert ":-hlta}" not in COMPOSE and ":hlta}" not in CADDY_LAN and "user hlta" not in SRC


def test_a_network_install_without_questions_signs_in_as_nightdeskuser(tmp_path):
    h = tmp_path / "lan"
    h.mkdir()
    r = run(h, reconf=0, lan=1)
    assert r.returncode == 0, r.stderr
    lines = env_lines(h)
    assert "HLTA_AUTH_USER='nightdeskuser'" in lines and "ND_BIND='0.0.0.0'" in lines
    assert any(ln.startswith("HLTA_AUTH_HASH='$2a$14$") for ln in lines)


def test_the_user_name_asked_for_is_kept_on_reconfigure(tmp_path):
    h = tmp_path / "lan"
    h.mkdir()
    assert run(h, reconf=0, lan=1, answer="alice_2").returncode == 0
    assert "HLTA_AUTH_USER='alice_2'" in env_lines(h)
    hash_line = [ln for ln in env_lines(h) if ln.startswith("HLTA_AUTH_HASH=")]
    r = run(h, reconf=1, lan=1)                           # no terminal: every default, so the current name and password
    assert r.returncode == 0, r.stderr
    lines = env_lines(h)
    assert "HLTA_AUTH_USER='alice_2'" in lines and [ln for ln in lines if ln.startswith("HLTA_AUTH_HASH=")] == hash_line
    assert sum("HLTA_AUTH_USER" in ln for ln in lines) == 1


def test_a_this_computer_install_has_no_sign_in_user(home):
    assert not any("HLTA_AUTH_USER" in ln for ln in env_lines(home))


def test_an_unusable_user_name_stops_without_a_terminal(tmp_path):
    h = tmp_path / "lan"
    h.mkdir()
    r = run(h, reconf=0, lan=1, answer="bad name:x")
    assert r.returncode != 0 and "can use only letters, digits" in r.stderr
    assert not (h / ".env").exists()


@pytest.mark.skipif(not DASH, reason="dash is not installed")
def test_the_user_name_step_works_in_dash(tmp_path):
    h = tmp_path / "lan"
    h.mkdir()
    r = run(h, reconf=0, lan=1, answer="bob-2", sh=DASH)
    assert r.returncode == 0, r.stderr
    assert "HLTA_AUTH_USER='bob-2'" in env_lines(h)


def test_import_is_refused_as_a_user_name(tmp_path):
    """Caddy reads a line starting with `import` as an import of another file, so it would not start."""
    h = tmp_path / "lan"
    h.mkdir()
    r = run(h, reconf=0, lan=1, answer="import")
    assert r.returncode != 0 and "a word Caddy reserves" in r.stderr and not (h / ".env").exists()
    assert run(h, reconf=0, lan=1, answer="importer").returncode == 0      # only the word itself
