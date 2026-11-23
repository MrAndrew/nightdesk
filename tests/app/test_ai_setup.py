"""Settings › AI (osinthub/ai/setup.py): nothing downloads until asked, the checks before a download, the job,
turning off, and the API. No network, no MLX, no real helper: the steps and the machine are faked.

    uv run --with pytest pytest tests/app/test_ai_setup.py -q
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path

from _lake import make_lake
LAKE = make_lake("ai-setup", offline=False)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db  # noqa: E402
from osinthub.ai import setup  # noqa: E402
from osinthub.api import app  # noqa: E402

db.connect()
C = TestClient(app, base_url="http://localhost")
H = {"Origin": "http://localhost"}
ROOT = Path(__file__).resolve().parents[2]


def _fake_model(cache: Path, repo: str) -> None:
    d = cache / ("models--" + repo.replace("/", "--"))
    (d / "snapshots" / "abc").mkdir(parents=True)
    (d / "snapshots" / "abc" / "config.json").write_text("{}")
    (d / "blobs").mkdir()
    (d / "refs").mkdir()
    (d / "refs" / "main").write_text("abc")


@pytest.fixture()
def mac(monkeypatch, tmp_path):
    """An Apple-silicon Mac with 64 GB, its own HF cache and config folder, the AI libraries already importable."""
    monkeypatch.setenv("HF_HUB_CACHE", str(tmp_path / "hf"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(config, "AI_URL", "http://127.0.0.1:9")
    monkeypatch.setattr(config, "OFFLINE", False)
    monkeypatch.setattr(setup, "apple_silicon", lambda: True)
    monkeypatch.setattr(setup, "_in_docker", lambda: False)
    monkeypatch.setattr(setup, "memory", lambda: 64 * setup.GIB)
    monkeypatch.setattr(setup, "_free", lambda p: 500 * setup.GIB)   # not the runner's real disk (CI has ~15 GB free)
    monkeypatch.setattr(setup, "libs_where", lambda: "app")
    monkeypatch.setattr(setup, "start_helper", lambda: "started")
    monkeypatch.setattr(setup, "stop_helper", lambda: False)

    def no_real_steps(cmd, *a, **k):   # a test that needs a step fakes it; nothing here may install or download
        raise RuntimeError(f"tests run no real step: {cmd[:3]}")
    monkeypatch.setattr(setup, "_step", no_real_steps)
    setup._job.update(running=False, error=None, step=None)
    yield tmp_path
    _wait_job()


def _wait_job():
    for _ in range(200):
        if not setup.job()["running"]:
            return setup.job()
        time.sleep(0.02)
    raise AssertionError("the job did not finish")


def test_ai_libs_pin_is_the_locked_version():
    lock = (ROOT / "uv.lock").read_text()
    v = re.search(r'name = "mlx-lm"\nversion = "([^"]+)"', lock).group(1)
    assert setup.AI_LIBS == [f"mlx-lm=={v}"]


def test_nothing_is_on_or_downloaded_by_default(mac):
    s = C.get("/api/ai/setup").json()
    assert s["enabled"] is False and s["chosen"] == [] and s["job"]["running"] is False
    assert s["why_not"] is None
    assert not (mac / "hf").exists() and not (mac / "cfg" / "nightdesk" / "ai").exists()


def test_where_ai_cannot_be_turned_on(mac, monkeypatch):
    monkeypatch.setattr(setup, "_in_docker", lambda: True)
    assert "Docker" in setup.why_not()
    monkeypatch.setattr(setup, "_in_docker", lambda: False)
    monkeypatch.setattr(setup, "apple_silicon", lambda: False)
    assert "Apple silicon" in setup.why_not()
    monkeypatch.setattr(setup, "apple_silicon", lambda: True)
    monkeypatch.setattr(config, "AI_URL", "http://192.0.2.5:8790")
    assert "another computer" in setup.why_not()
    r = C.post("/api/ai/setup", json={"models": ["search"]}, headers=H)
    assert r.status_code == 409 and "another computer" in r.json()["detail"]


def test_the_checks_before_a_download(mac, monkeypatch):
    assert "both" in setup.plan(["chat"])["problem"]
    assert setup.plan([])["problem"] == "Choose at least one model."
    p = setup.plan(["search"])
    assert p["problem"] is None and p["download"] == ["search"] and p["need"] == setup.MODELS["search"]["size"]
    monkeypatch.setattr(setup, "memory", lambda: 16 * setup.GIB)
    assert "48 GB" in setup.plan(["search", "chat"])["problem"]
    assert setup.status()["models"]["chat"]["enough_memory"] is False
    monkeypatch.setattr(setup, "memory", lambda: 64 * setup.GIB)
    monkeypatch.setattr(config, "OFFLINE", True)
    assert "Offline mode" in setup.plan(["search"])["problem"]
    _fake_model(mac / "hf", setup.MODELS["search"]["repo"])     # already on disk: no download, so offline is fine
    assert setup.plan(["search"]) | {"free": None} == {"download": [], "libs": False, "need": 0, "free": None, "problem": None}
    monkeypatch.setattr(setup, "_free", lambda p: 100)
    monkeypatch.setattr(config, "OFFLINE", False)
    assert "disk space" in setup.plan(["search", "chat"])["problem"]


def test_the_libraries_need_uv_when_missing(mac, monkeypatch):
    monkeypatch.setattr(setup, "libs_where", lambda: None)
    monkeypatch.setattr(setup, "_uv", lambda: None)
    assert "uv" in setup.plan(["search"])["problem"]


def test_model_present_needs_a_complete_snapshot(mac):
    repo = setup.MODELS["search"]["repo"]
    assert not setup.model_present(repo)
    _fake_model(mac / "hf", repo)
    assert setup.model_present(repo)
    (mac / "hf" / ("models--" + repo.replace("/", "--")) / "blobs" / "x.incomplete").write_text("")
    assert not setup.model_present(repo)


def test_turning_on_downloads_what_is_missing_then_saves_the_choice(mac, monkeypatch):
    ran = []

    def step(cmd, env, name, progress):
        ran.append((name, cmd[-1]))
        _fake_model(mac / "hf", cmd[-1])
        setup._job.update(total=10, done=10)
    monkeypatch.setattr(setup, "_step", step)
    r = C.post("/api/ai/setup", json={"models": ["search", "chat"]}, headers=H)
    assert r.status_code == 202
    j = _wait_job()
    assert j["error"] is None and j["step"] == "done"
    assert ran == [("search", setup.MODELS["search"]["repo"]), ("chat", setup.MODELS["chat"]["repo"])]
    s = C.get("/api/ai/setup").json()
    assert s["enabled"] and s["chosen"] == ["search", "chat"]
    assert s["models"]["search"]["present"] and s["models"]["chat"]["present"]
    # once on, the helper counts as expected, so a stopped helper shows as a problem rather than "optional"
    assert C.get("/api/ai/status").json()["helper"]["configured"] is True


def test_a_failed_download_leaves_ai_off_and_says_why(mac, monkeypatch):
    def step(cmd, env, name, progress):
        raise RuntimeError("ConnectionError: huggingface.co could not be reached")
    monkeypatch.setattr(setup, "_step", step)
    assert C.post("/api/ai/setup", json={"models": ["search"]}, headers=H).status_code == 202
    j = _wait_job()
    assert "could not be reached" in j["error"]
    assert setup.enabled() is False


def test_the_libraries_install_into_nightdesks_folder(mac, monkeypatch):
    calls = []
    monkeypatch.setattr(setup, "libs_where", lambda: None if not calls else "libs")
    monkeypatch.setattr(setup, "_uv", lambda: "/usr/local/bin/uv")
    _fake_model(mac / "hf", setup.MODELS["search"]["repo"])

    def step(cmd, env, name, progress):
        calls.append(cmd)
        Path(cmd[cmd.index("--target") + 1], "mlx_lm").mkdir(parents=True)
    monkeypatch.setattr(setup, "_step", step)
    setup.start(["search"])
    assert _wait_job()["error"] is None
    cmd = calls[0]
    assert cmd[:3] == ["/usr/local/bin/uv", "pip", "install"] and cmd[-1] == setup.AI_LIBS[0]
    assert (setup.libs_dir() / "mlx_lm").is_dir() and not setup.libs_dir().with_name("libs.part").exists()
    assert str(setup.libs_dir()).startswith(str(mac / "cfg" / "nightdesk"))


def test_turning_off_stops_and_deletes_only_on_request(mac, monkeypatch):
    monkeypatch.setattr(setup, "libs_where", lambda: None)   # no huggingface_hub here: the model's own folder goes
    for k in ("search", "chat"):
        _fake_model(mac / "hf", setup.MODELS[k]["repo"])
    other = mac / "hf" / "models--someone--else"
    other.mkdir()
    setup._save(enabled=True, models=["search", "chat"])
    r = C.post("/api/ai/setup/off", json={}, headers=H).json()
    assert r["deleted"] == [] and setup.enabled() is False
    assert setup.model_present(setup.MODELS["search"]["repo"])
    setup._save(enabled=True, models=["search"])
    r = C.post("/api/ai/setup/off", json={"delete_models": True}, headers=H).json()
    assert r["deleted"] == [setup.MODELS["search"]["repo"]]
    assert not setup.model_present(setup.MODELS["search"]["repo"])
    assert setup.model_present(setup.MODELS["chat"]["repo"]) and other.is_dir()   # nothing it was not using


def _fake_mlx(cache: Path, repo: str, cfg: dict, size: int = 1000) -> None:
    _fake_model(cache, repo)
    snap = cache / ("models--" + repo.replace("/", "--")) / "snapshots" / "abc"
    (snap / "config.json").write_text(__import__("json").dumps(cfg))
    (snap / "model.safetensors").write_bytes(b"x" * size)


def test_the_built_in_chat_model_can_be_one_already_on_this_mac(mac):
    llm = {"architectures": ["Qwen3ForCausalLM"], "quantization": {"bits": 4}}
    _fake_mlx(mac / "hf", "mlx-community/Tiny-4bit", llm)
    _fake_mlx(mac / "hf", "someone/Llama-plain", {"architectures": ["LlamaForCausalLM"]})       # no MLX weights
    _fake_mlx(mac / "hf", "mlx-community/bert-mlx", {"architectures": ["BertModel"]})        # not a chat model
    _fake_mlx(mac / "hf", setup.MODELS["search"]["repo"], llm)                               # the search model
    ms = setup.mlx_chat_models()
    assert [m["repo"] for m in ms] == [setup.MODELS["chat"]["repo"], "mlx-community/Tiny-4bit"]   # recommended first
    assert ms[0]["present"] is False and ms[1]["present"] is True and ms[1]["size"] >= 1000
    assert ms[1]["enough_memory"] is True
    p = setup.plan(["search", "chat"], "mlx-community/Tiny-4bit")
    assert p["problem"] is None and p["download"] == []        # both already here: nothing to download
    assert "not one the built-in helper can run" in setup.plan(["search", "chat"], "someone/Llama-plain")["problem"]


def test_turning_off_deletes_only_what_night_desk_downloaded(mac, monkeypatch):
    _fake_mlx(mac / "hf", "mlx-community/Mine-4bit", {"architectures": ["Qwen3ForCausalLM"], "quantization": {}})

    def step(cmd, env, name, progress):
        _fake_model(mac / "hf", cmd[-1])
    monkeypatch.setattr(setup, "_step", step)
    setup.start(["search", "chat"], "mlx-community/Mine-4bit")
    assert _wait_job()["error"] is None
    from osinthub.ai import chatconn
    assert setup.repo("chat") == "mlx-community/Mine-4bit" and chatconn.via() == "builtin"
    assert setup.saved()["downloaded"] == [setup.MODELS["search"]["repo"]]
    assert [d["repo"] for d in C.get("/api/ai/setup").json()["deletable"]] == [setup.MODELS["search"]["repo"]]
    monkeypatch.setattr(setup, "libs_where", lambda: None)    # no huggingface_hub here: the model's own folder goes
    r = C.post("/api/ai/setup/off", json={"delete_models": True}, headers=H).json()
    assert r["deleted"] == [setup.MODELS["search"]["repo"]]
    assert setup.model_present("mlx-community/Mine-4bit")              # it was here before: never deleted
    assert chatconn.via() is None                                       # the built-in chat went with the helper


def test_writes_from_another_site_are_refused(mac):
    bad = {"Origin": "https://evil.example"}
    assert C.post("/api/ai/setup", json={"models": ["search"]}, headers=bad).status_code == 403
    assert C.post("/api/ai/setup/off", json={}, headers=bad).status_code == 403
    assert setup.job()["running"] is False


def test_only_the_app_that_started_the_helper_stops_it_at_exit(mac, monkeypatch):
    stopped = []
    monkeypatch.setattr(setup, "stop_helper", lambda: stopped.append(1))
    setup._save(helper_pid=12345, helper_owner=os.getpid() + 1)
    setup.stop_at_exit()
    assert stopped == []
    setup._save(helper_owner=os.getpid())
    setup.stop_at_exit()
    assert stopped == [1]


def test_the_helper_is_never_started_for_a_choice_that_is_not_ready(mac, monkeypatch):
    monkeypatch.undo()   # the real start_helper, on a machine set up by hand below
    monkeypatch.setenv("HF_HUB_CACHE", str(mac / "hf"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(mac / "cfg"))
    monkeypatch.setattr(config, "AI_URL", "http://127.0.0.1:9")
    monkeypatch.setattr(setup, "apple_silicon", lambda: True)
    monkeypatch.setattr(setup, "_in_docker", lambda: False)
    monkeypatch.setattr(setup, "libs_where", lambda: "app")
    started = []
    monkeypatch.setattr(setup.subprocess, "Popen", lambda *a, **k: started.append(a) or pytest.fail("started"))
    assert setup.start_helper() == "not started"            # AI is off
    setup._save(enabled=True, models=["search"])
    assert setup.start_helper() == "not ready"              # the model is not downloaded
    assert started == []


def test_models_that_were_already_here_are_never_deleted(mac, monkeypatch):
    for k in ("search", "chat"):
        _fake_model(mac / "hf", setup.MODELS[k]["repo"])             # another app downloaded them before
    setup.start(["search"])
    assert _wait_job()["error"] is None and setup.saved()["downloaded"] == []
    assert C.get("/api/ai/setup").json()["deletable"] == []
    monkeypatch.setattr(setup, "libs_where", lambda: None)
    assert C.post("/api/ai/setup/off", json={"delete_models": True}, headers=H).json()["deleted"] == []
    assert setup.model_present(setup.MODELS["search"]["repo"])

