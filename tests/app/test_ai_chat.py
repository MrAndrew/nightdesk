"""Settings › AI › Chat (osinthub/ai/chatconn.py, the other-server path of osinthub/ai/client.py): addresses, the API
key tied to its host and never shown, offline mode, finding Ollama, and chat requests to an OpenAI-compatible server
(JSON fallbacks, the repair turn, thinking off for Ollama, a refused key). A small fake server on a scratch port
stands in for Ollama; nothing leaves this computer.

    uv run --with pytest pytest tests/app/test_ai_chat.py -q
"""
from __future__ import annotations

import json
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from _lake import make_lake
LAKE = make_lake("ai-chat", offline=False)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db, diagnostics  # noqa: E402
from osinthub.ai import chatconn, client, setup  # noqa: E402
from osinthub.api import app  # noqa: E402

db.connect()
C = TestClient(app, base_url="http://localhost")
H = {"Origin": "http://localhost"}
SCHEMA = {"type": "object", "properties": {"names": {"type": "array", "items": {"type": "string"}}},
          "required": ["names"]}


class Fake:
    """An OpenAI-compatible chat server with Ollama's model list. `replies` are answered in turn; `reject` lists the
    response_format kinds it answers 400 to; `status` forces a status code."""

    def __init__(self):
        self.requests: list[dict] = []
        self.replies: list[str] = []
        self.reject: set[str] = set()
        self.status = 200
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_GET(self):
                if self.path == "/api/tags":
                    return self._send(200, {"models": [
                        {"name": "tiny:1b", "size": 800_000_000, "capabilities": ["completion"]},
                        {"name": "nomic-embed-text", "size": 270_000_000, "capabilities": ["embedding"]}]})
                if self.path == "/v1/models":
                    return self._send(200, {"data": [{"id": "tiny:1b"}, {"id": "text-embedding-x"}]})
                self._send(404, {"error": "no"})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.requests.append({"body": body, "auth": self.headers.get("Authorization")})
                if fake.status != 200:
                    return self._send(fake.status, {"error": {"message": "invalid api key"}})
                kind = (body.get("response_format") or {}).get("type")
                if kind in fake.reject:
                    return self._send(400, {"error": {"message": f"response_format {kind} not supported"}})
                text = fake.replies.pop(0) if fake.replies else "ready"
                self._send(200, {"choices": [{"index": 0, "message": {"role": "assistant", "content": text}}]})

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.srv.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}/v1"
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture()
def cfg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("HF_HUB_CACHE", str(tmp_path / "hf"))
    monkeypatch.setattr(config, "OFFLINE", False)
    monkeypatch.setattr(config, "AI_URL", "http://127.0.0.1:9")
    monkeypatch.setattr(setup, "_in_docker", lambda: False)
    monkeypatch.setattr(chatconn, "_in_docker", lambda: False)
    yield tmp_path


@pytest.fixture()
def fake(cfg):
    f = Fake()
    yield f
    f.close()


def test_addresses_are_normalised():
    n = chatconn.normalise
    assert n("localhost:11434") == "http://localhost:11434/v1"
    assert n("http://127.0.0.1:11434/") == "http://127.0.0.1:11434/v1"
    assert n("http://127.0.0.1:1234/v1/chat/completions") == "http://127.0.0.1:1234/v1"
    assert n("openrouter.ai/api/v1") == "https://openrouter.ai/api/v1"          # not local: https
    assert n("https://generativelanguage.googleapis.com/v1beta/openai/") == \
        "https://generativelanguage.googleapis.com/v1beta/openai"
    for bad in ("", "ftp://x", "http://user:pw@host/v1", "http://host/v1?key=1", "http://host:port/v1"):
        with pytest.raises(ValueError):
            n(bad)


def test_local_addresses():
    for url in ("http://127.0.0.1:1/v1", "http://localhost/v1", "http://192.168.1.10:11434/v1",
                "http://desk.lan:11434/v1", "http://host.docker.internal:11434/v1", "http://[::1]:1/v1"):
        assert chatconn.is_local(url), url
    assert not chatconn.is_local("https://203.0.113.7/v1")


def test_chat_is_off_until_chosen(cfg):
    s = C.get("/api/ai/setup").json()
    assert s["chat"]["via"] is None and s["helper_chat"]["via"] is None
    assert chatconn.external() is None


def test_the_api_key_is_tied_to_its_host_and_never_shown(fake):
    r = C.post("/api/ai/chat", json={"via": "other", "url": fake.url, "model": "tiny:1b", "key": "test-key-0123456789"},
               headers=H)
    assert r.status_code == 200 and r.json()["has_key"] is True
    f = setup.ai_dir() / "chat-key.json"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    page = C.get("/api/ai/setup").text
    assert "test-key-0123456789" not in page and "test-key" not in page
    assert chatconn.external()["key"] == "test-key-0123456789"
    # saving again without a key keeps it for the same host ...
    C.post("/api/ai/chat", json={"via": "other", "url": fake.url, "model": "tiny:1b"}, headers=H)
    assert chatconn.key_for(fake.url) == "test-key-0123456789"
    # ... but a new host never gets the old key
    other = f"http://127.0.0.2:{fake.port}/v1"
    C.post("/api/ai/chat", json={"via": "other", "url": other, "model": "tiny:1b"}, headers=H)
    assert chatconn.key_for(other) is None and chatconn.external()["key"] is None
    # and the key never reaches a diagnostics report
    C.post("/api/ai/chat", json={"via": "other", "url": fake.url, "model": "tiny:1b", "key": "test-key-0123456789"},
           headers=H)
    assert "test-key-0123456789" not in diagnostics.scrub("auth test-key-0123456789 failed")
    assert "test-key-0123456789" not in C.get("/api/settings/diagnostics").text


def test_offline_mode_allows_only_local_servers(fake, monkeypatch):
    monkeypatch.setattr(config, "OFFLINE", True)
    r = C.post("/api/ai/chat", json={"via": "other", "url": "https://203.0.113.7/v1", "model": "m"}, headers=H)
    assert r.status_code == 409 and "Offline mode" in r.json()["detail"]
    assert C.post("/api/ai/chat", json={"via": "ollama", "url": fake.url, "model": "tiny:1b"}, headers=H).status_code == 200


def test_finding_ollama_lists_its_chat_models_only(fake, monkeypatch):
    monkeypatch.setitem(chatconn.PRESETS, "ollama", {"label": "Ollama", "port": fake.port})
    monkeypatch.setitem(chatconn.PRESETS, "lmstudio", {"label": "LM Studio", "port": 9})   # nothing there
    d = C.post("/api/ai/chat/discover", json={}, headers=H).json()
    assert d["ollama"]["running"] is True and [m["id"] for m in d["ollama"]["models"]] == ["tiny:1b"]
    assert d["lmstudio"]["running"] is False and "Nothing answers" in d["lmstudio"]["error"]
    r = C.post("/api/ai/chat/models", json={"via": "other", "url": fake.url}, headers=H).json()
    assert [m["id"] for m in r["models"]] == ["tiny:1b"]              # /v1/models without the embedding model


def test_the_test_button_sends_one_short_chat(fake):
    r = C.post("/api/ai/chat/test", json={"via": "ollama", "url": fake.url, "model": "tiny:1b"}, headers=H).json()
    assert r["ok"] is True and r["reply"] == "ready"
    assert fake.requests[-1]["body"]["reasoning_effort"] == "none"     # Ollama: thinking off
    fake.status = 401
    r = C.post("/api/ai/chat/test", json={"via": "other", "url": fake.url, "model": "tiny:1b"}, headers=H).json()
    assert r["ok"] is False and "API key" in r["error"]


def _use(fake, via="ollama", key=None):
    chatconn.save(via, fake.url, "tiny:1b", key)


def test_chat_goes_to_the_chosen_server_with_json_checked_here(fake):
    _use(fake, key="sk-abc")
    fake.replies = ['<think>hmm</think>```json\n{"names": ["LockBit"]}\n```']
    out = client.chat([{"role": "system", "content": "Find names."}, {"role": "user", "content": "LockBit hit"}],
                      json_schema=SCHEMA)
    assert json.loads(out) == {"names": ["LockBit"]}
    req = fake.requests[-1]
    assert req["auth"] == "Bearer sk-abc" and req["body"]["model"] == "tiny:1b"
    assert req["body"]["response_format"]["type"] == "json_schema"
    assert "JSON Schema" in req["body"]["messages"][0]["content"]          # the instruction is in the prompt too
    assert "chat_template_kwargs" not in req["body"]                         # no helper-only fields


def test_a_server_that_rejects_json_schema_gets_json_object_then_nothing(fake):
    _use(fake, via="other")
    fake.reject = {"json_schema", "json_object"}
    fake.replies = ['{"names": []}']
    assert json.loads(client.chat([{"role": "user", "content": "x"}], json_schema=SCHEMA)) == {"names": []}
    kinds = [(r["body"].get("response_format") or {}).get("type") for r in fake.requests]
    assert kinds == ["json_schema", "json_object", None]
    assert "reasoning_effort" not in fake.requests[-1]["body"]               # only Ollama gets it


def test_a_wrong_json_reply_gets_one_repair_turn(fake):
    _use(fake)
    fake.replies = ['{"nam": 1}', '{"names": ["Emotet"]}']
    assert json.loads(client.chat([{"role": "user", "content": "x"}], json_schema=SCHEMA)) == {"names": ["Emotet"]}
    assert "That was not valid" in fake.requests[-1]["body"]["messages"][-1]["content"]
    fake.replies = ['nope', 'still nope']
    assert client.chat([{"role": "user", "content": "x"}], json_schema=SCHEMA) is None


def test_a_refused_key_marks_chat_down_but_not_search(fake):
    _use(fake)
    fake.status = 401
    assert client.chat([{"role": "user", "content": "x"}]) is None
    assert client.is_down() is True and client.helper_down() is False
    st = client.chat_status()
    assert st["via"] == "ollama" and st["down"] and "API key" in st["last_error"]
    chatconn.turn_off()
    assert client.chat_status()["via"] is None


def test_moving_chat_off_the_built_in_helper_drops_its_chat_model(fake, monkeypatch):
    setup._save(enabled=True, models=["search", "chat"])
    restarted = []
    monkeypatch.setattr(setup, "helper_running", lambda: {"up": True, "ours": True, "pid": 1})
    monkeypatch.setattr(setup, "restart_helper", lambda: restarted.append(setup.chosen_models()) or "started")
    assert chatconn.via() == "builtin"
    _use(fake)
    assert setup.chosen_models() == ["search"]
    for _ in range(100):
        if restarted:
            break
        threading.Event().wait(0.02)
    assert restarted == [["search"]]


def test_writes_from_another_site_are_refused(fake):
    bad = {"Origin": "https://evil.example"}
    for path, body in (("/api/ai/chat", {"via": "other", "url": fake.url, "model": "m"}), ("/api/ai/chat/off", {}),
                       ("/api/ai/chat/test", {"via": "other", "url": fake.url, "model": "m"}),
                       ("/api/ai/chat/models", {"via": "other", "url": fake.url}), ("/api/ai/chat/discover", {})):
        assert C.post(path, json=body, headers=bad).status_code == 403, path
    assert fake.requests == []
