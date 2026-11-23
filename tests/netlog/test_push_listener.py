"""Connect logs (v1.1): the upload port's safe default and plain-words bind status, and the inbox as the user can reach
it (Docker: the host folder from compose, or a docker compose cp command). The push security model is unchanged.

    uv run --quiet --with pytest pytest -q -p no:cacheprovider tests/test_v11_connect.py

No network beyond loopback: the one listener test binds a free port on 127.0.0.1.
"""
from __future__ import annotations

import os
import socket

for k in ("OSINTHUB_INGEST", "OSINTHUB_INGEST_HOST", "OSINTHUB_INGEST_PORT", "OSINTHUB_INGEST_URL", "OSINTHUB_INGEST_CERT",
          "OSINTHUB_INGEST_KEY", "OSINTHUB_DOCKER", "OSINTHUB_LAKE_HOST"):
    os.environ.pop(k, None)
from _lake import make_lake  # noqa: E402
LAKE = make_lake("connect")

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db  # noqa: E402
from osinthub.netlog import ingest  # noqa: E402

db.connect()
ui = FastAPI()
ui.include_router(ingest.mgmt, prefix="/api/netlog")
UI = TestClient(ui)


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    db.set_setting(ingest.SETTINGS_KEY, {})
    monkeypatch.setenv("OSINTHUB_DOCKER", "0")
    monkeypatch.setattr(ingest, "_lan_addresses", lambda: ["192.0.2.10", "fd4e:6400:d35c::10"])
    monkeypatch.setattr(ingest, "_route_addresses", lambda: ["192.0.2.10"])
    monkeypatch.setattr(ingest, "_iface_addrs", lambda: IFACES)
    yield
    ingest.LISTENER.stop()


IFACES = {"lo0": ["127.0.0.1", "::1"], "en0": ["192.0.2.10", "fe80::1%en0", "fd4e:6400:d35c::10"],
          "utun3": ["10.86.24.7"], "docker0": ["198.51.100.1"], "br-1a2b": ["198.51.100.65"], "wg0": ["10.86.24.9"]}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ------------------------------------------------------------------ the safe default
def test_default_is_home_network_only():
    c = ingest.cfg()
    assert c["host"] == "auto" and not c["enabled"]
    assert ingest.bind_host(c) == "192.0.2.10"           # private IPv4 first
    b = ingest.bind_info(c)
    assert b["scope"] == "lan" and b["auto"] and b["warn"] is None
    assert "home network" in b["explain"] and "192.0.2.10" in b["explain"]
    assert b["choices"] == ["192.0.2.10", "fd4e:6400:d35c::10"]
    assert ingest.status()["urls"] == ["https://192.0.2.10:8788"]   # devices are told the address it really binds


def test_auto_prefers_the_default_route_and_skips_vpn_and_container_interfaces(monkeypatch):
    assert "10.86.24.7" not in ingest.home_addresses() and "198.51.100.1" not in ingest.home_addresses()
    assert "fe80::1" not in ingest.home_addresses()                    # link-local needs a scope id: never auto
    # a full-tunnel VPN owns the default route: auto still binds the home interface, not the tunnel
    monkeypatch.setattr(ingest, "_route_addresses", lambda: ["10.86.24.7"])
    assert ingest.bind_host() == "192.0.2.10"
    # the default route's address wins over other home addresses
    monkeypatch.setattr(ingest, "_iface_addrs", lambda: {"en0": ["192.0.2.10"], "en1": ["198.51.100.20"]})
    monkeypatch.setattr(ingest, "_route_addresses", lambda: ["198.51.100.20"])
    assert ingest.home_addresses() == ["198.51.100.20", "192.0.2.10"]
    # without interface names (no ip / ifconfig) it falls back to the route and host addresses
    monkeypatch.setattr(ingest, "_iface_addrs", lambda: {})
    monkeypatch.setattr(ingest, "_route_addresses", lambda: [])
    assert ingest.home_addresses() == ["192.0.2.10", "fd4e:6400:d35c::10"]


def test_iface_parsers(monkeypatch):
    class R:
        def __init__(self, out): self.stdout = out
    ip_out = ("1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 192.0.2.10/24 brd 192.0.2.255 scope global eth0\n"
              "2: eth0    inet6 fd4e:6400:d35c::10/64 scope global\n5: veth9@if4    inet6 fe80::2/64 scope link\n")
    ifc_out = ("en0: flags=8863<UP> mtu 1500\n\tinet6 fe80::1%en0 prefixlen 64\n\tinet 192.0.2.11 netmask 0xffffff00\n"
               "utun3: flags=8051<UP> mtu 1380\n\tinet 10.86.24.7 --> 10.86.24.7 netmask 0xffffffff\n")
    monkeypatch.undo()
    for which, out, want in (("ip", ip_out, {"lo": ["127.0.0.1"], "eth0": ["192.0.2.10", "fd4e:6400:d35c::10"], "veth9": ["fe80::2"]}),
                             ("ifconfig", ifc_out, {"en0": ["fe80::1", "192.0.2.11"], "utun3": ["10.86.24.7"]})):
        ingest._IFACE_CACHE[0] = 0.0
        monkeypatch.setattr(ingest.shutil, "which", lambda x, w=which: f"/sbin/{x}" if x == w else None)
        monkeypatch.setattr(ingest.subprocess, "run", lambda *a, o=out, **k: R(o))
        assert ingest._iface_addrs() == want
    ingest._IFACE_CACHE[0] = 0.0


def test_auto_without_a_home_address_falls_back_to_this_machine(monkeypatch):
    monkeypatch.setattr(ingest, "_route_addresses", lambda: [])
    monkeypatch.setattr(ingest, "_iface_addrs", lambda: {"lo0": ["127.0.0.1"], "utun0": ["10.86.24.7"]})
    b = ingest.bind_info()
    assert b["bound"] == "127.0.0.1" and b["scope"] == "loopback"
    assert "no home-network address" in b["explain"]


def test_every_network_warns_in_plain_words():
    r = UI.put("/api/netlog/ingest", json={"host": "0.0.0.0"})
    assert r.status_code == 200
    b = r.json()["bind"]
    assert b["scope"] == "all" and not b["auto"]
    assert b["warn"] and "beyond your home network" in b["warn"] and "token" in b["warn"]
    assert set(r.json()["status"]["urls"]) == {"https://192.0.2.10:8788", "https://[fd4e:6400:d35c::10]:8788"}


def test_loopback_and_a_specific_lan_address():
    b = UI.put("/api/netlog/ingest", json={"host": "127.0.0.1"}).json()["bind"]
    assert b["scope"] == "loopback" and b["warn"] is None and "Only this machine" in b["explain"]
    b = UI.put("/api/netlog/ingest", json={"host": "192.0.2.10"}).json()["bind"]
    assert b["scope"] == "lan" and b["warn"] is None and not b["auto"]


def test_host_values_are_checked_and_auto_is_accepted():
    assert UI.put("/api/netlog/ingest", json={"host": "example.com"}).status_code == 400
    assert UI.put("/api/netlog/ingest", json={"host": "AUTO"}).json()["config"]["host"] == "auto"
    assert UI.put("/api/netlog/ingest", json={"host": ""}).json()["config"]["host"] == "auto"   # empty = the safe default
    assert UI.put("/api/netlog/ingest", json={"host": "2001:DB8::1"}).json()["config"]["host"] == "2001:db8::1"


def test_env_host_still_wins(monkeypatch):
    monkeypatch.setenv("OSINTHUB_INGEST_HOST", "127.0.0.1")
    d = UI.get("/api/netlog/ingest").json()
    assert d["config"]["host"] == "127.0.0.1" and "OSINTHUB_INGEST_HOST" in d["env_overrides"]
    assert d["bind"]["scope"] == "loopback"


def test_docker_explains_the_published_port(monkeypatch):
    monkeypatch.setenv("OSINTHUB_DOCKER", "1")
    monkeypatch.setenv("OSINTHUB_INGEST_HOST", "0.0.0.0")
    b = ingest.bind_info()
    assert b["docker"] and b["scope"] == "all"
    assert "Docker" in b["explain"] and "INGEST_PORT=" in b["warn"]
    monkeypatch.setenv("OSINTHUB_INGEST_HOST", "127.0.0.1")
    assert "cannot reach" in ingest.bind_info()["warn"]


def test_auto_listener_binds_the_resolved_address(monkeypatch):
    """With no home address, auto binds loopback: the listener really runs there and says so."""
    monkeypatch.setattr(ingest, "_lan_addresses", lambda: [])
    monkeypatch.setattr(ingest, "_route_addresses", lambda: [])
    monkeypatch.setattr(ingest, "_iface_addrs", lambda: {})
    port = free_port()
    d = UI.put("/api/netlog/ingest", json={"enabled": True, "host": "auto", "port": port, "tls": False}).json()
    try:
        assert d["status"]["running"], d["status"]
        assert ingest.LISTENER.key[1] == "127.0.0.1"
        assert d["status"]["urls"] == [f"http://127.0.0.1:{port}"]
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            assert b"200 OK" in s.recv(4096)
    finally:
        d = UI.put("/api/netlog/ingest", json={"enabled": False}).json()
    assert not d["status"]["running"]


def test_upload_listener_routes_are_unchanged():
    paths = {getattr(r, "path", "") for r in ingest.build_app().routes} - {""}
    assert paths == {"/health", "/hlta-push.sh", "/ingest", "/ingest/check", "/ingest/{name}", "/ingest/uploads/{uid}"}


# ------------------------------------------------------------------ where files go
def test_inbox_outside_docker_is_the_lake_path():
    w = ingest.inbox_location()
    assert not w["docker"] and w["path"] == str(config.LAKE / "inbox" / "zeek") + "/" and w["copy_cmd"] is None


def test_inbox_in_docker_with_a_host_folder(monkeypatch):
    monkeypatch.setenv("OSINTHUB_DOCKER", "1")
    monkeypatch.setenv("OSINTHUB_LAKE_HOST", "/Volumes/Drive/night-desk/")
    w = ingest.inbox_location()
    assert w["docker"] and w["path"] == "/Volumes/Drive/night-desk/inbox/zeek/"
    assert w["inside"].endswith("inbox/zeek/")


def test_inbox_in_docker_named_volume_gives_a_copy_command(monkeypatch):
    monkeypatch.setenv("OSINTHUB_DOCKER", "1")
    monkeypatch.delenv("OSINTHUB_LAKE_HOST", raising=False)
    w = ingest.inbox_location()
    assert w["path"] is None and w["docker"]
    assert w["copy_cmd"].startswith("docker compose cp ") and w["copy_cmd"].endswith(f"app:{w['inside']}")
    assert "LAKE_DIR" in w["note"]
    assert UI.get("/api/netlog/ingest").json()["inbox"]["copy_cmd"] == w["copy_cmd"]


def test_api_paths_carries_the_inbox_as_the_user_reaches_it(monkeypatch):
    import osinthub.api as A
    monkeypatch.setenv("OSINTHUB_DOCKER", "1")
    monkeypatch.setenv("OSINTHUB_LAKE_HOST", "./lake")
    p = A.paths()
    assert p["inbox"] == str(config.LAKE / "inbox" / "zeek")          # unchanged for older clients
    assert p["inbox_where"]["path"] == "./lake/inbox/zeek/"
