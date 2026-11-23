#!/usr/bin/env python3
"""Offline and smoke test for HLTA (build brief, "Measured tests", Offline row).

Starts the server on a scratch lake with OSINTHUB_OFFLINE=1 and a dead proxy
(HTTPS_PROXY/HTTP_PROXY=http://127.0.0.1:9), all extensions enabled, and checks:

  1 startup time            5 log import + alerts + evidence chain
  2 every GET API route     6 AI helper down (search in keyword mode, nothing hangs)
  3 semantic search         7 web UI with no internet (tools/shot.py --offline, every tab)
  4 entity pages + graph    8 stability soak, then grep the log for FATAL/Traceback/"Only deleted"

Outbound traffic is watched two ways: the server runs under a socket guard (a wrapper that
logs and refuses every non-loopback connect, every DNS lookup of a non-local name and every
connect to the dead proxy) and `lsof -i` is sampled on the server's process tree.

    uv run python tests/eval/offline_check.py --lake <scratch lake> --port 8819 [--soak-min 20]

Never point --lake at the real lake: refused when ND_LIVE_LAKE names it, and any lake on an external drive
(/Volumes/...) is refused unless --allow-volume is given. The AI helper (127.0.0.1:8790) and Qdrant are local
and allowed.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
PY = sys.executable
HANG_S = 10.0
LOOPBACK = ("127.0.0.1", "::1", "localhost", "0.0.0.0", "::ffff:127.0.0.1")
PROXY_PORT = 9
TABS = ["ops", "news", "entities", "network", "explorer", "cinema", "sources"]

GUARD = r'''
import os, socket, sys, time, errno, runpy, threading
LOG = os.environ["NETGUARD_LOG"]
LOOP = ("127.0.0.1", "::1", "localhost", "0.0.0.0", "::ffff:127.0.0.1", "")
_lock = threading.Lock()
def _log(kind, what):
    import traceback
    st = "".join(traceback.format_stack(limit=8)[:-2]).replace("\n", " | ")[-600:]
    with _lock, open(LOG, "a") as fh:
        fh.write(f"{time.time():.3f}\t{kind}\t{what}\t{st}\n")
def _bad_addr(addr):
    if not isinstance(addr, tuple) or not addr:
        return False  # unix sockets
    host, port = str(addr[0]), addr[1] if len(addr) > 1 else None
    if host in LOOP or host.startswith("127."):
        return port == 9
    return True
_connect, _connect_ex = socket.socket.connect, socket.socket.connect_ex
def connect(self, addr):
    if _bad_addr(addr):
        _log("connect", repr(addr))
        if not (str(addr[0]).startswith("127.")):
            raise OSError(errno.ENETUNREACH, "netguard: outbound blocked")
    return _connect(self, addr)
def connect_ex(self, addr):
    if _bad_addr(addr):
        _log("connect_ex", repr(addr))
        if not (str(addr[0]).startswith("127.")):
            return errno.ENETUNREACH
    return _connect_ex(self, addr)
socket.socket.connect, socket.socket.connect_ex = connect, connect_ex
_gai = socket.getaddrinfo
def getaddrinfo(host, *a, **k):
    h = host.decode() if isinstance(host, bytes) else (host or "")
    if h and h not in LOOP and not h.startswith("127.") and not h.replace(".", "").isdigit() and ":" not in h:
        _log("dns", h)
        raise socket.gaierror(socket.EAI_NONAME, "netguard: no DNS offline")
    return _gai(host, *a, **k)
socket.getaddrinfo = getaddrinfo
sys.argv = ["osinthub"]
sys.path.insert(0, os.getcwd())
runpy.run_module("osinthub", run_name="__main__", alter_sys=True)
'''


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def port_busy(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


# ---------------------------------------------------------------- server under a socket guard
class Server:
    def __init__(self, lake: Path, port: int, work: Path, tag: str, ai_url: str | None = None):
        self.lake, self.port, self.work, self.tag, self.ai_url = lake, port, work, tag, ai_url
        self.base = f"http://127.0.0.1:{port}"
        self.log_path = work / f"server-{tag}.log"
        self.guard_log = work / f"netguard-{tag}.log"
        self.lsof_hits: list[str] = []
        self._stop = threading.Event()
        self.proc: subprocess.Popen | None = None
        self.startup_s: float | None = None

    def start(self, timeout: float = 120) -> float:
        if port_busy(self.port):
            raise SystemExit(f"port {self.port} already in use")
        guard = self.work / "netguard_run.py"
        guard.write_text(GUARD)
        self.guard_log.write_text("")
        env = dict(os.environ)
        env.pop("OSINTHUB_DISABLE_EXT", None)
        env.update(OSINTHUB_LAKE=str(self.lake), OSINTHUB_PORT=str(self.port), OSINTHUB_OFFLINE="1",
                   HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9",
                   https_proxy="http://127.0.0.1:9", http_proxy="http://127.0.0.1:9",
                   NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost",
                   HF_HUB_OFFLINE="1", NETGUARD_LOG=str(self.guard_log), PYTHONUNBUFFERED="1",
                   # check_routes walks /openapi.json, which the app serves only in debug mode (it also turns the
                   # SQL console on; this check sends GETs only)
                   OSINTHUB_DEBUG="1")
        if self.ai_url:
            env["AI_URL"] = self.ai_url
        self.logf = open(self.log_path, "w")
        t0 = time.perf_counter()
        self.proc = subprocess.Popen([PY, str(guard)], cwd=ROOT, env=env, stdout=self.logf, stderr=subprocess.STDOUT,
                                     start_new_session=True)
        threading.Thread(target=self._lsof_loop, daemon=True).start()
        while time.perf_counter() - t0 < timeout:
            if self.proc.poll() is not None:
                raise SystemExit(f"server exited during startup ({self.proc.returncode}); see {self.log_path}")
            try:
                if httpx.get(self.base + "/api/health", timeout=2, trust_env=False).status_code == 200:
                    self.startup_s = time.perf_counter() - t0
                    return self.startup_s
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
        raise SystemExit(f"server not healthy after {timeout}s; see {self.log_path}")

    def pids(self) -> list[int]:
        if not self.proc:
            return []
        out = [self.proc.pid]
        try:
            kids = subprocess.run(["pgrep", "-P", str(self.proc.pid)], capture_output=True, text=True).stdout.split()
            out += [int(k) for k in kids]
        except Exception:
            pass
        return out

    def _lsof_loop(self):
        while not self._stop.is_set() and self.proc and self.proc.poll() is None:
            for pid in self.pids():
                r = subprocess.run(["lsof", "-nP", "-i", "-a", "-p", str(pid)], capture_output=True, text=True)
                for line in r.stdout.splitlines()[1:]:
                    name = line.split()[-2] if line.endswith(")") else line.split()[-1]
                    if "->" not in name:
                        continue
                    remote = name.split("->", 1)[1]
                    host = remote.rsplit(":", 1)[0].strip("[]")
                    rport = remote.rsplit(":", 1)[-1]
                    if host not in LOOPBACK and not host.startswith("127."):
                        self.lsof_hits.append(f"{time.strftime('%H:%M:%S')} {line}")
                    elif rport == str(PROXY_PORT):
                        self.lsof_hits.append(f"{time.strftime('%H:%M:%S')} proxy {line}")
            self._stop.wait(0.5)

    def guard_events(self) -> list[str]:
        try:
            return [l for l in self.guard_log.read_text().splitlines() if l.strip()]
        except FileNotFoundError:
            return []

    def stop(self):
        self._stop.set()
        if self.proc and self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGINT)
            try:
                self.proc.wait(30)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
                self.proc.wait(10)
        # DuckDB lock: wait for the port and the process to be gone before the next start
        for _ in range(100):
            if not port_busy(self.port):
                break
            time.sleep(0.2)
        self.logf.close()


# ---------------------------------------------------------------- helpers
class Client:
    def __init__(self, base: str):
        self.base = base
        self.c = httpx.Client(base_url=base, timeout=httpx.Timeout(HANG_S + 5, connect=5), trust_env=False)

    def get(self, path, **params):
        t0 = time.perf_counter()
        try:
            r = self.c.get(path, params={k: v for k, v in params.items() if v is not None})
            return r, time.perf_counter() - t0
        except httpx.HTTPError as e:
            return e, time.perf_counter() - t0

    def json(self, path, **params):
        r, _ = self.get(path, **params)
        if isinstance(r, Exception) or r.status_code != 200:
            return None
        try:
            return r.json()
        except ValueError:
            return None


def items_of(x):
    if isinstance(x, list):
        return x
    if isinstance(x, dict):
        for k in ("items", "results", "stories", "articles", "alerts", "devices", "rows", "files", "sources", "data"):
            if isinstance(x.get(k), list):
                return x[k]
    return []


def first_id(x, key="id"):
    for it in items_of(x):
        if isinstance(it, dict) and it.get(key) is not None:
            return str(it[key])
    return None


# ---------------------------------------------------------------- 2: every GET route
def discover_ids(cl: Client) -> dict:
    ids = {}
    ents = cl.json("/api/entities", limit=200) or {}
    ent_items = items_of(ents)
    ids["eid"] = first_id(ents) or "actor:lazarus-group"
    ids["entity_ids"] = ",".join(str(e["id"]) for e in ent_items[:5] if isinstance(e, dict) and e.get("id")) or ids["eid"]
    ids["eid_event"] = first_id(cl.json("/api/events", limit=5)) or "x"
    ids["sid_source"] = first_id(cl.json("/api/sources")) or "cisa_kev"
    ids["sid_story"] = first_id(cl.json("/api/news/stories", limit=5)) or "x"
    ids["aid_article"] = first_id(cl.json("/api/news/articles", limit=5)) or "x"
    ids["aid_alert"] = first_id(cl.json("/api/netlog/alerts", limit=5)) or "x"
    ids["did"] = first_id(cl.json("/api/netlog/devices", limit=5)) or "x"
    ids["cve"] = "CVE-2024-3400"
    return ids


QPARAM = {  # sensible values for required (and some useful) query params
    "q": "ransomware", "values": "8.8.8.8,CVE-2024-3400,example.com", "metric": "count",
    "since_hours": None, "limit": None,
}


def path_value(path: str, name: str, ids: dict) -> str:
    if name == "eid" and path.startswith("/api/events"):
        return ids["eid_event"]
    if name == "eid":
        return ids["eid"]
    if name == "sid" and "/news/" in path:
        return ids["sid_story"]
    if name == "sid":
        return ids["sid_source"]
    if name == "aid" and "/news/" in path:
        return ids["aid_article"]
    if name == "aid":
        return ids["aid_alert"]
    if name == "did":
        return ids["did"]
    return "x"


def check_routes(srv: Server, label: str) -> dict:
    cl = Client(srv.base)
    spec = cl.json("/openapi.json")
    if not spec:
        return {"pass": False, "error": "no /openapi.json"}
    ids = discover_ids(cl)
    routes, skipped = [], []
    for path, ops in spec["paths"].items():
        if "get" not in ops:
            skipped.append(f"{'/'.join(m.upper() for m in ops)} {path}")
            continue
        op = ops["get"]
        url = path
        params = {}
        for p in op.get("parameters", []):
            if p["in"] == "path":
                url = url.replace("{" + p["name"] + "}", path_value(path, p["name"], ids))
            elif p["in"] == "query" and p.get("required"):
                n = p["name"]
                if n == "id":
                    params[n] = ids["eid"]
                elif n == "ids":
                    params[n] = ids["entity_ids"]
                elif n == "group":
                    params[n] = "device"
                else:
                    params[n] = QPARAM.get(n) or "ransomware"
        if path == "/api/news/intel":
            params["story"] = ids["sid_story"]
        if path == "/api/entities/graph":
            params["id"] = ids["eid"]
        if path in ("/api/events", "/api/news/search", "/api/entities", "/api/netlog/connections"):
            routes.append((path, url, {**params, "q": "ransomware"}))
        routes.append((path, url, params))
    routes.append(("/", "/", {}))
    rows = []
    for path, url, params in routes:
        if path == "/api/stream":
            t0 = time.perf_counter()
            try:
                with cl.c.stream("GET", url, timeout=httpx.Timeout(HANG_S, connect=5)) as r:
                    st = r.status_code
            except httpx.HTTPError as e:
                st = type(e).__name__
            rows.append((path, url, params, st, time.perf_counter() - t0))
            continue
        r, dt = cl.get(url, **params)
        st = type(r).__name__ if isinstance(r, Exception) else r.status_code
        body = "" if isinstance(r, Exception) else r.text[:200]
        rows.append((path, url, params, st, dt, body))
    fails = [x for x in rows if not isinstance(x[3], int) or x[3] >= 500 or x[4] > HANG_S]
    c4 = [x for x in rows if isinstance(x[3], int) and 400 <= x[3] < 500]
    slow = sorted(rows, key=lambda x: -x[4])[:3]
    print(f"[{label}] routes: {len(rows)} GETs, {len(fails)} failures, {len(c4)} 4xx, max {slow[0][4]:.2f}s ({slow[0][0]})")
    for x in fails:
        print(f"   FAIL {x[3]} {x[4]:.2f}s GET {x[1]} {x[2]} {x[5] if len(x) > 5 else ''}")
    for x in c4:
        print(f"   4xx  {x[3]} {x[4]:.2f}s GET {x[1]} {x[2]} {x[5][:120] if len(x) > 5 else ''}")
    print(f"   not GET (skipped): {len(skipped)}")
    return {"pass": not fails, "n": len(rows), "fails": len(fails), "4xx": len(c4),
            "max_s": round(slow[0][4], 2), "slowest": slow[0][0], "skipped": len(skipped)}


# ---------------------------------------------------------------- 3 / 6: semantic search
SEARCH_Q = {"cve": "remote code execution in a VPN gateway", "article": "ransomware attack on hospital",
            "entity": "north korean threat actor"}


def check_search(srv: Server, label: str, expect_keyword_only: bool = False) -> dict:
    cl = Client(srv.base)
    out, ok = {}, True
    for t, q in SEARCH_Q.items():
        r, dt = cl.get("/api/search/semantic", q=q, types=t, k=10)
        res = r.json() if not isinstance(r, Exception) and r.status_code == 200 else None
        n = len(res or [])
        typed = sum(1 for x in (res or []) if x.get("type") == t)
        vec = sum(1 for x in (res or []) if (x.get("match") or {}).get("vector") is not None)
        good = n > 0 and typed == n and dt <= HANG_S
        if expect_keyword_only and vec:
            good = False
        ok &= good
        out[t] = {"n": n, "s": round(dt, 2), "vector_hits": vec, "top": (res or [{}])[0].get("title", "")[:60] if res else None}
        print(f"[{label}] search {t}: {n} results ({typed} of type), {vec} with vector score, {dt:.2f}s, top={out[t]['top']!r}"
              + ("" if good else f"  <-- FAIL {'' if isinstance(r, Exception) else r.status_code}"))
    # mixed-type default query
    r, dt = cl.get("/api/search/semantic", q="CVE-2024-3400", k=10)
    out["mixed_s"] = round(dt, 2)
    ok &= not isinstance(r, Exception) and r.status_code == 200 and dt <= HANG_S
    return {"pass": ok, **out}


# ---------------------------------------------------------------- 4: entities
def check_entities(srv: Server, rng: random.Random) -> dict:
    cl = Client(srv.base)
    allents = items_of(cl.json("/api/entities", limit=2000) or {})
    ids = [e["id"] for e in allents if isinstance(e, dict) and e.get("id")]
    if len(ids) < 5:
        print(f"[entities] only {len(ids)} entities listed  <-- FAIL")
        return {"pass": False, "listed": len(ids)}
    pick = rng.sample(ids, 5)
    ok, rows = True, []
    for eid in pick:
        r1, d1 = cl.get(f"/api/entities/{eid}")
        r2, d2 = cl.get("/api/entities/graph", id=eid)
        s1 = getattr(r1, "status_code", type(r1).__name__)
        s2 = getattr(r2, "status_code", type(r2).__name__)
        nodes = edges = None
        if s2 == 200:
            g = r2.json()
            nodes, edges = len(g.get("nodes", [])), len(g.get("edges", []))
        good = s1 == 200 and s2 == 200 and d1 <= HANG_S and d2 <= HANG_S and (nodes or 0) >= 1
        if s1 == 200:
            good &= r1.json().get("id") is not None
        ok &= good
        rows.append((eid, s1, round(d1, 2), s2, round(d2, 2), nodes, edges))
        print(f"[entities] {eid}: page {s1} {d1:.2f}s, graph {s2} {d2:.2f}s {nodes} nodes {edges} edges" + ("" if good else "  <-- FAIL"))
    return {"pass": ok, "listed": len(ids), "max_s": max(max(r[2], r[4]) for r in rows),
            "edges": [r[6] for r in rows]}


# ---------------------------------------------------------------- 5: log import
def gen_zeek(lake: Path, out: Path, conn_lines: int, seed: int) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    r = subprocess.run([PY, str(ROOT / "tests/eval/zeek_planted.py"), "--out-dir", str(out), "--lake", str(lake),
                        "--conn-lines", str(conn_lines), "--seed", str(seed)], cwd=ROOT, capture_output=True, text=True,
                       env={**os.environ, "HTTPS_PROXY": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9"})
    print(r.stdout.strip()[-400:], r.stderr.strip()[-400:])
    if r.returncode:
        raise SystemExit("zeek_planted failed")
    return json.loads((out / "manifest.json").read_text())


def check_import(srv: Server, zdir: Path, manifest: dict) -> dict:
    cl = Client(srv.base)
    cl.c.put("/api/netlog/settings", json={"home_prefixes": manifest.get("home_prefixes") or ["192.0.2.0/24", "2001:db8:1::/48"]})
    before = items_of(cl.json("/api/netlog/alerts", limit=0) or [])
    files = sorted(p for p in zdir.iterdir() if p.is_file() and p.name != "manifest.json")
    uids = set()
    for p in files:
        import gzip
        op = gzip.open if p.suffix == ".gz" else open
        with op(p, "rt") as fh:
            for line in fh:
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if d.get("uid"):
                    uids.add(d["uid"])
                for u in d.get("uids") or []:
                    uids.add(u)
    t0 = time.perf_counter()
    handles = [("files", (p.name, open(p, "rb"))) for p in files]
    try:
        r = httpx.post(srv.base + "/api/netlog/import", files=handles, timeout=600, trust_env=False)
    finally:
        for _, (_, fh) in handles:
            fh.close()
    dt = time.perf_counter() - t0
    if r.status_code != 200:
        print(f"[import] POST {r.status_code} {r.text[:300]}  <-- FAIL")
        return {"pass": False, "status": r.status_code}
    res = r.json()
    after = items_of(cl.json("/api/netlog/alerts", limit=0) or [])
    mine = [a for a in after if set((a.get("evidence") or {}).get("uids") or []) & uids]
    pos_uids = {t["uid"] for t in manifest.get("truth", []) if t.get("kind") == "positive"}
    hit_uids = {u for a in mine for u in (a.get("evidence") or {}).get("uids") or []}
    recall = len(pos_uids & hit_uids) / len(pos_uids) if pos_uids else None
    chain_ok, chain_n, chain_max = 0, 0, 0.0
    for a in mine[:10]:
        rr, d = cl.get(f"/api/netlog/alerts/{a['id']}")
        chain_n += 1
        chain_max = max(chain_max, d)
        if not isinstance(rr, Exception) and rr.status_code == 200:
            j = rr.json()
            if (j.get("rows") or j.get("related")) and d <= HANG_S and "intervals" in j:
                chain_ok += 1
    missed = [t for t in manifest.get("truth", []) if t.get("kind") == "positive" and t["uid"] not in hit_uids]
    for t in missed[:12]:
        print(f"   missed positive: {t.get('category')} {t.get('indicator')} via {t.get('source')} at {t.get('ts_iso')}")
    ok = (not res.get("errors")) and (res.get("inserted") or 0) > 0 and len(mine) > 0 and chain_n > 0 and chain_ok == chain_n
    print(f"[import] {len(files)} files, {res.get('inserted')} rows inserted in {dt:.1f}s, errors={len(res.get('errors') or [])}; "
          f"alerts {len(before)} -> {len(after)}, {len(mine)} on imported uids, planted-positive recall {recall}; "
          f"evidence chain ok {chain_ok}/{chain_n} (max {chain_max:.2f}s)" + ("" if ok else "  <-- FAIL"))
    return {"pass": ok, "files": len(files), "inserted": res.get("inserted"), "import_s": round(dt, 1),
            "alerts_new": len(mine), "recall": recall, "chain": f"{chain_ok}/{chain_n}"}


# ---------------------------------------------------------------- 7: UI
def check_ui(srv: Server, shots: Path) -> dict:
    shots.mkdir(exist_ok=True)
    js = ("JSON.stringify({bad: performance.getEntriesByType('resource').filter(e => e.responseStatus === 0 || e.responseStatus >= 400)"
          ".map(e => e.responseStatus + ' ' + e.name).slice(0, 30), n: performance.getEntriesByType('resource').length,"
          " text: (document.body.innerText || '').length})")
    ok, out = True, {}
    for tab in TABS:
        log_mark = srv.log_path.stat().st_size
        png = shots / f"offline-{tab}.png"
        r = subprocess.run([PY, str(ROOT / "tools/shot.py"), f"{srv.base}/#{tab}", str(png), "--offline", "--wait", "12",
                            "--js", js, "--js-wait", "1"], cwd=ROOT, capture_output=True, text=True, timeout=180)
        txt = r.stdout
        ext = int(m.group(1)) if (m := re.search(r"external requests: (\d+)", txt)) else -1
        probs = re.findall(r"^\s+(\[(?:error|exception|warning)\].*)$", txt, re.M)
        errors = [p for p in probs if not p.startswith("[warning]")]
        bad, nres, ntext = [], 0, 0
        if m := re.search(r"js -> (.*)$", txt, re.M):
            try:
                j = json.loads(json.loads(m.group(1)))
                bad, nres, ntext = j["bad"], j["n"], j["text"]
            except Exception:
                pass
        with open(srv.log_path) as fh:
            fh.seek(log_mark)
            srv_bad = [l.strip() for l in fh if re.search(r'" (4\d\d|5\d\d)\b', l)]
        good = r.returncode == 0 and png.exists() and ext == 0 and not errors and not bad and ntext > 50 \
            and not any(re.search(r'" 5\d\d', l) for l in srv_bad)
        ok &= good
        out[tab] = {"external": ext, "console_errors": len(errors), "warnings": len(probs) - len(errors),
                    "failed_requests": len(bad), "server_4xx_5xx": len(srv_bad)}
        print(f"[ui] #{tab}: external={ext} console_errors={len(errors)} warnings={len(probs) - len(errors)} "
              f"failed_requests={len(bad)} resources={nres} text_chars={ntext} server_4xx/5xx={len(srv_bad)}" + ("" if good else "  <-- FAIL"))
        for p in errors[:6]:
            print("     console:", p[:240])
        for b in bad[:6]:
            print("     failed:", b[:200])
        for l in srv_bad[:6]:
            print("     server:", l[:200])
        if r.returncode:
            print("     shot.py stderr:", r.stderr[-400:])
        ext_urls = re.findall(r"^\s{3}(https?://\S+)$", txt, re.M)
        for u in ext_urls[:6]:
            print("     external:", u)
    return {"pass": ok, **out}


# ---------------------------------------------------------------- 8: soak
def soak(srv: Server, minutes: float) -> dict:
    cl = Client(srv.base)
    t_end = time.time() + minutes * 60
    worst, misses, rss = 0.0, 0, []
    while time.time() < t_end:
        if srv.proc.poll() is not None:
            print(f"[soak] server died ({srv.proc.returncode})  <-- FAIL")
            break
        r, d = cl.get("/api/health")
        worst = max(worst, d)
        if isinstance(r, Exception) or r.status_code != 200 or d > HANG_S:
            misses += 1
        r2, d2 = cl.get("/api/entities/status")
        worst = max(worst, d2)
        if isinstance(r2, Exception) or r2.status_code != 200 or d2 > HANG_S:
            misses += 1
        try:
            rss.append(int(subprocess.run(["ps", "-o", "rss=", "-p", str(srv.proc.pid)], capture_output=True, text=True).stdout.strip()) // 1024)
        except ValueError:
            pass
        time.sleep(30)
    alive = srv.proc.poll() is None
    text = srv.log_path.read_text(errors="replace")
    greps = {k: len(re.findall(re.escape(k), text)) for k in ("FATAL", "Traceback", "Only deleted")}
    ok = alive and misses == 0 and not any(greps.values())
    print(f"[soak] {minutes} min: alive={alive}, health/status misses={misses}, worst {worst:.2f}s, "
          f"RSS {rss[0] if rss else '?'} -> {rss[-1] if rss else '?'} MB (max {max(rss) if rss else '?'}), log greps {greps}"
          + ("" if ok else "  <-- FAIL"))
    for k in greps:
        if greps[k]:
            for m in list(re.finditer(re.escape(k), text))[:2]:
                s = text.rfind("\n", 0, max(0, m.start() - 300))
                print(f"   --- {k} context:\n" + text[s:m.start() + 900])
    return {"pass": ok, "alive": alive, "misses": misses, "worst_s": round(worst, 2), "greps": greps,
            "rss_mb": [rss[0], rss[-1]] if rss else None}


def outbound(srv: Server, label: str) -> dict:
    g = srv.guard_events()
    print(f"[{label}] outbound: guard events={len(g)}, lsof non-loopback/proxy sockets={len(srv.lsof_hits)}")
    for l in g[:8]:
        print("   guard:", l[:500])
    for l in srv.lsof_hits[:5]:
        print("   lsof:", l)
    return {"pass": not g and not srv.lsof_hits, "guard": len(g), "lsof": len(srv.lsof_hits),
            "sample": [l.split("\t")[1:3] for l in g[:5]]}


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lake", type=Path, required=True)
    ap.add_argument("--port", type=int, default=8819)
    ap.add_argument("--soak-min", type=float, default=20)
    ap.add_argument("--conn-lines", type=int, default=3000)
    ap.add_argument("--rng", type=int, default=int(time.time()))
    ap.add_argument("--skip-ui", action="store_true")
    ap.add_argument("--allow-volume", action="store_true", help="allow a scratch lake under /Volumes")
    a = ap.parse_args()
    lake = a.lake.resolve()
    live = os.environ.get("ND_LIVE_LAKE", "")   # the owner's live lake, set per machine (never named in the repo)
    # the live lake sits on an external drive; scratch lakes belong on the internal disk
    on_volume = len(lake.parts) > 1 and lake.parts[1].casefold() == "volumes" and not a.allow_volume
    if (live and (lake == Path(live).resolve() or Path(live).resolve() in lake.parents)) or on_volume \
            or a.port in (8787, 8080):
        raise SystemExit("refusing: real lake or reserved port")
    work = Path(tempfile.mkdtemp(prefix="offline-check-"))
    print(f"work dir {work}; rng seed {a.rng}")
    rng = random.Random(a.rng)
    R: dict[str, dict] = {}

    zdir = work / "zeek"
    manifest = gen_zeek(lake, zdir, a.conn_lines, a.rng)  # fresh uids every run: a re-import is deduped

    srv = Server(lake, a.port, work, "main")
    try:
        st = srv.start()
        ext = Client(srv.base).json("/api/extensions") or {}
        print(f"[startup] healthy in {st:.2f}s; extensions: {json.dumps(ext)[:600]}")
        failed_ext = (ext.get("failed_imports") or None, [e["name"] for e in ext.get("extensions", []) if e.get("errors")] or None) if isinstance(ext, dict) else "no status"
        failed_ext = None if failed_ext == (None, None) else failed_ext
        R["1 startup"] = {"pass": st <= 30 and not failed_ext, "s": round(st, 2), "failed_ext": failed_ext}
        R["2 routes"] = check_routes(srv, "main")
        R["3 search"] = check_search(srv, "main")
        R["4 entities"] = check_entities(srv, rng)
        R["5 import"] = check_import(srv, zdir, manifest)
        if not a.skip_ui:
            R["7 ui"] = check_ui(srv, ROOT / "shots")
        R["8 soak"] = soak(srv, a.soak_min)
        R["outbound main"] = outbound(srv, "main")
    finally:
        srv.stop()

    dead = free_port()
    srv2 = Server(lake, a.port, work, "helperdown", ai_url=f"http://127.0.0.1:{dead}")
    try:
        st2 = srv2.start()
        print(f"[helper-down] healthy in {st2:.2f}s (AI_URL -> dead port {dead})")
        ai = Client(srv2.base).json("/api/ai/status")
        print(f"[helper-down] /api/ai/status: {json.dumps(ai)[:300]}")
        s = check_search(srv2, "helper-down", expect_keyword_only=True)
        rt = check_routes(srv2, "helper-down")
        R["6 helper down"] = {"pass": s["pass"] and rt["pass"], "startup_s": round(st2, 2), "search": s, "routes": rt}
        R["outbound helper-down"] = outbound(srv2, "helper-down")
    finally:
        srv2.stop()

    print("\n==== SUMMARY ====")
    for k, v in R.items():
        print(f"{'PASS' if v.get('pass') else 'FAIL'}  {k}: {json.dumps({x: y for x, y in v.items() if x != 'pass'}, default=str)[:400]}")
    print(f"logs: {work}")
    return 0 if all(v.get("pass") for v in R.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
