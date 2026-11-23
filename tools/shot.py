"""Screenshot tool for builders and critics, driven over the Chrome DevTools protocol.

uv run python tools/shot.py <url-or-path> <out.png> [--w 1600] [--h 1000] [--wait 8] [--js "code"] [--js-wait 2]

- Paths starting with / or # are resolved against http://127.0.0.1:8787
- --wait seconds after load before capture (live pages never go idle, so we wait explicitly)
- --js runs JavaScript in the page after the wait (click a tab, open a drawer...), then waits --js-wait
- Software WebGL is enabled, so MapLibre / globe.gl / echarts-gl render.
- --offline sends every non-loopback request to a dead proxy (no internet) and lists the requests that left the machine
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

import websockets

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


async def run(a) -> None:
    url = a.url
    if url.startswith("/") or url.startswith("#"):
        url = "http://127.0.0.1:8787" + (url if url.startswith("/") else "/" + url)
    port = free_port()
    prof = tempfile.mkdtemp()
    proc = subprocess.Popen([
        CHROME, "--headless=new", f"--remote-debugging-port={port}", f"--user-data-dir={prof}",
        "--enable-unsafe-swiftshader", "--use-angle=swiftshader", "--enable-webgl", "--ignore-gpu-blocklist",
        "--hide-scrollbars", f"--window-size={a.w},{a.h}", "--no-first-run", "--no-default-browser-check",
        *(["--proxy-server=http://127.0.0.1:9"] if a.offline else []),
        "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        ws_url = None
        for _ in range(100):
            try:
                tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json"))
                ws_url = next(t["webSocketDebuggerUrl"] for t in tabs if t.get("type") == "page")
                break
            except Exception:
                time.sleep(0.1)
        if not ws_url:
            raise SystemExit("chrome did not start")
        async with websockets.connect(ws_url, max_size=2**28) as ws:
            n = 0
            logs: list[str] = []
            external: list[str] = []

            async def call(method, **params):
                nonlocal n
                n += 1
                mid = n
                await ws.send(json.dumps({"id": mid, "method": method, "params": params}))
                while True:
                    m = json.loads(await ws.recv())
                    if m.get("method") == "Runtime.consoleAPICalled":
                        args = " ".join(str(x.get("value", x.get("description", ""))) for x in m["params"]["args"])
                        logs.append(f"[{m['params']['type']}] {args}"[:300])
                    elif m.get("method") == "Network.requestWillBeSent":
                        u = m["params"]["request"]["url"]
                        if u.startswith("http") and not u.startswith(("http://127.0.0.1", "http://localhost")):
                            external.append(u[:160])
                    elif m.get("method") == "Runtime.exceptionThrown":
                        d = m["params"]["exceptionDetails"]
                        logs.append(f"[exception] {d.get('exception', {}).get('description', d.get('text'))}"[:400])
                    if m.get("id") == mid:
                        return m.get("result", {})

            await call("Runtime.enable")
            await call("Page.enable")
            if a.offline:
                await call("Network.enable")
            await call("Emulation.setDeviceMetricsOverride", width=a.w, height=a.h, deviceScaleFactor=a.scale, mobile=a.w < 700)
            await call("Page.navigate", url=url)
            t_end = time.time() + a.wait
            while time.time() < t_end:
                await call("Runtime.evaluate", expression="1")
                await asyncio.sleep(0.25)
            if a.js:
                r = await call("Runtime.evaluate", expression=a.js, awaitPromise=True, returnByValue=True)
                if r.get("result", {}).get("value") is not None:
                    print("js ->", json.dumps(r["result"]["value"])[:2000])
                t_end = time.time() + a.js_wait
                while time.time() < t_end:
                    await call("Runtime.evaluate", expression="1")
                    await asyncio.sleep(0.25)
            shot = await call("Page.captureScreenshot", format="png")
            with open(a.out, "wb") as fh:
                fh.write(base64.b64decode(shot["data"]))
            print(f"saved {a.out} ({a.w}x{a.h})")
            if a.offline:
                print(f"external requests: {len(external)}")
                for u in sorted(set(external))[:25]:
                    print("  ", u)
            errs = [l for l in logs if l.startswith(("[error]", "[exception]", "[warning]"))]
            if errs:
                print("console problems:")
                for l in errs[:25]:
                    print("  ", l)
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except Exception:
            proc.kill()
        shutil.rmtree(prof, ignore_errors=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("url"); p.add_argument("out")
    p.add_argument("--w", type=int, default=1600); p.add_argument("--h", type=int, default=1000)
    p.add_argument("--scale", type=float, default=1)
    p.add_argument("--wait", type=float, default=8); p.add_argument("--js"); p.add_argument("--js-wait", type=float, default=2)
    p.add_argument("--offline", action="store_true")
    asyncio.run(run(p.parse_args()))
