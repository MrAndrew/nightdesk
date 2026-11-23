"""UI regression smoke (tools/gate.sh runs it against a scratch server).
Visits every top-level view (read from the nav, so new views are picked up) plus known sub-routes at desktop and
phone width, opens search/drawer/back, and reports page errors, console errors, HTTP errors, egress.
Usage: ND_BASE=http://127.0.0.1:PORT uv run --quiet --with playwright python tests/e2e/smoke.py OUTDIR
(screenshots of every view at both widths and smoke.json go to OUTDIR)"""
import sys, asyncio, json, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nd import session, settle, BASE
OUT = sys.argv[1] if len(sys.argv) > 1 else "."
os.makedirs(OUT, exist_ok=True)
EXTRA = ["network/alerts", "network/hunt", "network/devices", "network/import", "entities/graph", "news"]
async def run(w, h, tag):
    res = {}
    async with session(width=w, height=h) as (page, log):
        await page.goto(BASE + "/", wait_until="domcontentloaded"); await settle(page, log)
        views = await page.evaluate("[...document.querySelectorAll('[data-view]')].filter(b=>b.tagName==='BUTTON'||b.tagName==='A').map(b=>b.dataset.view)")
        views = list(dict.fromkeys([v for v in views if v] + EXTRA))
        res["views"] = views
        for v in views:
            n0 = len(log["page_errors"]) + len(log["console_errors"])
            await page.evaluate(f"location.hash = {json.dumps(v)}"); await settle(page, log)
            await page.screenshot(path=f"{OUT}/{tag}-{v.replace('/','_')}.png")
            if len(log["page_errors"]) + len(log["console_errors"]) > n0: res.setdefault("errors_on", []).append(v)
        await page.keyboard.press("/"); await page.keyboard.type("qakbot"); await page.wait_for_timeout(1500); await page.keyboard.press("Escape")
        await page.go_back(); await page.wait_for_timeout(1000); await page.go_back(); await page.wait_for_timeout(1000)
        # a module that fails to import only logs a warning ("module … not loaded"); treat it as an error
        log["console_errors"] += [w for w in log.get("console_warnings", []) if "not loaded" in w or "failed to load" in w.lower()]
        for k in ("page_errors", "console_errors", "http_errors", "blocked"):
            res[k] = log[k][:12]; res[k + "_n"] = len(log[k])
    return res
async def main():
    d, p = await asyncio.gather(run(1440, 900, "d"), run(390, 844, "p"))   # desktop and phone side by side
    out = {"desktop": d, "phone": p}
    json.dump(out, open(f"{OUT}/smoke.json", "w"), indent=1)
    bad = sum(out[t][k + "_n"] for t in out for k in ("page_errors", "console_errors", "blocked"))
    print(json.dumps({t: {k: out[t][k] for k in out[t] if k.endswith("_n") or k == "errors_on"} for t in out}))
    print("SMOKE", "FAIL" if bad else "PASS")
asyncio.run(main())
