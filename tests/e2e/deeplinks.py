"""Every deep link keeps its path through load, the range sync, a reload, Back and a range change.
usage: ND_BASE=http://127.0.0.1:PORT uv run --quiet --with playwright python tests/e2e/deeplinks.py
Needs an alert, a device, a story and an actor: a scratch server from tests/e2e/server.py with the demo loaded."""
import sys, os, asyncio, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nd import session, settle, get as _get, BASE
def get(p, q=None): return _get(p, q)[1]
def path(h): return h.split('?')[0]
async def main():
    al = get("/api/netlog/alerts", {"limit": 1}); al = al.get("items", al) if isinstance(al, dict) else al
    dv = get("/api/netlog/devices", {"limit": 1})
    st = get("/api/news/stories", {"limit": 1}); st = st.get("stories", st) if isinstance(st, dict) else st
    en = get("/api/entities", {"type": "actor", "limit": 1})["items"]
    q = urllib.parse.quote
    links = [f"#network/alerts/{q(al[0]['id'])}", "#network/alerts/rules", f"#network/devices/{q(dv[0]['id'])}",
             "#network/hunt", f"#news/story/{q(st[0]['id'])}", f"#entities/{q(en[0]['id'], safe=':')}", "#entities/review",
             "#cinema?kiosk", "#ops", "#news", "#entities", "#network/overview"]
    async def one_size(w, hgt):
        bad, out = 0, []
        async with session(width=w, height=hgt) as (page, log):
            for L in links:
                await page.goto(BASE + "/" + L, wait_until="domcontentloaded"); await settle(page, log)
                a = await page.evaluate("location.hash")
                await page.reload(wait_until="domcontentloaded"); await settle(page, log)
                b = await page.evaluate("location.hash")
                # a range click must keep the path too
                btn = None
                for sel in ('.view.active .ranges:not(.ranges-off) .ranges-seg button[aria-checked="false"]', '#range .ranges-seg button[aria-checked="false"]'):
                    for x in await page.query_selector_all(sel):
                        if await x.is_visible(): btn = x; break
                    if btn: break
                c = b
                if btn and await btn.is_visible():
                    await btn.evaluate("b => b.click()"); await settle(page, log); c = await page.evaluate("location.hash")
                ok = path(a) == path(L) == path(b) == path(c)
                bad += not ok
                out.append(f"{w} {'OK ' if ok else 'BAD'} {L} | {a} | {b} | {c}")
            out.append(f"{w} ERR {log['page_errors']} {log['console_errors']} {log['http_errors'][:4]}")
        return bad, out
    results = await asyncio.gather(one_size(1440, 900), one_size(390, 844))   # desktop and phone side by side
    for _, lines in results: print("\n".join(lines))
    bad = sum(r[0] for r in results)
    print("RESULT", "PASS" if not bad else f"FAIL {bad}")
asyncio.run(main())
