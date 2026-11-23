"""Small helpers the journeys share (Playwright sync API). Waits are condition-based (expect / wait_for_function),
never fixed sleeps, so a journey is as fast as the app and fails with the condition it was waiting for."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from playwright.sync_api import Page, expect

expect.set_options(timeout=10_000)


def open_app(page: Page, hash_: str = "#watch") -> Page:
    """Load the app at a route and wait until the view on screen has rendered something."""
    page.goto("/" + hash_)
    page.wait_for_function("window.ndMain === 1")
    expect(page.locator(".view.active")).not_to_be_empty()
    return page


def focus_settled(loc) -> None:
    """Focus an element and wait two animation frames. Focusing an element lower in a scrolling pane scrolls the pane,
    and the browser fires that scroll event on the next frame; a key pressed before it would open something that the
    late scroll event then closes (the evidence card closes on any scroll)."""
    loc.focus()
    loc.page.evaluate("() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))")


def path_of(page: Page) -> str:
    return page.evaluate("location.hash").split("?")[0]


def wait_path(page: Page, pattern: str) -> None:
    """Wait until location.hash (without its ?query) matches the regex `pattern`."""
    page.wait_for_function("p => new RegExp(p).test(location.hash.split('?')[0])", arg=pattern)


def toast(page: Page, text: str | re.Pattern) -> None:
    """A toast (desktop stack or phone toast) with this text appears."""
    expect(page.locator("#toasts .toast, .m-toasts .m-toast").filter(has_text=text).first).to_be_visible()


def undo(page: Page) -> None:
    """Press Undo in the Undo toast on screen."""
    page.locator(".m-toasts .m-toast button, #toasts .m-toast-d button").filter(has_text="Undo").first.click()


def sheet(page: Page, sid: str | None = None):
    """The phone bottom sheet on screen (optionally the one with data-sheet=<sid>)."""
    sel = f'.m-sheet[data-sheet="{sid}"]' if sid else ".m-sheet"
    loc = page.locator(sel).last
    expect(loc).to_be_visible()
    return loc


def action_bar(page: Page):
    return page.locator("#m-actbar")


def more_tab(page: Page, label: str) -> None:
    """Phone: open More in the tab bar and choose an item."""
    page.locator('#m-tabbar [data-tab="more"]').tap()
    s = sheet(page)
    s.get_by_text(label, exact=True).first.tap()


def drop_zeek_conn(folder: Path, name: str, orig: str, resp: str, n: int = 3, uid: str = "CE2E") -> Path:
    """Write a small Zeek conn.log (JSON lines) from `orig` to `resp`:443 ending an hour ago into `folder`, with an
    mtime old enough that the inbox treats it as settled (finished writing)."""
    now = time.time()
    rows = [{"ts": now - 3600 - (n - i) * 60, "uid": f"{uid}{i:04d}", "id.orig_h": orig, "id.orig_p": 50000 + i,
             "id.resp_h": resp, "id.resp_p": 443, "proto": "tcp", "service": "ssl", "conn_state": "SF",
             "orig_bytes": 500, "resp_bytes": 900, "duration": 1.0, "history": "ShADadFf", "orig_pkts": 3,
             "resp_pkts": 3} for i in range(n)]
    folder.mkdir(parents=True, exist_ok=True)
    p = folder / name
    p.write_text("".join(json.dumps(r) + "\n" for r in rows))
    import os
    os.utime(p, (now - 120, now - 120))
    return p
