"""Escaping journey: provider text that arrived entity-encoded ('&lt;img src=x onerror=alert(1)&gt;' in an NVD
description, decoded at ingest by the source's own parse(), seeded by seed.py) is shown in the event drawer as the text
'<img src=x onerror=alert(1)>': no element is created and no handler runs."""
from __future__ import annotations

import pytest
from journey import open_app
from playwright.sync_api import expect

IMG = "<img src=x onerror=alert(1)>"
INIT = ("window.alert = () => { window.__xss = 'alert'; };"
        "try { localStorage.setItem('nd.deck', JSON.stringify('Vulnerabilities')); } catch (e) {}")


@pytest.mark.parametrize("form", ["desktop", "phone"])
def test_decoded_markup_shows_as_text_in_the_drawer(nd, ui, form):
    ev = next(r for r in nd.get("/api/events", sources="nvd_recent", limit=50) if r["title"].startswith("CVE-2026-90003"))
    assert IMG in ev["summary"] and "&lt;" not in ev["summary"]      # stored decoded
    page = ui(form)
    page.context.add_init_script(INIT)
    open_app(page, "#ops?panel=cve-feed" if form == "phone" else "#ops")   # phone: the New CVEs panel full screen
    row = page.locator(f'.feeds-row[data-id="{ev["id"]}"]').first
    row.scroll_into_view_if_needed()
    expect(row).to_contain_text(IMG)                                  # the New CVEs row shows it as text
    row.click()
    drawer = page.locator("#drawer-body")
    expect(drawer).to_contain_text("CVE-2026-90003")
    expect(drawer).to_contain_text(IMG)
    assert page.locator('img[src="x"], img[onerror]').count() == 0
    assert page.evaluate("window.__xss === undefined")
