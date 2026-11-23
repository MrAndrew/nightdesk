"""The SQL console is off unless the server says it is on (/api/health sql_console, set by OSINTHUB_SQL_CONSOLE=1).

The journeys' server runs with it on (server.py). Most off checks answer /api/health and /api/settings/about with
sql_console false and /api/sql with the server's 403 (what a server started without the variable sends), so one
server covers both; test_a_real_server_started_off starts a second, empty server with ND_SQL_CONSOLE=0 to prove it."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

import pytest
from journey import open_app
from playwright.sync_api import expect

OFF = "The SQL console is off. Start Night Desk with OSINTHUB_SQL_CONSOLE=1 to turn it on."
COMMANDS = "() => import('./js/core/commands.js').then((m) => m.commands().filter((c) => !c.when || c.when()).map((c) => c.id))"


def console_off(page):
    """Make this page see a server started without OSINTHUB_SQL_CONSOLE."""
    def patched(route):
        r = route.fetch()
        body = r.json()
        body["sql_console"] = False
        route.fulfill(response=r, body=json.dumps(body), headers={**r.headers, "content-type": "application/json"})
    page.route("**/api/health", patched)
    page.route("**/api/settings/about", patched)
    page.route("**/api/sql", lambda route: route.fulfill(status=403, content_type="application/json",
                                                         body=json.dumps({"detail": OFF})))


def start_tour(page):
    page.evaluate("import('./js/core/tour.js').then((m) => m.startTour('page'))")
    card = page.locator(".tour-card")
    expect(card).to_be_visible()
    return card


def test_console_on_shows_its_entry_points(nd, ui):
    assert nd.get("/api/health")["sql_console"] is True
    page = open_app(ui("desktop"), "#watch")
    expect(page.locator("html")).to_have_attribute("data-sql-console", "on")
    page.locator("#gear-btn").click()
    expect(page.locator('#gear-menu a[href="#explorer"]')).to_be_visible()
    assert "go.explorer" in page.evaluate(COMMANDS)
    page.evaluate("location.hash = '#explorer'")
    expect(page.locator("#view-explorer .ex-ta")).to_be_visible()
    expect(page.locator("#view-explorer .ex-pnl-table .panel-badge")).not_to_have_text("—")   # the first query ran
    page.evaluate("location.hash = '#settings/about'")
    expect(page.locator(".set-about")).to_contain_text("SQL console")
    expect(page.locator(".set-about")).to_contain_text("On: read-only SQL")
    # Help and the tour point at it as before
    page.evaluate("location.hash = '#help/guides/sql'")
    expect(page.locator(".help-steps")).to_contain_text("Open it from the gear menu or")
    expect(page.get_by_role("button", name="Open SQL console")).to_be_visible()
    page.keyboard.press("Escape")
    page.evaluate("location.hash = '#explorer'")
    expect(page.locator("#view-explorer .ex-ta")).to_be_visible()
    card = start_tour(page)
    expect(card).to_contain_text("analyst workbench")
    page.keyboard.press("Escape")


@pytest.mark.parametrize("form", ["desktop", "phone"])
def test_console_off_hides_it_and_explains(nd, ui, form):
    page = ui(form)
    console_off(page)
    sql_calls = []
    page.on("request", lambda r: r.url.endswith("/api/sql") and sql_calls.append(r.url))
    open_app(page, "#watch")
    expect(page.locator("html")).to_have_attribute("data-sql-console", "off")
    assert "go.explorer" not in page.evaluate(COMMANDS)
    if form == "desktop":
        page.locator("#gear-btn").click()
        expect(page.locator("#gear-menu")).to_be_visible()
        expect(page.locator('#gear-menu a[href="#explorer"]')).to_be_hidden()
        page.keyboard.press("Escape")
    else:
        page.locator('#m-tabbar [data-tab="more"]').tap()
        sheet = page.locator(".m-more-sheet")
        expect(sheet).to_contain_text("Settings")
        expect(sheet.locator('[data-go="#explorer"]')).to_have_count(0)
        page.keyboard.press("Escape")
    # a deep link to the console (an old pivot link) lands on the explanation, and nothing asks /api/sql
    page.evaluate("location.hash = '#explorer/find?q=198.51.100.7'")
    view = page.locator("#view-explorer")
    expect(view).to_contain_text(OFF)
    expect(view.locator(".ex-ta")).to_have_count(0)
    page.evaluate("location.hash = '#settings/about'")
    expect(page.locator(".set-about")).to_contain_text("Off. Start Night Desk with OSINTHUB_SQL_CONSOLE=1")
    page.evaluate("location.hash = '#settings/data'")
    expect(page.locator("#view-settings")).to_contain_text("Bring your own data")
    expect(page.locator('#view-settings a[href="#explorer"]')).to_be_hidden()
    # Help and the tour say it is off instead of pointing at it
    page.evaluate("location.hash = '#help/guides/sql'")
    steps = page.locator(".help-steps")
    expect(steps).to_contain_text("It is off now. The SQL console is off. Start Night Desk with OSINTHUB_SQL_CONSOLE=1")
    expect(steps).not_to_contain_text("Open it from the gear menu")
    expect(page.get_by_role("button", name="Open SQL console")).to_have_count(0)
    page.evaluate("location.hash = '#help/glossary/sql-console'")
    term = page.locator("#help-g-sql-console")
    expect(term).to_be_visible()
    expect(term.locator('a[href^="#explorer"]')).to_have_count(0)
    expect(term.locator('a[href="#help/guides/sql"]')).to_have_count(1)
    page.keyboard.press("Escape")
    page.evaluate("location.hash = '#explorer'")
    expect(page.locator("#view-explorer .ex-off")).to_be_visible()
    card = start_tour(page)
    expect(card).to_contain_text(OFF)
    expect(card).not_to_contain_text("gear menu")
    page.keyboard.press("Escape")
    # the Ops panels that used to ask the console (KEV marks, ASN names) now use their own GETs
    page.evaluate("location.hash = '#ops'")
    page.wait_for_timeout(1500)
    assert sql_calls == [], sql_calls


def test_a_real_server_started_off(nd, ui, run_dir):
    """A server started without the variable (ND_SQL_CONSOLE=0): health says off, /api/sql is 403, the page hides it."""
    import server

    lake = run_dir / "lake-off"
    lake.mkdir()
    port = server.pick_port("0")
    old = os.environ.get("ND_SQL_CONSOLE")
    os.environ["ND_SQL_CONSOLE"] = "0"
    try:
        proc = server.start(lake, port, run_dir / "server-off.log", ttl=300)
    finally:
        if old is None:
            os.environ.pop("ND_SQL_CONSOLE")
        else:
            os.environ["ND_SQL_CONSOLE"] = old
    base = f"http://127.0.0.1:{port}"
    try:
        server.wait_healthy(base, proc)
        with urllib.request.urlopen(base + "/api/health") as r:
            assert json.load(r)["sql_console"] is False
        req = urllib.request.Request(base + "/api/sql", data=b'{"sql": "SELECT 1"}', method="POST",
                                     headers={"Content-Type": "application/json", "Origin": base})
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req)
        assert e.value.code == 403 and json.loads(e.value.read())["detail"] == OFF
        page = ui("desktop", base=base)
        open_app(page, "#explorer")
        expect(page.locator("#view-explorer")).to_contain_text(OFF)
        expect(page.locator("html")).to_have_attribute("data-sql-console", "off")
        page.locator("#gear-btn").click()
        expect(page.locator("#gear-menu")).to_be_visible()
        expect(page.locator('#gear-menu a[href="#explorer"]')).to_be_hidden()
    finally:
        server.stop(proc, port)
