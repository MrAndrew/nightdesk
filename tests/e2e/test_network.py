"""Network journeys: first run with the demo, logs from the inbox folder through triage, hunting, a device page."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from journey import action_bar, drop_zeek_conn, open_app, path_of, sheet, toast, undo, wait_path
from playwright.sync_api import expect

FORMS = ["desktop", "phone"]
HOME = "192.0.2.0/24"                       # the imported fixture's home network (RFC 5737)
BAD = {"desktop": "203.0.113.66", "phone": "203.0.113.67"}   # on the E2E list; one per form, so each starts fresh
LIST_NAME = "E2E test list"


@pytest.mark.parametrize("form", FORMS)
def test_first_run_load_demo_watch_shows_answer(nd, ui, form):
    """A first visit has no network data; loading the demo from Watch's checklist puts its alert on Watch, and it is
    still there after a reload."""
    if nd.get("/api/netlog/demo").get("loaded"):
        nd.delete("/api/netlog/demo")
    page = open_app(ui(form), "#watch")
    view = page.locator(".view.active")
    if form == "phone":
        expect(view).to_contain_text("No network logs yet")
        view.get_by_role("button", name="Try the demo").tap()
        expect(view).to_contain_text("1 demo alert (made-up) not counted")
        assert nd.get("/api/netlog/demo")["loaded"]
        page.reload()
        expect(view).to_contain_text("demo alert")
        view.get_by_role("link", name="Open the demo alerts").tap()
        wait_path(page, r"^#network/alerts$")
        expect(view.get_by_text("IoT camera beaconing").first).to_be_visible()
        return
    load = page.get_by_role("button", name="Load demo data")
    expect(load).to_be_visible()
    expect(view).not_to_contain_text("Remove demo data")
    load.click()
    toast(page, "Demo data loaded")
    assert nd.get("/api/netlog/demo")["loaded"]
    row = page.locator(".view.active a.watch-row", has_text="Demo-doorbell").first
    expect(row).to_be_visible()
    expect(row).to_contain_text("high")
    expect(row.locator(".watch-demo")).to_have_text("DEMO")
    page.reload()
    expect(page.locator(".view.active a.watch-row", has_text="Demo-doorbell").first).to_be_visible()
    expect(page.get_by_text("Remove demo data")).to_be_visible()
    row = page.locator(".view.active a.watch-row", has_text="Demo-doorbell").first
    row.click()
    wait_path(page, r"^#network/alerts/nl-")
    expect(page.locator(".view.active")).to_contain_text("IoT camera beaconing")


@pytest.fixture(scope="module")
def own_list(demo):
    """Home network 192.0.2.0/24 and a list of the two fixture addresses, set up the way a user would (API)."""
    nd = demo
    s = nd.get("/api/netlog/settings")
    prefs = list(dict.fromkeys((s.get("home_prefixes") or []) + [HOME, "10.86.24.0/24", "fd4e:6400:d35c::/48"]))
    nd.put("/api/netlog/settings", {"home_prefixes": prefs})
    if not any(x["name"] == LIST_NAME for x in nd.get("/api/netlog/lists")):
        nd.post("/api/netlog/lists", form={"name": LIST_NAME, "text": "\n".join(BAD.values())})
    return nd


def _alert_for(nd, ip):
    return next((a for a in nd.get("/api/netlog/alerts", limit=0) if a["indicator"] == ip), None)


@pytest.mark.parametrize("form", FORMS)
def test_inbox_import_alert_triage_and_undo(own_list, ui, form):
    """Drop a Zeek log in the inbox folder, scan it from Connect logs, see the alert, acknowledge it and take that
    back, then mark it as expected and take that back too. The server agrees at every step."""
    nd = own_list
    ip = BAD[form]
    inbox = Path(nd.get("/api/netlog/inbox")["path"])
    drop_zeek_conn(inbox, f"conn-{form}.log", "192.0.2.10", ip, uid=f"CE2E{form[0].upper()}")
    if form == "desktop":
        page = open_app(ui(form), "#network/import")
        page.locator(".view.active .connect-pick", has_text="Just files").click()
        page.get_by_role("button", name="Scan inbox now").click()
        # the folder watcher may have picked the file up first; either way it is imported exactly once
        toast(page, re.compile(r"Imported 1 file from the inbox|No new files in the inbox"))
        expect(page.locator(".finbox-counts")).to_contain_text(re.compile(r"[1-9]\d* imported"))
    else:
        # a phone's Connect logs only explains the setup (it is done on a computer); the folder is scanned there
        nd.post("/api/netlog/inbox/scan")
        page = open_app(ui(form), "#network/import")
        expect(page.locator(".view.active")).to_contain_text("Connect logs")
    a = nd.wait_for(lambda: _alert_for(nd, ip), what=f"an alert for {ip}")
    assert a["severity"] == "medium" and a["status"] == "new"
    assert nd.get("/api/netlog/inbox")["imported"] >= 1

    page.goto("/#network/alerts?range=all")
    row = page.locator(".view.active").get_by_text(f"contacted {ip}").first
    expect(row).to_be_visible()
    row.click()
    wait_path(page, r"^#network/alerts/.+")
    detail = page.locator(".view.active")
    expect(detail).to_contain_text(f"on your list '{LIST_NAME}'")
    status = lambda: nd.get(f"/api/netlog/alerts/{a['id']}")["status"]   # noqa: E731

    if form == "phone":
        bar = action_bar(page)
        bar.get_by_role("button", name="Acknowledge").tap()
        toast(page, "Alert acknowledged")
        nd.wait_for(lambda: status() == "ack", what="ack on the server")
        undo(page)
        nd.wait_for(lambda: status() == "new", what="Undo to put it back to new")
        expect(bar.get_by_role("button", name="Acknowledge")).to_be_visible()
        bar.get_by_role("button", name="This is expected…").tap()
        sh = sheet(page, "nv-expect")
        sh.get_by_role("button", name="Save rule").tap()
        toast(page, "Rule saved")
        nd.wait_for(lambda: len(nd.get("/api/netlog/rules")) == 1 and nd.get("/api/netlog/rules")[0]["indicator"] == ip,
                    what="the rule on the server")
        undo(page)
        nd.wait_for(lambda: not nd.get("/api/netlog/rules"), what="Undo to delete the rule")
    else:
        detail.get_by_role("button", name="✓ Acknowledge").click()
        toast(page, "Alert acknowledged")
        nd.wait_for(lambda: status() == "ack", what="ack on the server")
        detail.get_by_role("button", name="Reopen").click()          # desktop's way back
        toast(page, "Alert reopened")
        nd.wait_for(lambda: status() == "new", what="reopened on the server")
        detail.get_by_role("button", name="This is expected…").click()
        detail.locator('[data-form="expect"]').get_by_role("button", name="Save rule").click()
        toast(page, "Marked as expected")
        rules = nd.wait_for(lambda: [r for r in nd.get("/api/netlog/rules") if r["indicator"] == ip], what="the rule")
        page.once("dialog", lambda d: d.accept())
        detail.get_by_role("button", name="Stop treating as expected").first.click()
        nd.wait_for(lambda: not [r for r in nd.get("/api/netlog/rules") if r["id"] == rules[0]["id"]],
                    what="the rule deleted")
    page.reload()
    expect(page.locator(".view.active")).to_contain_text(f"on your list '{LIST_NAME}'")
    assert status() == "new"


def test_hunt_filter_zoom_and_zoom_out(demo, ui):
    """Search logs: a field filter narrows the rows, dragging across the timeline zooms the time range, Zoom out
    puts it back."""
    page = open_app(ui("desktop"), "#network/hunt?range=all")
    total = page.locator(".nv-total")
    expect(total).to_contain_text(re.compile(r"\d"))
    q = page.locator(".nv-qchips input")
    q.fill("log_type:dns")
    q.press("Enter")
    expect(page.locator(".nv-fc")).to_contain_text("dns")
    agg = demo.get("/api/netlog/aggregate", group="log_type", limit=50)
    n_dns = next(g["count"] for g in agg["groups"] if g["key"] == "dns")
    expect(total).to_contain_text(f"{n_dns:,}")
    rows = page.locator(".nv-ev tbody tr, .nv-ev .nv-crow")
    expect(rows.first).to_be_visible()
    expect(page.locator(".nv-ev")).not_to_contain_text("ssl")
    before = total.inner_text()
    box = page.locator(".nv-hh canvas").first.bounding_box()
    y = box["y"] + box["height"] * 0.5
    page.mouse.move(box["x"] + box["width"] * 0.3, y)
    page.mouse.down()
    page.mouse.move(box["x"] + box["width"] * 0.45, y, steps=8)
    page.mouse.move(box["x"] + box["width"] * 0.6, y, steps=8)
    page.mouse.up()
    zoom = page.locator(".nv-hist .panel-badge")
    expect(zoom).to_contain_text("Zoomed to")
    assert "range=" in page.evaluate("location.hash") and "range=all" not in page.evaluate("location.hash")
    expect(total).not_to_have_text(before)
    expect(page.locator(".nv-fc")).to_contain_text("dns")       # the filter survives the zoom
    zoom.get_by_role("button", name="Zoom out").click()
    expect(zoom).to_contain_text("drag to narrow")
    expect(total).to_have_text(before)


@pytest.mark.parametrize("form", FORMS)
def test_device_page_rename_persists(demo, ui, form):
    """Devices: open the demo laptop's page, rename it, see the new name after a reload and on the server, then
    give it its name back."""
    nd = demo
    dev = next(d for d in nd.get("/api/netlog/devices", limit=0) if "demo-laptop" in (d.get("hostnames") or []))
    new = f"E2E laptop {form}"
    page = open_app(ui(form), "#network/devices?range=all")
    page.locator(".view.active").get_by_text("demo-laptop", exact=False).first.click()
    wait_path(page, r"^#network/devices/mac")
    view = page.locator(".view.active")
    expect(view).to_contain_text("identified by MAC" if form == "phone" else "02:4e:44:00:00:21")
    if form == "phone":
        action_bar(page).get_by_role("button", name="Rename…").tap()
        sh = sheet(page, "nv-rename")
        sh.locator('input[name="name"]').fill(new)
        sh.get_by_role("button", name="Save").tap()
    else:
        view.get_by_role("button", name="Rename or set type").click()
        f = view.locator('form input[name="name"]')
        f.fill(new)
        f.press("Enter")
    nd.wait_for(lambda: nd.get(f"/api/netlog/devices/{dev['id']}").get("name") == new,
                what="the new name on the server")
    page.reload()
    expect(page.locator(".view.active")).to_contain_text(new)
    nd.call("PATCH", f"/api/netlog/devices/{dev['id']}", body={"name": ""})
    assert path_of(page).startswith("#network/devices/")
