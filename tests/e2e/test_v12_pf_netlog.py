"""Network copy before the public release (v1.2 pre-public lane pf-netlog), on the demo's one-contact IDS alert:
its span is true for one contact (list and detail), the "This is expected" form and phone sheet name the signature in
plain words (no raw "sid:…", never "alert alert"), and the command palette finds Search logs for "hunt".

    uv run --with playwright --with pytest pytest tests/e2e/test_v12_pf_netlog.py -q
"""
from __future__ import annotations

import json
import re
import time

import pytest
from journey import open_app
from playwright.sync_api import expect

FORMS = ["desktop", "phone"]
RAW_SID = re.compile(r"\bsid:\s*\d", re.I)


def _ids_alert(nd) -> dict:
    a = next((x for x in nd.get("/api/netlog/incidents", limit=0) if x["rule"] == "ids_signature"), None)
    assert a, "the demo's Suricata alert is missing"
    assert a["count"] == 1 and a["days"] == 1, a   # one contact on one day: the case this lane fixes
    return a


@pytest.mark.parametrize("form", FORMS)
def test_one_contact_span_and_expected_wording(demo, ui, form):
    nd = demo
    a = _ids_alert(nd)
    page = open_app(ui(form), "#network/alerts")
    view = page.locator(".view.active")
    if form == "desktop":
        row = view.locator(f'.nv-arow[data-id="{a["id"]}"]')
        expect(row).to_be_visible()
        span = row.locator('span.nv-dim[title*="→"]')       # the Span column (its tooltip is first → last)
        expect(span).to_have_text("one contact")
        expect(row).not_to_contain_text("1 day")
    else:
        expect(view.get_by_text("IoT camera beaconing").first).to_be_visible()
        expect(view).not_to_contain_text("1 day")
    page.goto(f"/#network/alerts/{a['id']}")
    meta = view.locator(".al-meta")
    expect(meta).to_contain_text("1 contact")
    expect(meta).to_contain_text(re.compile(r"\bat \d"))      # the single time, not a from–to span
    assert "day" not in meta.inner_text()
    page.goto(f"/#network/alerts/{a['id']}/expected")
    if form == "desktop":
        box = view.locator('[data-form="expect"]')
    else:
        box = page.locator(".nv-m-exp")
        expect(box).to_be_visible()
        box.locator("[data-more]").tap()
        if box.locator("[data-sure]").count():
            box.locator("[data-sure]").tap()
        expect(box.locator('input[value="indicator"]')).to_be_attached()
    expect(box).to_contain_text("IoT camera beaconing to unknown C2")
    expect(box).to_contain_text("intrusion alert")
    text = box.inner_text()
    assert not re.search(r"\balerts?\s+alerts?\b", text, re.I), text
    assert not RAW_SID.search(text), text
    if form == "phone":   # the caution says what the chosen scope hides
        expect(box).to_contain_text("hides future alerts about the signature")
        box.locator('input[value="device_kind"]').check()
        expect(box).to_contain_text("hides future intrusion alerts from")


NAMELESS_SID = 2099777


def _nameless_alert(nd, page) -> dict:
    """An EVE alert whose rule has no signature name (Suricata leaves `signature` out), imported once."""
    def find():
        return next((x for x in nd.get("/api/netlog/incidents", limit=0) if x["indicator"] == f"sid:{NAMELESS_SID}"), None)
    if not find():
        ts = time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime(time.time() - 3600))
        line = json.dumps({"timestamp": ts, "event_type": "alert", "src_ip": "10.86.24.31", "src_port": 50123,
                           "dest_ip": "203.0.113.77", "dest_port": 443, "proto": "TCP", "flow_id": 990001,
                           "alert": {"signature_id": NAMELESS_SID, "severity": 2}})
        r = page.request.post(nd.base + "/api/netlog/import", headers={"Origin": nd.base},
                              multipart={"files": {"name": "eve.json", "mimeType": "application/json",
                                                   "buffer": (line + "\n").encode()}})
        assert r.ok, r.text()
    a = find()
    assert a, "the nameless signature raised no alert"
    return a


@pytest.mark.parametrize("form", FORMS)
def test_a_nameless_signature_reads_this_intrusion_signature(demo, ui, form):
    nd = demo
    page = ui(form)
    a = _nameless_alert(nd, page)
    open_app(page, f"#network/alerts/{a['id']}")
    view = page.locator(".view.active")
    expect(view.locator(".al-h")).to_contain_text("this intrusion signature has no name")
    for t in ("look its number up in your Suricata rules", "an alert from this intrusion signature"):
        expect(view).to_contain_text(t)
    assert "(no signature)" not in view.inner_text()
    page.goto(f"/#network/alerts/{a['id']}/expected")
    if form == "desktop":
        box = view.locator('[data-form="expect"]')
    else:
        box = page.locator(".nv-m-exp")
        expect(box).to_be_visible()
        box.locator("[data-more]").tap()
        if box.locator("[data-sure]").count():
            box.locator("[data-sure]").tap()
        expect(box.locator('input[value="indicator"]')).to_be_attached()
    expect(box).to_contain_text("this intrusion signature")
    text = box.inner_text()
    assert "(no signature)" not in text and "“”" not in text and not RAW_SID.search(text), text


def test_palette_finds_search_logs_for_hunt(nd, ui):
    page = open_app(ui("desktop"), "#watch")
    page.keyboard.press("ControlOrMeta+k")
    box = page.locator("#global-search")
    expect(box).to_be_focused()
    box.fill("hunt")
    expect(page.locator(".gs-item", has_text="Search logs").first).to_be_visible()
