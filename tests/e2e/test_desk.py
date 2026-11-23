"""Desk journeys: Settings (sources, inbox folder, routing watch), notes, and Ops on a computer and a phone."""
from __future__ import annotations

from pathlib import Path

import pytest
from journey import action_bar, more_tab, open_app, path_of, sheet, toast, wait_path
from playwright.sync_api import expect

STORY = "APT28 exploits ExampleGate zero-day CVE-2026-1111"
STORY_ID = "story:e2e-art-1"


def _enabled(nd, sid):
    return next(s for s in nd.get("/api/sources") if s["id"] == sid)["enabled"]


def test_settings_sources_toggle_persists(nd, ui):
    """Settings › Sources: the first visit asks which sources to use; after choosing, turning one source off and on
    again is saved (after a reload too) and nothing is fetched (offline)."""
    page = open_app(ui("desktop"), "#settings/sources")
    view = page.locator(".view.active")
    use = view.get_by_role("button", name="Use the ticked sources")
    if use.count():                                   # the first-run chooser (only once per lake)
        box = view.locator('input[type="checkbox"][value="cins_army"]')
        if not box.is_checked():
            box.check()
        use.click()
        nd.wait_for(lambda: _enabled(nd, "cins_army"), what="the ticked source turned on")
        expect(use).to_be_hidden()
    card = view.locator('.src-card[data-id="cins_army"]')
    expect(card).to_be_visible()
    before = _enabled(nd, "cins_army")
    card.locator("label.src-toggle").click()
    nd.wait_for(lambda: _enabled(nd, "cins_army") is (not before), what="the toggle saved on the server")
    page.reload()
    card = page.locator('.view.active .src-card[data-id="cins_army"]')
    expect(card.locator('input[data-act="toggle"]')).to_be_checked(checked=not before)
    card.locator("label.src-toggle").click()
    nd.wait_for(lambda: _enabled(nd, "cins_army") is before, what="the toggle back on the server")
    expect(card.locator('input[data-act="toggle"]')).to_be_checked(checked=before)
    assert nd.get("/api/health")["offline"] is True


def test_settings_inbox_folder_change_and_reset(nd, ui):
    """Connect logs › Just files: point the inbox at another folder (kept after a reload), refuse a system folder
    with a plain reason, then go back to the default folder."""
    alt = Path(nd.run_dir) / "inbox-alt"
    alt.mkdir(exist_ok=True)
    page = open_app(ui("desktop"), "#network/import")
    view = page.locator(".view.active")
    view.locator(".connect-pick", has_text="Just files").click()
    view.locator("details.finbox-change > summary").click()
    field = view.locator("#finbox-path")
    save = view.get_by_role("button", name="Save folder")
    field.fill("/usr")
    save.click()
    expect(view.locator("#finbox-err")).to_contain_text("system folder")
    field.fill(str(alt))
    save.click()
    toast(page, "Inbox folder saved")
    expect(view.locator("#finbox-err")).to_have_text("")
    real = str(alt.resolve())
    nd.wait_for(lambda: nd.get("/api/netlog/inbox")["path"] == real, what="the new inbox folder on the server")
    page.reload()
    view.locator(".connect-pick", has_text="Just files").click()
    expect(view.locator(".finbox-where")).to_contain_text(real)
    view.locator("details.finbox-change > summary").click()
    view.get_by_role("button", name="Use the default folder").click()
    nd.wait_for(lambda: nd.get("/api/netlog/inbox")["is_default"], what="the default folder back")
    expect(view.locator(".finbox-where")).not_to_contain_text(real)


def test_settings_routing_watch_add_remove(nd, ui):
    """Settings › Sources › Routing watch: a documentation AS number is refused with the reason; a preset network is
    watched (kept after a reload) and then removed. Offline mode: nothing is looked up."""
    page = open_app(ui("desktop"), "#settings/sources")
    page.on("dialog", lambda d: d.accept())
    view = page.locator(".view.active")
    expect(view).to_contain_text("Offline mode is on, so nothing is checked.")
    view.locator("#rw-in").fill("AS64500")
    view.locator("button.rw-go").click()
    expect(view.get_by_text("reserved for documentation").first).to_be_visible()
    assert not nd.get("/api/routing")["watchlist"]
    view.locator("button.rw-preset", has_text="Quad9 AS19281").click()
    watched = lambda: [w for w in nd.get("/api/routing")["watchlist"] if "19281" in str(w)]   # noqa: E731
    nd.wait_for(watched, what="the watch on the server")
    card = view.locator(".rw-card", has_text="AS19281")
    expect(card).to_be_visible()
    page.reload()
    card = page.locator(".view.active .rw-card", has_text="AS19281")
    expect(card).to_contain_text("Not checked yet")
    card.locator("button.rw-rm").click()
    nd.wait_for(lambda: not watched(), what="the watch removed on the server")
    expect(card).to_be_hidden()


def _notes(nd):
    return nd.get("/api/notes", kind="story", item=STORY_ID).get("notes", [])


@pytest.mark.parametrize("form", ["desktop", "phone"])
def test_notes_create_edit_delete(nd, ui, form):
    """A note on a story: write it on the story page, find it in Notes, edit it, delete it (a confirm sheet on a
    phone, then Undo brings it back)."""
    text, edited = f"E2E note from the {form}", f"E2E note from the {form}, edited"
    for n in _notes(nd):
        if n["body"].startswith(f"E2E note from the {form}"):
            nd.delete(f"/api/notes/{n['id']}")
    page = open_app(ui(form), f"#news/story/{STORY_ID}")
    view = page.locator(".view.active")
    expect(view).to_contain_text(STORY)
    if form == "phone":
        action_bar(page).get_by_role("button", name="Add note").tap()
        sh = sheet(page, "note")
        sh.locator("textarea").fill(text)
        sh.get_by_role("button", name="Add note").tap()
        expect(sh).to_be_hidden()
    else:
        view.locator("textarea.notes-ta").fill(text)
        view.get_by_role("button", name="Add note").click()
    nd.wait_for(lambda: any(n["body"] == text for n in _notes(nd)), what="the note on the server")

    if form == "phone":
        page.locator(".m-tb-back").tap()                  # a pushed page has an action bar, not the tab bar
        wait_path(page, r"^#news$")
        more_tab(page, "Notes")
        wait_path(page, r"^#notes")
        expect(page.locator(".notes-m-it", has_text=text)).to_be_visible()
        page.locator(".notes-m-it", has_text=text).tap()
        sh = sheet(page, "note")
        sh.locator("textarea").fill(edited)
        sh.get_by_role("button", name="Save").tap()
        nd.wait_for(lambda: any(n["body"] == edited for n in _notes(nd)), what="the edit on the server")
        page.locator(".notes-m-it", has_text=edited).tap()
        sheet(page, "note").get_by_role("button", name="Delete").tap()
        conf = sheet(page, "confirm")
        expect(conf).to_contain_text("Delete this note?")
        conf.get_by_role("button", name="Delete").tap()
        toast(page, "Note deleted")
        nd.wait_for(lambda: not any(n["body"] == edited for n in _notes(nd)), what="the note deleted")
        expect(page.locator(".notes-m-it", has_text=edited)).to_have_count(0)
        page.locator(".m-toasts .m-toast button", has_text="Undo").tap()
        nd.wait_for(lambda: any(n["body"] == edited for n in _notes(nd)), what="Undo to bring the note back")
        expect(page.locator(".notes-m-it", has_text=edited)).to_be_visible()
        return
    expect(view.locator(".notes-it", has_text=text)).to_be_visible()
    page.goto("/#notes")
    group = page.locator(".view.active a.notes-gt", has_text=STORY)
    expect(page.locator(".view.active").get_by_text(text)).to_be_visible()
    group.click()                                         # the note's item opens from Notes
    wait_path(page, r"^#news/story/")
    row = page.locator(".view.active .notes-it", has_text=text).first
    row.get_by_role("button", name="Edit").click()
    row.locator("textarea").fill(edited)
    row.get_by_role("button", name="Save").click()
    nd.wait_for(lambda: any(n["body"] == edited for n in _notes(nd)), what="the edit on the server")
    row = page.locator(".view.active .notes-it", has_text=edited).first
    row.get_by_role("button", name="Delete").click()
    expect(row).to_contain_text("Delete this note?")
    row.get_by_role("button", name="Delete", exact=True).click()
    toast(page, "Note deleted")
    nd.wait_for(lambda: not any(n["body"] == edited for n in _notes(nd)), what="the note deleted")
    expect(page.locator(".view.active .notes-it", has_text=edited)).to_have_count(0)


def test_ops_desktop_grid(demo, ui):
    """Ops on a computer: the deck's panels are laid out in the grid; the network panel counts the demo alert."""
    page = open_app(ui("desktop"), "#ops")
    items = page.locator("#grid .grid-stack-item")
    expect(items.first).to_be_visible()
    assert items.count() >= 6, items.count()
    expect(page.locator('#grid .grid-stack-item[gs-id^="net-attention"]')).to_contain_text("demo")
    expect(page.locator('#grid .grid-stack-item[gs-id^="news-wire"]')).to_contain_text("Offline mode is on")
    expect(page.locator("#subbar .vh-title")).to_have_text("Ops")
    expect(page.locator("#deck-name")).not_to_be_empty()
    # the world-map panel's MapLibre canvas painted and its event-markers layer was added (a broken paint expression throws in addOverlays before wm-pts, failing here)
    page.wait_for_function("""() => { const i = document.querySelector('#grid .grid-stack-item[gs-id^="world-map"]'); const h = i && [i, ...i.querySelectorAll('*')].find((n) => n.__wm); const m = h && h.__wm.map; return !!(m && m.isStyleLoaded() && m.getLayer('wm-pts') && i.querySelector('canvas.maplibregl-canvas')); }""")
    page.reload()
    expect(page.locator("#grid .grid-stack-item")).to_have_count(items.count())


def test_ops_phone_summary(nd, demo, ui):
    """Ops on a phone (from More): a summary of cards, not the grid; a card opens full screen and Back returns."""
    page = open_app(ui("phone"), "#watch")
    more_tab(page, "Ops")
    wait_path(page, r"^#ops$")
    view = page.locator(".view.active")
    expect(view).to_contain_text("Needs attention")
    expect(view).to_contain_text("demo alert")
    expect(view.locator("a.ops-m-row", has_text=STORY)).to_be_visible()
    expect(page.locator("#grid .grid-stack-item:visible")).to_have_count(0)
    view.get_by_role("link", name="Open Latest news full screen").tap()
    page.wait_for_function("location.hash.includes('panel=news-wire')")
    expect(page.locator(".view.active").get_by_text(STORY).first).to_be_visible()
    page.go_back()
    page.wait_for_function("!location.hash.includes('panel=')")
    assert path_of(page) == "#ops"
    expect(view).to_contain_text("Latest news")


def test_logo_icon_starts_the_tour_and_the_name_goes_home(nd, ui):
    page = open_app(ui("desktop"), "#news")
    page.locator(".topbar .brand .brand-mark").click()
    expect(page.locator(".tour-root")).to_be_visible()
    assert path_of(page) == "#news", "the icon tours the page on screen, it does not navigate"
    page.locator(".tour-root").get_by_role("button", name="Skip").click()
    expect(page.locator(".tour-root")).to_have_count(0)
    page.locator(".topbar .brand .brand-name").click()
    wait_path(page, "^#watch")
    expect(page.locator(".tour-root")).to_have_count(0)


def test_settings_ai_downloads_nothing_until_asked(nd, ui):
    """Settings › AI: search and chat start off. On a Mac with Apple silicon the search form shows the model with its
    size, and in offline mode it says nothing can be downloaded and keeps the button off; elsewhere it explains why.
    The chat form offers the built-in helper, Ollama, LM Studio and another server, and Cancel leaves chat off.
    Nothing is downloaded, started or saved either way."""
    page = open_app(ui("desktop"), "#settings/ai")
    sbox = page.locator(".view.active .set-ai-search")
    cbox = page.locator(".view.active .set-ai-chat")
    st = nd.get("/api/ai/setup")
    assert st["enabled"] is False and st["job"]["running"] is False and st["chat"]["via"] is None
    expect(cbox).to_contain_text("Off.")
    if st["why_not"]:
        expect(sbox).to_contain_text(st["why_not"])
    else:
        sbox.get_by_role("button", name="Turn on…").click()
        form = sbox.locator(".set-ai-form")
        expect(form).to_contain_text("Search model")
        expect(form.locator(".set-ai-plan")).to_contain_text("Offline mode is on")
        expect(form.locator(".set-ai-go")).to_be_disabled()
        form.get_by_role("button", name="Cancel").click()
        expect(sbox.get_by_role("button", name="Turn on…")).to_be_visible()
    cbox.get_by_role("button", name="Set up chat…").click()
    form = cbox.locator(".set-ai-form")
    for name in ("Built-in (this Mac)", "Ollama", "LM Studio", "Another server"):
        expect(form.get_by_text(name, exact=True)).to_be_visible()
    form.locator("input[name=via][value=other]").check()
    expect(form.locator("input[name=url]")).to_be_visible()
    expect(form.locator("input[name=key]")).to_have_attribute("type", "password")
    form.get_by_role("button", name="Cancel").click()
    expect(cbox.get_by_role("button", name="Set up chat…")).to_be_visible()
    st = nd.get("/api/ai/setup")
    assert st["job"]["running"] is False and st["chat"]["via"] is None


def test_settings_saved_under_the_old_name_carry_over(ui):
    """A browser that saved settings under the project's old name (localStorage "vantage.*") keeps them: on load
    web/js/core/storage-names.js moves them to "nd.*", and the app reads them there (the Ops deck chosen earlier)."""
    page = ui("desktop")
    page.context.add_init_script("try { if (!sessionStorage.getItem('seeded')) { sessionStorage.setItem('seeded', '1');"
                                 " localStorage.setItem('vantage.deck', JSON.stringify('Vulnerabilities'));"
                                 " localStorage.setItem('vantage.explorer.sql', JSON.stringify('SELECT 42')); } } catch (e) {}")
    open_app(page, "#ops")
    got = page.evaluate("() => [localStorage.getItem('nd.deck'), localStorage.getItem('nd.explorer.sql'),"
                        " Object.keys(localStorage).filter((k) => k.startsWith('vantage.'))]")
    assert got == ['"Vulnerabilities"', '"SELECT 42"', []]
    expect(page.locator("#deck-name")).to_have_text("Vulnerabilities")
