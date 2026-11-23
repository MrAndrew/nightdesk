"""Intel journeys: news to a story, its article and an entity and back; global search; the Help desk; the entity
graph with every link type switched off."""
from __future__ import annotations

import re

import pytest
from journey import action_bar, more_tab, open_app, path_of, wait_path
from playwright.sync_api import expect

FORMS = ["desktop", "phone"]
STORY = "APT28 exploits ExampleGate zero-day CVE-2026-1111"      # tests/e2e/fixtures/news.json


@pytest.mark.parametrize("form", FORMS)
def test_news_story_article_entity_and_back(nd, ui, form):
    """News: the two reports on one campaign are one story; open it, read the lead article, open APT28 from the
    article text (a side panel on a computer, its own page on a phone), and come back to the story."""
    st = nd.get("/api/news/stories")["stories"]
    lead = next(s for s in st if s["title"] == STORY)
    assert lead["article_count"] == 2
    page = open_app(ui(form), "#news")
    view = page.locator(".view.active")
    card = view.locator(".nw-m-card" if form == "phone" else ".nw-card", has_text=STORY).first
    expect(card).to_contain_text("APT28")
    card.click()
    wait_path(page, r"^#news/story/")
    expect(view).to_contain_text("Northwind Security Blog")
    (action_bar(page) if form == "phone" else view).get_by_role("button", name="Read lead article").click()
    wait_path(page, r"^#news/article/e2e-art-1$")
    expect(view).to_contain_text("planted a web shell")
    view.locator("a.nw-hl.e-act", has_text="APT28").first.click()
    if form == "phone":
        wait_path(page, r"^#entities/actor:apt28$")
        # a phone shows the first six names in the reference's own order; Fancy Bear is MITRE's eighth
        view.locator(".enp-alias.more").click()
        expect(view).to_contain_text("Fancy Bear")                    # the alias from the ATT&CK/MISP reference
        expect(view).to_contain_text("Russian Federation")
        page.go_back()                                                # the system Back gesture
        wait_path(page, r"^#news/article/e2e-art-1$")
        back = page.locator(".m-tb-back")
        expect(back).to_have_text("Story")
        back.click()
    else:
        panel = page.locator("aside.ep")
        expect(panel).to_have_class(re.compile(r"\bopen\b"))
        expect(panel).to_contain_text("Fancy Bear")
        assert path_of(page) == "#news/article/e2e-art-1"             # a panel over the article, not a new page
        page.keyboard.press("Escape")
        expect(panel).not_to_have_class(re.compile(r"\bopen\b"))
        page.go_back()
    wait_path(page, r"^#news/story/story(%3A|:)e2e-art-1$")
    expect(view).to_contain_text(STORY)


@pytest.mark.parametrize("form", FORMS)
def test_global_search_result_and_back(nd, ui, form):
    """Search everything from Watch: APT28 finds the actor, the story and both articles; a result opens the story,
    Back returns to where the search started."""
    page = open_app(ui(form), "#watch")
    if form == "phone":
        page.locator(".m-tb-search, #gs-open").first.tap()
    else:
        page.keyboard.press("/")
        expect(page.locator("#global-search")).to_be_focused()
    page.locator("#global-search").fill("APT28")
    drop = page.locator("#gs-list")
    expect(drop.locator("a.search-entity", has_text="APT28")).to_be_visible()
    expect(drop.locator("a.search-article")).to_have_count(2)
    drop.locator("a.search-story", has_text=STORY).click()
    wait_path(page, r"^#news/story/")
    expect(page.locator(".view.active")).to_contain_text(STORY)
    page.go_back()
    page.wait_for_function("!location.hash.startsWith('#news')")
    assert re.match(r"^#(watch|search)", path_of(page)), path_of(page)
    expect(page.locator('.view.active[data-view="watch"]')).to_be_visible()


@pytest.mark.parametrize("form", FORMS)
def test_help_desk_open_close_and_glossary(nd, ui, form):
    """Help: opens from ? (More on a phone), closes with × and with Esc / Back, finds a glossary term by search."""
    page = open_app(ui(form), "#news")
    close = page.locator(".help-x")
    if form == "phone":
        more_tab(page, "Help")
    else:
        page.locator("#help-btn").click()
    expect(close).to_be_visible()
    close.click()
    expect(close).to_be_hidden()
    if form == "phone":
        more_tab(page, "Help")
        expect(close).to_be_visible()
        page.go_back()                                    # Back closes the sheet, the page stays
    else:
        page.keyboard.press("?")
        expect(close).to_be_visible()
        page.keyboard.press("Escape")
        expect(page.locator("#help-btn")).to_be_focused()   # focus goes back to where it was
    expect(close).to_be_hidden()
    assert path_of(page) == "#news"
    if form == "phone":
        more_tab(page, "Help")
    else:
        page.locator("#help-btn").click()
    page.get_by_placeholder(re.compile("Search help", re.I)).fill("command and control")
    hit = page.locator(".help-res", has_text="C2 (command and control)").first
    hit.click()
    expect(page.get_by_text("A server that criminals use to give orders").first).to_be_visible()


@pytest.mark.parametrize("form", FORMS)
def test_graph_every_link_type_off(nd, ui, form):
    """Entity graph: switching every link type off empties the side panel's link list (it lists exactly what is drawn)
    and shows an empty-state card on the canvas; its button turns the types back on, the links return and focus lands
    on the first link-type switch (desktop). Phone: the full-screen graph, the switches folded behind Controls."""
    page = open_app(ui(form), "#entities/graph/actor:apt28")
    card = page.locator(".gr-msg .gr-empty")
    switches = page.locator(".gr-origins [data-o]")
    if form == "phone":
        page.get_by_role("button", name="Open the graph").tap()
        page.locator(".gr-ctl").tap()
        for i in range(switches.count()):
            switches.nth(i).tap()
        page.locator(".gr-fold-x").tap()
    else:
        side = page.locator(".gr-side")
        expect(side.locator(".gs-links a", has_text="RU")).to_be_visible()   # the root's card: attributed to Russia
        for i in range(switches.count()):
            switches.nth(i).click()
            expect(switches.nth(i)).to_have_attribute("aria-pressed", "false")
        expect(side.locator(".gs-links a")).to_have_count(0)
        expect(side.locator(".gs-links")).to_contain_text("Every link type is switched off")
    expect(card).to_be_visible()
    expect(card).to_contain_text("Every link type is switched off")
    expect(card).to_contain_text("back on")
    expect(page.locator(".gr-legh")).to_contain_text("1/")                      # only the root is drawn
    button = card.get_by_role("button", name="Turn all link types on")
    if form == "phone":
        button.tap()
    else:
        button.focus()
        page.keyboard.press("Enter")
        expect(switches.first).to_be_focused()                                    # focus is not lost with the card
        expect(side.locator(".gs-links a", has_text="RU")).to_be_visible()
    expect(card).to_have_count(0)
    for i in range(switches.count()):
        expect(switches.nth(i)).to_have_attribute("aria-pressed", "true")
    expect(page.locator(".gr-legh")).not_to_contain_text("1/")
