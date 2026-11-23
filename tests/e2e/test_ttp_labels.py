"""ATT&CK techniques read from article text say how sure they are (okf/data/entities.md#technique-labels): the story
with a stored extraction (tests/e2e/fixtures/news.json, e2e-art-4) shows one technique of each label, each with the
sentence it came from on a click or tap (never on hover or focus); the exports carry named and likely ones only, with their confidence; the
Intel strip labels article techniques and keeps MITRE's own catalogue link (APT28 uses T1566.001) confirmed, even
though e2e-art-1 reports it too; every other place an article technique link shows (actors table, reported
relationships, the entity panel, a technique's own page) carries the same label; Esc closes only the card."""
from __future__ import annotations

import json
import re

from journey import focus_settled, open_app
from playwright.sync_api import expect

STORY = "#news/story/story:e2e-art-4"
CAVEAT = "Found automatically from the text. They can be wrong; check the sentence each one came from."


def test_story_page_labels_sentences_and_exports(nd, ui):
    page = open_app(ui("desktop"), STORY)
    sec = page.locator("#nw-ttps")
    expect(sec).to_contain_text("Techniques read from this article")
    expect(sec).to_contain_text(CAVEAT)
    assert sec.locator(".nw-ttpk").all_inner_texts() == ["NAMED IN THE ARTICLE", "LIKELY", "POSSIBLE"]
    for tid, kind in (("T1566.001", "named"), ("T1505.003", "likely"), ("T1071.001", "likely"), ("T1552.001", "possible")):
        expect(sec.locator(f".nw-ttpg.k-{kind} [data-ttp='{tid}']")).to_have_count(1)
    expect(sec).not_to_contain_text("T1566.001 T1566.001")          # the catalogue name's leading id is not repeated
    tip = page.locator("#ttp-tip")
    sec.locator("[data-ttp='T1505.003'] a").hover()                  # pointing at a technique opens nothing
    page.wait_for_timeout(400)
    expect(tip).to_be_hidden()
    sec.locator("[data-ttp='T1505.003'] [data-ttp-ev]").click()
    expect(tip).to_be_visible()
    expect(tip).to_contain_text("Likely")
    expect(tip).to_contain_text("dropped a small web shell on the firm's internet-facing mail server")
    sec.locator("[data-ttp='T1071.001'] [data-ttp-ev]").click()       # no sentence stored for this one
    expect(tip).to_contain_text("No sentence was kept for this one")
    sec.locator("[data-ttp='T1566.001'] [data-ttp-ev]").click()
    expect(tip).to_contain_text("Named in the article")
    expect(tip).to_contain_text("the delivery method MITRE ATT&CK lists as T1566.001.")

    with page.expect_download() as d:
        sec.locator("[data-x='layer']").click()
    layer = json.loads(open(d.value.path()).read())
    assert {t["techniqueID"]: (t["score"], t["comment"]) for t in layer["techniques"]} == {
        "T1566.001": (85, "Named in the article"), "T1505.003": (50, "Likely — found automatically"),
        "T1071.001": (50, "Likely — found automatically")}
    with page.expect_download() as d:
        page.locator(".view.active [data-x='stix']").first.click()
    pats = {o["name"]: o for o in json.loads(open(d.value.path()).read())["objects"] if o["type"] == "attack-pattern"}
    assert set(pats) == {"T1566.001", "T1505.003", "T1071.001"}, "possible techniques stay out of STIX"
    assert pats["T1566.001"]["confidence"] == 85 and "Named in the article" in pats["T1566.001"]["description"]
    assert pats["T1505.003"]["confidence"] == 50 and "can be wrong" in pats["T1505.003"]["description"]


def test_phone_story_tap_shows_the_sentence(nd, ui):
    page = open_app(ui("phone"), STORY)
    acc = page.locator(".m-acc[data-acc='ttps']")
    expect(acc).to_contain_text("1 named · 2 likely · 1 possible")
    acc.locator(".m-acc-q").tap()
    expect(acc).to_contain_text(CAVEAT)
    chip = acc.locator("[data-ttp='T1552.001']")
    chip.scroll_into_view_if_needed()
    chip.tap()
    tip = page.locator("#ttp-tip")
    expect(tip).to_be_visible()
    expect(tip).to_contain_text("Possible")
    expect(tip).to_contain_text("searched shared folders for spreadsheets")
    assert page.evaluate("document.documentElement.scrollWidth") <= 390


def test_entity_strip_labels_article_techniques_not_catalogue_ones(nd, ui):
    page = open_app(ui("desktop"), "#entities/malware:examplerat")
    strip = page.locator("#enp-attack")
    expect(strip).to_contain_text("1 likely · 1 possible")
    expect(strip.locator(".ak-c.k-likely[data-ttp='T1505.003']")).to_contain_text("likely")
    expect(strip.locator(".ak-c.k-possible[data-ttp='T1552.001']")).to_contain_text("possible")
    # APT28 uses T1566.001 is in MITRE's catalogue AND reported by e2e-art-1: it stays confirmed, scored 100
    page2 = open_app(ui("desktop"), "#entities/actor:apt28")
    strip2 = page2.locator("#enp-attack")
    expect(strip2.locator(".ak-c.conf")).to_contain_text("T1566.001")
    expect(strip2.locator(".ak-c.conf")).to_contain_text("also in 1 article")
    expect(strip2.locator("[data-ttp]")).to_have_count(0)               # MITRE's catalogue link gets no article label
    expect(strip2).to_contain_text("1 confirmed")
    expect(strip2).not_to_contain_text(re.compile(r"likely|possible|named in"))
    claims = page2.locator(".enp-claim", has_text="Spearphishing")
    expect(claims.first).to_be_visible()
    expect(claims.locator(".ttp-tag")).to_have_count(0)
    with page2.expect_download() as d:
        strip2.locator("[data-act2='nav']").click()
    layer = json.loads(open(d.value.path()).read())
    assert [(t["techniqueID"], t["score"]) for t in layer["techniques"]] == [("T1566.001", 100)]


def test_every_article_technique_link_carries_its_label(nd, ui):
    page = open_app(ui("desktop"), STORY)
    view = page.locator(".view.active")
    table = view.locator("table.nw-at")
    expect(table.locator(".ttp-tag.k-likely[data-ttp='T1505.003']")).to_have_text("likely")
    expect(table.locator(".ttp-tag.k-possible[data-ttp='T1552.001']")).to_have_text("possible")
    table.locator(".ttp-tag[data-ttp='T1552.001']").click()
    expect(page.locator("#ttp-tip")).to_contain_text("searched shared folders")
    table.locator("a.nw-chip", has_text="ExampleRAT").first.click()     # the entity panel
    panel = page.locator("aside.ep")
    expect(panel).to_have_class(re.compile(r"\bopen\b"))
    expect(panel.locator(".ttp-tag.k-possible")).to_have_count(1)
    expect(panel).not_to_contain_text("suggested")
    page.keyboard.press("Escape")
    # the APT28 story: the same catalogue link has no article label in the actors table
    page2 = open_app(ui("desktop"), "#news/story/story:e2e-art-1")
    t2 = page2.locator(".view.active table.nw-at")
    expect(t2).to_contain_text("Spearphishing Attachment")
    expect(t2.locator(".ttp-tag")).to_have_count(0)
    # the article's reported relationships
    page3 = open_app(ui("desktop"), "#news/article/e2e-art-4")
    rel = page3.locator(".view.active .nw-claims")
    expect(rel.locator(".ttp-tag.k-possible[data-ttp='T1552.001']")).to_have_count(1)
    # the technique's own page: "used by ExampleRAT" says possible, never "suggested"
    page4 = open_app(ui("desktop"), "#entities/technique:T1552.001")
    row = page4.locator(".enp-claim", has_text="ExampleRAT")
    expect(row.locator(".ttp-tag.k-possible")).to_have_text("possible")
    expect(page4.locator(".view.active")).not_to_contain_text(re.compile(r"\bsuggested\b"))


def test_escape_closes_only_the_card_and_keeps_focus(nd, ui):
    page = open_app(ui("desktop"), STORY)
    sec = page.locator("#nw-ttps")
    focus_settled(sec.locator("[data-ttp='T1505.003'] a"))
    page.keyboard.press("Tab")                                      # the chip's quote button
    btn = sec.locator("[data-ttp='T1505.003'] [data-ttp-ev]")
    expect(btn).to_be_focused()
    page.keyboard.press("Enter")                                    # pins the card
    tip = page.locator("#ttp-tip")
    expect(tip).to_be_visible()
    expect(btn).to_have_attribute("aria-expanded", "true")
    page.keyboard.press("Escape")
    expect(tip).to_be_hidden()
    expect(btn).to_be_focused()                                     # focus back on what opened it
    assert "e2e-art-4" in page.evaluate("location.hash"), "the story pane stays open"
    expect(sec).to_be_visible()
    page.keyboard.press("Escape")                                   # the next Esc is the view's again
    page.wait_for_function("!location.hash.includes('story')")


def test_phone_strip_first_tap_shows_the_card(nd, ui):
    page = open_app(ui("phone"), "#entities/malware:examplerat")
    cell = page.locator("#enp-attack [data-ttp='T1552.001']")
    cell.scroll_into_view_if_needed()
    expect(page.locator("#enp-attack .ak-cav")).to_contain_text("tap")
    cell.tap()
    tip = page.locator("#ttp-tip")
    expect(tip).to_be_visible()
    expect(tip).to_contain_text("searched shared folders")
    assert "malware:examplerat" in page.evaluate("location.hash"), "the first tap does not navigate"
    tip.get_by_role("link", name=re.compile("technique’s page")).tap()
    page.wait_for_function("location.hash.includes('technique')")


def test_copy_summary_keeps_the_labels(nd, ui):
    page = open_app(ui("desktop"), STORY)
    page.locator(".view.active").get_by_role("button", name="Copy summary").first.click()
    ta = page.locator(".notes-dlg-ta")
    expect(ta).to_have_value(re.compile(r"ATT&CK techniques named in the articles:\*\* T1566\.001 Spearphishing Attachment"))
    expect(ta).to_have_value(re.compile(r"likely \(found automatically; can be wrong\):\*\* T1071\.001 Web Protocols, T1505\.003 Web Shell"))
    expect(ta).to_have_value(re.compile(r"possible \(a guess by the local AI; often wrong\):\*\* T1552\.001 Credentials In Files"))


def test_escape_in_the_entity_panel_closes_only_the_card(nd, ui):
    page = open_app(ui("desktop"), STORY)
    page.locator(".view.active table.nw-at a.nw-chip", has_text="ExampleRAT").first.click()
    panel = page.locator("aside.ep")
    expect(panel).to_have_class(re.compile(r"\bopen\b"))
    tag = panel.locator(".ttp-tag.k-likely").first
    tag.click()
    tip = page.locator("#ttp-tip")
    expect(tip).to_be_visible()
    page.keyboard.press("Escape")
    expect(tip).to_be_hidden()
    expect(panel).to_have_class(re.compile(r"\bopen\b"))              # the panel under the card stays
    expect(tag).to_be_focused()
    tag.evaluate("e => e.blur()")
    focus_settled(tag)                                                # focus alone opens nothing ...
    expect(tip).to_be_hidden()
    page.keyboard.press("Enter")                                      # ... Enter does
    expect(tip).to_be_visible()
    page.keyboard.press("Escape")
    expect(tip).to_be_hidden()
    expect(panel).to_have_class(re.compile(r"\bopen\b"))
    page.keyboard.press("Escape")                                     # the next Esc is the panel's
    expect(panel).not_to_have_class(re.compile(r"\bopen\b"))
    assert "e2e-art-4" in page.evaluate("location.hash")
    # APT28's catalogue link: the panel's "also in N articles" is the server's count of every article reporting it
    page2 = open_app(ui("desktop"), "#news/story/story:e2e-art-1")
    page2.locator(".view.active table.nw-at a.nw-chip", has_text="APT28").first.click()
    expect(page2.locator("aside.ep")).to_contain_text("also in 1 article")


def test_the_card_opens_on_click_only_and_closes_on_scroll(nd, ui):
    page = open_app(ui("desktop"), STORY)
    page.set_viewport_size({"width": 1440, "height": 560})
    pane = page.locator(".view.active .nw-pane-body").first
    tip = page.locator("#ttp-tip")
    link = page.locator("#nw-ttps [data-ttp='T1071.001'] a")
    link.focus()                                                      # keyboard focus opens nothing
    link.hover()                                                      # nor does pointing at it
    page.wait_for_timeout(400)
    expect(tip).to_be_hidden()
    tag = page.locator(".view.active table.nw-at .ttp-tag").first
    tag.scroll_into_view_if_needed()
    tag.click()
    expect(tip).to_be_visible()
    top_of = lambda loc: loc.evaluate("e => e.getBoundingClientRect().top")  # noqa: E731
    assert top_of(tip) >= top_of(page.locator("header.topbar")) + page.locator("header.topbar").evaluate("e => e.offsetHeight") - 1
    pane.evaluate("p => p.scrollBy(0, 40)")                           # any scroll closes it; it never follows
    expect(tip).to_be_hidden()
    tag.click()
    expect(tip).to_be_visible()
    page.mouse.click(5, 300)                                          # a click elsewhere closes it too
    expect(tip).to_be_hidden()
    focus_settled(tag)
    page.keyboard.press("Enter")
    expect(tip).to_be_visible()
    page.keyboard.press("Escape")                                     # one Esc, focus stays on the label
    expect(tip).to_be_hidden()
    expect(tag).to_be_focused()
    assert "e2e-art-4" in page.evaluate("location.hash")


def test_phone_card_closes_on_scroll_and_never_covers_the_header(nd, ui):
    page = open_app(ui("phone"), "#entities/malware:examplerat")
    # a label low on the screen: its card must still fit on screen (fix round 3 final check)
    low = page.locator(".enp-claim .ttp-tag").first
    low.scroll_into_view_if_needed()
    page.evaluate("([y]) => { const t = document.querySelector('.enp-claim .ttp-tag'); window.scrollBy(0, t.getBoundingClientRect().top - y); document.querySelectorAll('*').forEach(e => { if (e.scrollHeight > e.clientHeight + 40 && /auto|scroll/.test(getComputedStyle(e).overflowY) && e.contains(t)) e.scrollTop += t.getBoundingClientRect().top - y; }); }", [700])
    low.tap()
    card = page.locator("#ttp-tip")
    expect(card).to_be_visible()
    box = card.bounding_box()
    head = page.evaluate("(() => { const h = document.querySelector('.m-topbar, header.topbar'); return h ? h.getBoundingClientRect().bottom : 0; })()")
    assert box["y"] >= head - 1 and box["y"] + box["height"] <= 844 + 1, (box, head)
    page.mouse.click(5, 120)
    expect(card).to_be_hidden()
    cell = page.locator("#enp-attack [data-ttp='T1552.001']")
    cell.scroll_into_view_if_needed()
    cell.tap()
    tip = page.locator("#ttp-tip")
    expect(tip).to_be_visible()
    page.evaluate("window.scrollBy(0, 120); document.querySelectorAll('*').forEach(e => { if (e.scrollHeight > e.clientHeight + 40 && getComputedStyle(e).overflowY !== 'visible') e.scrollTop += 120; })")
    expect(tip).to_be_hidden()


def test_technique_page_opened_directly_shows_the_card(nd, ui):
    page = open_app(ui("desktop"), "#entities/technique:T1552.001")    # a fresh tab, straight to the page
    tag = page.locator(".enp-claim", has_text="ExampleRAT").locator(".ttp-tag.k-possible")
    tag.click()
    tip = page.locator("#ttp-tip")
    expect(tip).to_be_visible()
    expect(tip).to_contain_text("Possible")


def test_desktop_card_never_covers_the_top_bar_or_leaves_the_pane(nd, ui):
    page = open_app(ui("desktop"), STORY)
    page.set_viewport_size({"width": 1440, "height": 600})
    pane = page.locator(".view.active .nw-pane-body").first
    card = page.locator("#ttp-tip")
    tags = page.locator(".view.active table.nw-at .ttp-tag")
    expect(tags.first).to_be_visible()                        # wait for the story to draw before counting
    tested = 0
    for k in range(min(1, tags.count())):
        t = tags.nth(k)
        ptop, pbot = pane.evaluate("p => [p.getBoundingClientRect().top, p.getBoundingClientRect().bottom]")
        for y in range(int(ptop) + 4, int(pbot) - 24, 5):      # the opener at every height in the pane, 5 px apart
            page.evaluate("([p, t, y]) => { p.scrollTop += t.getBoundingClientRect().top - y; }",
                          [pane.element_handle(), t.element_handle(), y])
            if abs(t.evaluate("e => e.getBoundingClientRect().top") - y) > 2:
                continue                                        # the pane cannot scroll that far
            tested += 1
            t.click()
            expect(card).to_be_visible()
            box = card.bounding_box()
            # never above the story pane's top (the top bar, banner and title rows are above it), never off screen
            assert box["y"] >= ptop - 1 and box["y"] + box["height"] <= 600 + 1, (k, y, box, ptop)
            page.keyboard.press("Escape")
            expect(card).to_be_hidden()
    assert tested >= 10, f"only {tested} opener positions could be tested"
