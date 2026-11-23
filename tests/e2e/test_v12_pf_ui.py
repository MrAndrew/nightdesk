"""v1.2 pf-ui journey: the entity graph re-runs its layout only when what is drawn really changes. A filter switched off
and back on (the drawn set ends where it was) keeps the user's zoom and pan; a change that stays re-lays out once."""
from __future__ import annotations

import pytest
from journey import open_app

CY = "document.querySelector('.gr-cv')?._cyreg?.cy"   # the Cytoscape instance Cytoscape keeps on its container


@pytest.mark.parametrize("form", ["desktop"])
def test_graph_round_trip_keeps_zoom_and_a_real_change_relayouts(nd, ui, form):
    page = open_app(ui(form), "#entities/graph/actor:apt28")
    page.wait_for_function(f"() => {CY}?.nodes(':visible').length > 1")
    page.evaluate(f"""() => {{ const cy = {CY}; window.__lay = 0; window.__stop = 0;
        cy.on('layoutstart', () => window.__lay++); cy.on('layoutstop', () => window.__stop++); }}""")
    page.locator(".gr-hyp").click()                                    # a real change: lays out once
    page.wait_for_function("() => window.__lay >= 1 && window.__stop >= window.__lay")
    view = page.evaluate(f"() => {{ const cy = {CY}; cy.zoom(1.4); cy.pan({{ x: 120, y: -40 }}); window.__lay = 0;"
                         f" return [cy.zoom(), cy.pan().x, cy.pan().y, cy.elements(':visible').length]; }}")
    reported = page.locator('.gr-origins [data-o="reported"]')
    reported.click()                                                   # off ...
    reported.click()                                                   # ... and on again within the 180 ms wait
    # Asserting that nothing happens needs time to pass: well past the 180 ms the re-layout waits for.
    page.wait_for_timeout(700)
    after = page.evaluate(f"() => {{ const cy = {CY}; return [cy.zoom(), cy.pan().x, cy.pan().y, cy.elements(':visible').length]; }}")
    assert page.evaluate("() => window.__lay") == 0, "the graph re-ran its layout although the drawn set ended unchanged"
    assert after == view
    reported.click()                                                   # off and left off: the drawn set shrinks
    page.wait_for_function("() => window.__lay >= 1")
