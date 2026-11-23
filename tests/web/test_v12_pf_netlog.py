"""Network copy fixed before the public release (lane pf-netlog), checked in the source; the browser checks are in
tests/e2e/test_v12_pf_netlog.py.

    uv run --with pytest pytest tests/web/test_v12_pf_netlog.py -q
"""
from __future__ import annotations

import re
from pathlib import Path

NET = Path(__file__).resolve().parents[2] / "web" / "js"


def test_palette_finds_search_logs_for_hunt():
    shell = (NET / "core" / "shell.js").read_text()
    entry = re.search(r"\['go\.network\.hunt', 'Network › Search logs', '#network/hunt', '([^']*)'\]", shell)
    assert entry and "hunt" in entry.group(1).split()


def test_alert_list_span_has_no_one_day_fallback():
    alerts = (NET / "views" / "net" / "alerts.js").read_text()
    assert "'1 day'" not in alerts and "spanText(a)" in alerts
    text = (NET / "views" / "net" / "alert-text.js").read_text()
    assert "'one contact'" in text


def test_expected_sheet_never_says_alert_alert():
    m = (NET / "views" / "net" / "m-alerts.js").read_text()
    assert "String(k.kindLabel || 'matching').toLowerCase()" not in m      # "intrusion alert" + " alert"
    assert "kindWordOf(k.kindLabel)" in m
    assert ": d.indicator;" not in m.split("export function expectSheet", 1)[1].split("\n}\n", 1)[0].replace(
        "noun === 'signature' ? 'this intrusion signature' : d.indicator;", "")   # no raw sid for a nameless signature


def test_a_nameless_signature_is_never_shown_by_its_placeholder():
    text = (NET / "views" / "net" / "alert-text.js").read_text()
    assert "export const NO_SIG = '(no signature)';" in text and "n === NO_SIG ? ''" in text
    assert "'this intrusion signature'" in text and "sig(a)" not in text
    alerts = (NET / "views" / "net" / "alerts.js").read_text()
    assert "esc(sigQuoted(d))" in alerts and "“${esc(sigName(d))}”" not in alerts
