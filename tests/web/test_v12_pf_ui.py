"""v1.2 pf-ui: small UI follow-ups before the repo goes public (no server, no lake).

* Primary text says "offline mode" and "the abuse.ch key" in plain words: the variable names OSINTHUB_OFFLINE,
  ABUSECH_AUTH_KEY and CLOUDFLARE_RADAR_TOKEN appear only in comments, hover titles (`title="…"`, a status line's `tech`), a "Technical details"
  block, or the Help guides and glossary (the reference pages the plain text points to).
* Top Offenders: the row your search matches is drawn in a colour apart from the tab's own bars, never red, and
  readable on the panel.
* The entity graph's date label keeps each date on one line; the graph re-runs its layout when what is drawn changes.

    uv run --with pytest pytest tests/web/test_v12_pf_ui.py -q
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
JS = ROOT / "web" / "js"
NAMES = ("OSINTHUB_OFFLINE", "ABUSECH_AUTH_KEY", "CLOUDFLARE_RADAR_TOKEN")
# How-to reference: the guide "Run it offline" and the glossary say which setting to use (the "technical details"
# the plain text elsewhere points to).
REFERENCE = {"help/guides.js", "help/glossary.js"}


def _code(src: str) -> str:
    """JS without comments (same rule as tests/web/test_client_lint.py)."""
    src = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), src, flags=re.S)
    return re.sub(r"(^|[^:'\"`\\])//[^\n]*", r"\1", src)


def _primary(line: str) -> str:
    """The line with what may name a setting taken out: hover titles, a `tech` field, Technical details blocks."""
    line = re.sub(r'title="[^"]*"', "", line)
    line = re.sub(r"\btech: '[^']*'", "", line)
    line = re.sub(r"<details\b.*?</details>", "", line)
    return line


def test_setting_names_stay_out_of_primary_text():
    bad = []
    for f in sorted(JS.rglob("*.js")):
        rel = f.relative_to(JS).as_posix()
        if "vendor" in f.parts or rel in REFERENCE:
            continue
        for n, line in enumerate(_code(f.read_text()).splitlines(), 1):
            if any(name in _primary(line) for name in NAMES):
                bad.append(f"web/js/{rel}:{n}: {line.strip()[:140]}")
    assert not bad, "a setting's name in primary text (say it in plain words; the name may go in a title or Technical details):\n" + "\n".join(bad)


def test_the_lint_catches_a_name_in_primary_text():
    assert any(n in _primary("detail: 'Restart without OSINTHUB_OFFLINE=1 to fetch.'") for n in NAMES)
    assert not any(n in _primary('<span title="the OSINTHUB_OFFLINE=1 setting">offline</span>') for n in NAMES)
    assert not any(n in _primary("detail: 'Nothing is fetched.', tech: 'OSINTHUB_OFFLINE=1'") for n in NAMES)


def test_server_texts_for_the_ui_name_no_setting():
    """Setup checklist, Watch briefing, demo readiness, AI setup and the abuse.ch sources: plain words; a `tech`
    hover string or a constant may hold the name."""
    files = ["osinthub/watch/setup.py", "osinthub/watch/briefing.py", "osinthub/netlog/demo.py", "osinthub/ai/setup.py"]
    for rel in files:
        for n, line in enumerate((ROOT / rel).read_text().splitlines(), 1):
            if line.lstrip().startswith("#") or re.match(r"\s*[A-Z_]+_TECH\s*=", line) or '"tech"' in line:
                continue
            assert not any(name in line for name in NAMES), f"{rel}:{n}: {line.strip()}"
    src = (ROOT / "osinthub/sources/abusech.py").read_text()
    for m in re.finditer(r'description = \((.*?)\)\n', src, re.S):
        assert "ABUSECH_AUTH_KEY" not in m.group(1)
    unavailable = re.search(r"def unavailable\(self\).*?return None", src, re.S).group(0)
    assert "KEY_ENV" not in unavailable and "ABUSECH_AUTH_KEY" not in unavailable


def _lum(hex_: str) -> float:
    c = [int(hex_.lstrip("#")[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]


def _contrast(a: str, b: str) -> float:
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def _lab(hex_: str) -> tuple[float, float, float]:
    r, g, b = (int(hex_.lstrip("#")[i:i + 2], 16) / 255 for i in (0, 2, 4))
    r, g, b = (c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in (r, g, b))
    x, y, z = ((0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047, 0.2126 * r + 0.7152 * g + 0.0722 * b,
               (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883)
    f = lambda t: t ** (1 / 3) if t > 0.008856 else 7.787 * t + 16 / 116   # noqa: E731
    return 116 * f(y) - 16, 500 * (f(x) - f(y)), 200 * (f(y) - f(z))


def _delta_e(a: str, b: str) -> float:
    """CIE76 colour difference: about 2 is just noticeable; the amber accent and --orange are 21 apart."""
    import math
    return math.dist(_lab(a), _lab(b))


def test_top_offenders_match_bar_is_distinct_on_every_tab():
    util = (JS / "core" / "util.js").read_text()
    pal = dict(re.findall(r"(\w+): '(#[0-9a-f]{6})'", re.search(r"export const PAL = \{(.*?)\};", util, re.S).group(1)))
    series = re.search(r"export const SERIES = \[(.*?)\];", util).group(1).replace("PAL.", "").replace(" ", "").split(",")
    css = (ROOT / "web" / "css" / "app.css").read_text()
    accent = re.search(r"--accent:\s*(#[0-9a-f]{6})", css).group(1)
    panel = re.search(r"--panel:\s*(#[0-9a-f]{6})", css).group(1)
    charts = (JS / "panels" / "charts.js").read_text()
    text = re.search(r"const C = \{ text: '(#[0-9a-f]{6})'", charts).group(1)
    # the rule in charts.js: the accent, unless the tab's bars are the accent; then the text colour
    assert "const matchC = sameColor(t.color, accentColor()) ? C.text : accentColor();" in charts
    assert "const c = q && r.key.toLowerCase() === q ? matchC : t.color;" in charts
    # hover lifts the bar's own colour; nothing hovers to near-white, which would read as the match
    assert "emphasis: { itemStyle: { color: echarts.color.lift(c, 0.15) } }" in charts
    top = charts[charts.index("// ================================================================== Top Offenders"):charts.index("// ================================================================== BGP Live")]
    assert "'#ffffff'" not in top
    tabs = re.search(r"const TABS = \[(.*?)\];", charts, re.S).group(1)
    for i in map(int, re.findall(r"color: SERIES\[(\d)\]", tabs)):
        bar = pal[series[i]]
        match = text if bar.lower() == accent.lower() else accent
        assert match.lower() != bar.lower()
        assert match.lower() != pal["red"].lower()                       # red only on flagged things
        assert _contrast(match, panel) >= 3, (match, panel)              # a graphic on the panel: WCAG 1.4.11
        assert _delta_e(match, bar) >= 30, (match, bar)                  # clearly apart (amber vs orange is 21)


def test_graph_date_label_never_breaks_inside_a_date():
    g = (JS / "views" / "entities" / "graph.js").read_text()
    body = re.search(r"function setTv\(S, text\) \{(.*?)\n\}", g, re.S).group(1)
    assert "\\u00a0" in body and r"\d{1,2} [A-Z][a-z]{2}(?: \d{4})?" in body


def test_graph_relayouts_when_the_drawn_set_changes():
    g = (JS / "views" / "entities" / "graph.js").read_text()
    apply = re.search(r"function applyFilters\(S, relayout = false\) \{(.*?)\n\}", g, re.S).group(1)
    # a change that brings the drawn set back cancels the queued re-layout (the timer is cleared before the test),
    # and the timer checks again when it fires, so zoom and pan stay (the journey: tests/e2e/test_v12_pf_ui.py)
    tail = apply[apply.index("if (relayout)"):]
    assert tail.index("clearTimeout(S.layT)") < tail.index("visSig(cy) !== S.visSig")
    assert "setTimeout(() => { if (S.cy === cy && visSig(cy) !== S.visSig) layout(S, true); }" in tail
    lay = re.search(r"function layout\(S, animate, around\) \{(.*?)\n\}", g, re.S).group(1)
    assert "S.visSig = visSig(cy)" in lay and "clearTimeout(S.layT)" in lay
