"""The client's colours, computed: every palette colour is distinguishable (CIEDE2000), readable on every surface (WCAG
contrast), red only for flags, and one severity map and one entity-type map that every view draws from.

    uv run --with pytest pytest tests/web/test_palette.py -q
"""
from __future__ import annotations

import itertools
import math
import re
from pathlib import Path

JS = Path(__file__).resolve().parents[2] / "web" / "js"
UTIL = (JS / "core" / "util.js").read_text()
RED, AMBER = "#e2674a", "#e4a84c"     # the flag colour and the one accent

# Every colour of the v1 palette (v1-archive: web/css/app.css, core/util.js, core/chips.js). Palette colours keep
# >= 12 CIEDE2000 from all of them (no v1 colour back under another name), except red and amber, kept on purpose.
V1_COLOURS = """
    #020305 #04130c #04140c #06080d #0a0c0f #0a0d12 #0b0d10 #0c0d0f #0d1117 #0d1118 #0d1418 #10131a #111317 #111621
    #161c28 #181c22 #1a1405 #1a1d23 #222a39 #262b33 #2a2f37 #2a3038 #2a3039 #2c3547 #2dd4bf #343a43 #38d4e8 #3ddc97
    #4fd1a5 #585650 #59606b #5aa9ff #5b626d #5be6aa #5f4a22 #67e8f9 #6b727d #6fae8a #6fe3bd #6ff0b6 #79a6cc #7c9cc4
    #7dd3fc #7f8792 #7ff3ff #8a8578 #8b929c #8b93a1 #8cc4ff #8e959f #9aa1ab #a3a9b2 #a78bfa #b7b1a2 #b7e4c7 #b9c0ca
    #b9e8d2 #c084fc #c3c8cf #c4b5fd #c98f3a #c9ced5 #c9ced6 #cfd4da #d7dbe0 #e2674a #e4a84c #e4e7ea #e8795a #e879f9
    #e9cf7f #e9e3d4 #e9ecef #eef0f2 #eef0f3 #f0524f #f08a3c #f1c27a #f1f3f5 #f2c94c #f472b6 #f4f5f7 #f4f6f8 #f9a8d4
    #fb7185 #ff4d6d #ff8a87 #ff9a97 #ffb27a #ffe08a #ffe9c2
""".split()
TEXT = "#e9e3d4"
SURFACES = {"panel": "#111621", "panel-2 / hover card": "#161c28", "graph label background": "#0a0d12"}
MAP_BG = {"map land": "#1a1c20", "map sea": "#0c0d0f"}


# ---------------------------------------------------------------- colour maths
def _rgb(h):
    return [int(h[i:i + 2], 16) / 255 for i in (1, 3, 5)]


def _lin(c):
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def contrast(a, b):
    lum = lambda h: sum(w * _lin(c) for w, c in zip((0.2126, 0.7152, 0.0722), _rgb(h)))
    la, lb = lum(a), lum(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


def mix(c, base, t):
    return "#" + "".join(f"{round(int(c[i:i + 2], 16) * t + int(base[i:i + 2], 16) * (1 - t)):02x}" for i in (1, 3, 5))


def hue_sat(h):
    r, g, b = _rgb(h)
    mx, mn = max(r, g, b), min(r, g, b)
    if mx == mn:
        return 0.0, 0.0
    d, light = mx - mn, (mx + mn) / 2
    sat = d / (2 - mx - mn) if light > 0.5 else d / (mx + mn)
    hue = ((g - b) / d) % 6 if mx == r else (b - r) / d + 2 if mx == g else (r - g) / d + 4
    return hue * 60, sat


def redish(h):
    """Within 20 degrees of the flag red's hue and saturated."""
    hue, s = hue_sat(h)
    return min(abs(hue - 11), 360 - abs(hue - 11)) <= 20 and s > 0.4


def _lab(h):
    r, g, b = (_lin(c) for c in _rgb(h))
    x, y, z = ((0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047, 0.2126 * r + 0.7152 * g + 0.0722 * b,
               (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883)
    f = lambda t: t ** (1 / 3) if t > 0.008856 else 7.787 * t + 16 / 116
    return 116 * f(y) - 16, 500 * (f(x) - f(y)), 200 * (f(y) - f(z))


def de2000(h1, h2):
    (L1, a1, b1), (L2, a2, b2) = _lab(h1), _lab(h2)
    cb = (math.hypot(a1, b1) + math.hypot(a2, b2)) / 2
    g = 0.5 * (1 - math.sqrt(cb ** 7 / (cb ** 7 + 25 ** 7)))
    a1, a2 = (1 + g) * a1, (1 + g) * a2
    c1, c2 = math.hypot(a1, b1), math.hypot(a2, b2)
    h1p, h2p = math.degrees(math.atan2(b1, a1)) % 360, math.degrees(math.atan2(b2, a2)) % 360
    dh = 0 if c1 * c2 == 0 else (h2p - h1p if abs(h2p - h1p) <= 180 else (h2p - h1p - 360 if h2p > h1p else h2p - h1p + 360))
    dH = 2 * math.sqrt(c1 * c2) * math.sin(math.radians(dh / 2))
    lb, cbp = (L1 + L2) / 2, (c1 + c2) / 2
    if c1 * c2 == 0:
        hb = h1p + h2p
    elif abs(h1p - h2p) <= 180:
        hb = (h1p + h2p) / 2
    else:
        hb = (h1p + h2p + 360) / 2 if h1p + h2p < 360 else (h1p + h2p - 360) / 2
    t = (1 - 0.17 * math.cos(math.radians(hb - 30)) + 0.24 * math.cos(math.radians(2 * hb))
         + 0.32 * math.cos(math.radians(3 * hb + 6)) - 0.20 * math.cos(math.radians(4 * hb - 63)))
    rc = 2 * math.sqrt(cbp ** 7 / (cbp ** 7 + 25 ** 7))
    sl = 1 + 0.015 * (lb - 50) ** 2 / math.sqrt(20 + (lb - 50) ** 2)
    sc, sh = 1 + 0.045 * cbp, 1 + 0.015 * cbp * t
    rt = -math.sin(math.radians(60 * math.exp(-((hb - 275) / 25) ** 2))) * rc
    return math.sqrt(((L2 - L1) / sl) ** 2 + ((c2 - c1) / sc) ** 2 + (dH / sh) ** 2 + rt * ((c2 - c1) / sc) * (dH / sh))


# ---------------------------------------------------------------- the maps in core/util.js
def js_map(src: str, start: str) -> str:
    i = src.index(start)
    return src[i:src.index("};", i)]


def palette() -> dict[str, str]:
    return dict(re.findall(r"(\w+): '(#[0-9a-f]{6})'", js_map(UTIL, "export const PAL")))


def kinds_and_types():
    pal = palette()
    kb = js_map(UTIL, "export const KINDS")
    kinds = {k: pal[c] for k, c in re.findall(r"\n  (\w+):\s*\{[^}]*color: PAL\.(\w+)", kb)}
    rings = set(re.findall(r"\n  (\w+):\s*\{[^}]*mark: 'ring'", kb))
    types = {t: pal[c] for t, c in re.findall(r"'?([\w-]+)'?: PAL\.(\w+)", js_map(UTIL, "export const TYPE_COLORS"))}
    return kinds, types, rings


def _strip_js_comments(text: str) -> str:
    return re.sub(r"(^|[^:'\"`\\])//[^\n]*", r"\1", re.sub(r"/\*.*?\*/", "", text, flags=re.S))


# ---------------------------------------------------------------- tests
def test_palette_is_distinct_readable_and_keeps_red_for_flags():
    pal = palette()
    assert len(pal) >= 11 and len(set(pal.values())) == len(pal)
    worst = min((de2000(a, b), a, b) for a, b in itertools.combinations(pal.values(), 2))
    assert worst[0] >= 15, worst                                        # every pair distinguishable
    assert pal["red"] == RED
    for name, c in pal.items():
        if c in (RED, AMBER):
            continue
        near = min((de2000(c, v), v) for v in V1_COLOURS)
        assert near[0] >= 12, (name, c, near)                            # no v1 colour back under another name
        hue, s = hue_sat(c)
        assert not (160 <= hue <= 270 and s > 0.45), (name, c, s)        # no saturated blue, teal or cyan
        assert not redish(c), (name, c)                                  # red is for flags only
        assert de2000(c, TEXT) >= 15, (name, c, "reads as body text")
        for where, bg in SURFACES.items():
            assert contrast(c, bg) >= 4.5, (name, c, where)              # readable as text on every surface
            assert contrast(c, mix(c, bg, 0.12)) >= 4.5, (name, c, "chip tint on " + where)
        for where, bg in MAP_BG.items():
            assert contrast(c, bg) >= 3, (name, c, where)                # visible as a mark on the map


def test_kinds_and_entity_types_use_the_palette_and_red_only_for_kev():
    kinds, types, rings = kinds_and_types()
    assert len(kinds) >= 15 and len(types) >= 15
    assert [k for k, c in kinds.items() if c == RED] == ["kev"]           # known-exploited is the one flag
    assert RED not in types.values()
    assert types["cve"] == kinds["cve"]
    by: dict[str, list[str]] = {}
    for k, c in kinds.items():
        by.setdefault(c, []).append(k)
    for c, ks in by.items():                                              # kinds sharing a hue differ by mark
        assert len(ks) <= 2 and (len(ks) == 1 or len(rings & set(ks)) == 1), (c, ks)
    series = [palette()[n] for n in re.findall(r"PAL\.(\w+)", re.search(r"export const SERIES = \[([^\]]+)\]", UTIL).group(1))]
    assert series[0] == AMBER and RED not in series                     # charts are led by amber, never red


def test_one_severity_map_and_one_entity_type_map():
    sev = re.search(r"export const SEV = Object\.freeze\(\{([^}]*)\}\)", UTIL)
    assert sev and all(f"{b}:" in sev.group(1) for b in ("high", "medium", "low", "info"))
    assert "high: PAL.red" in sev.group(1)
    fn = UTIL[UTIL.index("export function sevColor"):UTIL.index("}", UTIL.index("export function sevColor"))]
    assert "SEV." in fn and len(re.findall(r"#[0-9a-f]{6}", fn)) <= 1    # only the "no score" grey is its own
    own_maps, own_types = [], []
    for p in JS.rglob("*.js"):
        code = _strip_js_comments(p.read_text())
        own_maps += [f"{p.relative_to(JS)}" for ln in code.splitlines()
                     if re.search(r"high:\s*'#[0-9a-f]{3,6}'.*info:\s*'#", ln, re.I)]
        if p.name != "util.js" and re.search(r"(?:const|let) TYPE(?:S|_COLORS)\s*=\s*\{[^}]*#[0-9a-f]{6}", code):
            own_types.append(f"{p.relative_to(JS)}")
    assert not own_maps, f"severity colours belong in core/util.js SEV: {own_maps}"
    assert not own_types, f"entity-type colours belong in core/util.js TYPE_COLORS: {own_types}"
