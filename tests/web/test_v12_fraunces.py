"""Vendored webfonts (web/vendor/fonts/fonts.css): every face is a real local woff2 next to its licence, the first family of
each of the --mono, --sans and --serif stacks in css/app.css is vendored, and every weight/style the --serif rules ask
for has its own Fraunces face (so nothing falls back to a system serif or a synthesised bold).

    uv run --with pytest pytest tests/web/test_v12_fraunces.py -q
"""
from __future__ import annotations

import re
from pathlib import Path

WEB = Path(__file__).resolve().parents[2] / "web"
FONTS = WEB / "vendor" / "fonts"
FONTS_CSS = (FONTS / "fonts.css").read_text()
APP_CSS = (WEB / "css" / "app.css").read_text()
FACES = re.findall(r"@font-face\s*\{([^}]*)\}", FONTS_CSS)


def _prop(block: str, name: str) -> str:
    m = re.search(rf"{name}\s*:\s*([^;]+);", block)
    return m.group(1).strip() if m else ""


def _faces() -> list[tuple[str, str, str, str]]:
    """(family, weight, style, src url) for every @font-face."""
    out = []
    for b in FACES:
        url = re.search(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)", _prop(b, "src"))
        out.append((_prop(b, "font-family").strip("\"'"), _prop(b, "font-weight"), _prop(b, "font-style") or "normal",
                    url.group(1) if url else ""))
    return out


def test_every_face_is_a_local_woff2_with_its_licence():
    assert FACES, "fonts.css declares no @font-face"
    assert "http:" not in FONTS_CSS and "https:" not in FONTS_CSS and "//" not in re.sub(r"/\*.*?\*/", "", FONTS_CSS, flags=re.S)
    for fam, weight, style, url in _faces():
        assert url.endswith(".woff2"), (fam, url)
        f = FONTS / url
        assert f.is_file(), f"{fam} {weight} {style}: {url} is not vendored"
        assert f.read_bytes()[:4] == b"wOF2", f"{url} is not a woff2 file"
        assert re.fullmatch(r"[a-z-]+@\d+\.\d+\.\d+", f.parent.name), f"{url}: folder must be <package>@<exact version>"
        lic = f.parent / "LICENSE"
        assert lic.is_file() and "Open Font License" in lic.read_text(), f"{f.parent.name} lacks its OFL LICENSE"
        assert "font-display: swap" in next(b for b in FACES if url in b)


def test_first_family_of_each_stack_is_vendored():
    families = {fam for fam, *_ in _faces()}
    for var in ("mono", "sans", "serif"):
        stack = re.search(rf"--{var}\s*:\s*([^;]+);", APP_CSS).group(1)
        first = stack.split(",")[0].strip().strip("\"'")
        assert first in families, f"--{var} names {first} first, but fonts.css does not vendor it"


def test_every_serif_weight_and_style_has_a_fraunces_face():
    have = {(w, s) for fam, w, s, _ in _faces() if fam == "Fraunces"}
    want = set()
    for rule in re.findall(r"\{([^{}]*var\(--serif\)[^{}]*)\}", APP_CSS):
        for short in re.findall(r"(?<![-\w])font\s*:\s*([^;]*var\(--serif\)[^;]*)", rule):
            words = short.split("var(--serif)")[0].split()
            style = "italic" if "italic" in words else "normal"
            weight = next((w for w in words if re.fullmatch(r"[1-9]00", w)), "400")
            want.add((weight, style))
        if re.search(r"font-family\s*:\s*var\(--serif\)", rule):
            m = re.search(r"font-weight\s*:\s*([1-9]00)", rule)
            want.add((m.group(1) if m else "400", "normal"))
    assert want, "found no --serif rules in app.css"
    missing = want - have
    assert not missing, f"--serif is used at {sorted(missing)} but fonts.css has no Fraunces face for it"
