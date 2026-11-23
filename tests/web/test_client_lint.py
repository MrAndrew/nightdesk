"""Codebase-wide rules for the web client that a browser run cannot see (no server, no lake). Eight rules, each one a
property of every file, never a pinned string of one file: what a page looks like and does is the E2E journeys' job
(tests/e2e). Add a rule here only when it guards every file at once.

    uv run --with pytest pytest tests/web/test_client_lint.py -q
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
JS = WEB / "js"
CSS = (WEB / "css" / "app.css").read_text()


def _js(sub: str = ""):
    for f in sorted((JS / sub).rglob("*.js")):
        if "vendor" not in f.parts:
            yield f.relative_to(JS).as_posix(), f.read_text()


def _code(src: str) -> str:
    """JS without comments (keeps line numbers)."""
    src = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), src, flags=re.S)
    return re.sub(r"(^|[^:'\"`\\])//[^\n]*", r"\1", src)


def _exported(src: str) -> set[str]:
    names = set(re.findall(r"^export\s+(?:async\s+)?(?:const|let|function\*?|class)\s+([A-Za-z_$][\w$]*)", src, re.M))
    for group in re.findall(r"^export\s*\{([^}]*)\}", src, re.M):
        names |= {p.split(" as ")[-1].strip() for p in group.split(",") if p.strip()}
    return names


# (a) + (b) ------------------------------------------------------------------------------------------- phone shell
PHONE_MQ = re.search(r"export const PHONE_MQ = '([^']+)';", (JS / "core" / "mobile.js").read_text()).group(1)
# The phone modules' API (core/*.js headers document it). Some names have no caller yet; owner decision 2026-11-18:
# they stay as API, so this list keeps them from being "cleaned up".
PHONE_API = {
    "mobile.js": ["PHONE_MQ", "isPhone", "isShort", "onPhoneChange", "onShortChange"],
    "page.js": ["pushPage", "back", "addLayer", "addPopup", "closeOverlay", "topOverlay", "setActionBar"],
    "sheet.js": ["openSheet", "confirmSheet", "actionSheet", "navigateFromSheet", "topSheet", "closeAllSheets"],
    "libs.js": ["need", "preloadAll"],
}


def test_phone_css_stays_inside_the_phone_query():
    """(a) Every `/* == m:NAME == */` block is wrapped in the phone media query, so phone CSS never reaches a desktop.
    The one every-width part: the Close button of a maximised panel (core/page.js) and its panel head."""
    blocks = re.findall(r"/\* == m:([a-z]+) == \*/(.*?)/\* == /m:\1 == \*/", CSS, flags=re.S)
    assert blocks, "no m: blocks found: phone CSS lives in /* == m:NAME == */ blocks"
    for name, body in blocks:
        body = re.sub(r"/\*.*?\*/", "", body, flags=re.S).strip()
        if not body:
            continue
        assert body.startswith(f"@media {PHONE_MQ} {{"), f"m:{name} must open with the phone media query"
        depth = 0
        for i, ch in enumerate(body):  # noqa: B007  (i is read after the loop)
            depth += (ch == "{") - (ch == "}")
            if depth == 0 and ch == "}":
                break
        for sel in re.findall(r"([^{}]+)\{[^{}]*\}", body[i + 1:]):
            assert all(re.search(r"\.m-layer-x|\.panel\.maximized|\.ex-pnl\.max", s) for s in sel.split(",")), \
                f"m:{name} styles {sel.strip()!r} outside the phone media query"


def test_phone_query_and_phone_api_agree():
    """(b) The query string in core/mobile.js is the one in the CSS, and the phone modules export their API."""
    assert f"@media {PHONE_MQ} {{" in CSS
    for f, names in PHONE_API.items():
        missing = set(names) - _exported((JS / "core" / f).read_text())
        assert not missing, f"core/{f} no longer exports {sorted(missing)}"


# (c) + (d) ------------------------------------------------------------------------------------------- libraries
def test_libraries_are_vendored_only():
    """(c) core/libs.js loads only files under web/vendor, never another host; index.html loads no vendor script."""
    src = (JS / "core" / "libs.js").read_text()
    assert "http://" not in src and "https://" not in src
    files = re.findall(r"'([\w.-]+@[\w.]+/[\w./-]+\.js)'", src)
    assert len(files) >= 4, files   # echarts, maplibre, gridstack, globe (echarts-gl dropped: it needs eval)
    for f in files:
        assert (WEB / "vendor" / f).is_file(), f"core/libs.js names {f}, which is not in web/vendor"
    assert not re.search(r"<script[^>]+vendor/", (WEB / "index.html").read_text())


def test_library_globals_wait_for_need():
    """(d) A module that uses a library global (echarts, maplibregl, GridStack, Globe) gets it from need() first."""
    use = re.compile(r"\b(echarts|maplibregl|GridStack|Globe)\b[.(]")
    for rel, src in _js():
        if rel == "core/libs.js":
            continue
        if any(use.search(ln) for ln in _code(src).splitlines()):
            assert "need('" in src, f"{rel} uses a library global but never calls need()"


# (e) ------------------------------------------------------------------------------------------- error states
def _calls(src: str, name: str) -> list[str]:
    out, i = [], 0
    while (i := src.find(name + "({", i)) >= 0:
        j, depth = i + len(name) + 1, 0
        for k in range(j, len(src)):
            depth += (src[k] == "{") - (src[k] == "}")
            if depth == 0:
                out.append(src[j:k + 1])
                break
        i = j
    return out


def test_every_error_state_has_a_next_step():
    """(e) Each errorState()/vError() names a retry (re-runs the load) or an action of its own."""
    n = 0
    for rel, src in _js():
        if rel == "core/view.js":
            continue
        for args in _calls(src, "errorState") + _calls(src, "vError"):
            n += 1
            assert re.search(r"\bretry\b|\bact:", args), f"{rel}: an error state without a next step: {args[:120]}"
    assert n >= 20, "error states are found by their errorState()/vError() calls"


# (f) ------------------------------------------------------------------------------------------- one clock
# Files allowed to build times by hand: the helper itself, Copy summary (says UTC on purpose), the Cinema sun position
# (astronomy) and the SQL console (raw values). Elsewhere these calls build API parameters, "now" or file names.
TIME_FILES_OK = {"core/time.js", "core/summary.js", "views/cinema.js", "views/explorer.js"}
# A line that says "calendar" (in its comment) builds a day key.
TIME_LINES_OK = ("download", "Generated:", "calendar", "const unix = (t)", "at = new Date().toISOString()",
                 "S.newSince = new Date(Date.now() - 864e5).toISOString()", "const iso = (t) => new Date(t).toISOString();",
                 "since: new Date(r.from).toISOString()", "const now = new Date().toISOString();",
                 "date: (published || new Date().toISOString())", "ctx.setUpdated(",
                 "since: new Date(end - 24 * 3600e3).toISOString()")
BY_HAND = re.compile(r"toLocale(?:Date|Time)String\(|toLocaleString\(\s*['\[{]|toUTCString\(|getUTCHours\(|getHours\(|"
                     r"toISOString\(\)\.slice\((?:5|11|0, 1[0369])")
VIEW_TIME = re.compile(r"toLocale(?:Date|Time)String\(|Date\([^)]*\)\.toLocaleString\(|toISOString\(|toUTCString\(")


def test_every_shown_time_goes_through_core_time():
    """(f) Times a person reads are formatted by core/time.js (one zone setting, one "ago" rounding)."""
    bad = []
    for rel, src in _js():
        if rel in TIME_FILES_OK:
            continue
        strict = rel.startswith(("views/", "panels/"))
        for n, line in enumerate(src.splitlines(), 1):
            if line.lstrip().startswith("//"):
                continue
            hit = BY_HAND.search(line) or (strict and VIEW_TIME.search(line))
            if hit and not any(ok in line for ok in TIME_LINES_OK):
                bad.append(f"{rel}:{n}: {line.strip()[:120]}")
    assert not bad, "format these with core/time.js:\n" + "\n".join(bad)


# (g) ------------------------------------------------------------------------------------------- Help content
def _glossary() -> dict[str, str]:
    body = (JS / "help" / "glossary.js").read_text().split("export const GLOSSARY = [", 1)[1].split("\n];", 1)[0]
    out = {}
    for e in re.split(r"\n  \{ id: ", body)[1:]:
        gid = re.match(r"'([a-z0-9-]+)'", e).group(1)
        assert gid not in out, f"duplicate glossary id {gid}"
        out[gid] = e
    return out


def test_help_content_is_complete_and_links_resolve():
    """(g) Every glossary entry is complete; every data-term, glossary/guide link and documented shortcut resolves."""
    g = _glossary()
    assert len(g) >= 40
    for gid, e in g.items():
        for field in ("term:", "cat:", "short:", "why:", "where: [["):
            assert field in e, f"glossary {gid} lacks {field}"
    used = {m.group(1): rel for rel, src in _js() for m in re.finditer(r'data-term=\\?"([a-z0-9-]+)\\?"', src)}
    assert len(used) >= 10 and not {t: f for t, f in used.items() if t not in g}
    guides_js = (JS / "help" / "guides.js").read_text()
    guides = set(re.findall(r"^\s+id: '([a-z0-9-]+)', title:", guides_js, re.M))
    for f in ("glossary.js", "pages.js", "guides.js"):
        for kind, ref in re.findall(r"(?:#help/|help: ')(glossary|guides)/([a-z0-9-]+)", (JS / "help" / f).read_text()):
            assert ref in (g if kind == "glossary" else guides), (f, kind, ref)
    for ref in re.findall(r"terms: \[([^\]]*)\]", (JS / "help" / "pages.js").read_text() + guides_js):
        assert set(re.findall(r"'([a-z0-9-]+)'", ref)) <= set(g), ref
    rows = re.findall(r"src: '([^']+)', probe: (\"[^\"]+\"|'[^']+')", (JS / "help" / "keys.js").read_text())
    assert len(rows) >= 15
    for path, probe in rows:
        assert probe[1:-1] in (ROOT / path).read_text(), f"Help documents a shortcut that {path} no longer has: {probe}"


# (h) ------------------------------------------------------------------------------------------- no native dialogs
# Native dialogs block the page and look foreign on a phone: use core/sheet.js (confirmSheet) or an inline confirm.
# These call sites predate the rule (sheet.js's is the desktop fallback of confirmSheet); no new file may add one.
DIALOGS_OK = {"core/sheet.js", "views/net/connect.js", "views/net/push.js", "views/entities/intelx.js"}


def test_no_native_dialogs():
    """(h) No window.confirm, alert or prompt outside the files that already had them."""
    bad = [f"{rel}:{n}: {ln.strip()[:100]}" for rel, src in _js() if rel not in DIALOGS_OK
           for n, ln in enumerate(_code(src).splitlines(), 1)
           if re.search(r"(^|[^.\w$])(window\.)?(confirm|alert|prompt)\(", ln)]
    assert not bad, "\n".join(bad)
