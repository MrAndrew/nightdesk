"""v1.2 harden (L1): values from the API never go raw into a class or attribute value.

The article role is whitelisted (news/detail.js), and the other attribute sinks found by the same grep are
escaped. The scan below fails if a raw `${obj.field}` from API data comes back in any of these places.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
JS = ROOT / "web" / "js"

# (file, raw interpolation that must not appear, its safe replacement)
FIXED = [
    ("views/news/detail.js", '<span class="nw-rolet ${a.role}">', '<span class="nw-rolet ${roleCls(a.role)}">'),
    ("help/desk.js", 'data-s="${s.state}"', 'data-s="${esc(s.state)}"'),
    ("help/desk.js", 'data-s="${l.state}"', 'data-s="${esc(l.state)}"'),
    ("views/entities/page.js", 'class="ev-v ${e.verdict}"', 'class="ev-v ${esc(e.verdict)}"'),
    ("views/entities/page.js", 'o-${c.origin}"', 'o-${esc(c.origin)}"'),
    ("views/entities/page.js", 'o-${r.origin} sm"', 'o-${esc(r.origin)} sm"'),
    ("views/entities/page.js", 'k-${it.kind}"', 'k-${esc(it.kind)}"'),
    ("views/net/devices.js", 'class="devices-tl-${e.kind}"', 'class="devices-tl-${esc(e.kind)}"'),
    ("views/net/push.js", 'data-sp="${s.id}"', 'data-sp="${esc(s.id)}"'),
    ("views/net/push.js", 'data-sa="${s.id}"', 'data-sa="${esc(s.id)}"'),
    ("views/net/push.js", 'class="nv-pu-up ${u.status}"', 'class="nv-pu-up ${esc(u.status)}"'),
    ("views/news.js", 'title="Relevance ${x.score}"', 'title="Relevance ${esc(x.score)}"'),
    ("views/news.js", 'title="${s.source_count} distinct', 'title="${esc(s.source_count)} distinct'),
    ("views/settings/routing.js", 'aria-pressed="${p.added}"', "aria-pressed=\"${p.added ? 'true' : 'false'}\""),
    ("panels/feeds.js", '<span class="feeds-dim">${r.country}</span>', '<span class="feeds-dim">${esc(r.country)}</span>'),
]


def test_fixed_sinks_stay_fixed():
    for rel, raw, safe in FIXED:
        src = (JS / rel).read_text()
        assert raw not in src, f"{rel}: raw {raw}"
        assert safe in src, f"{rel}: expected {safe}"


def test_role_class_is_whitelisted():
    src = (JS / "views/news/detail.js").read_text()
    m = re.search(r"const roleCls = \(r\) => \((.*?)\);", src)
    assert m, "roleCls helper missing"
    assert "'research'" in m.group(1) and "'newsroom'" in m.group(1) and ": ''" in m.group(1)
    assert "${a.role}" not in src


ATTR = re.compile(r'\b(?:class|data-[a-z-]+|title|id|aria-[a-z]+|value|for|name)="[^"<>]*?\$\{([^}]*)\}')
# objects the views read straight from API responses (rows, articles, events, alerts, devices, senders, claims, ...)
API_OBJ = re.compile(r"^(?:a|r|e|d|it|x|row|art|ev|al|dev|s|l|c|u|f|g|n|m|p|o|t|w|v|item|rec)\.[A-Za-z_]+$")
# values in these files are built in the client (palettes, constant tables) and checked by hand
SAFE_ANYWAY = {"${s.name}", "${t.id}", "${c.k}", "${c.i}", "${g.id}", "${tip.id}", "${s.cls}", "${l.id}",
               "${o.v}", "${m.cls}", "${a._n}", "${c.id}", "${c.value}"}


def test_no_raw_api_field_in_attributes():
    """Every bare `${obj.field}` inside a class/data/title/id attribute in web/js is escaped, except the
    client-built values listed in SAFE_ANYWAY (checked by hand: constant tables and ids made in the page)."""
    bad = []
    for p in sorted(JS.rglob("*.js")):
        for i, line in enumerate(p.read_text().splitlines(), 1):
            for m in ATTR.finditer(line):
                expr = m.group(1).strip()
                if API_OBJ.match(expr) and "${" + expr + "}" not in SAFE_ANYWAY:
                    bad.append(f"{p.relative_to(ROOT)}:{i}: ${{{expr}}}")
    assert not bad, "raw API values in attributes:\n" + "\n".join(bad)
