"""Notes: CRUD, counts, the one-time import of browser notes, markdown-lite escaping and "redact my network".

    uv run --with pytest pytest tests/app/test_notes.py -q
"""
from __future__ import annotations

import re

from _lake import make_lake
LAKE = make_lake("notes")

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db  # noqa: E402
from osinthub.notes import store  # noqa: E402
from osinthub.notes.api import router  # noqa: E402

db.connect()
db.cursor().execute(store.SCHEMA)
from osinthub.netlog.schema import SCHEMA_SQL  # noqa: E402
from osinthub.netlog import devices, util  # noqa: E402
db.cursor().execute(SCHEMA_SQL)
devices.ensure_tables()

app = FastAPI()
app.include_router(router)
c = TestClient(app)


@pytest.fixture(autouse=True)
def clean():
    db.execute("DELETE FROM notes")
    yield


# ------------------------------------------------------------------ CRUD
def test_create_list_update_delete():
    r = c.post("/api/notes", json={"kind": "incident", "item": "a1", "body": "Checked the **laptop**.", "title": "Laptop reached a C2"})
    assert r.status_code == 200, r.text
    n = r.json()
    assert n["kind"] == "incident" and n["item"] == "a1" and n["title"] == "Laptop reached a C2"
    assert n["created_at"] and n["updated_at"] and n["href"] == "#network/alerts/a1"
    assert "<strong>laptop</strong>" in n["html"]
    c.post("/api/notes", json={"kind": "incident", "item": "a1", "body": "Second thought"})
    got = c.get("/api/notes", params={"kind": "incident", "item": "a1"}).json()["notes"]
    assert [x["body"] for x in got] == ["Checked the **laptop**.", "Second thought"]   # oldest first

    u = c.put(f"/api/notes/{n['id']}", json={"body": "Re-imaged the laptop."}).json()
    assert u["body"] == "Re-imaged the laptop." and u["updated_at"] >= n["updated_at"] and u["created_at"] == n["created_at"]
    assert u["title"] == "Laptop reached a C2"   # an edit keeps the title

    assert c.delete(f"/api/notes/{n['id']}").json() == {"ok": True}
    assert c.delete(f"/api/notes/{n['id']}").status_code == 404
    assert c.put(f"/api/notes/{n['id']}", json={"body": "x"}).status_code == 404
    assert [x["body"] for x in c.get("/api/notes", params={"kind": "incident", "item": "a1"}).json()["notes"]] == ["Second thought"]


def test_validation():
    assert c.post("/api/notes", json={"kind": "bogus", "item": "x", "body": "y"}).status_code == 400
    assert c.post("/api/notes", json={"kind": "story", "item": "", "body": "y"}).status_code == 400
    assert c.post("/api/notes", json={"kind": "story", "item": "s", "body": "   "}).status_code == 400
    assert c.post("/api/notes", json={"kind": "story", "item": "s", "body": "x" * (store.BODY_MAX + 1)}).status_code == 400
    n = c.post("/api/notes", json={"kind": "story", "item": "s", "body": "ok"}).json()
    assert c.put(f"/api/notes/{n['id']}", json={"body": ""}).status_code == 400
    assert c.get("/api/notes", params={"kind": "nope", "item": "x"}).status_code == 400
    assert c.get("/api/notes/counts", params={"kind": "nope"}).status_code == 400


def test_counts_and_search():
    for kind, item, body in [("entity", "actor:apt29", "watch this"), ("entity", "actor:apt29", "and this"),
                             ("story", "s1", "100% sure_thing"), ("article", "art1", "nothing")]:
        c.post("/api/notes", json={"kind": kind, "item": item, "body": body, "title": f"T {item}"})
    cn = c.get("/api/notes/counts").json()
    assert cn["entity"] == {"actor:apt29": 2} and cn["story"] == {"s1": 1} and cn["incident"] == {}
    allx = c.get("/api/notes").json()
    assert allx["total"] == 4 and allx["kinds"] == {"entity": 2, "story": 1, "article": 1}
    assert c.get("/api/notes", params={"kind": "entity"}).json()["total"] == 2
    assert c.get("/api/notes", params={"q": "T art1"}).json()["total"] == 1       # matches the title
    assert c.get("/api/notes", params={"q": "100%"}).json()["total"] == 1          # % is literal
    assert c.get("/api/notes", params={"q": "s_re"}).json()["total"] == 0          # _ is literal
    assert c.get("/api/notes", params={"q": "e_th"}).json()["total"] == 1


# ------------------------------------------------------------------ migration of browser notes
def test_import_once_is_idempotent():
    payload = {"notes": [{"kind": "article", "item": "art9", "body": "old browser note"},
                         {"kind": "article", "item": "art8", "body": "another"}, {"kind": "article", "item": "", "body": "bad"}]}
    r = c.post("/api/notes/import", json=payload).json()
    assert r["imported"] == 2 and r["skipped"] == 0 and len(r["errors"]) == 1
    r2 = c.post("/api/notes/import", json=payload).json()
    assert r2["imported"] == 0 and r2["skipped"] == 2
    assert c.get("/api/notes/counts").json()["article"] == {"art9": 1, "art8": 1}
    assert c.post("/api/notes/import", json={"notes": "x"}).status_code == 400


# ------------------------------------------------------------------ escaping
@pytest.mark.parametrize("raw", [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", '"><svg onload=alert(1)>',
    "[click](javascript:alert(1))", "[x](https://ok.example/\" onmouseover=\"alert(1))", "`<b>`", "> <i>quote</i>",
    "- <a href=x>item</a>", "```\n<script>x</script>\n```", "**<u>bold</u>**",
])
def test_render_escapes_everything(raw):
    h = store.render(raw)
    # the only tags are the renderer's own; every link is http(s) with no extra attributes
    rest = re.sub(r'</?(p|br|ul|ol|li|blockquote|pre|code|strong|em)>|<p class="notes-h">', "", h)
    rest = re.sub(r'<a href="https?://[^"<>]*" target="_blank" rel="noopener noreferrer">|</a>', "", rest)
    assert "<" not in rest and ">" not in rest.replace("&gt;", ""), (raw, h)


def test_render_markdown_lite():
    h = store.render("# Head\nline one\nline two\n\n- a\n- b\n\n1. x\n2. y\n\n> quoted\n\n`code` and *it* and _it2_ and "
                     "[link](https://example.com/a?b=1&c=2)\n\nsnake_case_name and 2*3*4")
    assert '<p class="notes-h"><strong>Head</strong></p>' in h
    assert "<p>line one<br>line two</p>" in h
    assert "<ul><li>a</li><li>b</li></ul>" in h and "<ol><li>x</li><li>y</li></ol>" in h
    assert "<blockquote>quoted</blockquote>" in h
    assert "<code>code</code>" in h and "<em>it</em>" in h and "<em>it2</em>" in h
    assert '<a href="https://example.com/a?b=1&amp;c=2" target="_blank" rel="noopener noreferrer">link</a>' in h
    assert "snake_case_name" in h and "2*3*4" in h          # no stray emphasis inside words


def test_api_html_is_escaped():
    n = c.post("/api/notes", json={"kind": "story", "item": "s", "body": "<img src=x onerror=alert(1)>"}).json()
    assert n["body"] == "<img src=x onerror=alert(1)>"      # stored as typed
    assert n["html"] == "<p>&lt;img src=x onerror=alert(1)&gt;</p>"


# ------------------------------------------------------------------ redaction
def _home():
    db.execute("DELETE FROM devices"); db.execute("DELETE FROM netlog_device_labels")
    db.execute("""INSERT INTO devices (id, identity, mac, ips, hostnames) VALUES
        ('mac:02:00:5e:10:00:01', 'mac', '02:00:5e:10:00:01', ['10.86.24.23', '2001:db8:1::23'], ['demo-laptop.lan']),
        ('ip:10.86.24.40', 'ip', NULL, ['10.86.24.40'], ['kitchen-speaker'])""")
    db.execute("INSERT INTO netlog_device_labels VALUES ('mac:02:00:5e:10:00:01', 'Study PC', 'laptop', 'Robin', NULL, now())")
    db.set_setting(util.SETTINGS_KEY, {**(db.get_setting(util.SETTINGS_KEY) or {}), "home_prefixes": ["198.51.100.0/24"]})


def test_redact_home_addresses_macs_and_names():
    _home()
    text = ("Study PC (demo-laptop.lan, 02:00:5E:10:00:01, mac:02:00:5e:10:00:01) at 10.86.24.23 and 2001:db8:1::23 "
            "reached 203.0.113.9 and 2001:db8:ffff::9. Robin's kitchen-speaker 10.86.24.40 too; "
            "fd4e:6400:d35c::7 and 198.51.100.4 are home. demo-laptop again, 10.86.24.23 again. Time 21:40:05.")
    r = c.post("/api/notes/redact", json={"text": text}).json()
    t = r["text"]
    for leak in ("Study PC", "demo-laptop", "02:00:5E", "02:00:5e", "10.86.24.", "2001:db8:1::23", "Robin",
                 "kitchen-speaker", "fd4e:6400", "198.51.100.4"):
        assert leak not in t, (leak, t)
    assert "203.0.113.9" in t and "2001:db8:ffff::9" in t      # the outside addresses stay
    assert "21:40:05" in t
    assert t.count("[home IP 1]") == 2                          # the same address, the same placeholder
    assert "[MAC 1]" in t and "[device 1]" in t
    assert r["replaced"]["macs"] == 1 and r["replaced"]["ips"] >= 5 and r["replaced"]["names"] >= 4
    assert c.post("/api/notes/redact", json={"text": 5}).status_code == 400


def test_redact_keeps_text_without_home_data():
    _home()
    s = "APT29 used 203.0.113.50 and evil.example; see https://example.com/x and CVE-2024-3400."
    assert store.redact(s)["text"] == s


# ------------------------------------------------------------------ redaction, evaluator round 1 cases
def _short_labels():
    _home()
    db.execute("""INSERT INTO devices (id, identity, mac, ips, hostnames) VALUES
        ('mac:02:00:5e:10:00:02', 'mac', '02:00:5e:10:00:02', ['10.86.24.50'], ['mac']),
        ('ip:10.86.24.51', 'ip', NULL, ['10.86.24.51'], []), ('ip:10.86.24.52', 'ip', NULL, ['10.86.24.52'], [])""")
    db.execute("""INSERT INTO netlog_device_labels VALUES ('ip:10.86.24.40', 'TV', 'tv', 'Q', NULL, now()),
        ('ip:10.86.24.51', 'Router', 'network', 'Pat', NULL, now()), ('ip:10.86.24.52', 'Xo', 'phone', NULL, NULL, now()),
        ('mac:02:00:5e:10:00:02', 'Dad''s Laptop', 'laptop', NULL, NULL, now())""")


def test_redact_short_and_generic_labels_and_owners():
    _short_labels()
    t = store.redact("# TV contacted an address. Router is using Tor. Xo too; owners Q and Pat. "
                     "Dad's Laptop-2 and dad's laptop 3 as well. - **Device:** TV")["text"]
    for leak in ("TV", "Router", "Xo", " Q ", "Pat", "Laptop", "laptop"):
        assert leak not in t, (leak, t)
    assert "Tor" in t and "contacted an address" in t


def test_redact_v6_with_port_prefix_and_mapped_forms():
    _home()
    cases = ["fd4e:6400:d35c:1:4e:44ff:fe00:21:443 -> 2606:4700::1111:443", "src:fd4e:6400:d35c:1:4e:44ff:fe00:21",
             "[fd4e:6400:d35c::21]:443", "::ffff:10.86.24.21", "::FFFF:10.86.24.21:8080", "10.86.24.21:443.",
             "fd4e:6400:d35c:0001:0000:0000:0000:0021", "FD4E:6400:D35C::21", "2001:db8:1::23:443", "fe80::1%en0"]
    for c in cases:
        t = store.redact(c)["text"]
        for leak in ("fd4e", "FD4E", "10.86.24", "2001:db8:1::23", "fe80"):
            assert leak not in t, (c, t)
    t = store.redact("fd4e:6400:d35c:1:4e:44ff:fe00:21:443 -> 2606:4700::1111:443")["text"]
    assert t.startswith("[home IP 1]") and "2606:4700::1111" in t
    assert store.redact("[fd4e:6400:d35c::21]:443")["text"] == "[[home IP 1]]:443"
    assert store.redact("::ffff:10.86.24.21 and 10.86.24.21")["text"] == "[home IP 1] and [home IP 1]"


def test_redact_placeholders_cannot_be_corrupted():
    _short_labels()   # a device announces itself as "mac"
    r = store.redact("MAC aa:bb:cc:dd:ee:ff and mac:02:00:5e:10:00:01, home IP 10.86.24.23, device TV")
    t = r["text"]
    assert "[MAC 1]" in t and "[[" not in t and "aa:bb" not in t and "02:00:5e" not in t
    assert "[home IP 1]" in t and t.count("[") == t.count("]")
    # forged sentinel or marker characters in the input do nothing
    assert store.redact("x y ip")["text"] == "x y ip"


def test_redact_reverse_dns_and_mac_notations():
    _home()
    t = store.redact("query 23.24.86.10.in-addr.arpa and 24.86.10.in-addr.arpa, keep 9.113.0.203.in-addr.arpa; "
                     + ".".join(reversed("fd4e6400d35c00010000000000000021")) + ".ip6.arpa")["text"]
    assert "10.in-addr" not in t and "ip6.arpa" not in t and "9.113.0.203.in-addr.arpa" in t
    for mac in ("02005e100001", "0200.5e10.0001", "02-00-5E-10-00-01", "02:00:5e:10:00:01"):
        out = store.redact(f"seen {mac} here")["text"]
        assert out == "seen [MAC 1] here", (mac, out)


def test_redact_structural_markers():
    _home()
    M = lambda k, v: f"{k}{v}"   # noqa: E731
    text = (f"# {M('name', 'Kids Tablet')} called out\n- {M('ipq', '10.86.24.23')}:51000 -> {M('ipq', '203.0.113.9')}:443\n"
            f"- {M('ipq', 'fd4e:6400:d35c::21')}:443 mac {M('mac', '02:00:5e:10:00:09')}\nnote: kids tablet again")
    t = store.redact(text)["text"]
    assert t == ("# [device 1] called out\n- [home IP 1]:51000 -> 203.0.113.9:443\n"
                 "- [home IP 2]:443 mac [MAC 1]\nnote: [device 1] again"), t
