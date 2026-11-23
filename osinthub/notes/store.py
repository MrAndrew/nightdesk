"""Notes on incidents, entities, stories and articles, and the "redact my network" pass for summaries.

* A note belongs to one item: (kind, item) where kind is incident | entity | story | article and item is that
  item's id (an incident's first alert id, an entity id such as actor:apt29, a story or article id). An item can
  have many notes; each is timestamped (created, updated), editable and deletable.
* The body is plain text with a little Markdown ("markdown-lite"). render() escapes everything first and only
  then turns a few patterns into tags, so no HTML a user types ever reaches the page as HTML.
* The browser's old article notes (localStorage) move here once, through import_notes(), which skips a note
  already stored so a repeated migration adds nothing.
* redact() replaces home addresses, MACs and device names (the user's names, owners and the names devices
  announce) with numbered placeholders, for a summary that is about to leave the machine.

Reference: okf/architecture/notes.md
"""
from __future__ import annotations

import datetime as dt
import functools
import html
import ipaddress
import logging
import re
import uuid

import duckdb

from .. import apiutil, db

log = logging.getLogger("osinthub.notes")

KINDS = ("incident", "entity", "story", "article")
BODY_MAX = 10_000
TITLE_MAX = 300
ITEM_MAX = 500

SCHEMA = """
CREATE TABLE IF NOT EXISTS notes (
    id         VARCHAR PRIMARY KEY,
    kind       VARCHAR NOT NULL,      -- incident | entity | story | article
    item       VARCHAR NOT NULL,      -- the item's id
    title      VARCHAR,               -- the item's title when the note was written (for the Notes list)
    body       VARCHAR NOT NULL,      -- markdown-lite, stored as typed
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);
"""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def href(kind: str, item: str) -> str:
    """The app link that opens the item."""
    from urllib.parse import quote
    q = quote(item, safe="")
    return {"incident": f"#network/alerts/{q}", "entity": f"#entities/{q}", "story": f"#news/story/{q}",
            "article": f"#news/article/{q}"}.get(kind, "#notes")


_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(s, limit: int) -> str:
    return _CTRL.sub("", str(s or "")).strip()[:limit]


def check(kind, item) -> tuple[str, str]:
    kind = str(kind or "").strip().lower()
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}")
    item = _clean(item, ITEM_MAX)
    if not item:
        raise ValueError("item is required")
    return kind, item


def _body(body) -> str:
    b = _CTRL.sub("", str(body or "")).replace("\r\n", "\n").strip()
    if not b:
        raise ValueError("the note is empty")
    if len(b) > BODY_MAX:
        raise ValueError(f"a note is at most {BODY_MAX:,} characters")
    return b


def _lookup_title(kind: str, item: str) -> str | None:
    """The item's current title from its own table, when it has one (best effort)."""
    sql = {"article": "SELECT title FROM articles WHERE id = ?", "story": "SELECT title FROM stories WHERE id = ?",
           "entity": "SELECT name FROM entities WHERE id = ? LIMIT 1"}.get(kind)
    if not sql:
        return None
    try:
        r = db.query(sql, [item])
        return (r[0][next(iter(r[0]))] or None) if r else None
    except Exception:
        return None


_EV_KEYS = ("indicator", "device", "sample", "also_listed", "rule", "state", "sinkhole", "capped", "original_severity")


def incidents_now(items: list[str]) -> dict[str, dict]:
    """{alert id: the incident it belongs to, as it reads now}: severity, kind, device with the user's current
    name, indicator and a trimmed evidence, enough for the client's headline (views/net/alert-text.js), and
    `title`, the stored alert title with the current device name. A note shows its incident's title from here, read
    when the note is shown, so renaming a device or a rule change never leaves a note with an old title."""
    items = [i for i in dict.fromkeys(items) if i]
    if not items:
        return {}
    try:
        import json

        from ..netlog import incidents as I
        from ..netlog.api import _name_alerts
        I.ensure()
        inc_of = {r["id"]: r["inc"] for r in db.query(
            "SELECT id, coalesce(incident, id) AS inc FROM alerts WHERE id IN (SELECT unnest(?::VARCHAR[]))", [items])}
        if not inc_of:
            return {}
        rows = db.query(I.incidents_sql("WHERE coalesce(incident, id) IN (SELECT unnest(?::VARCHAR[]))"), [list(set(inc_of.values()))])
        for r in rows:
            try:
                r["evidence"] = json.loads(r["evidence"] or "{}") if isinstance(r.get("evidence"), str) else (r.get("evidence") or {})
            except (TypeError, ValueError):
                r["evidence"] = {}
        _name_alerts(rows)
    except Exception:   # the network package is optional, and a title is a nicety: never fail a note over it
        return {}
    by_inc = {}
    for r in rows:
        t, name = r.get("title") or "", r.get("device_name")
        hn = ((r["evidence"].get("device") or {}).get("hostnames") or [None])[0] if isinstance(r["evidence"].get("device"), dict) else None
        if name and hn and hn in t and name not in t:   # "demo-doorbell: ..." reads with the name you gave it
            r["title"] = t.replace(hn, name, 1)
        ev = {k: r["evidence"][k] for k in _EV_KEYS if k in r["evidence"]}
        if isinstance(ev.get("sample"), list):
            ev["sample"] = ev["sample"][:3]
        by_inc[r["inc"]] = {k: (v.isoformat() if isinstance(v, dt.datetime) else v) for k, v in {
            "id": r["id"], "title": r.get("title") or r.get("indicator"), "severity": r.get("severity"),
            "state": r.get("state"), "demo": bool(r.get("demo")), "kind": r.get("kind"), "device": r.get("device"),
            "device_name": r.get("device_name"), "indicator": r.get("indicator"), "source": r.get("source"),
            "rule": r.get("rule"), "direction": r.get("direction"), "evidence": ev, "ts": r.get("ts"),
            "last_ts": r.get("last_ts"), "days": r.get("days"), "n_alerts": r.get("n_alerts")}.items()}
    return {a: by_inc[i] for a, i in inc_of.items() if i in by_inc}


def _with_titles(rows: list[dict]) -> list[dict]:
    """Incident notes carry their incident as it reads now (`incident`) and its current title; the stored title
    is only the fallback for an incident that no longer exists (its logs or the demo were removed)."""
    now = incidents_now([r["item"] for r in rows if r.get("kind") == "incident"])
    for r in rows:
        inc = now.get(r["item"]) if r.get("kind") == "incident" else None
        if inc:
            r["incident"] = inc
            r["title"] = inc["title"] or r.get("title")
    return rows


def public(r: dict) -> dict:
    out = {k: (v.isoformat() if isinstance(v, dt.datetime) else v) for k, v in r.items()}
    out["html"] = render(out.get("body") or "")
    out["href"] = href(out["kind"], out["item"])
    return out


def get(nid: str) -> dict | None:
    r = db.query("SELECT * FROM notes WHERE id = ?", [nid])
    return public(_with_titles(r)[0]) if r else None


def for_item(kind, item) -> list[dict]:
    kind, item = check(kind, item)
    return [public(r) for r in _with_titles(db.query("SELECT * FROM notes WHERE kind = ? AND item = ? ORDER BY created_at, id",
                                                     [kind, item]))]


def search(q: str = "", kind: str | None = None, limit: int = 200, offset: int = 0) -> dict:
    """All notes, newest change first, optionally of one kind and containing `q` (in the note or the item title)."""
    w, p = [], []
    if kind:
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {', '.join(KINDS)}")
        w.append("kind = ?"); p.append(kind)
    if q and q.strip():
        w.append("(body ILIKE ? OR coalesce(title, '') ILIKE ? OR item ILIKE ?)")
        like = apiutil.like(q.strip())
        p += [like, like, like]
        w[-1] = w[-1].replace("ILIKE ?", "ILIKE ? ESCAPE '\\'")
    if q and q.strip():
        # an incident note also matches its incident's title as it reads now (a renamed device, say)
        ql = q.strip().lower()
        w[-1] = f"({w[-1]} OR kind = 'incident')"
        where = f"WHERE {' AND '.join(w)}"
        cand = _with_titles(db.query(f"SELECT * FROM notes {where} ORDER BY updated_at DESC, id", p))
        hits = [r for r in cand if ql in str(r.get("body") or "").lower() or ql in str(r.get("item") or "").lower()
                or ql in str(r.get("title") or "").lower()
                or (r.get("incident") and ql in " ".join(str(r["incident"].get(k) or "") for k in ("title", "device_name", "indicator")).lower())]
        total, rows = len(hits), hits[int(offset): int(offset) + int(limit)]
    else:
        where = f"WHERE {' AND '.join(w)}" if w else ""
        total = db.query(f"SELECT count(*) AS n FROM notes {where}", p)[0]["n"]
        rows = _with_titles(db.query(f"SELECT * FROM notes {where} ORDER BY updated_at DESC, id LIMIT ? OFFSET ?",
                                     p + [int(limit), int(offset)]))
    kinds = {r["kind"]: r["n"] for r in db.query("SELECT kind, count(*) AS n FROM notes GROUP BY kind")}
    return {"total": int(total), "kinds": kinds, "notes": [public(r) for r in rows]}


def counts(kind: str | None = None) -> dict:
    """{kind: {item: number of notes}}: the badges in lists."""
    w, p = ("WHERE kind = ?", [kind]) if kind else ("", [])
    out: dict = {k: {} for k in KINDS}
    for r in db.query(f"SELECT kind, item, count(*) AS n FROM notes {w} GROUP BY kind, item", p):
        out.setdefault(r["kind"], {})[r["item"]] = int(r["n"])
    return out


def create(kind, item, body, title=None, at: dt.datetime | None = None) -> dict:
    kind, item = check(kind, item)
    b = _body(body)
    t = _clean(title, TITLE_MAX) or _lookup_title(kind, item)
    nid = uuid.uuid4().hex[:16]
    ts = at or _now()
    db.execute("INSERT INTO notes VALUES (?, ?, ?, ?, ?, ?, ?)", [nid, kind, item, t, b, ts, ts])
    return get(nid)


def update(nid: str, body=None, title=None) -> dict:
    cur = get(nid)
    if not cur:
        raise KeyError(nid)
    b = _body(body) if body is not None else cur["body"]
    t = _clean(title, TITLE_MAX) or cur.get("title") if title is not None else cur.get("title")
    db.execute("UPDATE notes SET body = ?, title = ?, updated_at = ? WHERE id = ?", [b, t, _now(), nid])
    return get(nid)


def delete(nid: str) -> bool:
    if not get(nid):
        return False
    db.execute("DELETE FROM notes WHERE id = ?", [nid])
    return True


def import_notes(items: list) -> dict:
    """Bring notes in from the browser (the old article notes). A note whose kind, item and text are already
    stored is skipped, so running the same migration twice adds nothing."""
    imported = skipped = 0
    errors: list[str] = []
    for x in items or []:
        try:
            kind, item = check((x or {}).get("kind", "article"), (x or {}).get("item"))
            b = _body(x.get("body"))
        except (ValueError, AttributeError) as e:
            errors.append(str(e)); continue
        if db.query("SELECT 1 FROM notes WHERE kind = ? AND item = ? AND body = ?", [kind, item, b]):
            skipped += 1; continue
        create(kind, item, b, x.get("title"))
        imported += 1
    return {"imported": imported, "skipped": skipped, "errors": errors[:20]}


# ------------------------------------------------------------------------------------------- markdown-lite
_LINK = re.compile(r"\[([^\]\n]{1,300})\]\((https?://[^\s()<>\"']{1,2000})\)")
_BOLD = re.compile(r"\*\*(?=\S)(.+?)(?<=\S)\*\*")
_ITAL = re.compile(r"(?<![\w*])\*(?=[^\s*])(.+?)(?<=[^\s*])\*(?![\w*])")
_UND = re.compile(r"(?<![\w])_(?=\S)(.+?)(?<=\S)_(?![\w])")
_UL = re.compile(r"^\s{0,3}[-*+]\s+(.*)$")
_OL = re.compile(r"^\s{0,3}\d{1,3}[.)]\s+(.*)$")
_QUOTE = re.compile(r"^\s{0,3}(?:>|&gt;)\s?(.*)$")
_HEAD = re.compile(r"^\s{0,3}#{1,6}\s+(.*)$")


def _inline(raw: str) -> str:
    """One line of text: escaped, then `code`, [text](https://link), **bold**, *italic* / _italic_."""
    out = []
    for i, part in enumerate(raw.split("`")):
        if i % 2 and i < len(raw.split("`")) - 1:          # inside a closed pair of backticks
            out.append(f"<code>{html.escape(part, quote=True)}</code>")
            continue
        if i % 2:                                           # an unclosed backtick stays a backtick
            part = "`" + part
        links: list[str] = []

        def keep(m, links=links):
            links.append(f'<a href="{html.escape(m.group(2), quote=True)}" target="_blank" rel="noopener noreferrer">'
                         f"{html.escape(m.group(1), quote=True)}</a>")
            return f"\x00{len(links) - 1}\x00"
        s = html.escape(_LINK.sub(keep, part), quote=True)
        s = _BOLD.sub(r"<strong>\1</strong>", s)
        s = _ITAL.sub(r"<em>\1</em>", s)
        s = _UND.sub(r"<em>\1</em>", s)
        s = re.sub(r"\x00(\d+)\x00", lambda m, links=links: links[int(m.group(1))], s)
        out.append(s)
    return "".join(out)


def render(text: str) -> str:
    """Markdown-lite to safe HTML: paragraphs (a single newline is a line break), - or 1. lists, > quotes,
    # headings (shown bold), ``` code blocks, and the inline forms of _inline(). Every character the user typed is
    escaped; the only tags are the ones this function writes, and links are http(s) only."""
    lines = _CTRL.sub("", str(text or "")).replace("\r\n", "\n").split("\n")
    out: list[str] = []
    para: list[str] = []
    lst: tuple[str, list[str]] | None = None
    quote: list[str] = []

    def flush():
        nonlocal lst
        if para:
            out.append("<p>" + "<br>".join(_inline(x) for x in para) + "</p>"); para.clear()
        if lst:
            out.append(f"<{lst[0]}>" + "".join(f"<li>{_inline(x)}</li>" for x in lst[1]) + f"</{lst[0]}>"); lst = None
        if quote:
            out.append("<blockquote>" + "<br>".join(_inline(x) for x in quote) + "</blockquote>"); quote.clear()

    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.strip().startswith("```"):
            flush()
            j = i + 1
            code = []
            while j < len(lines) and not lines[j].strip().startswith("```"):
                code.append(lines[j]); j += 1
            out.append(f"<pre><code>{html.escape(chr(10).join(code), quote=True)}</code></pre>")
            i = j + 1
            continue
        if not ln.strip():
            flush(); i += 1; continue
        m_ul, m_ol, m_q, m_h = _UL.match(ln), _OL.match(ln), _QUOTE.match(ln), _HEAD.match(ln)
        if m_ul or m_ol:
            tag = "ul" if m_ul else "ol"
            if para or quote or (lst and lst[0] != tag):
                flush()
            if not lst:
                lst = (tag, [])
            lst[1].append((m_ul or m_ol).group(1))
        elif m_q:
            if para or lst:
                flush()
            quote.append(m_q.group(1))
        elif m_h:
            flush()
            out.append(f"<p class=\"notes-h\"><strong>{_inline(m_h.group(1))}</strong></p>")
        else:
            if lst or quote:
                flush()
            para.append(ln)
        i += 1
    flush()
    return "".join(out)


# ------------------------------------------------------------------------------------------- redaction
# How "Redact my network" works (leak-proof by construction, as far as text allows):
#  1. Structural: the summary builder already knows which values are home-side and wraps each one in a marker
#     (MARK_OPEN kind MARK_SEP value MARK_CLOSE; kind ip | mac | name, or ipq = "an address: redact it if it is
#     home"). Each marked value becomes a token before any text matching runs.
#  2. Backstop over the remaining free text (titles, notes): MACs in every common notation, reverse-DNS names,
#     home IPv4/IPv6 in any form (parsed with ipaddress, :port, [v6]:port, ::ffff:a.b.c.d), then device names,
#     the user's labels and owners at any length (whole word, longest first, with numeric-suffix variants).
#  3. Every match becomes an unforgeable private-use sentinel, so a later pass can never touch it (a device named
#     "mac" cannot corrupt "[MAC 1]"); placeholders are numbered in reading order and substituted last.
MARK_OPEN, MARK_SEP, MARK_CLOSE = "\ue010", "\ue012", "\ue011"
_MARKED = re.compile("\ue010(ip|ipq|mac|name)\ue012([^\ue010\ue011\ue012]{0,300})\ue011")
_S0, _S1, _SBASE = "\ue000", "\ue001", 0xE100           # a token: _S0 + digits in U+E100.. + _S1
_STRAY = re.compile("[\ue000-\ue0ff\ue100-\uf8ff]")
_TOKEN = re.compile("\ue000([\ue100-\ue1ff]+)\ue001")
# colon or dash runs of 2-hex groups: a run longer than 6 groups ("mac:aa:..." reads as "ac:aa:...") keeps its
# leading groups as text and treats the last 6 as the MAC
_MAC = [re.compile(r"(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4,}(?![0-9A-Fa-f])"),
        re.compile(r"(?<![0-9A-Fa-f.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![0-9A-Fa-f])"),
        re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{12}(?![0-9A-Fa-f])")]
_PTR4 = re.compile(r"(?<![\w.])((?:\d{1,3}\.){1,4})in-addr\.arpa\.?", re.IGNORECASE)
_PTR6 = re.compile(r"(?<![\w.])((?:[0-9a-f]\.){1,32})ip6\.arpa\.?", re.IGNORECASE)
_CAND = re.compile(r"[0-9A-Fa-f:.]{3,200}")                # anything an address (plus :port) could hide in
PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10"]
HOST_STOP = {"localhost", "unknown", "wpad", "lan", "local", "home", "none", "null", "_gateway"}


def _home_context(extra_names=()) -> dict:
    """What counts as "my network": the effective home prefixes (Network settings, or private ranges plus the
    busiest /24 and /64), every address a device used, its MAC, and the names devices go by."""
    nets = []
    prefs = list(PRIVATE)
    try:
        from ..netlog import devices
        prefs += devices.effective_prefixes()[0]
    except (ImportError, duckdb.CatalogException):
        pass   # netlog not installed, or no network tables yet: private ranges still redact
    except Exception:
        log.exception("redaction: effective_prefixes failed; failing closed")
        raise
    for p in prefs:
        try:
            nets.append(ipaddress.ip_network(p, strict=False))
        except ValueError:
            pass
    ips: set[str] = set()
    labels: set[str] = set(n for n in extra_names if n and n.strip())
    hosts: set[str] = set()
    try:
        for r in db.query("SELECT ips, hostnames FROM devices"):
            for x in r["ips"] or []:
                try:
                    ips.add(str(ipaddress.ip_address(str(x).split("%")[0])))
                except ValueError:
                    pass
            for h in r["hostnames"] or []:
                h = str(h).strip().rstrip(".")
                hosts.add(h)
                hosts.add(h.split(".")[0])
    except (ImportError, duckdb.CatalogException):
        pass   # the devices table is absent (netlog off): nothing home-side to add from it
    except Exception:
        log.exception("redaction: reading devices failed; failing closed")
        raise
    for sql in ("SELECT name, owner FROM netlog_device_labels", "SELECT src_name AS name, NULL AS owner FROM netlog_device_merges"):
        try:
            for r in db.query(sql):
                for v in (r.get("name"), r.get("owner")):
                    if v and str(v).strip():
                        labels.add(str(v).strip())
        except (ImportError, duckdb.CatalogException):
            pass   # the labels/merges table is absent (netlog off)
        except Exception:
            log.exception("redaction: reading device labels failed; failing closed")
            raise
    # The user's own labels and owners: any length, no stop list (over-redaction beats a leak).
    # Names devices announce: skip only generic words and anything that is an address (handled above).
    hosts = {h for h in hosts if len(h) >= 2 and h.lower() not in HOST_STOP and not _is_addr(h)}
    return {"nets": nets, "ips": ips, "labels": labels, "hosts": hosts}


def _is_addr(s: str) -> bool:
    try:
        ipaddress.ip_address(s.split("%")[0])
        return True
    except ValueError:
        return False


@functools.lru_cache(maxsize=65536)
def _parse(s: str):
    if len(s) < 3 or (":" not in s and s.count(".") != 3):
        return None
    try:
        return ipaddress.ip_address(s.strip("[]").split("%")[0])
    except ValueError:
        return None


def _home_ip(a, ctx: dict) -> bool:
    """`a` (an ip_address or text) is in the home network."""
    if not isinstance(a, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        a = _parse(str(a))
        if a is None:
            return False
    if a.is_loopback or a.is_unspecified:
        return False
    if str(a) in ctx["ips"]:
        return True
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        return _home_ip(a.ipv4_mapped, ctx)
    return any(a.version == n.version and a in n for n in ctx["nets"])


def _home_net(n, ctx: dict) -> bool:
    """A network (from a partial reverse-DNS name) touches the home network."""
    return any(n.version == h.version and n.overlaps(h) for h in ctx["nets"]) or any(
        _parse(ip) in n for ip in ctx["ips"] if _parse(ip) is not None and _parse(ip).version == n.version)


def _best_home(c: str, ctx: dict):
    """The longest piece of a candidate run (cut at ':' or '.') that parses as a home address: (start, end, ip)."""
    cuts = [0] + [i + 1 for i, ch in enumerate(c) if ch in ":."]
    ends = [len(c)] + [i for i, ch in enumerate(c) if ch in ":."]
    best = None
    for a in cuts:
        for b in ends:
            if b - a < 3 or b - a > 64 or (best and b - a <= best[1] - best[0]):
                continue
            ip = _parse(c[a:b])
            if ip is not None and _home_ip(ip, ctx):
                best = (a, b, ip)
    return best


def _name_pattern(names: list[str], suffix: bool):
    names = sorted({n for n in names if n}, key=lambda n: (-len(n), n.lower()))
    if not names:
        return None
    suf = r"(?:[-_ #]?\d{1,4})?" if suffix else ""
    return re.compile(r"(?<!\w)(?:" + "|".join(re.escape(n) for n in names) + r")" + suf + r"(?!\w)", re.IGNORECASE)


def redact(text: str, ctx: dict | None = None) -> dict:
    """Replace home addresses, MAC addresses and device names with numbered placeholders ([home IP 1], [MAC 1],
    [device 1]), numbered in reading order; the same value gets the same placeholder. Addresses outside the home
    network (the threat itself) are kept. Returns {text, replaced: {ips, macs, names}}."""
    s = str(text or "")
    marked_names = [m.group(2).strip() for m in _MARKED.finditer(s) if m.group(1) == "name"]
    ctx = ctx or _home_context(marked_names)
    if marked_names and ctx is not None:
        ctx = {**ctx, "labels": set(ctx["labels"]) | {n for n in marked_names if n}}
    toks: list[tuple[str, str]] = []

    def tok(kind: str, key: str) -> str:
        toks.append((kind, key))
        n, digits = len(toks) - 1, ""
        while True:
            digits = chr(_SBASE + n % 256) + digits
            n //= 256
            if not n:
                break
        return _S0 + digits + _S1

    # 1. structural markers (stray private-use characters in the input are dropped first, so nothing can forge one)
    s = re.sub("[\ue000\ue001\ue013-\ue0ff\ue100-\uf8ff]", "", s)

    def marked(m):
        kind, v = m.group(1), m.group(2)
        if kind == "ipq":
            ip = _parse(v.strip())
            if ip is None:
                return v                      # not an address: left to the text passes below
            return tok("ip", str(ip.ipv4_mapped or ip) if isinstance(ip, ipaddress.IPv6Address) else str(ip)) if _home_ip(ip, ctx) else v
        if kind == "ip":
            ip = _parse(v.strip())
            return tok("ip", str(ip) if ip else v.strip().lower())
        if kind == "mac":
            return tok("mac", re.sub(r"[^0-9a-f]", "", v.lower()))
        return tok("name", v.strip().lower()) if v.strip() else ""
    s = _MARKED.sub(marked, s)
    s = re.sub("[\ue010-\ue012]", "", s)      # a broken marker never shows a raw value's delimiters

    # 2. MAC addresses, every notation
    def mac(m):
        v = m.group(0)
        head, v = (v[:-17], v[-17:]) if len(v) > 17 and v[-15] in ":-" and v[2] in ":-" else ("", v)
        return head + tok("mac", re.sub(r"[^0-9a-f]", "", v.lower()))
    for rx in _MAC:
        s = rx.sub(mac, s)

    # 3. reverse-DNS names of home addresses
    def ptr4(m):
        parts = m.group(1).rstrip(".").split(".")[::-1]
        try:
            net = ipaddress.ip_network(".".join(parts + ["0"] * (4 - len(parts))) + f"/{8 * len(parts)}", strict=False)
        except ValueError:
            return m.group(0)
        return tok("ip", str(net.network_address) if len(parts) == 4 else str(net)) if _home_net(net, ctx) else m.group(0)

    def ptr6(m):
        nib = m.group(1).rstrip(".").split(".")[::-1]
        h = "".join(nib).ljust(32, "0")
        try:
            net = ipaddress.ip_network(":".join(h[i:i + 4] for i in range(0, 32, 4)) + f"/{4 * len(nib)}", strict=False)
        except ValueError:
            return m.group(0)
        return tok("ip", str(net.network_address) if len(nib) == 32 else str(net)) if _home_net(net, ctx) else m.group(0)
    s = _PTR4.sub(ptr4, s)
    s = _PTR6.sub(ptr6, s)

    # 4. home addresses in any written form
    def cand(m):
        c = m.group(0)
        if ":" not in c and c.count(".") < 3:
            return c
        out, rest = [], c
        while True:
            b = _best_home(rest, ctx)
            if not b:
                out.append(rest)
                break
            a, e, ip = b
            key = str(ip.ipv4_mapped) if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else str(ip)
            out.append(rest[:a]); out.append(tok("ip", key))
            rest = rest[e:]
        return "".join(out)
    s = _CAND.sub(cand, s)

    # 5. names: the user's labels and owners (with numeric-suffix variants), then names devices announce
    for names, suffix in ((ctx["labels"], True), (ctx["hosts"], False)):
        rx = _name_pattern(list(names), suffix)
        if rx:
            s = rx.sub(lambda m: tok("name", m.group(0).lower()), s)

    # 6. placeholders, numbered in reading order, substituted last
    label = {"ip": "home IP", "mac": "MAC", "name": "device"}
    nums: dict[str, dict[str, int]] = {"ip": {}, "mac": {}, "name": {}}

    def final(m):
        n = 0
        for ch in m.group(1):
            n = n * 256 + (ord(ch) - _SBASE)
        kind, key = toks[n]
        k = nums[kind]
        if key not in k:
            k[key] = len(k) + 1
        return f"[{label[kind]} {k[key]}]"
    s = _TOKEN.sub(final, s)
    s = _STRAY.sub("", s)
    return {"text": s, "replaced": {"ips": len(nums["ip"]), "macs": len(nums["mac"]), "names": len(nums["name"])}}
