"""Defender text: the parts of a report that address defenders, not the attacker.

Technique extraction (the artefact cues, the procedure-example proposals and the model's technique
quotes in extract.py) must only read what the attackers did. Vendor reports end with hunting
queries, detection-coverage tables and "Use / Verify / Turn on Microsoft Defender ..." advice, and
analysts write "To deobfuscate the command line, it's necessary to ...". Those sentences look like
procedure examples to the kNN and to the cues. A wrong drop costs a real technique and a missed drop
costs one false positive, so this module only marks what is clearly defender material:

* sections: a real heading line (a bare line or a Markdown heading, never a list item) from a fixed
  list, followed by text within three lines (a site menu or table of contents has only short labels).
  End-of-report sections ("Advanced hunting", "Hunting queries", "Mitigation and protection guidance",
  "Microsoft Defender XDR detections", "Actionable investigation methods", "YARA rules") run to a reset
  heading (ATT&CK, indicators, references, summary, conclusion, a tactic name) or the end of the text.
  Other defender headings ("Detections", "Mitigations", "Recommendations", "Protection and mitigation",
  "Remediation", "Prevention") end at the next heading whose first line is text (not a heading, code or
  a rule listing);
* query code anywhere: a KQL or SPL block (it must hold a table line such as DeviceProcessEvents
  or a "| where"-style pipe line; Markdown table rows never count), a YARA rule (rule ... { condition:
  ... }) and the YAML block of a Sigma rule around its "detection:" / "logsource:" line;
* analyst procedure sentences anywhere, only the shapes the 2026-11-19 audit found ("To deobfuscate
  ..., it's necessary to", "... decoded using this CyberChef recipe", "Once deobfuscated, we can see",
  "deobfuscated and refactored for readability").

Not masked, by design (kept simple, owner 2026-11-19): advice sentences outside a defender section,
and defender headings outside the fixed lists. A defender heading placed before attacker narrative
hides that narrative until the section ends.

IOCs, actor and malware names and the model's input are not affected: only technique extraction
reads the masked text. Stdlib only. Docs: okf/data/entities.md#defender-text

    python -m osinthub.entities.defender FILE [--cut MARKER] [-v]   # what would be removed, and why
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------- headings
_LIST_ITEM = re.compile(r"^(?:[-*•–—·▪◦]|\(?\d{1,2}[.)]|\(?[a-z][.)])\s")
_NUMBERED = re.compile(r"^\d{1,2}[.)]\s+(?=\S)")

# End-of-report defender sections (Microsoft's standard closing sections, hunting and rule appendices).
# They run to a reset heading or the end of the text: sub-headings inside them do not close them.
_OPEN_STRONG = re.compile(r"""(?:
    advanced\ hunting(?:\ (?:queries|query|guidance))?
  | (?:threat\ )?hunting\ (?:queries|query|guidance)
  | (?:mitigation|protection|detection|defen[cs]e|hardening|security)
        (?:\ (?:and|&)\ (?:mitigation|protection|detection|response|hunting|remediation))?\ guidance
  | microsoft\ defender(?:\ xdr|\ for\ [\w ]{1,20}?|\ antivirus)?\ (?:detections?|coverage)
        (?:\ (?:and|&)\ \w+)?
  | (?:yara|sigma|snort|suricata|kql)\ (?:rules?|queries|signatures)
  | actionable\ investigation\ methods
)""", re.X | re.I)
# Defender headings that open a section which ends at the very next heading (unless that heading is
# itself in _CONTINUE): no guessing from the text under them.
_OPEN_WEAK = re.compile(r"""(?:
    detections? | detection\ (?:opportunities|rules|logic|coverage|signatures|queries)
  | (?:detection|protection|prevention)\ (?:and|&)\ (?:response|hunting|mitigations?|prevention|remediation)
  | (?:recommended\ )?mitigations? | mitigation\ (?:steps|measures|strategies|recommendations)
  | (?:security\ )?recommendations?(?:\ for\ (?:defenders|organi[sz]ations|customers))?
  | recommended\ (?:actions?|steps|mitigations|controls)
  | remediation(?:\ (?:actions?|steps|guidance))? | prevention
  | investigation\ (?:guidance|steps|actions)
  | how\ to\ (?:protect|defend|stay\ protected)(?:\ .{0,60})?
)""", re.X | re.I)
# Defender-side headings that keep an open section open but never open one.
_CONTINUE = re.compile(r"""(?:
    .{0,60}\b(?:microsoft\ defender|defender\ (?:xdr|for|antivirus|experts)|security\ copilot|microsoft\ sentinel)
        \b.{0,60}
  | threat\ intelligence\ reports
  | (?:immediate|preventive|preventative|remediation|investigation|response|containment|recovery)
        \ (?:actions|controls|steps|measures)
  | follow-up\ investigation.{0,40}
  | (?:sigma|yara|suricata|snort)(?:\ (?:rules?|rule\ set|repo))?
)""", re.X | re.I)
# A heading that always ends a defender section: back to report structure.
_RESET_HEAD = re.compile(r"""(?:
    (?:mitre\ )?att&ck.{0,60} | mitre(?:\ .{0,60})?
  | (?:indicators?\ of\ compromise|iocs?|indicators|network\ indicators|file\ indicators|host\ indicators)
        (?:\ .{0,40})?
  | references | sources | appendix.{0,80} | acknowledge?ments? | about\ (?:the\ )?authors?
  | (?:case\ |executive\ )?summary | conclusions?(?:\ .{0,40})? | outlook | (?:key\ )?findings | key\ takeaways
  | timeline | diamond\ model
  | (?:attack\ chain|activity|campaign|technical)\ (?:overview|analysis|details)
  | overview | analysis | technical\ analysis | background | introduction | attribution
  | initial\ access | execution | persistence | privilege\ escalation | defen[cs]e\ evasion
  | credential\ access | discovery | lateral\ movement | collection | command\ and\ control
  | exfiltration | impact
)""", re.X | re.I)


def _heading(line: str, numbered: bool = False) -> str | None:
    """The heading text when a line looks like a heading: short, no sentence end, starts with a capital
    or digit, not a list item. A Markdown "#" prefix is allowed. With `numbered` (only used to END a
    section, where a missed heading costs attacker text) "1. Title", a lower-case start ("macOS variant")
    and a question ("What happened next?") count too; such lines never open a section."""
    s = line.strip()
    if not (2 < len(s) <= 100) or s[-1] in ".!;,|" or (s[-1] == "?" and not numbered):
        return None
    s = re.sub(r"^#{1,6}\s+", "", s)
    if numbered and _NUMBERED.match(s):
        s = _NUMBERED.sub("", s)
    elif _LIST_ITEM.match(s):
        return None
    s = re.sub(r"\s+", " ", s.rstrip(":").strip().replace("&amp;", "&"))
    return s if s and (s[0].isupper() or s[0].isdigit() or (numbered and s[0].isalpha())) else None


def _is_prose(s: str) -> bool:
    return len(s) >= 50 and len(s.split()) >= 7


# ---------------------------------------------------------------- query code
_KQL_TABLE = re.compile(
    r"^(?:Device\w*(?:Events|Info)|Email\w*(?:Events|Info)|Identity\w*Events|CloudAppEvents|AlertInfo|AlertEvidence|"
    r"UrlClickEvents|BehaviorEntities|BehaviorInfo|SecurityEvent|SigninLogs|AADSignInEventsBeta|AuditLogs|"
    r"OfficeActivity|Syslog|CommonSecurityLog|ThreatIntelligenceIndicator)\b\s*(?:\|.*)?$")
_PIPE = re.compile(r"^\|\s*(?:where|project|extend|summarize|join|distinct|take|top|sort|order|parse|mv-expand|"
                   r"count|limit|union|invoke|evaluate|stats|table|search|eval|rex|dedup|fields|rename|lookup|"
                   r"inputlookup|tstats|make-series|render)\b", re.I)
_CODE_OPS = re.compile(r"==|=~|!=|\bin~|\bhas(?:_any|_all|prefix|suffix)?\b|\bstartswith\b|\bendswith\b|"
                       r"\bcontains\b|\bmatches regex\b|\||\bago\(\d")
_YARA_START = re.compile(r"^rule\s+\w+(?:\s*:\s*[\w ]+)?\s*\{?\s*$")
_SIGMA_ANCHOR = re.compile(r"^(?:logsource|detection):\s*$")
_YAML_LINE = re.compile(r"^(?:[\w.|-]+:(?:\s|$)|-\s)")


def _table_row(s: str) -> bool:
    """A Markdown table row ("| a | b |", "| a |", "|---|"), as trafilatura writes HTML tables: never query code."""
    return len(s) >= 2 and s.startswith("|") and s.endswith("|")


def _codeish(s: str) -> bool:
    """A line that can sit inside a KQL / SPL query (the block still needs a table or pipe line)."""
    if _table_row(s):
        return False
    if s.endswith((".", ":")) and len(s.split()) >= 6:
        return False                                        # a sentence introducing the query
    return bool(_KQL_TABLE.match(s) or _PIPE.match(s) or re.match(r"^(?:let\s+\w+\s*=|//\s|index\s*=)", s)
                or _CODE_OPS.search(s) or re.match(r"^(?:[(){}\[\]@\"']|(?:or|and|not)\b)", s)
                or re.match(r"^[\w.]+,?\)?;?$", s) or (s.endswith((",", "(", ")")) and len(s.split()) <= 4))


def _code_lines(lines) -> set[int]:
    """Indexes of the lines that are query code. Linear in the number of lines."""
    st = [raw.strip() for _, raw in lines]
    out: set[int] = set()
    i, n = 0, len(st)
    while i < n:
        s = st[i]
        if _YARA_START.match(s):                            # YARA: rule ... { ... condition: ... }
            j, cond, body = i + 1, False, False             # (a page may cut the rule off before its "}":
            while j < n and j - i < 300 and st[j] != "}":   #  then it ends at the first blank line after the
                if body and not st[j]:                      #  condition's own text)
                    break
                body = body or (cond and bool(st[j]))
                cond = cond or st[j].startswith("condition:")
                j += 1
            if cond and j < n:
                out.update(range(i, j + 1 if st[j] == "}" else j))
                i = j + 1
                continue
        if s and _codeish(s):                               # KQL / SPL block: contiguous lines
            j = i
            while j < n and st[j] and _codeish(st[j]):
                j += 1
            if any(_KQL_TABLE.match(st[k]) or _PIPE.match(st[k]) for k in range(i, j)):
                out.update(range(i, j))
            i = max(j, i + 1)
            continue
        i += 1
    done = -1                                               # Sigma: only the YAML block around the anchor
    for i, s in enumerate(st):
        if i <= done or not _SIGMA_ANCHOR.match(s):
            continue
        a = i
        while a > 0 and a - 1 > done and st[a - 1] and _YAML_LINE.match(st[a - 1]):
            a -= 1
        b = i
        while b + 1 < n and st[b + 1] and _YAML_LINE.match(st[b + 1]):
            b += 1
        out.update(range(a, b + 1))
        done = b
    return out


# ---------------------------------------------------------------- sentences
# A sentence ends at . ! ? or 。 (plus a closing quote or bracket) followed by space, or right after 。.
_SPLIT = re.compile(r"[.!?][\"'”’)]?(\s+)|。[\"'”’)]?(\s*)")
_BULLET = re.compile(r"^(?:[-*•–—]\s*|\d{1,2}[.)]\s+)")
# Analyst procedure, masked anywhere: only the shapes the 2026-11-19 audit found (its category D).
_ANALYST = re.compile(
    r"^To (?:deobfuscate|decode|decrypt)\b[^.]{0,80}?,\s*(?:it(?:'|’)s|it is) necessary to\b"
    r"|\b(?:deobfuscated|decoded) using (?:the following|this) cyberchef recipe\b"
    r"|^Once deobfuscated, we can (?:see|spot)\b"
    r"|\b(?:deobfuscated|decoded) and (?:refactored|beautified|cleaned up) for readability\b", re.I)


def _sentences(s: str) -> list[tuple[int, str]]:
    """(offset, sentence) pieces of a line. Splits at every sentence end, so a masked analyst sentence
    never takes the next sentence with it."""
    out, start = [], 0
    for m in _SPLIT.finditer(s):
        g = 1 if m.group(1) is not None else 2
        if m.end() >= len(s):
            break
        out.append((start, s[start:m.start(g)]))
        start = m.end()
    out.append((start, s[start:]))
    return out


def _followed_by_text(lines, code, i: int) -> bool:
    """A defender heading opens a section only when text follows within three lines (a site menu or a
    table of contents holds only short labels)."""
    seen = 0
    for j in range(i + 1, min(len(lines), i + 8)):
        s = lines[j][1].strip()
        if not s:
            continue
        if j in code or _is_prose(s) or _rule_line(s):
            return True
        hh = _heading(s)
        if hh and _RESET_HEAD.fullmatch(hh):
            return False
        seen += 1
        if seen >= 3:
            return False
    return False


# IDS signature names ("ET POLICY PsExec service created", "2035258 - ET EXPLOIT ...", "(Snort VRT) ..."):
# rule listings, never headings and never attacker text.
_ET_RULE = re.compile(r"^(?:\d+ - )?(?:ETPRO|ET) [A-Z_]{3,} \S|^\(Snort[^)]*\) ")
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")


def _rule_line(s: str) -> bool:
    """A line of a rule listing: an IDS signature name, a bare URL (a rule repository link) or a short
    line naming a rule by its id ("AdFind Discovery id: 5004…", "5004… : AdFind Discovery"). A sentence
    that mentions a GUID (a CLSID, a mutex) ends with a full stop and is not one."""
    return bool(_ET_RULE.search(s) or re.fullmatch(r"https?://\S+", s) or s.startswith(("/*", "*/", 'import "'))
                or (_UUID.search(s) and len(s) < 160 and not s.endswith(".")))


def _text_follows(lines, code, i: int) -> bool:
    """The first non-empty line after line i is attacker-side text: not code, not another heading and
    not an IDS rule name (a short sentence, a command line or a list item all count)."""
    for j in range(i + 1, len(lines)):
        s = lines[j][1].strip()
        if s:
            return j not in code and not _rule_line(s) and _heading(s) is None
    return False


_RULESET_HEAD = re.compile(r"(?:sigma|yara|suricata|snort)(?:\ (?:rules?|rule\ set|repo))?", re.I)


def _closes(lines, code, i: int, kind: str, h: str) -> bool:
    if kind == "strong":                    # an end-of-report section: only a reset heading ends it
        return bool(_RESET_HEAD.fullmatch(h)) and not _CONTINUE.fullmatch(h)
    if _rule_line(h) or _RULESET_HEAD.fullmatch(h):
        return False                        # a rule listing's own sub-heading ("Sigma", "YARA") or entry
    return _RESET_HEAD.fullmatch(h) is not None or _text_follows(lines, code, i)   # weak: the next heading with text


# ---------------------------------------------------------------- spans
def defender_spans(text: str) -> list[tuple[int, int, str]]:
    """[(start, end, why)] character spans of defender text, sorted and non-overlapping.
    why is "section: <heading>", "code" or "analyst"."""
    text = text or ""
    lines, off = [], 0
    for raw in text.splitlines(keepends=True):
        lines.append((off, raw))
        off += len(raw)
    code = _code_lines(lines)
    spans: list[tuple[int, int, str]] = []
    section: str | None = None       # heading of the open defender section
    kind = ""
    for i, (start, raw) in enumerate(lines):
        line = raw.rstrip("\r\n")
        s = line.strip()
        if not s:
            continue
        end = start + len(line)
        if section is not None:
            h = None if i in code else _heading(line, numbered=True)
            if h and _closes(lines, code, i, kind, h):
                section = None
            else:
                spans.append((start, end, f"section: {section}"))
                continue
        if i in code:
            spans.append((start, end, "code"))
            continue
        h = _heading(line)
        if h and (_OPEN_STRONG.fullmatch(h) or _OPEN_WEAK.fullmatch(h)) and _followed_by_text(lines, code, i):
            section, kind = h, ("strong" if _OPEN_STRONG.fullmatch(h) else "weak")
            spans.append((start, end, f"section: {h}"))
            continue
        base = start + (len(line) - len(line.lstrip()))
        for off_, part in _sentences(s):
            part = part.rstrip()
            if part and _ANALYST.search(_BULLET.sub("", part.strip())):
                spans.append((base + off_, base + off_ + len(part), "analyst"))
    return _merge(spans)


def _merge(spans):
    out: list[tuple[int, int, str]] = []
    for a, b, why in sorted(spans):
        if out and a <= out[-1][1]:
            pa, pb, pw = out[-1]
            out[-1] = (pa, max(pb, b), pw)
        else:
            out.append((a, b, why))
    return out


def mask(text: str, spans=None) -> str:
    """The text with defender spans blanked (newlines kept), so offsets, lines and sentence ends
    stay where they were."""
    text = text or ""
    spans = defender_spans(text) if spans is None else spans
    if not spans:
        return text
    out, prev = [], 0
    for a, b, _ in spans:
        out.append(text[prev:a])
        out.append(re.sub(r"[^\n]", " ", text[a:b]))
        prev = b
    out.append(text[prev:])
    return "".join(out)


def norm_flags(text: str, spans) -> tuple[str, list[bool]]:
    """(re.sub(r"\\s+", " ", text).strip(), a defender flag per character of it)."""
    inside = bytearray(len(text))
    for a, b, _ in spans:
        inside[a:b] = b"\x01" * (b - a)
    chars: list[str] = []
    flags: list[bool] = []
    space = False
    for i, ch in enumerate(text):
        if ch.isspace():
            space = True
            continue
        if space and chars:
            chars.append(" ")
            flags.append(bool(inside[i]))
        space = False
        chars.append(ch)
        flags.append(bool(inside[i]))
    return "".join(chars), flags


def mostly_defender(norm: str, flags: list[bool], a: int, b: int) -> bool:
    """More than half of the non-space characters of norm[a:b] are defender text."""
    tot = dfn = 0
    for i in range(max(a, 0), min(b, len(norm))):
        if norm[i] != " ":
            tot += 1
            dfn += flags[i]
    return tot > 0 and dfn * 2 > tot


def summary(text: str) -> dict:
    """What the filter removes from a text: characters, share, section headings and counts."""
    spans = defender_spans(text)
    removed = sum(len(re.sub(r"\s", "", text[a:b])) for a, b, _ in spans)
    total = len(re.sub(r"\s", "", text or "")) or 1
    heads: list[str] = []
    kinds: dict[str, int] = {}
    for _, _, why in spans:
        if why.startswith("section: "):
            h = why[len("section: "):]
            if h not in heads:
                heads.append(h)
            kinds["section"] = kinds.get("section", 0) + 1
        else:
            kinds[why] = kinds.get(why, 0) + 1
    return {"chars": total, "removed": removed, "pct": round(100 * removed / total, 1), "sections": heads,
            "spans": kinds}


def _main(argv=None) -> int:
    import argparse
    from pathlib import Path
    ap = argparse.ArgumentParser(description="Show what the defender-text filter removes from text files.")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--cut", help="score only the text before this marker (e.g. an IoC heading)")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every removed span")
    a = ap.parse_args(argv)
    for f in a.files:
        t = Path(f).read_text(encoding="utf-8")
        if a.cut:
            marker = a.cut.encode().decode("unicode_escape")
            if marker in t:
                t = t[:t.find(marker)]
            else:
                print(f"{f}: WARNING: --cut marker {a.cut!r} not found, scoring the whole text")
        s = summary(t)
        print(f"{f}: removed {s['removed']}/{s['chars']} non-space chars ({s['pct']}%) {s['spans']}")
        for h in s["sections"]:
            print(f"    section: {h}")
        if a.verbose:
            for x, y, why in defender_spans(t):
                if not why.startswith("section"):
                    print(f"    {why}: {re.sub(chr(10), ' / ', t[x:y])[:160]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
