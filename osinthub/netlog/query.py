"""The netlog hunt query grammar: filters, exclusions and group-by fields over logs and alerts.

    query = term ( whitespace term )*
    term  = ["-" | "!"] field ":" values      include (or, with - / !, exclude) rows where field matches any value
          | ["-" | "!"] word                  text contains (or does not contain) word
    values = value ("," value)*               OR within one term; terms are ANDed
    value  = literal | prefix* | *suffix      wildcards with *
           | CIDR (ip fields)                 192.0.2.0/24, 2001:db8::/32
           | >N | >=N | <N | <=N              numeric comparison
           | null                             field is missing

Fields on logs: any netlog column, the virtual fields ip (orig_h, resp_h or a DNS answer), port (orig_p or
resp_p), device, text, and raw.<field> for any field of the original JSON (raw.ja3, raw.id.orig_h,
raw.flow.bytes_toserver). Fields on alerts: any alerts column and evidence.<path>. Quote values with spaces:
query='raw.user_agent:"curl/8.0"'. Grammar and examples: okf/data/netlog.md#hunt-queries
"""
from __future__ import annotations

import re

from fastapi import HTTPException

from .. import apiutil
from . import ipnum

LOG_COLS = {"ts", "uid", "log_type", "orig_h", "orig_p", "resp_h", "resp_p", "proto", "service", "duration",
            "orig_bytes", "resp_bytes", "conn_state", "history", "query", "answers", "server_name", "host", "uri",
            "mac", "resp_mac", "hostname", "file_id"}
LOG_NUM = {"orig_p", "resp_p", "duration", "orig_bytes", "resp_bytes"}
LOG_IP = {"orig_h", "resp_h"}
ALERT_COLS = {"id", "ts", "last_ts", "severity", "device", "indicator", "source", "rule", "direction", "title",
              "count", "status"}
ALERT_NUM = {"count"}
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*$")
DEVICE_VIEW = """(SELECT n.*, coalesce(d1.device, d2.device) AS device FROM netlog n
    ASOF LEFT JOIN netlog_ipdev d1 ON d1.ip = n.orig_h AND n.ts >= d1.from_ts
    ASOF LEFT JOIN netlog_ipdev d2 ON d2.ip = n.resp_h AND n.ts >= d2.from_ts)"""


_SEG_RE = re.compile(r"^[A-Za-z0-9_\-]+$")


def _json_path(col: str, path: str) -> str:
    """Flat Zeek key ("id.orig_h") first, then the nested path (EVE "flow.bytes_toserver")."""
    if not path or not all(_SEG_RE.match(p) for p in path.split(".")):
        raise HTTPException(400, f"bad field path: {path!r} (letters, digits, _ and - separated by dots)")
    flat = path.replace('"', "")
    nested = ".".join(f'"{p}"' for p in path.split("."))
    return f"""coalesce(json_extract_string({col}, '$."{flat}"'), json_extract_string({col}, '$.{nested}'))"""


def log_expr(field: str) -> str:
    """SQL expression for a groupable log field."""
    f = field.strip()
    if f in LOG_COLS:
        return f
    if f == "device":
        return "device"
    if f in ("hour", "day", "minute"):
        return f"date_trunc('{f}', ts)"
    if f.startswith("raw."):
        return _json_path("raw", f[4:])
    raise HTTPException(400, f"unknown field: {field} (columns, device, hour, day, raw.<field>)")


def alert_expr(field: str) -> str:
    f = field.strip()
    if f in ALERT_COLS:
        return f
    if f in ("hour", "day"):
        return f"date_trunc('{f}', ts)"
    if f.startswith("evidence."):
        return _json_path("evidence", f[9:])
    raise HTTPException(400, f"unknown alert field: {field} (columns, day, hour, evidence.<path>)")


def _value_clause(expr: str, v: str, numeric: bool, ip: bool, params: list) -> str:
    if v.lower() == "null":
        return f"{expr} IS NULL"
    m = re.match(r"^(>=|<=|>|<)(-?\d+(\.\d+)?)$", v)
    if m:
        params.append(float(m.group(2)))
        return f"try_cast({expr} AS DOUBLE) {m.group(1)} ?"
    if ip and "/" in v:
        r = ipnum.net_range(v)
        if not r:
            raise HTTPException(400, f"bad prefix: {v}")
        params += [str(r[0]), str(r[1])]
        return f"{expr} IN (SELECT ip FROM netlog_ipnum WHERE n BETWEEN ?::UHUGEINT AND ?::UHUGEINT)"
    if "*" in v:
        params.append(like_escape(v).replace("*", "%"))
        return f"CAST({expr} AS VARCHAR) ILIKE ? ESCAPE '\\'"
    if numeric:
        try:
            params.append(float(v))
            return f"{expr} = ?"
        except ValueError:
            raise HTTPException(400, f"not a number: {v}")
    if ip:
        v = ipnum.canonical(v) or v
    params.append(v)
    return f"lower(CAST({expr} AS VARCHAR)) = lower(?)"


like_escape = apiutil.like_escape


def log_term(field: str, values: list[str], params: list) -> str:
    ors = []
    for v in values:
        if field == "ip":
            if "/" in v:
                r = ipnum.net_range(v)
                if not r:
                    raise HTTPException(400, f"bad prefix: {v}")
                # either end, or a DNS answer: netlog_ipnum holds every address seen in all three (update_ipnum).
                # Every part is a hash semi-join, so a broad range costs what a narrow one does: the answers part
                # unnests only rows that have answers and joins them to the range (never a list of the range per row)
                params += [str(r[0]), str(r[1])] * 3
                sub = "SELECT ip FROM netlog_ipnum WHERE n BETWEEN ?::UHUGEINT AND ?::UHUGEINT"
                ors.append(f"(orig_h IN ({sub}) OR resp_h IN ({sub}) OR rk IN (SELECT rk FROM (SELECT rk, "
                           f"unnest(answers) AS a FROM netlog WHERE answers IS NOT NULL) WHERE a IN ({sub})))")
            elif "*" in v:
                ors.append("(" + _value_clause("orig_h", v, False, True, params) + " OR "
                           + _value_clause("resp_h", v, False, True, params) + ")")
            else:
                c = ipnum.canonical(v) or v
                params += [c, c, c]
                ors.append("(orig_h = ? OR resp_h = ? OR list_contains(answers, ?))")
        elif field == "port":
            ors.append("(" + _value_clause("resp_p", v, True, False, params) + " OR "
                       + _value_clause("orig_p", v, True, False, params) + ")")
        elif field == "device":
            # time-aware: the row's IP must have been held by the device at the row's time
            params += [v, v, v, v]
            ors.append("""rk IN (
                SELECT n.rk FROM netlog n ASOF JOIN netlog_ipdev d ON d.ip = n.orig_h AND n.ts >= d.from_ts
                WHERE n.orig_h IN (SELECT ip FROM netlog_ipdev WHERE device = ?) AND d.device = ?
                UNION ALL
                SELECT n.rk FROM netlog n ASOF JOIN netlog_ipdev d ON d.ip = n.resp_h AND n.ts >= d.from_ts
                WHERE n.resp_h IN (SELECT ip FROM netlog_ipdev WHERE device = ?) AND d.device = ?)""")
        elif field == "text":
            ors.append(text_clause(v, params))
        elif field in ("uid", "file_id") and "*" not in v:
            params.append(v)
            ors.append(f"{field} = ?")
        else:
            expr = log_expr(field)
            ors.append(_value_clause(expr, v, field in LOG_NUM, field in LOG_IP, params))
    return "(" + " OR ".join(ors) + ")"


def text_clause(v: str, params: list) -> str:
    """Literal substring (no LIKE wildcards) in query, SNI, host, URI or raw JSON, or an exact uid."""
    e = f"%{like_escape(v)}%"
    params += [e] * 4 + [v, e]
    return ("(query ILIKE ? ESCAPE '\\' OR server_name ILIKE ? ESCAPE '\\' OR host ILIKE ? ESCAPE '\\' "
            "OR uri ILIKE ? ESCAPE '\\' OR uid = ? OR raw ILIKE ? ESCAPE '\\')")


def _tokens(query: str) -> list[tuple[bool, str, bool, bool]]:
    """Split on whitespace, keeping "quoted parts" together. Returns (negated, text, wholly_quoted, has_quotes)."""
    out, i, n = [], 0, len(query)
    while i < n:
        while i < n and query[i].isspace():
            i += 1
        if i >= n:
            break
        neg = query[i] in "-!" and i + 1 < n and not query[i + 1].isspace()
        if neg:
            i += 1
        buf, quoted_whole, start = [], query[i] == '"', i
        while i < n and not query[i].isspace():
            if query[i] == '"':
                j = i + 1
                while j < n and query[j] != '"':
                    j += 2 if query[j] == "\\" else 1
                if j >= n:
                    raise HTTPException(400, "bad query: unbalanced quote")
                buf.append(query[i + 1:j].replace('\\"', '"'))
                i = j + 1
            else:
                buf.append(query[i])
                i += 1
        quoted_whole = quoted_whole and query[i - 1] == '"' and query[start:i].count('"') == 2
        out.append((neg, "".join(buf), quoted_whole, '"' in query[start:i]))
    return out


def _is_log_field(f: str) -> bool:
    return f in LOG_COLS or f in ("ip", "port", "device", "text", "hour", "day", "minute") or f.startswith("raw.")


def _is_alert_field(f: str) -> bool:
    return f in ALERT_COLS or f in ("text", "day", "hour") or f.startswith("evidence.")


def _terms(query: str, known=_is_log_field) -> list[tuple[bool, str | None, list[str]]]:
    """Terms of a query. `field:value` only when field is known; anything else (URLs, host:port,
    [v6]:port) is free text."""
    out = []
    for neg, t, quoted, has_q in _tokens(query):
        if not quoted and ":" in t:
            f, v = t.split(":", 1)
            if _FIELD_RE.match(f) and known(f):
                vals = [x for x in v.split(",") if x != ""] if "," in v and not has_q else [v]
                out.append((neg, f, vals or [""]))
                continue
        out.append((neg, None, [t]))
    return out


def log_where(query: str | None, params: list) -> list[str]:
    """Clauses for a log query string."""
    clauses = []
    for neg, f, vals in _terms(query or ""):
        c = log_term(f or "text", vals, params)
        clauses.append(f"NOT coalesce({c}, false)" if neg else c)
    return clauses


def alert_where(query: str | None, params: list) -> list[str]:
    clauses = []
    for neg, f, vals in _terms(query or "", _is_alert_field):
        ors = []
        for v in vals:
            if f is None or f == "text":
                params += [f"%{like_escape(v)}%"] * 4
                ors.append("(title ILIKE ? ESCAPE '\\' OR indicator ILIKE ? ESCAPE '\\' "
                           "OR device ILIKE ? ESCAPE '\\' OR evidence ILIKE ? ESCAPE '\\')")
            else:
                ors.append(_value_clause(alert_expr(f), v, f in ALERT_NUM, False, params))
        c = "(" + " OR ".join(ors) + ")"
        clauses.append(f"NOT coalesce({c}, false)" if neg else c)
    return clauses


def _quote(v: str) -> str:
    """A value as one query token: quoted when it has whitespace or quotes."""
    if not any(ch.isspace() or ch == '"' for ch in v):
        return v
    return '"' + v.replace('"', '\\"') + '"'


def excludes(not_ip=None, not_port=None, not_device=None, not_log_type=None, not_q=None) -> str:
    """The not_* parameters as an equivalent query string.

    Each comma-separated value becomes its own -field:value term (NOT a AND NOT b), with spaces
    around commas dropped as the include filters do, so "a, b" cannot turn b into free text."""
    parts = []
    for f, v in (("ip", not_ip), ("port", not_port), ("device", not_device), ("log_type", not_log_type)):
        for x in (y.strip() for y in str(v or "").split(",")):
            if x:
                parts.append(f"-{f}:{_quote(x)}")
    if not_q:
        parts.append('-"' + not_q.replace('"', '\\"') + '"')
    return " ".join(parts)
