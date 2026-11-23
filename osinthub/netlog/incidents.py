"""Incidents, "this is expected" rules and the one "needs you" count, over the per-day alerts.

* An alert is still one per device, indicator, list, rule and UTC day (matcher.py). An **incident** joins the
  alerts of one device + indicator + kind whose contacts continue (no gap longer than GAP_HOURS), so a beacon that
  runs across UTC midnight, or every night for a month, is one incident with its first and last time.
* A **rule** ("this is expected") hides matching alerts, current and future, without deleting them: scope this
  device + this indicator, any device + this indicator, or this device + this kind; optional note and expiry
  (contacts after the expiry alert again). Deleting a rule brings its alerts straight back.
* **Needs you** = incidents that are untriaged, not hidden by a rule, not demo data, of high or medium severity.
  The top-bar badge, the Network header and tab, and the alerts list all show this number.

Docs: okf/data/netlog.md#incidents-and-expected-traffic
"""
from __future__ import annotations

import datetime as dt
import threading
import uuid

from .. import db
from . import util

GAP_HOURS = 26          # a contact this soon after the last one continues the incident (a daily check-in does)
DEMO_FILES = "(SELECT id FROM netlog_files WHERE origin = 'demo' OR name LIKE 'night-desk-demo%')"

# The kind of an alert, from its rule, direction and listed category. One expression, used for incidents,
# rules and the API: ids | kev | historical | retro | sensor | newdev | <category>:out | <category>:in | <category>:other
KIND_SQL = """(CASE WHEN {t}rule = 'sensor_silent' THEN 'sensor'
     WHEN {t}rule = 'new_device' THEN 'newdev'
     WHEN {t}rule = 'ids_signature' THEN 'ids'
     WHEN {t}direction IN ('historical', 'retro') THEN {t}direction
     WHEN json_extract_string({t}evidence, '$.indicator.category') = 'kev' THEN 'kev'
     ELSE coalesce(json_extract_string({t}evidence, '$.indicator.category'), 'other') || ':' ||
          CASE WHEN {t}direction IN ('outbound', 'dns') THEN 'out' WHEN {t}direction = 'inbound' THEN 'in' ELSE 'other' END
END)"""


def kind_sql(table: str = "") -> str:
    return KIND_SQL.replace("{t}", f"{table}." if table else "")


# The incident key: the direction family (not the list's category) + device + the value actually seen in the logs
# (an address inside a listed range is that address), so two lists naming the same contact are one incident.
# Inbound and historical alerts are already aggregated across devices: their incident is per value.
_FAM = f"""regexp_replace({kind_sql()}, '^[^:]*:', '')"""
_OBS = "coalesce(json_extract_string(evidence, '$.indicator.observed[0]'), indicator, '')"
_IKEY = f"""concat_ws('|', {_FAM}, CASE WHEN {_FAM} IN ('in', 'historical') THEN '*' ELSE coalesce(device, '?') END,
                     CASE WHEN {kind_sql()} IN ('ids', 'kev', 'sensor', 'newdev') THEN coalesce(indicator, '') ELSE {_OBS} END,
                     CASE WHEN coalesce(demo, false) THEN 'demo' ELSE '' END)"""

SCHEMA = """
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS incident VARCHAR;   -- the incident's first alert id (incidents.py)
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS demo BOOLEAN;       -- every matched row came from the demo files
CREATE TABLE IF NOT EXISTS netlog_rules (                       -- "this is expected" (incidents.py)
    id         VARCHAR PRIMARY KEY,
    device     VARCHAR,               -- NULL: any device
    indicator  VARCHAR,               -- NULL: any indicator
    kind       VARCHAR,               -- NULL: any kind (incidents.KIND_SQL)
    note       VARCHAR,
    expires_at TIMESTAMPTZ,           -- contacts from then on alert again; NULL: never
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,
    from_alert VARCHAR                -- the alert it was made from
);
"""

_ready: set = set()
_lock = threading.Lock()


def ensure(cur=None) -> None:
    """Add the incident columns and the rules table (once per database), and group alerts made before them."""
    key = id(db.connect())
    if key in _ready:
        return
    with _lock:
        if key in _ready:
            return
        if cur is not None:
            cur.execute(SCHEMA)
            regroup(cur, migrate=True)
        else:
            with db._write_lock:
                c = db.cursor()
                c.execute(SCHEMA)
                regroup(c, migrate=True)
        _ready.add(key)


def regroup(cur, migrate: bool = False) -> None:
    """Recompute every alert's incident (and, for alerts from before this column, the demo flag)."""
    if migrate:
        cur.execute(f"""UPDATE alerts SET demo = coalesce((SELECT bool_and(n.file_id IN {DEMO_FILES})
                                                          FROM netlog_matches m JOIN netlog n ON n.rk = m.rk
                                                          WHERE m.alert_id = alerts.id), false)
                        WHERE demo IS NULL""")
    cur.execute(f"""
        WITH k AS (SELECT id, ts, last_ts, {_IKEY} AS ikey FROM alerts),
        b AS (SELECT *, CASE WHEN ts > max(last_ts) OVER (PARTITION BY ikey ORDER BY ts, id
                                                          ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING)
                                      + INTERVAL {GAP_HOURS} HOUR THEN 1 ELSE 0 END AS brk FROM k),
        c AS (SELECT *, sum(brk) OVER (PARTITION BY ikey ORDER BY ts, id ROWS UNBOUNDED PRECEDING) AS g FROM b),
        d AS (SELECT id, first_value(id) OVER (PARTITION BY ikey, g ORDER BY ts, id) AS inc FROM c)
        UPDATE alerts SET incident = d.inc FROM d WHERE alerts.id = d.id AND alerts.incident IS DISTINCT FROM d.inc""")


def members(ids: list[str]) -> list[str]:
    """Every alert id in the incidents of these alert ids."""
    if not ids:
        return []
    ensure()
    return [r["id"] for r in db.query(f"""
        SELECT id FROM alerts WHERE coalesce(incident, id) IN
            (SELECT coalesce(incident, id) FROM alerts WHERE id IN ({','.join('?' * len(ids))}))
        ORDER BY ts, id""", ids)]


# ------------------------------------------------------------------ incident rows
_SEV = "CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"


def incidents_sql(member_where: str = "", inc_where: str = "", order: str = "", limit: str = "") -> str:
    """One row per incident. member_where (on alerts) picks incidents with at least one matching alert;
    inc_where filters the incident rows (status, severity, suppressed, demo)."""
    return f"""
    WITH a0 AS (SELECT al.*, coalesce(al.incident, al.id) AS inc, {kind_sql('al')} AS akind,
                       {_SEV.replace('severity', 'al.severity')} AS srank FROM alerts al),
    sup AS (SELECT a0.id AS aid, min(r.id) AS rid FROM a0 JOIN netlog_rules r
              ON (r.device IS NULL OR r.device IS NOT DISTINCT FROM a0.device)
             AND (r.indicator IS NULL OR r.indicator = a0.indicator)
             AND (r.kind IS NULL OR r.kind = a0.akind)
             AND (r.expires_at IS NULL OR a0.ts < r.expires_at)
            GROUP BY a0.id),
    a AS (SELECT a0.*, sup.rid AS rule_hit FROM a0 LEFT JOIN sup ON sup.aid = a0.id),
    hit AS (SELECT DISTINCT coalesce(incident, id) AS inc FROM alerts {member_where}),
    g AS (SELECT inc, arg_min(id, (ts, id)) AS id, arg_max(id, (srank, last_ts, id)) AS lead,
                 min(ts) AS ts, max(last_ts) AS last_ts, ['info', 'low', 'medium', 'high'][max(srank) + 1] AS severity,
                 sum("count") AS count, count(*) AS n_alerts, list(id ORDER BY ts, id) AS alerts,
                 date_diff('day', CAST(timezone('UTC', min(ts)) AS DATE), CAST(timezone('UTC', max(last_ts)) AS DATE)) + 1 AS days,
                 CASE WHEN bool_or(status = 'new') THEN 'new' WHEN bool_or(status = 'ack') THEN 'ack' ELSE 'dismissed' END AS status,
                 bool_or(status = 'new') AND bool_or(status <> 'new') AS reopened,
                 bool_and(rule_hit IS NOT NULL) AS suppressed, min(rule_hit) AS expected_rule,
                 bool_and(coalesce(demo, false)) AS demo, list(DISTINCT source) AS sources
          FROM a SEMI JOIN hit USING (inc) GROUP BY inc),
    i AS (SELECT g.*, CASE WHEN g.suppressed THEN 'expected' ELSE g.status END AS state,
                 l.device, l.indicator, l.source, l.rule, l.direction, l.title, l.evidence, l.akind AS kind,
                 l.created_at, l.updated_at
          FROM g JOIN a l ON l.id = g.lead)
    SELECT * FROM i {inc_where} {order} {limit}"""


ORDER = f"ORDER BY {_SEV} DESC, last_ts DESC, id"


def needs_you(member_where: str = "", inc_where: str = "", params: list | None = None) -> dict:
    """The one alert count: incidents that need the owner, and the rest by kind of reason they do not. `open` is
    every untriaged incident (any severity, demo included): the Alerts list's "New" count over all time.
    member_where/params (api._inc_where) limit it to incidents with an alert in a time range (Network Overview's card)."""
    ensure()
    r = db.query(f"""SELECT
        count(*) FILTER (WHERE state = 'new' AND NOT demo AND severity IN ('high', 'medium')) AS needs_you,
        count(*) FILTER (WHERE state = 'new' AND NOT demo AND severity = 'high') AS high,
        count(*) FILTER (WHERE state = 'new' AND NOT demo AND severity = 'medium') AS medium,
        count(*) FILTER (WHERE state = 'new' AND NOT demo AND severity = 'low') AS low,
        count(*) FILTER (WHERE state = 'new' AND NOT demo AND severity = 'info') AS info,
        count(*) FILTER (WHERE state = 'new' AND demo) AS demo,
        count(*) FILTER (WHERE state = 'expected') AS expected,
        count(*) FILTER (WHERE state = 'new') AS open,
        count(*) AS incidents
        FROM ({incidents_sql(member_where, inc_where)})""", params or [])[0]
    return {k: int(v or 0) for k, v in r.items()}


# ------------------------------------------------------------------ rules
SCOPES = {   # which fields a rule fixes: the scopes offered from an alert
    "device_indicator": ("device", "indicator"),
    "indicator": ("indicator",),
    "device_kind": ("device", "kind"),
}


def _rule_where(r: dict) -> tuple[str, list]:
    c, p = [], []
    for col in ("device", "indicator"):
        if r.get(col) is not None:
            c.append(f"{col} = ?"); p.append(r[col])
    if r.get("kind") is not None:
        c.append(f"{kind_sql()} = ?"); p.append(r["kind"])
    if r.get("expires_at") is not None:
        c.append("ts < ?"); p.append(r["expires_at"])
    return " AND ".join(c) or "false", p


def list_rules() -> list[dict]:
    ensure()
    rules = db.query("SELECT * FROM netlog_rules ORDER BY created_at DESC, id")
    for r in rules:
        w, p = _rule_where(r)
        h = db.query(f"""SELECT count(*) AS alerts, count(DISTINCT coalesce(incident, id)) AS incidents,
                                count(*) FILTER (WHERE ts >= now() - INTERVAL 7 DAY) AS week, max(last_ts) AS last
                         FROM alerts WHERE {w}""", p)[0]
        r["hits"] = {k: (int(v) if isinstance(v, int) else v) for k, v in h.items()}
        r["active"] = r["expires_at"] is None or r["expires_at"] > util.now()
        # a Suricata rule's indicator is "sid:<n>": carry the signature's name so the list can say what it is
        if str(r.get("indicator") or "").startswith("sid:"):
            nm = db.query("""SELECT json_extract_string(evidence, '$.indicator.observed[0]') AS n FROM alerts
                             WHERE indicator = ? AND evidence IS NOT NULL ORDER BY ts DESC LIMIT 1""", [r["indicator"]])
            r["indicator_label"] = nm[0]["n"] if nm and nm[0]["n"] and nm[0]["n"] != "(no signature)" else None   # matcher.NO_SIG
    return util.jsonable(rules)


def _expiry(v) -> dt.datetime | None:
    if v in (None, "", 0):
        return None
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        if not 0 < v <= 3650:
            raise ValueError("expires_days must be from 1 to 3650")
        return util.now() + dt.timedelta(days=float(v))
    try:
        t = dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"bad expiry: {v}")
    return t if t.tzinfo else t.replace(tzinfo=dt.UTC)


def _clean(body: dict, base: dict | None = None) -> dict:
    r = dict(base or {})
    if "scope" in body and body.get("from_alert"):
        a = db.query(f"SELECT id, device, indicator, {kind_sql()} AS kind FROM alerts WHERE id = ?", [body["from_alert"]])
        if not a:
            raise LookupError("no such alert")
        if body["scope"] not in SCOPES:
            raise ValueError(f"scope must be one of {', '.join(SCOPES)}")
        keep = SCOPES[body["scope"]]
        r.update({k: (a[0][k] if k in keep else None) for k in ("device", "indicator", "kind")})
        r["from_alert"] = a[0]["id"]
    for k in ("device", "indicator", "kind"):
        if k in body and "scope" not in body:
            r[k] = (str(body[k]).strip() or None) if body[k] is not None else None
    if "note" in body:
        r["note"] = (str(body["note"] or "").strip()[:500]) or None
    if "expires_days" in body:
        r["expires_at"] = _expiry(body["expires_days"])
    elif "expires_at" in body:
        r["expires_at"] = _expiry(body["expires_at"])
    if not r.get("indicator") and not (r.get("device") and r.get("kind")):
        raise ValueError("a rule needs an indicator, or a device and a kind")
    return r


def create_rule(body: dict) -> dict:
    ensure()
    r = _clean(body)
    if r.get("expires_at") is not None and r["expires_at"] <= util.now():
        raise ValueError("the expiry is already past: a new rule would hide nothing")
    rid = "rule-" + uuid.uuid4().hex[:12]
    db.execute("""INSERT INTO netlog_rules (id, device, indicator, kind, note, expires_at, created_at, updated_at, from_alert)
                  VALUES (?, ?, ?, ?, ?, ?, now(), now(), ?)""",
               [rid, r.get("device"), r.get("indicator"), r.get("kind"), r.get("note"), r.get("expires_at"), r.get("from_alert")])
    return next(x for x in list_rules() if x["id"] == rid)


def update_rule(rid: str, body: dict) -> dict:
    ensure()
    cur = db.query("SELECT * FROM netlog_rules WHERE id = ?", [rid])
    if not cur:
        raise LookupError("no such rule")
    r = _clean(body, cur[0])
    db.execute("""UPDATE netlog_rules SET device = ?, indicator = ?, kind = ?, note = ?, expires_at = ?, updated_at = now()
                  WHERE id = ?""", [r.get("device"), r.get("indicator"), r.get("kind"), r.get("note"), r.get("expires_at"), rid])
    return next(x for x in list_rules() if x["id"] == rid)


def delete_rule(rid: str) -> bool:
    ensure()
    if not db.query("SELECT 1 FROM netlog_rules WHERE id = ?", [rid]):
        return False
    db.execute("DELETE FROM netlog_rules WHERE id = ?", [rid])
    return True
