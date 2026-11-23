"""Time-correct, direction-aware matching of log rows against indicator_intervals, and alerts.

A row matches an indicator only if its ts lies in [start - grace, end). Rows that hit an indicator
outside every interval are kept as `historical` info. Rules and severities: okf/data/netlog.md
"""
from __future__ import annotations

import gzip
import json
import logging
import time
from collections import defaultdict
from functools import lru_cache

from .. import db
from . import devices, incidents, intervals, ownlists, util

log = logging.getLogger("osinthub.netlog.match")

# (category, direction) -> (rule, severity, aggregate per indicator per day)
# direction: outbound (home -> indicator), dns (a DNS answer or looked-up name is the indicator),
# inbound (indicator -> home), unknown (neither side is home).
_OUT = {
    "c2": ("c2", "high"), "drop": ("drop", "high"),
    "compromised": ("compromised", "medium"), "reputation": ("bad_reputation", "medium"),
    "listed": ("listed", "medium"), "attacker": ("attacker", "medium"), "scanner": ("scanner", "medium"),
    "tor": ("tor", "low"), "reported": ("reported_ioc", "low"),
    "reported_corroborated": ("reported_corroborated", "medium"), "reported_tor": ("reported_tor", "low"),
    "kev": ("kev_cve", "low"), "malware": ("malware", "high"),
    "own": ("own_list", "medium"),   # your own lists (ownlists.py): you say it is bad, Night Desk cannot say how bad
}
_IN = {
    "c2": "low", "drop": "low", "compromised": "low", "reputation": "low", "listed": "low",
    "attacker": "info", "scanner": "info", "tor": "low", "reported": "info", "reported_corroborated": "info", "reported_tor": "info",
    "kev": "low", "malware": "low", "own": "low",
}
RULES: dict[tuple[str, str], tuple[str, str, bool]] = {}
for _c, (_r, _s) in _OUT.items():
    RULES[(_c, "outbound")] = (f"{_r}_outbound", _s, False)
    RULES[(_c, "dns")] = (f"{_r}_dns", _s, False)
    RULES[(_c, "inbound")] = (f"{_r}_inbound", _IN[_c], True)
    RULES[(_c, "unknown")] = (f"{_r}_unknown_direction", "low" if _s != "info" else "info", True)
RULES[("kev", "outbound")] = ("kev_cve_notice", "low", False)

DESCRIPTIONS = {
    "outbound": "A home device contacted the indicator while it was listed.",
    "dns": "A home device looked up a name that resolved to (or was) the indicator while it was listed: outbound intent.",
    "inbound": "The indicator contacted a home address while it was listed (aggregated per indicator per day).",
    "unknown": "Neither side of the connection is in the home prefixes.",
    "retro": ("Contacted before our listing began, but inside the period the provider itself reports the indicator "
              "active (its first_seen to last_online). Open, low: the provider's dates are not our observation."),
    "historical": "The indicator was contacted outside any interval in which it was listed (before listing or after removal).",
}
UID_CAP = 200   # evidence.uids holds at most this many; the rest are in netlog_matches
SEV_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}


def _rules_table(cur) -> None:
    cur.execute("""CREATE OR REPLACE TEMP TABLE _nl_rules (category VARCHAR, direction VARCHAR, rule VARCHAR,
                   severity VARCHAR, agg BOOLEAN)""")
    cur.executemany("INSERT INTO _nl_rules VALUES (?, ?, ?, ?, ?)", [(c, d, *v) for (c, d), v in RULES.items()])


ACCEPTED = "('SF', 'S1', 'S2', 'S3', 'RSTO', 'RSTR', 'established', 'closed')"
ESCALATE = "('drop', 'compromised', 'reputation', 'listed', 'attacker', 'scanner', 'reported_corroborated', 'own')"
SPAN_MIN_S = 300        # a session that began before listing must overlap the interval this long to count
BIG_BYTES = 1_000_000   # "significant data" for an accepted inbound session
LONG_S = 600
P2P_PEERS = 15          # distinct high-port peers in one hour that make a home address a P2P swarm member

# Malware URLs (ThreatFox, URLhaus) match plain-HTTP requests: lower-case Host (port already stripped at import)
# + request target without scheme/authority or fragment, the same shape as sources.abusech.norm_url.
URL_EXPR = ("(CASE WHEN log_type IN ('http', 'eve_http') AND coalesce(host, '') <> '' AND uri IS NOT NULL THEN host || "
            "coalesce(nullif(regexp_replace(split_part(uri, '#', 1), '^[A-Za-z][A-Za-z0-9+.-]*://[^/]*', ''), ''), '/') END)")
# File and certificate hashes: Zeek files.log md5/sha1/sha256, x509 fingerprint, ssl cert_chain_fps; Suricata
# tls.fingerprint (SHA1 with colons) and fileinfo hashes. Lower-case hex of 32, 40 or 64 digits.
HASH_LOGS = "('files', 'x509', 'ssl', 'eve_tls', 'eve_fileinfo')"
HASH_EXPR = ("list_distinct(list_filter(list_transform("
             "[json_extract_string(hraw, '$.md5'), json_extract_string(hraw, '$.sha1'), json_extract_string(hraw, '$.sha256'), "
             "json_extract_string(hraw, '$.fingerprint'), json_extract_string(hraw, '$.tls.fingerprint'), "
             "json_extract_string(hraw, '$.fileinfo.md5'), json_extract_string(hraw, '$.fileinfo.sha1'), "
             "json_extract_string(hraw, '$.fileinfo.sha256')] "
             "|| coalesce(try_cast(json_extract(hraw, '$.cert_chain_fps') AS VARCHAR[]), []), "
             "lambda x: lower(replace(x, ':', ''))), "
             "lambda x: x IS NOT NULL AND regexp_full_match(x, '[0-9a-f]{{32}}|[0-9a-f]{{40}}|[0-9a-f]{{64}}')))")


def _source_order_sql(col: str = "source") -> str:
    return "CASE " + col + " " + " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(intervals.SOURCES)) + " ELSE 99 END"


# abuse.ch indicator feeds (ThreatFox, URLhaus, SSLBL) corroborate the other lists instead of adding alerts of their
# own for the same contact (okf/data/netlog.md#cross-source). Every other list keeps exactly its own alert ids.
AB_SQL = "(" + ", ".join(f"'{x}'" for x in sorted(intervals.ABUSECH)) + ")"
# Which list leads an alert that holds several: a non-abuse.ch list first (it owns the alert id), then the more
# specific indicator (a URL or hash over its host), then the established list order, then the value. Nothing
# time-varying (interval state, severity) is involved, so the lead never flips.
LEAD_ORDER = (f"(source IN {AB_SQL}), "
              f"CASE kind WHEN 'url' THEN 4 WHEN 'hash' THEN 4 WHEN 'domain' THEN 3 WHEN 'ip' THEN 2 ELSE 1 END DESC, "
              f"{_source_order_sql()}, source, value")

MATCH_SQL = """
CREATE OR REPLACE TEMP TABLE _nl_new AS
WITH sc AS (SELECT rk, ts, uid, log_type, orig_h, resp_h, orig_p, resp_p, conn_state, answers, query, server_name, host,
                   duration, orig_bytes, resp_bytes, uri,
                   CASE WHEN log_type IN {hash_logs} THEN raw END AS hraw
            FROM netlog WHERE ({scope}) AND ts IS NOT NULL),
ips AS (SELECT orig_h AS ip FROM sc UNION SELECT resp_h FROM sc UNION SELECT unnest(answers) FROM sc WHERE answers IS NOT NULL),
ipn AS (SELECT i.ip, i.n FROM netlog_ipnum i SEMI JOIN ips USING (ip) WHERE i.ip NOT IN (SELECT ip FROM _nl_homeip)),
names AS (SELECT DISTINCT name FROM (SELECT query AS name FROM sc UNION SELECT server_name FROM sc UNION SELECT host FROM sc
                                      UNION SELECT unnest(answers) FROM sc WHERE answers IS NOT NULL)
          WHERE name IS NOT NULL AND name NOT LIKE '%:%' AND NOT regexp_full_match(name, '[0-9.]+')),
urls AS (SELECT DISTINCT u FROM (SELECT {url_expr} AS u FROM sc) WHERE u IS NOT NULL),
hashes AS (SELECT DISTINCT h FROM (SELECT unnest({hash_expr}) AS h FROM sc WHERE hraw IS NOT NULL)),
hits AS (
    SELECT ipn.ip AS observed, ii.* FROM ipn JOIN indicator_intervals ii ON ii.kind = 'ip' AND ii.lo = ipn.n
    UNION ALL
    SELECT ipn.ip, ii.* FROM ipn JOIN indicator_intervals ii ON ii.kind = 'cidr' AND ipn.n BETWEEN ii.lo AND ii.hi
    UNION ALL
    SELECT names.name, ii.* FROM names JOIN indicator_intervals ii
      ON ii.kind = 'domain' AND (names.name = ii.value OR ends_with(names.name, '.' || ii.value))
    UNION ALL
    SELECT urls.u, ii.* FROM urls JOIN indicator_intervals ii ON ii.kind = 'url' AND ii.value = urls.u
    UNION ALL
    SELECT hashes.h, ii.* FROM hashes JOIN indicator_intervals ii ON ii.kind = 'hash' AND ii.value = hashes.h),
hit_obs AS (SELECT DISTINCT observed FROM hits),
base AS (SELECT s.*, oh.ip IS NOT NULL AS orig_home, rh.ip IS NOT NULL AS resp_home
         FROM sc s LEFT JOIN _nl_homeip oh ON oh.ip = s.orig_h LEFT JOIN _nl_homeip rh ON rh.ip = s.resp_h),
obs AS (
    SELECT rk, ts, uid, log_type, orig_p, resp_p, conn_state, duration, orig_bytes, resp_bytes, 'resp' AS role,
           resp_h AS observed, CASE WHEN orig_home THEN orig_h END AS home_ip,
           CASE WHEN orig_home THEN 'outbound' ELSE 'unknown' END AS direction
    FROM base WHERE resp_h IN (SELECT observed FROM hit_obs)
    UNION ALL
    SELECT rk, ts, uid, log_type, orig_p, resp_p, conn_state, duration, orig_bytes, resp_bytes, 'orig', orig_h,
           CASE WHEN resp_home THEN resp_h END, CASE WHEN resp_home THEN 'inbound' ELSE 'unknown' END
    FROM base WHERE orig_h IN (SELECT observed FROM hit_obs) AND resp_h IS DISTINCT FROM orig_h
    UNION ALL
    -- a lookup is outbound intent only when the client asking is a home address
    SELECT rk, ts, uid, log_type, orig_p, resp_p, conn_state, duration, orig_bytes, resp_bytes, 'answer', a,
           CASE WHEN orig_home THEN orig_h END, CASE WHEN orig_home THEN 'dns' ELSE 'unknown' END
    FROM (SELECT *, unnest(answers) AS a FROM base WHERE answers IS NOT NULL) WHERE a IN (SELECT observed FROM hit_obs)
    UNION ALL
    SELECT rk, ts, uid, log_type, orig_p, resp_p, conn_state, duration, orig_bytes, resp_bytes, 'name', nm,
           CASE WHEN orig_home THEN orig_h END,
           CASE WHEN NOT orig_home THEN 'unknown' WHEN log_type IN ('dns', 'eve_dns') THEN 'dns' ELSE 'outbound' END
    FROM (SELECT *, unnest(list_distinct(list_filter([query, server_name, host], lambda x: x IS NOT NULL))) AS nm FROM base)
    WHERE nm IN (SELECT observed FROM hit_obs)
    UNION ALL
    -- a malware URL fetched over plain HTTP: Host + request target (http.log, EVE http)
    SELECT rk, ts, uid, log_type, orig_p, resp_p, conn_state, duration, orig_bytes, resp_bytes, 'url', {url_expr},
           CASE WHEN orig_home THEN orig_h END, CASE WHEN orig_home THEN 'outbound' ELSE 'unknown' END
    FROM base WHERE {url_expr} IN (SELECT observed FROM hit_obs)
    UNION ALL
    -- a file or certificate hash (files.log, x509 fingerprint, EVE tls.fingerprint / fileinfo): a home device received it
    SELECT rk, ts, uid, log_type, orig_p, resp_p, conn_state, duration, orig_bytes, resp_bytes, 'hash', hh,
           CASE WHEN orig_home THEN orig_h WHEN resp_home THEN resp_h END,
           CASE WHEN orig_home OR resp_home THEN 'outbound' ELSE 'unknown' END
    FROM (SELECT *, unnest({hash_expr}) AS hh FROM base WHERE hraw IS NOT NULL) WHERE hh IN (SELECT observed FROM hit_obs)
    UNION ALL
    SELECT rk, ts, uid, log_type, orig_p, resp_p, conn_state, duration, orig_bytes, resp_bytes, 'cve', cve, orig_h, 'outbound'
    FROM (SELECT n.*, unnest(regexp_extract_all(upper(n.raw), 'CVE-\\d{{4}}-\\d{{4,}}')) AS cve FROM netlog n
          WHERE ({scope}) AND n.log_type IN ('notice', 'weird', 'software') AND n.raw ILIKE '%cve-%')),
-- P2P swarms: a home address talking to many peers, high port to high port, with no recognised service in
-- one hour (or the hour either side). Residential peers on blocklists are expected there, so list hits (except C2) are capped at low.
-- Hours on the clock and hours offset by 30 minutes (labelled :30), so a swarm across a full hour still counts.
p2p_rows AS (
    SELECT orig_h AS ip, ts, resp_h AS peer FROM netlog
    WHERE log_type = 'conn' AND orig_h IN (SELECT DISTINCT home_ip FROM obs) AND orig_p >= 1024 AND resp_p >= 1024
      AND service IS NULL
    UNION ALL
    SELECT resp_h, ts, orig_h FROM netlog
    WHERE log_type = 'conn' AND resp_h IN (SELECT DISTINCT home_ip FROM obs) AND orig_p >= 1024 AND resp_p >= 1024
      AND service IS NULL),
p2p AS (
    SELECT ip, hr FROM (
        SELECT ip, date_trunc('hour', ts) AS hr, peer FROM p2p_rows
        UNION ALL
        SELECT ip, date_trunc('hour', ts + INTERVAL 30 MINUTE) - INTERVAL 30 MINUTE, peer FROM p2p_rows)
    GROUP BY ip, hr HAVING count(DISTINCT peer) >= {p2p_peers}),
cvehits AS (SELECT ii.value AS observed, ii.* FROM indicator_intervals ii WHERE ii.kind = 'cve'
            AND ii.value IN (SELECT observed FROM obs WHERE role = 'cve')),
j0 AS (
    SELECT o.*, x.source, x.kind, x.value, x.category, x."start" AS i_start, x."end" AS i_end, x.meta AS i_meta,
           -- your own lists say "bad" without "since when": any contact before the list's expiry is in it (ownlists.py)
           ((o.ts >= x."start" - to_seconds(?) OR x.category = 'own') AND (x."end" IS NULL OR o.ts < x."end")) AS strict_in,
           (o.ts < x."start" - to_seconds(?)
            AND o.ts + to_seconds(coalesce(o.duration, 0)) >= x."start" - to_seconds(?) + INTERVAL {span} SECOND) AS span_in
    FROM obs o JOIN (SELECT * FROM hits UNION ALL SELECT * FROM cvehits) x ON x.observed = o.observed
         AND (CASE WHEN o.role IN ('cve', 'url', 'hash') THEN x.kind = o.role ELSE x.kind NOT IN ('cve', 'url', 'hash') END)),
j AS (
    SELECT *, strict_in OR span_in AS in_interval FROM j0
    QUALIFY row_number() OVER (PARTITION BY rk, role, observed, source, value
                               ORDER BY strict_in DESC, span_in DESC,
                                        -- one ThreatFox address listed per port: the IOC for the port contacted
                                        (source IN {ab_sql} AND try_cast(json_extract_string(i_meta, '$.port') AS INTEGER)
                                         = CASE WHEN role = 'orig' THEN orig_p ELSE resp_p END) DESC,
                                        abs(epoch(ts) - epoch(i_start))) = 1),
r AS (
    SELECT j.*, coalesce(r.rule, j.category || '_' || j.direction) AS base_rule,
           coalesce(r.severity, 'low') AS base_sev, coalesce(r.agg, true) AS base_agg,
           j.log_type IN ('conn', 'eve_flow') AND j.conn_state IN {accepted} AS accepted,
           coalesce(j.orig_bytes, 0) + coalesce(j.resp_bytes, 0) AS vol,
           -- retro: before our listing but inside the provider's own [first_seen, last_online] (Feodo and similar)
           (NOT j.in_interval AND j.category = 'c2' AND j.direction IN ('outbound', 'dns')
            AND try_cast(json_extract_string(j.i_meta, '$.first_seen') AS TIMESTAMPTZ) IS NOT NULL
            AND j.ts >= try_cast(json_extract_string(j.i_meta, '$.first_seen') AS TIMESTAMPTZ)
            AND j.ts < j.i_start
            AND (try_cast(json_extract_string(j.i_meta, '$.last_online') AS DATE) IS NULL
                 OR j.ts < CAST(try_cast(json_extract_string(j.i_meta, '$.last_online') AS DATE) + INTERVAL 1 DAY AS TIMESTAMPTZ))
           ) AS retro,
           (j.log_type = 'conn' AND j.orig_p >= 1024 AND j.resp_p >= 1024 AND j.category <> 'c2'
            AND {p2p_cap}
            -- not if the same remote is also seen from this home address on non-P2P ports or a known service
            AND NOT EXISTS (SELECT 1 FROM netlog n2 WHERE n2.log_type = 'conn'
                            AND ((n2.orig_h = j.home_ip AND n2.resp_h = j.observed) OR (n2.resp_h = j.home_ip AND n2.orig_h = j.observed))
                            AND NOT (n2.orig_p >= 1024 AND n2.resp_p >= 1024 AND n2.service IS NULL))
            AND EXISTS (SELECT 1 FROM p2p WHERE p2p.ip = j.home_ip
                        AND p2p.hr BETWEEN date_trunc('hour', j.ts) - INTERVAL 1 HOUR AND date_trunc('hour', j.ts) + INTERVAL 1 HOUR)) AS p2p_ctx
    FROM j LEFT JOIN _nl_rules r ON r.category = j.category AND r.direction = j.direction),
g AS (
    SELECT r.*,
      CASE WHEN direction = 'inbound' AND accepted AND category = 'c2' AND (vol >= 10000 OR duration >= 60)
                THEN 'high'
           WHEN direction = 'inbound' AND accepted AND category = 'reported' AND vol >= 10000 THEN 'low'
           WHEN direction = 'inbound' AND accepted AND category IN {escalate}
                AND (vol >= {big} OR (coalesce(duration, 0) >= {long} AND vol >= 100000)) THEN 'medium'
           WHEN direction = 'inbound' AND accepted AND category IN {escalate} AND vol >= 10000
                AND base_sev = 'info' THEN 'low'
      END AS accepted_sev
    FROM r),
f AS (
    SELECT g.*,
      CASE WHEN retro THEN category || '_retro'
           WHEN NOT in_interval THEN 'historical'
           WHEN p2p_ctx AND coalesce(accepted_sev, base_sev) IN ('high', 'medium')
                THEN coalesce(CASE WHEN accepted_sev IS NOT NULL THEN category || '_inbound_accepted' END, base_rule) || '_p2p'
           WHEN accepted_sev IS NOT NULL THEN category || '_inbound_accepted' || CASE WHEN span_in AND NOT strict_in THEN '_spanning' ELSE '' END
           WHEN span_in AND NOT strict_in THEN base_rule || '_spanning'
           WHEN base_sev = 'medium' AND direction = 'outbound' AND log_type = 'conn'
                AND (conn_state = 'OTH' OR (orig_p < 1024 AND resp_p >= 1024)) THEN base_rule || '_ambiguous'
           ELSE base_rule END AS rule,
      CASE WHEN retro THEN 'low'
           WHEN NOT in_interval THEN 'info'
           WHEN p2p_ctx AND coalesce(accepted_sev, base_sev) IN ('high', 'medium') THEN 'low'
           WHEN span_in AND NOT strict_in THEN CASE coalesce(accepted_sev, base_sev) WHEN 'high' THEN 'medium'
                                                    ELSE coalesce(accepted_sev, base_sev) END
           WHEN accepted_sev IS NOT NULL THEN accepted_sev
           WHEN base_sev = 'medium' AND direction = 'outbound' AND log_type = 'conn'
                AND (conn_state = 'OTH' OR (orig_p < 1024 AND resp_p >= 1024)) THEN 'low'
           ELSE base_sev END AS severity,
      ((NOT in_interval) AND NOT retro) OR (base_agg AND accepted_sev IS NULL AND NOT retro) AS agg
    FROM g),
fa AS (SELECT f.*, d.device AS dev FROM f ASOF LEFT JOIN netlog_ipdev d ON d.ip = f.home_ip AND f.ts >= d.from_ts),
fk AS (
    SELECT fa.*, regexp_replace(rule, '_dns$', '_outbound') AS nrule, source IN {ab_sql} AS ab,
           -- a lookup and the connection it led to are one alert: the key uses the outbound form of the rule
           'nl-' || md5(concat_ws('|', regexp_replace(rule, '_dns$', '_outbound'),
                                  CASE WHEN agg THEN '*' ELSE coalesce(dev, home_ip, '?') END,
                                  source, value, strftime(ts, '%Y-%m-%d')))[:20] AS own_id,
           -- abuse.ch: one key for all three feeds, so ThreatFox and URLhaus on one value are one alert whichever leads
           'nl-' || md5(concat_ws('|', regexp_replace(rule, '_dns$', '_outbound'),
                                  CASE WHEN agg THEN '*' ELSE coalesce(dev, home_ip, '?') END,
                                  'abuse.ch', value, strftime(ts, '%Y-%m-%d')))[:20] AS ab_id
    FROM fa),
fj AS (
    SELECT fk.*,
           -- the same observation on a non-abuse.ch list (Feodo, ET, CINS ...), both inside or both outside a listing:
           min(CASE WHEN NOT ab THEN own_id END) OVER (PARTITION BY rk, role, observed, rule = 'historical') AS list_id,
           -- a malware URL fetched in this row: its host's abuse.ch match belongs to the URL's alert
           min(CASE WHEN ab AND kind = 'url' THEN ab_id END) OVER (PARTITION BY rk, rule = 'historical') AS url_id
    FROM fk)
SELECT rk, ts, uid, log_type, role, observed, home_ip, direction, dev AS device, source, kind, value,
       category, i_start, i_end, in_interval, rule, severity,
       -- every non-abuse.ch match keeps the id main always gave it; an abuse.ch match joins that alert when it hit the
       -- same observation (in a listing or not, like it), else the alert of a URL it is the host of, else its own abuse.ch alert
       CASE WHEN NOT ab THEN own_id
            ELSE coalesce(list_id, CASE WHEN kind IN ('ip', 'domain') THEN url_id END, ab_id) END AS alert_id,
       CASE WHEN p2p_ctx AND in_interval AND NOT retro AND coalesce(accepted_sev, base_sev) IN ('high', 'medium')
            THEN 'p2p_swarm' END AS capped,
       CASE WHEN p2p_ctx AND in_interval AND NOT retro AND coalesce(accepted_sev, base_sev) IN ('high', 'medium')
            THEN coalesce(accepted_sev, base_sev) END AS orig_severity
FROM fj
""".replace("{accepted}", ACCEPTED).replace("{escalate}", ESCALATE).replace("{span}", str(SPAN_MIN_S)) \
   .replace("{big}", str(BIG_BYTES)).replace("{long}", str(LONG_S)).replace("{p2p_peers}", str(P2P_PEERS)) \
   .replace("{url_expr}", URL_EXPR).replace("{hash_expr}", HASH_EXPR).replace("{hash_logs}", HASH_LOGS) \
   .replace("{ab_sql}", AB_SQL)


NO_SIG = "(no signature)"   # the observed value of a Suricata alert with no signature name (never shown as a name)
SIG_SQL = """
INSERT INTO _nl_new
WITH a AS (
    SELECT n.rk, n.ts, n.uid, n.log_type, n.orig_h, n.resp_h,
           json_extract_string(n.raw, '$.alert.signature_id') AS sid,
           coalesce(json_extract_string(n.raw, '$.alert.signature'), '(no signature)') AS sig,   -- NO_SIG
           try_cast(json_extract_string(n.raw, '$.alert.severity') AS INTEGER) AS ssev
    FROM netlog n WHERE ({scope}) AND n.log_type = 'eve_alert' AND n.ts IS NOT NULL),
b AS (SELECT a.*, oh.ip IS NOT NULL AS orig_home, rh.ip IS NOT NULL AS resp_home, tu.action, tu.severity AS tsev
      FROM a LEFT JOIN _nl_homeip oh ON oh.ip = a.orig_h LEFT JOIN _nl_homeip rh ON rh.ip = a.resp_h
      LEFT JOIN _nl_sigtune tu ON tu.sid = a.sid),
f AS (SELECT b.*, CASE WHEN orig_home THEN orig_h WHEN resp_home THEN resp_h END AS home_ip,
             CASE WHEN orig_home AND NOT resp_home THEN 'outbound' WHEN resp_home AND NOT orig_home THEN 'inbound'
                  WHEN orig_home THEN 'internal' ELSE 'unknown' END AS direction,
             coalesce(tsev, CASE ssev WHEN 1 THEN 'high' WHEN 2 THEN 'medium' WHEN 3 THEN 'low' ELSE 'info' END) AS severity
      FROM b WHERE action IS DISTINCT FROM 'suppress')
SELECT f.rk, f.ts, f.uid, f.log_type, 'signature', f.sig, f.home_ip, f.direction, d.device, 'suricata', 'signature',
       'sid:' || coalesce(f.sid, '?'), 'ids', NULL, NULL, true, 'ids_signature', f.severity,
       'nl-' || md5(concat_ws('|', 'ids_signature', coalesce(d.device, f.home_ip, '?'), coalesce(f.sid, f.sig),
                              strftime(f.ts, '%Y-%m-%d')))[:20], NULL, NULL
FROM f ASOF LEFT JOIN netlog_ipdev d ON d.ip = f.home_ip AND f.ts >= d.from_ts
"""


def _sigtune_table(cur) -> None:
    """Suricata tuning from settings: {"suppress": [sid, ...], "severity": {sid: high|medium|low|info}}."""
    t = util.settings().get("suricata") or {}
    rows = [(str(sid), "suppress", None) for sid in t.get("suppress") or []]
    rows += [(str(sid), "severity", sev) for sid, sev in (t.get("severity") or {}).items() if sev in SEV_RANK]
    cur.execute("CREATE OR REPLACE TEMP TABLE _nl_sigtune (sid VARCHAR, action VARCHAR, severity VARCHAR)")
    if rows:
        cur.executemany("INSERT INTO _nl_sigtune VALUES (?, ?, ?)", rows)


def carry_candidates(cur) -> dict[str, list[dict]]:
    """Statuses that may follow a re-keyed alert: for each new alert id with no status of its own, the vanished
    alerts (gone from the new matches) whose matches moved to it, with their status, lead source, indicator and
    severity (the one the user triaged it at, else its current one). _refresh_alerts decides (`carry_status`). Needs _nl_prev (matches before) and _nl_new (after)."""
    out: dict[str, list[dict]] = defaultdict(list)
    for new_id, old_id, status, source, indicator, severity in cur.execute("""
        SELECT DISTINCT n.alert_id, p.alert_id, s.status, a.source, a.indicator, coalesce(s.severity, a.severity)
        FROM _nl_prev p JOIN _nl_new n USING (rk, role, observed, source, value)
        JOIN netlog_alert_status s ON s.id = p.alert_id AND s.status IN ('ack', 'dismissed')
        JOIN alerts a ON a.id = p.alert_id
        WHERE p.alert_id <> n.alert_id
          AND p.alert_id NOT IN (SELECT DISTINCT alert_id FROM _nl_new)
          AND n.alert_id NOT IN (SELECT id FROM netlog_alert_status)""").fetchall():
        out[new_id].append({"id": old_id, "status": status, "source": source, "indicator": indicator, "severity": severity})
    return out


def carry_status(new: dict, cands: list[dict]) -> str | None:
    """The status a re-keyed alert keeps: only from the SAME alert (same lead list and indicator, e.g. its device
    key changed) and only if it is not more severe now than when the user triaged it. A different alert (a DROP or
    Feodo alert absorbing a ThreatFox match the user dismissed) or a more severe one starts new. Ack before
    dismissed when several qualify."""
    same = _same_alert(new, cands)
    if not same:
        return None
    return "ack" if any(c["status"] == "ack" for c in same) else "dismissed"


def _same_alert(new: dict, cands: list[dict]) -> list[dict]:
    return [c for c in cands if c["source"] == new["source"] and c["indicator"] == new["indicator"]
            and SEV_RANK.get(new["severity"], 0) <= SEV_RANK.get(c["severity"], 0)]


def match(scope: str, params: list | tuple = (), settings: bool = False) -> dict:
    """Re-match the netlog rows selected by `scope` (a WHERE clause) and refresh affected alerts. `settings`: the
    re-match follows a settings or device change, not new rows (only matters for statuses from before the triaged
    severity was stored, `_legacy_seen`)."""
    t0 = time.time()
    grace = float(util.settings().get("grace_seconds") or 0)
    with util.LOCK, db._write_lock:
        cur = db.cursor()
        incidents.ensure(cur)
        cur.execute(devices.IPDEV_SQL)
        devices.update_ipnum(cur, scope, params)
        devices.home_table(cur)
        _rules_table(cur)
        cap = "true" if util.settings().get("p2p_cap", True) else "false"
        cur.execute(MATCH_SQL.replace("{p2p_cap}", cap).format(scope=scope), [*params, *params, grace, grace, grace])
        _sigtune_table(cur)
        cur.execute(SIG_SQL.format(scope=scope), list(params))
        old = {r[0] for r in cur.execute(
            f"SELECT DISTINCT alert_id FROM netlog_matches WHERE rk IN (SELECT rk FROM netlog WHERE {scope})", list(params)).fetchall()}
        cur.execute(f"""CREATE OR REPLACE TEMP TABLE _nl_prev AS SELECT DISTINCT alert_id, rk, role, observed, source, value
                        FROM netlog_matches WHERE rk IN (SELECT rk FROM netlog WHERE {scope})""", list(params))
        cur.execute("BEGIN")
        try:
            cur.execute(f"DELETE FROM netlog_matches WHERE rk IN (SELECT rk FROM netlog WHERE {scope})", list(params))
            cur.execute("INSERT INTO netlog_matches SELECT * FROM _nl_new")
            cands = carry_candidates(cur)
            new = {r[0] for r in cur.execute("SELECT DISTINCT alert_id FROM _nl_new").fetchall()}
            n_alerts = _refresh_alerts(cur, old | new, cands, settings)
            cur.execute("COMMIT")
        except Exception:
            cur.execute("ROLLBACK")
            raise
        sev = dict(cur.execute("""SELECT severity, count(DISTINCT alert_id) FROM _nl_new GROUP BY 1""").fetchall())
        n = cur.execute("SELECT count(*) FROM _nl_new").fetchone()[0]
        cur.execute("DROP TABLE IF EXISTS _nl_new")
        cur.execute("DROP TABLE IF EXISTS _nl_prev")
    out = {"matches": int(n), "alerts_touched": n_alerts, "by_severity": sev, "seconds": round(time.time() - t0, 3)}
    if n:
        util.publish_alerts(out)
    return out


def match_file(file_id: str) -> dict:
    return match("file_id = ?", [file_id])


def rehunt(days: float | None = None) -> dict:
    """Re-match recent logs (by log time or import time) after threat data or settings changed."""
    # the API rejects a bad `days`; internal callers get the same rule as the saved setting (default 30)
    days = util.fit("rehunt_days", days if days is not None else util.settings().get("rehunt_days"))
    scope = (f"ts >= now() - INTERVAL ({days}) DAY OR file_id IN "
             f"(SELECT id FROM netlog_files WHERE imported_at >= now() - INTERVAL ({days}) DAY)")
    res = match(scope)
    res["days"] = days
    return res


@lru_cache(maxsize=4096)
def record_line(path: str | None, key: str | None) -> dict | None:
    """The record-delta line that put (or removed) an indicator, read back from the lake file."""
    if not path or not key:
        return None
    try:
        with gzip.open(path, "rt") as fh:
            for n, line in enumerate(fh, 1):
                if key in line:
                    rec = json.loads(line)
                    if str(rec.get("key")) == key:
                        return {"line": n, **rec}
    except (OSError, ValueError, EOFError):
        return None
    return None


def tier(sid: str) -> str:
    """Trust tier of a list: A-D for the public lists (intervals.TIERS), U for your own lists."""
    return "U" if ownlists.is_own(sid) else intervals.TIERS.get(sid, "C")


def _source_name(sid: str, meta: dict | None = None) -> str:
    if sid == "reported":
        return "news reports"
    if ownlists.is_own(sid):
        return f"your list '{(meta or {}).get('list_name') or sid[len(ownlists.PREFIX):]}'"
    try:
        from ..sources import SOURCES
        return SOURCES[sid].name if sid in SOURCES else sid
    except Exception:
        return sid


# What a listed category means, in words for alert titles (the web client writes the full headline).
CATEGORY_WORDS = {
    "c2": "a botnet controller", "drop": "a hijacked network", "compromised": "a compromised host",
    "reputation": "an address with a bad reputation", "listed": "a listed address", "attacker": "a known attacker",
    "scanner": "a known scanner", "tor": "a Tor relay", "reported": "named in threat reports",
    "reported_corroborated": "named in threat reports", "reported_tor": "a Tor relay named in threat reports",
    "kev": "an exploited vulnerability", "malware": "known malware", "own": "",
}
FOUND_LATER_S = 60
SINK_LOWER = {"high": "medium", "medium": "low", "low": "info"}   # every contact blocked by the DNS sinkhole
SINK_NAMES = {"pihole": "Pi-hole", "adguard": "AdGuard Home"}   # rows imported this long before the listing began were found by a later re-check


def _legacy_seen(last: str | None, settings: bool) -> str | None:
    """What a status set before netlog_alert_status.severity existed (NULL) is compared with. The triaged severity
    is unknown, and a setting may have held the alert low when the user upgraded, so a re-match after a settings or
    device change (no new rows) never reopens it (None), however often settings go back and forth; a re-match of
    rows (an import, a re-hunt after new threat data) compares with the last severity, as v1.2 did; an alert
    re-created with no last severity keeps its status (None). Nothing is filled in: the next ack, dismiss or
    reopen stores the severity."""
    if last is None or settings:
        return None
    return last


def _refresh_alerts(cur, ids: set[str], carry: dict | None = None, settings: bool = False) -> int:
    if not ids:
        return 0
    cur.execute("CREATE OR REPLACE TEMP TABLE _nl_ids (id VARCHAR)")
    cur.executemany("INSERT INTO _nl_ids VALUES (?)", [(i,) for i in ids])
    rows = util.rows_of(cur, """
        SELECT m.alert_id AS id, min(m.ts) AS ts, max(m.ts) AS last_ts,
               arg_max(m.severity, CASE m.severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS severity,
               mode(m.device) AS device, list(DISTINCT m.device) FILTER (WHERE m.device IS NOT NULL) AS devices,
               list(DISTINCT m.home_ip) FILTER (WHERE m.home_ip IS NOT NULL) AS home_ips,
               any_value(m.value) AS indicator, any_value(m.kind) AS kind, any_value(m.source) AS source,
               any_value(m.category) AS category, count(DISTINCT m.source) AS n_sources,
               arg_max(m.rule, (m.source NOT IN {ab})::INT * 100 + CASE m.direction WHEN 'outbound' THEN 3 WHEN 'inbound' THEN 2 WHEN 'dns' THEN 1 ELSE 0 END
                               * 10 + CASE m.severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS rule,
               arg_max(m.direction, (m.source NOT IN {ab})::INT * 100 + CASE m.direction WHEN 'outbound' THEN 3 WHEN 'inbound' THEN 2 WHEN 'dns' THEN 1 ELSE 0 END
                               * 10 + CASE m.severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS direction,
               list(DISTINCT m.rule) AS rules, list(DISTINCT m.direction) AS directions,
               -- main's count for list alerts; an abuse.ch match folded in does not count the same row again
               CASE WHEN count(*) FILTER (WHERE m.source NOT IN {ab}) > 0 THEN count(*) FILTER (WHERE m.source NOT IN {ab})
                    ELSE count(DISTINCT (m.rk, m.role, m.observed)) END AS rows,
               count(*) FILTER (WHERE m.source IN {ab}) AS ab_rows,
               count(DISTINCT m.uid) AS uid_count, count(DISTINCT m.rk) AS distinct_rows,
               list(DISTINCT m.uid ORDER BY m.uid) FILTER (WHERE m.uid IS NOT NULL) AS uids,
               list(DISTINCT m.observed) AS observed, list(DISTINCT m.log_type) AS log_types,
               list(DISTINCT m.role) AS roles,
               min(m.i_start) AS i_start, max(m.i_end) AS i_end, bool_or(m.i_end IS NULL) AS i_open,
               any_value(m.in_interval) AS in_interval,
               any_value(m.capped) FILTER (WHERE m.capped IS NOT NULL) AS capped,
               arg_max(m.orig_severity, CASE m.orig_severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 0 END)
                   FILTER (WHERE m.orig_severity IS NOT NULL) AS orig_severity
        FROM netlog_matches m SEMI JOIN _nl_ids i ON i.id = m.alert_id GROUP BY m.alert_id""".replace("{ab}", AB_SQL))
    meta, prov = {}, defaultdict(list)
    metas: dict = defaultdict(list)
    lists: dict[str, list[dict]] = defaultdict(list)   # alert -> one entry per (source, value), primary first
    if rows:
        for r in util.rows_of(cur, f"""
                SELECT * FROM (
                    SELECT alert_id, source, kind, value, category,
                           arg_max(severity, CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS severity,
                           bool_or(in_interval) AS in_interval, min(i_start) AS i_start, max(i_end) AS i_end,
                           bool_or(i_end IS NULL) AS i_open, list(DISTINCT rule) AS rules,
                           count(DISTINCT (rk, role, observed)) AS rows
                    FROM netlog_matches m SEMI JOIN _nl_ids i ON i.id = m.alert_id
                    GROUP BY ALL)
                ORDER BY alert_id, {LEAD_ORDER}"""):
            lists[r.pop("alert_id")].append(r)
        for r in util.rows_of(cur, """
                SELECT DISTINCT m.alert_id, ii.source, ii.value, ii.key, ii."start", ii."end", ii.meta, ii.start_path, ii.end_path
                FROM netlog_matches m SEMI JOIN _nl_ids i ON i.id = m.alert_id
                JOIN indicator_intervals ii ON ii.source = m.source AND ii.value = m.value AND ii."start" = m.i_start"""):
            meta[(r["source"], r["value"])] = json.loads(r["meta"] or "{}")
            metas[(r["source"], r["value"])].append(meta[(r["source"], r["value"])])
            if len(prov[r["alert_id"]]) < 5:
                prov[r["alert_id"]].append({
                    "key": r["key"], "start": r["start"], "end": r["end"],
                    "start_path": r["start_path"], "start_record": record_line(r["start_path"], r["key"]),
                    "end_path": r["end_path"], "end_record": record_line(r["end_path"], r["key"]) if r["end_path"] else None})
    devs = {}
    if rows:
        for r in util.rows_of(cur, """SELECT id, mac, ips, hostnames, confidence, identity FROM devices
                                       WHERE id IN (SELECT DISTINCT device FROM netlog_matches SEMI JOIN _nl_ids i ON i.id = alert_id)"""):
            devs[r["id"]] = r
    # demo: every matched row came from the demo files; imported: when the rows were first imported, to tell an
    # alert found at import from one a list change found later (a re-check of older logs)
    flags = {r["alert_id"]: r for r in util.rows_of(cur, f"""
        SELECT m.alert_id, bool_and(n.file_id IN {incidents.DEMO_FILES}) AS demo, min(f.imported_at) AS imported_at,
               -- DNS sinkholes (Pi-hole, AdGuard Home): how many of the contacts it blocked (sinkhole.py rows)
               count(DISTINCT n.rk) AS all_rows,
               count(DISTINCT n.rk) FILTER (WHERE json_extract_string(n.raw, '$.sinkhole') IS NOT NULL) AS sk_rows,
               count(DISTINCT n.rk) FILTER (WHERE json_extract_string(n.raw, '$.blocked') = 'true') AS sk_blocked,
               list(DISTINCT json_extract_string(n.raw, '$.sinkhole'))
                   FILTER (WHERE json_extract_string(n.raw, '$.sinkhole') IS NOT NULL) AS sk_src,
               list(DISTINCT json_extract_string(n.raw, '$.reason'))
                   FILTER (WHERE json_extract_string(n.raw, '$.blocked') = 'true'
                           AND json_extract_string(n.raw, '$.reason') IS NOT NULL) AS sk_reasons
        FROM netlog_matches m SEMI JOIN _nl_ids i ON i.id = m.alert_id JOIN netlog n ON n.rk = m.rk
        LEFT JOIN netlog_files f ON f.id = n.file_id GROUP BY 1""")} if rows else {}
    samples: dict[str, list] = {}
    for r in util.rows_of(cur, """
        SELECT m.alert_id, n.ts, n.uid, n.log_type, n.orig_h, n.orig_p, n.resp_h, n.resp_p, n.proto, n.service,
               n.conn_state, n.orig_bytes, n.resp_bytes, n.query, n.server_name, n.host
        FROM netlog_matches m SEMI JOIN _nl_ids i ON i.id = m.alert_id JOIN netlog n ON n.rk = m.rk
        QUALIFY row_number() OVER (PARTITION BY m.alert_id ORDER BY n.ts) <= 5"""):
        samples.setdefault(r.pop("alert_id"), []).append({k: v for k, v in r.items() if v is not None})
    out = []
    for r in rows:
        ls = lists.get(r["id"]) or []
        also: list[dict] = []
        if r["ab_rows"] and ls:   # abuse.ch matches in this alert: the lead decides; other sources corroborate it
            p0 = ls[0]
            lead = [x for x in ls if x["source"] == p0["source"]]
            r.update(source=p0["source"], indicator=p0["value"], kind=p0["kind"], category=p0["category"],
                     i_start=min(x["i_start"] for x in lead), i_end=max((x["i_end"] for x in lead if x["i_end"]), default=None),
                     i_open=any(x["i_open"] for x in lead))
            by_src: dict[str, list] = {}
            for x in ls:
                if x["source"] != p0["source"]:   # never the alert's own source
                    by_src.setdefault(x["source"], []).append(x)
            for src, xs in by_src.items():
                mws = [m.get("malware") for x in xs for m in metas.get((src, x["value"]), []) if m.get("malware")]
                m0 = next(iter(metas.get((src, xs[0]["value"]), [])), {})
                also.append({"source": src, "source_name": _source_name(src, m0), "source_tier": tier(src),
                             "values": [{"kind": x["kind"], "value": x["value"]} for x in xs], "value": xs[0]["value"],
                             "kind": xs[0]["kind"], "category": xs[0]["category"],
                             "severity": max((x["severity"] for x in xs), key=lambda v: SEV_RANK.get(v, -1)),
                             "in_listing": any(x["in_interval"] for x in xs), "start": min(x["i_start"] for x in xs),
                             "end": None if any(x["i_open"] for x in xs) else max(x["i_end"] for x in xs),
                             "rules": sorted({ru for x in xs for ru in x["rules"]}),
                             "malware": mws[0] if mws else None})
        md = dict(meta.get((r["source"], r["indicator"]), {}))
        if r["source"] in intervals.ABUSECH:   # one address listed for several ports or IOCs: say so
            ms = metas.get((r["source"], r["indicator"]), [])
            ports = sorted({m["port"] for m in ms if m.get("port") is not None})
            if len(ports) > 1:
                md["ports"] = ports
            ioc_ids = sorted({m.get("ioc_id") or m.get("url_id") for m in ms if m.get("ioc_id") or m.get("url_id")})
            if len(ioc_ids) > 1:
                md["ioc_ids"] = ioc_ids
        dev = devs.get(r["device"])
        fl0 = flags.get(r["id"]) or {}
        sk = None
        if fl0.get("sk_rows"):   # a DNS sinkhole saw these lookups: say what it did; all blocked lowers one level
            sk = {"sources": sorted(fl0["sk_src"] or []), "rows": fl0["sk_rows"], "blocked": fl0["sk_blocked"],
                  "allowed": fl0["sk_rows"] - fl0["sk_blocked"], "reasons": (fl0["sk_reasons"] or [])[:5],
                  "all_blocked": fl0["sk_blocked"] == fl0["all_rows"]}
            if sk["all_blocked"] and r["severity"] in SINK_LOWER:
                sk["lowered_from"] = r["severity"]
                r["severity"] = SINK_LOWER[r["severity"]]
        hist = r["rule"] == "historical"
        retro = r["rule"].endswith("_retro")
        dir_ = "historical" if hist else "retro" if retro else r["direction"]
        who = (dev["hostnames"][0] if dev and dev.get("hostnames") else
               str(r["device"] or "").split(":", 1)[-1] or "a home device")
        src = _source_name(r["source"], md)
        word = CATEGORY_WORDS.get(r["category"], "a listed address") + (f" ({md['malware']})" if md.get("malware") else "")
        on = f"{word} on {src}" if not r["category"].startswith("reported") else f"{word}"
        if r["category"] == "own":
            on = f"on {src}"
        homes = r["devices"] or r["home_ips"] or []
        if r["category"] == "ids":
            sig = (r["observed"] or [NO_SIG])[0]
            title = f"{who}: {sig if sig != NO_SIG else 'this intrusion signature has no name'} (Suricata)"
        elif r["category"] == "kev":
            title = f"{who} may run software with {r['indicator']}, an exploited vulnerability"
        elif retro:
            since = str(md.get("first_seen") or "?")[:10]
            title = f"{who} contacted {r['indicator']} before {src} listed it ({src} reports it active since {since})"
        elif hist:
            title = f"Contact with {r['indicator']} outside the time {src} listed it"
        elif r["direction"] == "inbound":
            title = f"{r['indicator']}, {on}, connected to {len(homes)} home device{'' if len(homes) == 1 else 's'}"
        elif r["direction"] == "dns":
            title = f"{who} looked up a name pointing to {r['indicator']}, {on}"
        else:
            title = f"{who} contacted {r['indicator']}, {on}"
        if r.get("capped"):
            title += f" (lowered from {r['orig_severity']}: peer-to-peer traffic)"
        if sk and sk["all_blocked"]:
            title += f" (blocked by {' and '.join(SINK_NAMES.get(x, x) for x in sk['sources'])})"
        if also and r["category"] != "ids":
            names = list(dict.fromkeys(a["source_name"] + (f" ({a['malware']})" if a.get("malware") and a["malware"] != md.get("malware") else "")
                                       for a in also))
            title += " · also listed by " + ", ".join(names[:4]) + (f" +{len(names) - 4}" if len(names) > 4 else "")
        ev = {
            # uids: up to UID_CAP (sorted); uid_count is the full total; GET /api/netlog/alerts/{id}/uids lists all
            "uids": (r["uids"] or [])[:UID_CAP], "uid_count": r["uid_count"], "uid_cap": UID_CAP,
            "uids_truncated": r["uid_count"] > UID_CAP, "rows": r["rows"], "distinct_rows": r["distinct_rows"],
            "indicator": {"value": r["indicator"], "kind": r["kind"], "category": r["category"],
                          "observed": r["observed"][:20], "meta": md},
            "source": r["source"],
            "source_tier": tier(r["source"]),
            # other lists that hold the same contact: one alert, corroborated (okf/data/netlog.md#cross-source)
            **({"also_listed": also, "sources": [r["source"], *(a["source"] for a in also)]} if also else {}),
            "listing": prov.get(r["id"], []),
            "interval": {"start": r["i_start"], "end": None if r["i_open"] else r["i_end"],
                         "contains_ts": bool(r["in_interval"]),
                         "grace_seconds": float(util.settings().get("grace_seconds") or 0)},
            "device": {"id": r["device"], "devices": r["devices"] or [], "home_ips": r["home_ips"] or [],
                       **({"mac": dev["mac"], "identity": dev["identity"], "confidence": dev["confidence"],
                           "hostnames": dev["hostnames"]} if dev else {})},
            "rule": {"id": r["rule"], "direction": dir_, "severity": r["severity"],
                     "description": DESCRIPTIONS.get(dir_, ""), "roles": r["roles"],
                     "rules": r["rules"], "directions": r["directions"]},
            **({"capped": r["capped"], "original_severity": r["orig_severity"],
                "capped_note": f"lowered from {r['orig_severity']}: P2P swarm"} if r.get("capped") else {}),
            "log_types": r["log_types"], "first_ts": r["ts"], "last_ts": r["last_ts"],
            **({"sinkhole": sk} if sk else {}),
            **({"found_later": {"imported_at": fl["imported_at"], "listed_at": r["i_start"]}}
               if (fl := flags.get(r["id"])) and fl.get("imported_at") and r.get("i_start")
               and (r["i_start"] - fl["imported_at"]).total_seconds() > (0 if ownlists.is_own(r["source"]) else FOUND_LATER_S)
               else {}),
            "sample": samples.get(r["id"], []),
        }
        out.append({"id": r["id"], "ts": r["ts"], "last_ts": r["last_ts"], "severity": r["severity"],
                    "device": r["device"], "indicator": r["indicator"], "source": r["source"], "rule": r["rule"],
                    "direction": dir_, "title": title, "count": r["rows"], "evidence": json.dumps(util.jsonable(ev), default=str),
                    "demo": bool((flags.get(r["id"]) or {}).get("demo"))})
    keep = {o["id"] for o in out}
    gone = [i for i in ids if i not in keep]
    # statuses: a re-keyed alert keeps its user's status only if it is the same alert at no higher severity
    # (carry_status); an acked or dismissed alert whose severity rises above the severity the user triaged it at
    # reopens as new. Against the triaged severity, not the last one: a setting that lowers severity (home prefixes,
    # grace, p2p_cap) and is changed back must not reopen it (okf/data/netlog.md#alert-status)
    status_rows, reopen = [], []   # (id, status, triaged severity)
    for o in out:
        if carry and o["id"] in carry and (st := carry_status(o, carry[o["id"]])):
            sev = max((c["severity"] for c in _same_alert(o, carry[o["id"]])), key=lambda v: SEV_RANK.get(v, 0))
            status_rows.append((o["id"], st, sev))
    if out:
        # per alert: its last severity and status (None when it does not exist now: deleted by an earlier re-match,
        # its user status kept by id), and the user's status and triaged severity
        prev = {r[0]: r[1:] for r in cur.execute(
            """SELECT o.id, a.severity, a.status, s.status, s.severity FROM (SELECT unnest(?) AS id) o
               LEFT JOIN alerts a ON a.id = o.id LEFT JOIN netlog_alert_status s ON s.id = o.id""",
            [[o["id"] for o in out]]).fetchall()}
        for o in out:
            a_sev, a_st, s_st, s_sev = prev.get(o["id"], (None, None, None, None))
            st = a_st if a_sev is not None else s_st   # what the user sees, or gets back when it is re-created
            if st not in ("ack", "dismissed"):
                continue
            seen = s_sev if s_sev is not None else _legacy_seen(a_sev, settings)
            if seen is None or SEV_RANK.get(o["severity"], 0) <= SEV_RANK.get(seen, 0):
                continue
            reopen.append(o["id"])
            status_rows.append((o["id"], "new", o["severity"]))
            ev = json.loads(o["evidence"])
            ev["reopened"] = {"was": st, "severity_from": seen, "severity_to": o["severity"]}
            o["evidence"] = json.dumps(ev, default=str)
    if status_rows:
        cur.executemany("""INSERT OR REPLACE INTO netlog_alert_status (id, status, updated_at, severity)
                           VALUES (?, ?, now(), ?)""", status_rows)
    if gone:
        cur.executemany("DELETE FROM alerts WHERE id = ?", [(i,) for i in gone])
    if out:
        p = util.scratch("alerts")
        util.write_ndjson(p, out)
        try:
            cur.execute(f"""
                INSERT INTO alerts (id, ts, last_ts, severity, device, indicator, source, rule, direction, title, count,
                                    evidence, status, created_at, updated_at, demo)
                SELECT a.id, ts, last_ts, a.severity, device, indicator, source, rule, direction, title, count, evidence,
                       coalesce(st.status, 'new'), now(), now(), demo
                FROM {util.read_src(p, {'id': 'VARCHAR', 'ts': 'TIMESTAMPTZ', 'last_ts': 'TIMESTAMPTZ', 'severity': 'VARCHAR',
                                        'device': 'VARCHAR', 'indicator': 'VARCHAR', 'source': 'VARCHAR', 'rule': 'VARCHAR',
                                        'direction': 'VARCHAR', 'title': 'VARCHAR', 'count': 'BIGINT', 'evidence': 'VARCHAR',
                                        'demo': 'BOOLEAN'})} a
                LEFT JOIN netlog_alert_status st ON st.id = a.id
                ON CONFLICT (id) DO UPDATE SET ts = excluded.ts, last_ts = excluded.last_ts, severity = excluded.severity,
                    device = excluded.device, indicator = excluded.indicator, source = excluded.source,
                    rule = excluded.rule, direction = excluded.direction, title = excluded.title,
                    count = excluded.count, evidence = excluded.evidence, demo = excluded.demo, updated_at = now()""")
        finally:
            p.unlink(missing_ok=True)
        if reopen:
            cur.executemany("UPDATE alerts SET status = 'new' WHERE id = ?", [(i,) for i in reopen])
    cur.execute("DROP TABLE IF EXISTS _nl_ids")
    incidents.regroup(cur)   # one beacon across UTC midnight is one incident (incidents.py)
    return len(out)
