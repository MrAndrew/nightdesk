"""DuckDB tables for netlog. Column meanings: okf/data/netlog.md"""
from __future__ import annotations

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS netlog_files (
    id          VARCHAR PRIMARY KEY,   -- sha256 of the decompressed content
    name        VARCHAR,
    path        VARCHAR,               -- gzipped original in the lake
    origin      VARCHAR,               -- upload | inbox | api
    format      VARCHAR,               -- ndjson | array
    size        BIGINT,                -- decompressed bytes
    imported_at TIMESTAMPTZ,
    rows        BIGINT,
    inserted    BIGINT,
    duplicates  BIGINT,
    log_types   VARCHAR,               -- JSON {type: rows}
    ts_min      TIMESTAMPTZ,
    ts_max      TIMESTAMPTZ,
    seconds     DOUBLE,
    status      VARCHAR,               -- ok | error
    error       VARCHAR
);
ALTER TABLE netlog_files ADD COLUMN IF NOT EXISTS skipped BIGINT;      -- lines that were not JSON objects
ALTER TABLE netlog_files ADD COLUMN IF NOT EXISTS warnings VARCHAR;    -- JSON list
CREATE TABLE IF NOT EXISTS netlog (
    rk            UBIGINT,             -- hash of (uid or fuid or raw, log_type, ts): row dedup key
    file_id       VARCHAR,
    ts            TIMESTAMPTZ,
    uid           VARCHAR,
    log_type      VARCHAR,
    orig_h        VARCHAR,
    orig_p        INTEGER,
    resp_h        VARCHAR,
    resp_p        INTEGER,
    proto         VARCHAR,
    service       VARCHAR,
    duration      DOUBLE,
    orig_bytes    BIGINT,
    resp_bytes    BIGINT,
    conn_state    VARCHAR,
    history       VARCHAR,
    query         VARCHAR,
    answers       VARCHAR[],
    server_name   VARCHAR,
    host          VARCHAR,
    uri           VARCHAR,
    mac           VARCHAR,             -- dhcp mac, or conn orig_l2_addr
    resp_mac      VARCHAR,             -- conn resp_l2_addr
    hostname      VARCHAR,             -- dhcp host_name
    raw           VARCHAR              -- the original JSON object
);
CREATE TABLE IF NOT EXISTS netlog_ipnum (
    ip  VARCHAR PRIMARY KEY,
    n   UHUGEINT,                      -- IPv6 integer; IPv4 as ::ffff:a.b.c.d
    v6  BOOLEAN
);
CREATE TABLE IF NOT EXISTS netlog_ipmap (
    ip       VARCHAR,
    mac      VARCHAR,
    first_ts TIMESTAMPTZ,
    last_ts  TIMESTAMPTZ,
    how      VARCHAR,                  -- dhcp | l2 | eui64 | behaviour
    confidence DOUBLE,
    rows     BIGINT
);
CREATE TABLE IF NOT EXISTS netlog_ipdev (
    ip         VARCHAR,
    from_ts    TIMESTAMPTZ,            -- the device held this IP from then (1970 for the first holder)
    device     VARCHAR,
    how        VARCHAR,
    confidence VARCHAR
);
CREATE TABLE IF NOT EXISTS devices (
    id          VARCHAR PRIMARY KEY,   -- mac:<mac> or ip:<ip>
    identity    VARCHAR,               -- mac | ip
    mac         VARCHAR,
    ips         VARCHAR[],
    hostnames   VARCHAR[],
    first_seen  TIMESTAMPTZ,
    last_seen   TIMESTAMPTZ,
    rows        BIGINT,
    conns       BIGINT,
    bytes_out   BIGINT,
    bytes_in    BIGINT,
    top_dests   VARCHAR,               -- JSON [{ip, bytes, conns}]
    top_names   VARCHAR,               -- JSON [{name, n}]
    confidence  VARCHAR,               -- certain | derived | probable | ip-only
    evidence    VARCHAR                -- JSON
);
CREATE TABLE IF NOT EXISTS indicator_intervals (
    source     VARCHAR,
    kind       VARCHAR,                -- ip | cidr | domain | cve
    value      VARCHAR,
    "start"    TIMESTAMPTZ,
    "end"      TIMESTAMPTZ,            -- NULL while still listed
    key        VARCHAR,                -- the provider record key
    category   VARCHAR,                -- c2 | drop | compromised | reputation | attacker | scanner | tor | kev | reported
    lo         UHUGEINT,
    hi         UHUGEINT,
    meta       VARCHAR,                -- JSON from the last put
    start_path VARCHAR,
    end_path   VARCHAR
);
CREATE TABLE IF NOT EXISTS netlog_ti_files (
    source VARCHAR,
    path   VARCHAR PRIMARY KEY,
    ts     TIMESTAMPTZ,
    puts   BIGINT,
    dels   BIGINT
);
CREATE TABLE IF NOT EXISTS netlog_matches (
    rk         UBIGINT,
    ts         TIMESTAMPTZ,
    uid        VARCHAR,
    log_type   VARCHAR,
    role       VARCHAR,                -- resp | orig | answer | name
    observed   VARCHAR,                -- the IP or name seen in the log
    home_ip    VARCHAR,
    direction  VARCHAR,                -- outbound | inbound | unknown
    device     VARCHAR,
    source     VARCHAR,
    kind       VARCHAR,
    value      VARCHAR,
    category   VARCHAR,
    i_start    TIMESTAMPTZ,
    i_end      TIMESTAMPTZ,
    in_interval BOOLEAN,
    rule       VARCHAR,
    severity   VARCHAR,
    alert_id   VARCHAR
);
ALTER TABLE netlog_matches ADD COLUMN IF NOT EXISTS capped VARCHAR;          -- p2p_swarm when severity was lowered
ALTER TABLE netlog_matches ADD COLUMN IF NOT EXISTS orig_severity VARCHAR;   -- severity before the cap
CREATE TABLE IF NOT EXISTS netlog_alert_status (   -- user status by alert id; survives an alert being re-created
    id         VARCHAR PRIMARY KEY,
    status     VARCHAR,
    updated_at TIMESTAMPTZ
);
-- the alert's severity when the user set that status: only a rise above it reopens the alert, so a setting that lowers
-- severity and is changed back leaves the status alone (okf/data/netlog.md#alert-status); NULL on rows from
-- before the column (matcher._legacy_seen: a settings re-match never reopens those)
ALTER TABLE netlog_alert_status ADD COLUMN IF NOT EXISTS severity VARCHAR;
CREATE TABLE IF NOT EXISTS alerts (
    id         VARCHAR PRIMARY KEY,
    ts         TIMESTAMPTZ,            -- first matching log row
    last_ts    TIMESTAMPTZ,
    severity   VARCHAR,                -- high | medium | low | info
    device     VARCHAR,
    indicator  VARCHAR,
    source     VARCHAR,
    rule       VARCHAR,
    direction  VARCHAR,
    title      VARCHAR,
    count      BIGINT,
    evidence   VARCHAR,                -- JSON
    status     VARCHAR DEFAULT 'new',  -- new | ack | dismissed
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);
"""


def ensure() -> None:
    """Create the tables (used when ext.py is not handling schema)."""
    from .. import db
    db.connect()
    from .devices import AGG_SQL
    with db._write_lock:
        db.cursor().execute(SCHEMA_SQL + AGG_SQL)
