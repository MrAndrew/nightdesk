"""DuckDB access. Data model and pipeline: okf/data/architecture.md"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import duckdb

from . import config

_conn: duckdb.DuckDBPyConnection | None = None
_write_lock = threading.Lock()
_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          VARCHAR PRIMARY KEY,
    source      VARCHAR NOT NULL,
    kind        VARCHAR NOT NULL,
    category    VARCHAR,
    ts          TIMESTAMPTZ NOT NULL,
    title       VARCHAR,
    summary     VARCHAR,
    severity    DOUBLE,
    lat         DOUBLE,
    lon         DOUBLE,
    country     VARCHAR,
    city        VARCHAR,
    ip          VARCHAR,
    asn         VARCHAR,
    url         VARCHAR,
    tags        VARCHAR[],
    value       DOUBLE,
    raw_path    VARCHAR,
    ingested_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS source_state (
    id          VARCHAR PRIMARY KEY,
    enabled     BOOLEAN,
    status      VARCHAR,
    message     VARCHAR,
    last_run    TIMESTAMPTZ,
    last_ok     TIMESTAMPTZ,
    items_last  BIGINT,
    items_total BIGINT
);
CREATE TABLE IF NOT EXISTS runs (
    source   VARCHAR,
    started  TIMESTAMPTZ,
    finished TIMESTAMPTZ,
    ok       BOOLEAN,
    items    BIGINT,
    raw_path VARCHAR,
    error    VARCHAR
);
CREATE TABLE IF NOT EXISTS record_hashes (
    source    VARCHAR,
    key       VARCHAR,
    hash      VARCHAR,
    stored_at TIMESTAMPTZ,
    PRIMARY KEY (source, key)
);
CREATE TABLE IF NOT EXISTS settings (
    key   VARCHAR PRIMARY KEY,
    value VARCHAR
);
CREATE TABLE IF NOT EXISTS metrics (
    ts     TIMESTAMPTZ,
    name   VARCHAR,
    value  DOUBLE
);
-- Latest FIRST EPSS score of every scored CVE, replaced by each new daily file (sources/vulns.py).
CREATE TABLE IF NOT EXISTS epss (
    cve           VARCHAR,
    epss          DOUBLE,
    percentile    DOUBLE,
    score_date    TIMESTAMPTZ,
    model_version VARCHAR,
    since         TIMESTAMPTZ,
    prev_epss     DOUBLE
);
-- Stored events their author asked to be deleted (Bluesky Jetstream delete events, sources/streams.py). Recorded
-- only: the event stays in the database and the lake and is shown as before. What to do with it is up to whoever
-- runs Night Desk (NOTICE, "Your data and the sources you turn on").
CREATE TABLE IF NOT EXISTS deletion_requests (
    event_id     VARCHAR PRIMARY KEY,
    source       VARCHAR NOT NULL,
    url          VARCHAR,
    requested_at TIMESTAMPTZ NOT NULL,
    recorded_at  TIMESTAMPTZ DEFAULT now()
);
-- One row per CISA CSAF advisory and CVE it covers (sources/vulns.py).
CREATE TABLE IF NOT EXISTS advisory_cves (
    advisory     VARCHAR,
    cve          VARCHAR,
    cvss         DOUBLE,
    cvss_version VARCHAR,
    severity     VARCHAR,
    cwe          VARCHAR,
    vendors      VARCHAR[],
    products     VARCHAR[],
    title        VARCHAR,
    kind         VARCHAR,
    published    TIMESTAMPTZ,
    updated      TIMESTAMPTZ,
    url          VARCHAR
);
"""


MIGRATIONS = [
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS content_hash VARCHAR",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS stored_at TIMESTAMPTZ",
    "ALTER TABLE runs ADD COLUMN IF NOT EXISTS records_changed BIGINT",
    "ALTER TABLE runs ADD COLUMN IF NOT EXISTS records_removed BIGINT",
    "ALTER TABLE runs ADD COLUMN IF NOT EXISTS events_changed BIGINT",
    "DROP TABLE IF EXISTS snapshots",
]

EVENT_COLS = (
    "id VARCHAR, source VARCHAR, kind VARCHAR, category VARCHAR, ts TIMESTAMPTZ, "
    "title VARCHAR, summary VARCHAR, severity DOUBLE, lat DOUBLE, lon DOUBLE, "
    "country VARCHAR, city VARCHAR, ip VARCHAR, asn VARCHAR, url VARCHAR, "
    "tags VARCHAR[], value DOUBLE, raw_path VARCHAR"
)


def _columns(extra: str = "") -> str:
    cols = EVENT_COLS + extra
    return ", ".join(f"'{c.split()[0]}': '{' '.join(c.split()[1:])}'" for c in cols.split(", "))


def _q(path: Path | str) -> str:
    return str(path).replace("'", "''")


# Every DuckDB the app opens: never download or auto-load an extension. Offline means zero egress, and a query that
# names an extension's feature (an http:// or s3:// path, sql_auto_complete, ...) would otherwise fetch it from
# extensions.duckdb.org. json, parquet, icu and core_functions are built into the duckdb wheel, so nothing is lost.
# DuckDB's own folders default to ~/.duckdb (secrets, extensions): they point into the database's folder in the lake
# instead, and persistent secrets are off, so nothing DuckDB reports or writes names the home folder.
_DUCKDB_HOME = str(config.DB_PATH.parent / ".duckdb")
DUCKDB_CONFIG = {"autoinstall_known_extensions": False, "autoload_known_extensions": False,
                 "allow_persistent_secrets": False, "python_enable_replacements": False,  # no scans of Python objects by name
                 "home_directory": _DUCKDB_HOME,
                 "secret_directory": _DUCKDB_HOME + "/stored_secrets", "extension_directory": _DUCKDB_HOME + "/extensions"}


def restrict(con: duckdb.DuckDBPyConnection, dirs=(), paths=(), lock: bool = False) -> None:
    """Shut a DuckDB connection off from the network and from every file except those in the folders `dirs` and the
    single files `paths` (each allowed as given and resolved: /var and /private/var). With neither it reads and writes
    no file at all. The database's own files (the .duckdb file, its .wal and its .tmp spill folder) stay usable either
    way. Once off, external access cannot be switched back on while the connection is open. `lock` also freezes every
    other setting (extension auto-load among them) for a connection that changes none later; the app database sets
    the time zone on each cursor, so it is not locked. Every DuckDB the app opens goes through this
    (okf/architecture/api.md#sql-console)."""
    ds = sorted({f"{d}/" for base in dirs for d in (Path(base), Path(base).resolve())})
    ps = sorted({str(f) for p in paths for f in (Path(p), Path(p).resolve())})
    if ds:
        con.execute("SET allowed_directories = [" + ", ".join(f"'{_q(d)}'" for d in ds) + "]")
    if ps:
        con.execute("SET allowed_paths = [" + ", ".join(f"'{_q(p)}'" for p in ps) + "]")
    con.execute("SET enable_external_access = false")
    if lock:
        con.execute("SET lock_configuration = true")


def connect() -> duckdb.DuckDBPyConnection:
    global _conn
    if _conn is None:
        _conn = duckdb.connect(str(config.DB_PATH), config=DUCKDB_CONFIG)
        _conn.execute("SET TimeZone='UTC'")
        # Defence in depth for the SQL console: this database may read and write files only in the lake and its own
        # folder (every app path is there: raw/, tmp/, uploads/, ref/, the .tmp spill folder) and never the network.
        restrict(_conn, dirs=(config.LAKE, config.DB_PATH.parent))
        _conn.execute(SCHEMA)
        for stmt in MIGRATIONS:
            _conn.execute(stmt)
        from . import ext  # feature packages add their tables (okf/architecture/system.md#extensions)
        ext.load_all()
        ext.apply_schema(_conn)
    return _conn


def close() -> None:
    """Checkpoint and close the database (before the process starts again; osinthub/__main__.py)."""
    global _conn
    if _conn is not None:
        try:
            _conn.execute("CHECKPOINT")
        finally:
            _conn.close()
            _conn = None


def cursor() -> duckdb.DuckDBPyConnection:
    cur = getattr(_local, "cur", None)
    if cur is None:
        cur = connect().cursor()
        cur.execute("SET TimeZone='UTC'")
        _local.cur = cur
    return cur


def query(sql: str, params: list[Any] | tuple = ()) -> list[dict[str, Any]]:
    cur = cursor()
    res = cur.execute(sql, params)
    cols = [d[0] for d in res.description]
    return [dict(zip(cols, row)) for row in res.fetchall()]


def execute(sql: str, params: list[Any] | tuple = ()) -> None:
    with _write_lock:
        cursor().execute(sql, params)


@contextmanager
def tx(cur: duckdb.DuckDBPyConnection):
    """BEGIN a transaction on `cur`, COMMIT on success, ROLLBACK and re-raise on any exception.

    It does NOT take `_write_lock`: that lock is a non-reentrant `threading.Lock`, so the caller keeps its own
    `with _write_lock:` around this. Without the ROLLBACK, a failed statement leaves the thread-local cursor stuck
    in an aborted transaction and every later statement on that worker's cursor fails.
    """
    cur.execute("BEGIN")
    try:
        yield cur
    except BaseException:
        cur.execute("ROLLBACK")
        raise
    else:
        cur.execute("COMMIT")


def tables() -> set[str]:
    """Every table name in the database."""
    return {r["table_name"] for r in query("SELECT table_name FROM information_schema.tables")}


def has_table(name: str) -> bool:
    """Whether a table of this name exists."""
    return bool(query("SELECT 1 FROM information_schema.tables WHERE table_name = ? LIMIT 1", [name]))


def load_events_ndjson(path: Path) -> int:
    """Upsert normalised events from an NDJSON file in the lake. Returns rows loaded."""
    src = f"read_json('{_q(path)}', format='newline_delimited', columns={{{_columns()}}})"
    with _write_lock:
        cur = cursor()
        cur.execute(
            f"""
            INSERT OR REPLACE INTO events
              (id, source, kind, category, ts, title, summary, severity, lat, lon,
               country, city, ip, asn, url, tags, value, raw_path, ingested_at, stored_at)
            SELECT id, source, kind, category, ts, title, summary, severity, lat, lon,
                   country, city, ip, asn, url, tags, value, raw_path, now(), now()
            FROM {src}
            QUALIFY row_number() OVER (PARTITION BY id ORDER BY ts DESC) = 1
            """
        )
        n = cur.execute(f"SELECT count(*) FROM {src}").fetchone()[0]
    return int(n)


def load_batch(scratch: Path, events_out: Path | None) -> tuple[int, int]:
    """Upsert a batch and write only its new or changed events to the lake.

    `scratch` holds every event of the batch with a `content_hash`. Rows whose hash matches
    the stored row are refreshed in DuckDB (timestamps, ingested_at) but not written again.
    Returns (rows in batch, rows new or changed).
    """
    src = f"read_json('{_q(scratch)}', format='newline_delimited', columns={{{_columns(', content_hash VARCHAR')}}})"
    with _write_lock:
        cur = cursor()
        cur.execute(f"""CREATE OR REPLACE TEMP TABLE _b AS SELECT * FROM {src}
                        QUALIFY row_number() OVER (PARTITION BY id ORDER BY ts DESC) = 1""")
        cur.execute("""CREATE OR REPLACE TEMP TABLE _d AS SELECT b.id FROM _b b LEFT JOIN events e ON e.id = b.id
                       WHERE e.id IS NULL OR e.content_hash IS DISTINCT FROM b.content_hash""")
        n = cur.execute("SELECT count(*) FROM _b").fetchone()[0]
        changed = cur.execute("SELECT count(*) FROM _d").fetchone()[0]
        if changed and events_out is not None:
            events_out.parent.mkdir(parents=True, exist_ok=True)
            cur.execute(f"""COPY (SELECT b.* EXCLUDE (content_hash) FROM _b b SEMI JOIN _d USING (id) ORDER BY b.id)
                            TO '{_q(events_out)}' (FORMAT json, COMPRESSION gzip)""")
        cur.execute("""
            INSERT OR REPLACE INTO events
              (id, source, kind, category, ts, title, summary, severity, lat, lon,
               country, city, ip, asn, url, tags, value, raw_path, ingested_at, content_hash, stored_at)
            SELECT b.id, b.source, b.kind, b.category, b.ts, b.title, b.summary, b.severity, b.lat, b.lon,
                   b.country, b.city, b.ip, b.asn, b.url, b.tags, b.value,
                   CASE WHEN d.id IS NOT NULL THEN coalesce(b.raw_path, e.raw_path) ELSE coalesce(e.raw_path, b.raw_path) END,
                   now(), b.content_hash,
                   CASE WHEN d.id IS NOT NULL THEN now() ELSE e.stored_at END
            FROM _b b LEFT JOIN _d d ON d.id = b.id LEFT JOIN events e ON e.id = b.id
        """)
        cur.execute("DROP TABLE _b")
        cur.execute("DROP TABLE _d")
    return int(n), int(changed)


def record_deletion_requests(source: str, gone: list[tuple[str, Any]]) -> int:
    """Mark this source's stored events whose author asked for them to be deleted. `gone` is (event id, when the
    author deleted it) pairs. Only ids already in `events` are recorded: a stream can send every deletion on the
    network, and Night Desk kept almost none of those posts. The first request for an event is kept; the event itself
    is not touched. Returns the number of events newly marked."""
    if not gone:
        return 0
    with _write_lock:
        rows = cursor().execute(
            """INSERT OR IGNORE INTO deletion_requests (event_id, source, url, requested_at)
               SELECT e.id, e.source, e.url, d.requested_at
               FROM (SELECT unnest(?::VARCHAR[]) AS id, unnest(?::TIMESTAMPTZ[]) AS requested_at) d
               JOIN events e ON e.id = d.id AND e.source = ?
               QUALIFY row_number() OVER (PARTITION BY e.id ORDER BY d.requested_at) = 1
               RETURNING event_id""",
            [[g[0] for g in gone], [g[1] for g in gone], source]).fetchall()
    return len(rows)


def record_hashes(source: str) -> dict[str, tuple[str, Any]]:
    rows = cursor().execute("SELECT key, hash, stored_at FROM record_hashes WHERE source = ?", [source]).fetchall()
    return {k: (h, t) for k, h, t in rows}


def replace_record_hashes(source: str, rows: dict[str, tuple[str, Any]]) -> None:
    """Make the stored record set for a source equal to `rows` (key -> (hash, stored_at))."""
    import csv
    tmp = config.TMP_DIR / f"hashes-{source}.csv"
    with tmp.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["key", "hash", "stored_at"])
        for k, (h, t) in rows.items():
            w.writerow([k, h, t.isoformat() if hasattr(t, "isoformat") else t])
    try:
        with _write_lock:
            cur = cursor()
            with tx(cur):
                cur.execute("DELETE FROM record_hashes WHERE source = ?", [source])
                cur.execute(f"""INSERT INTO record_hashes SELECT ?, key, hash, stored_at FROM read_csv('{_q(tmp)}', header=true,
                                columns={{'key': 'VARCHAR', 'hash': 'VARCHAR', 'stored_at': 'TIMESTAMPTZ'}}, quote='"', escape='"')""", [source])
    finally:
        tmp.unlink(missing_ok=True)


def get_setting(key: str, default: Any = None) -> Any:
    import json
    rows = cursor().execute("SELECT value FROM settings WHERE key = ?", [key]).fetchall()
    return json.loads(rows[0][0]) if rows else default


def set_setting(key: str, value: Any) -> None:
    import json
    execute("INSERT OR REPLACE INTO settings VALUES (?, ?)", [key, json.dumps(value)])


def record_metric(name: str, value: float) -> None:
    execute("INSERT INTO metrics VALUES (now(), ?, ?)", [name, float(value)])
