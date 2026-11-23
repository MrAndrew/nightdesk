"""Zeek JSON import: NDJSON or JSON-array, plain or gzipped, bulk-loaded through DuckDB. Pi-hole and AdGuard Home
DNS logs are recognised by content and converted to DNS rows first (sinkhole.py).

The original goes to the lake gzipped (raw/netlog/YYYY/MM/DD/), deduplicated by a sha256 of its
decompressed content; rows are deduplicated by a (uid, log_type, ts) key. Format: okf/data/netlog.md
"""
from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import re
import shutil
import tarfile
import stat
import threading
import time
import zlib
from pathlib import Path
from typing import BinaryIO

from .. import config, db
from . import ipnum, util

log = logging.getLogger("osinthub.netlog")

CHUNK = 1 << 20
LAKE_DIR = config.RAW_DIR / "netlog"
MAX_UNCOMPRESSED = 8 << 30      # 8 GiB per file/member: refuse a decompression bomb (gzip/zip/tar/xz/bz2)
MAX_BUNDLE_UNCOMPRESSED = 16 << 30   # total across all members of one bundle
MAX_BUNDLE_MEMBERS = 10000      # refuse an archive with an absurd number of members (index-parse DoS)
# A tar is decompressed to a temp file before parsing; cap that hard so that no crafted header can make
# tarfile allocate a huge buffer, even if a future tarfile quirk were to slip past the header pre-scan
# — nothing larger than this can physically exist in the temp. Large data goes through the per-file
# push/import path (MAX_UNCOMPRESSED), which has no such container limit; only tar *bundles* are capped.
MAX_TAR_DECOMPRESSED = 2 << 30   # 2 GiB


class _TooBig(Exception):
    """A file or archive member expands past MAX_UNCOMPRESSED (decompression bomb)."""


def _zip_entry_count(fh: BinaryIO) -> int | None:
    """An upper bound on the entries zipfile will parse, read cheaply from the end-of-central-
    directory record, so a zip with a huge central directory is rejected before zipfile parses the
    whole index into RAM. None if it cannot be determined (then zipfile handles it, bad files raise).

    zipfile reads `size_of_central_directory` bytes and parses one record (>= 46 bytes) at a time;
    the `total_entries` count field is NOT what bounds that loop, so we take max(count, size_cd//46)
    — a forged count cannot hide a large central directory."""
    import struct

    def done(v):
        try:
            fh.seek(0)
        except OSError:
            pass
        return v

    try:
        fh.seek(0, 2)
        size = fh.tell()
        fh.seek(max(0, size - 65557))   # the EOCD, and its 20-byte ZIP64 locator, live in this tail
        data = fh.read()
    except OSError:
        return done(None)
    i = data.rfind(b"PK\x05\x06")
    if i < 0 or i + 22 > len(data):
        return done(None)
    count = struct.unpack("<H", data[i + 10:i + 12])[0]
    size_cd = struct.unpack("<I", data[i + 12:i + 16])[0]
    # zipfile follows the ZIP64 locator whenever a valid one precedes the EOCD, regardless of the
    # regular fields — so we must too, or honest-looking small regular fields hide a huge ZIP64 index.
    if i - 20 >= 0 and data[i - 20:i - 16] == b"PK\x06\x07":
        z64 = struct.unpack("<Q", data[i - 12:i - 4])[0]   # locator: sig(4) disk(4) offset(8) ndisks(4)
        try:
            fh.seek(z64)
            rec = fh.read(48)
        except OSError:
            return done(None)
        if len(rec) < 48 or rec[:4] != b"PK\x06\x06":
            return done(None)
        count = max(count, struct.unpack("<Q", rec[32:40])[0])
        size_cd = max(size_cd, struct.unpack("<Q", rec[40:48])[0])
    elif count == 0xFFFF or size_cd == 0xFFFFFFFF:
        return done(None)   # sentinel claims ZIP64 but no locator is present → cannot validate → fail closed
    return done(max(count, size_cd // 46))


TAR_MAX_READ = 16 << 20   # defence-in-depth per-read cap (see _TarReader)
TAR_MAX_META = 8 << 20    # largest a GNU/PAX extended header (long name/link, PAX) may declare; tarfile
#                           reads that whole payload into memory while parsing, so an oversized one is a
#                           bomb. A real path is tiny; 8 MiB is generous. This is the real tar defence.


def _tar_size(field: bytes) -> int:
    """Parse a tar header size field (octal, or GNU base-256 when the high bit is set)."""
    if field and field[0] & 0x80:
        v = field[0] & 0x7F
        for c in field[1:]:
            v = (v << 8) | c
        return v
    s = field.split(b"\x00")[0].strip()
    return int(s or b"0", 8) if s else 0


def _pax_has_override(pax: bytes) -> bool:
    """True if a PAX extended-header payload carries a record that changes a member's data length
    (`size`, or any `GNU.sparse.*`). tarfile applies those to reposition the next member, but our
    header walk advances by the raw size field, so such a record would desync the two — we refuse it
    (Zeek bundles never use them). A record is `LEN KEY=VALUE\\n` where LEN covers the whole record."""
    i = 0
    while i < len(pax):
        sp = pax.find(b" ", i)
        if sp < 0:
            break                                  # trailing NUL padding: no more records
        try:
            length = int(pax[i:sp])
        except ValueError:
            return True                            # unparseable → refuse, don't risk a desync
        if length <= 0 or i + length > len(pax):
            return True
        key = pax[sp + 1:i + length].split(b"=", 1)[0]
        if key == b"size" or key.startswith(b"GNU.sparse"):
            return True
        i += length
    return False


# Derive the special header types from tarfile's own routing (not hardcoded literals, so a type the
# library handles — e.g. Solaris X — can't be missed): everything tarfile sends to _proc_pax is read
# and override-checked; everything it sends to _proc_gnulong is size-capped; sparse is refused.
_TAR_PAX = frozenset(getattr(tarfile, n) for n in ("XHDTYPE", "XGLTYPE", "SOLARIS_XHDTYPE") if hasattr(tarfile, n))
_TAR_LONG = frozenset(getattr(tarfile, n) for n in ("GNUTYPE_LONGNAME", "GNUTYPE_LONGLINK") if hasattr(tarfile, n))
_TAR_EXT = _TAR_PAX | _TAR_LONG
_TAR_SPARSE = getattr(tarfile, "GNUTYPE_SPARSE", b"S")
_TAR_REG = frozenset(getattr(tarfile, n) for n in ("REGTYPE", "AREGTYPE", "CONTTYPE") if hasattr(tarfile, n))
_TAR_SUPPORTED = frozenset(getattr(tarfile, "SUPPORTED_TYPES", ()))


def _prescan_tar(f) -> None:
    """Walk the decompressed, seekable tar's 512-byte headers and reject an oversized extended header
    before tarfile reads its payload into memory. Keys on the declared header size (independent of how
    tarfile chunks its reads, which varies by Python version), and refuses PAX size/sparse overrides and
    GNU sparse members so this walk cannot desync from tarfile's member boundaries."""
    f.seek(0)
    headers = 0
    while True:
        hdr = f.read(512)
        if len(hdr) < 512 or hdr == b"\x00" * 512:
            break
        headers += 1
        if headers > 4 * MAX_BUNDLE_MEMBERS:   # bound the scan itself (extraction enforces the real cap)
            raise _TooBig("tar has too many headers")
        typ = hdr[156:157]
        try:
            size = _tar_size(hdr[124:136])
        except ValueError:
            raise _TooBig("unreadable tar header")
        if typ in _TAR_EXT and size > TAR_MAX_META:
            raise _TooBig(f"oversized tar extended header ({size} bytes)")
        if typ == _TAR_SPARSE:                     # GNU sparse: extension blocks + realsize desync a size walk
            raise _TooBig("sparse tar members are not supported")
        nbytes = (size + 511) // 512 * 512
        if typ in _TAR_PAX:                         # PAX (incl. Solaris X): read the bounded payload, refuse overrides
            if _pax_has_override(f.read(nbytes)):
                raise _TooBig("tar with a PAX size/sparse override is not supported")
        elif typ in _TAR_LONG or typ in _TAR_REG or typ not in _TAR_SUPPORTED:
            f.seek(nbytes, 1)                      # payload follows: skip it (matches tarfile's _proc_builtin)
        # else: a supported non-regular type (dir/symlink/hardlink/char/block/fifo) — tarfile ignores
        # its size field and the next header follows immediately, so we advance 0 (no seek).
    f.seek(0)


class _TarReader:
    """A seekable wrapper (for tarfile mode 'r:') whose read() refuses any single read larger than
    TAR_MAX_READ. tarfile parses a GNU/PAX long-name header with one read() of its whole declared
    size, so an oversized header raises _TooBig before it is allocated; real member data is read in
    <=1 MiB chunks by _Seekable, well under the limit. Streaming 'r|' mode cannot be used for this: its
    internal _Stream services reads in fixed 10 KiB chunks, hiding the true requested size from us."""
    def __init__(self, raw, per_read: int | None = None):
        self._raw = raw
        self._pr = per_read or TAR_MAX_READ

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0 or n > self._pr:
            raise _TooBig(f"oversized tar read ({n} bytes)")
        return self._raw.read(n)

    def seek(self, *a):
        return self._raw.seek(*a)

    def tell(self):
        return self._raw.tell()

    def close(self) -> None:
        try:
            self._raw.close()
        except Exception:
            pass


def _tar_fileobj(fh: BinaryIO):
    """(seekable reader for tarfile 'r:', cleanup). A compressed tar is decompressed to a size-capped
    temp file on the lake drive — rejecting a decompression bomb — so tarfile gets a seekable file and
    the per-read cap sees the true size of each header read. A plain tar uses fh directly."""
    import bz2
    import lzma
    import os as _os
    import tempfile
    head = fh.read(6)
    fh.seek(0)
    if head[:2] == b"\x1f\x8b":
        dec: BinaryIO = gzip.open(fh, "rb")
    elif head[:3] == b"BZh":
        dec = bz2.open(fh, "rb")
    elif head[:6] == b"\xfd7zXZ\x00":
        dec = lzma.open(fh, "rb")
    else:                                         # already a plain, seekable tar
        try:
            fh.seek(0, 2)
            tsize = fh.tell()
            fh.seek(0)
        except OSError:
            tsize = 0
        if tsize > MAX_TAR_DECOMPRESSED:           # same structural bound as a compressed tar
            raise _TooBig(f"tar is larger than {MAX_TAR_DECOMPRESSED >> 30} GiB")
        _prescan_tar(fh)
        return _TarReader(fh), (lambda: None)
    config.TMP_DIR.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(dir=str(config.TMP_DIR), delete=False)
    try:
        n = 0
        while b := dec.read(CHUNK):
            n += len(b)
            if n > MAX_TAR_DECOMPRESSED:
                raise _TooBig(f"tar decompresses to more than {MAX_TAR_DECOMPRESSED >> 30} GiB")
            tmp.write(b)
        tmp.flush()
        _prescan_tar(tmp)   # reject oversized extended headers before tarfile reads them
        tmp.seek(0)
    except BaseException:
        tmp.close()
        _os.unlink(tmp.name)
        raise
    finally:
        dec.close()

    def cleanup():
        tmp.close()
        try:
            _os.unlink(tmp.name)
        except OSError:
            pass
    return _TarReader(tmp), cleanup

# ------------------------------------------------------------------ log type detection
_META = {"ts", "_path", "_write_ts", "_node", "_system_name"}


def classify(keys: set[str], path: str | None = None) -> str:
    """Zeek log type from a row's field names (or its _path when the writer included it)."""
    if path:
        p = re.sub(r"[^a-z0-9_]", "_", path.lower())[:40]
        return p or "unknown"
    k = keys
    if "conn_state" in k or ("proto" in k and "history" in k) or ("orig_pkts" in k and "resp_pkts" in k):
        return "conn"
    if k & {"qtype_name", "qclass_name", "rcode_name", "trans_id"} or ("query" in k and "id.resp_p" in k):
        return "dns"
    if k & {"msg_types", "assigned_addr", "lease_time"} or ("mac" in k and k & {"host_name", "client_addr"}):
        return "dhcp"
    if any(x.startswith("certificate.") for x in k) or "san.dns" in k:
        return "x509"
    if k & {"stratum", "ref_id", "ref_time"} or ("poll" in k and "mode" in k):
        return "ntp"
    if k & {"cipher", "server_name", "ja3", "ssl_history", "cert_chain_fps", "cert_chain_fuids"} or (
            "established" in k and "version" in k):
        return "ssl"
    if k & {"method", "status_code", "user_agent", "trans_depth"} or ("uri" in k and "host" in k):
        return "http"
    if "note" in k and "msg" in k:
        return "notice"
    if "fuid" in k and k & {"mime_type", "seen_bytes", "total_bytes", "analyzers", "depth", "md5", "sha1",
                             "sha256", "missing_bytes", "overflow_bytes", "timedout"}:
        return "files"
    if k & {"software_type", "unparsed_version"}:
        return "software"
    if "name" in k and k & {"addl", "notice", "peer"}:
        return "weird"
    if "port_num" in k and k & {"issuer_subject", "serial"}:
        return "known_certs"
    if "port_num" in k and k & {"service", "port_proto"}:
        return "known_services"
    if "mac" in k and k & {"dhcp_host_name", "vendor"}:
        return "known_devices"
    if k - _META == {"host"}:
        return "known_hosts"
    return "unknown"


# Fields pulled out of every row in one json_extract_string call (1-based in SQL).
# Zeek names are flat keys with dots ("id.orig_h"); Suricata EVE fields (prefixed "eve:") are nested paths.
PATHS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
         "orig_bytes", "resp_bytes", "conn_state", "history", "query", "server_name", "host", "uri", "mac",
         "orig_l2_addr", "resp_l2_addr", "host_name", "client_addr", "server_addr", "fuid", "src", "dst",
         "p", "id", "port_num", "host_p", "uids[0]", "tx_hosts[0]", "rx_hosts[0]", "port_proto",
         "eve:flow_id", "eve:src_ip", "eve:src_port", "eve:dest_ip", "eve:dest_port", "eve:app_proto",
         "eve:flow.bytes_toserver", "eve:flow.bytes_toclient", "eve:flow.age", "eve:flow.state",
         "eve:dns.rrname", "eve:dns.queries[0].rrname", "eve:tls.sni", "eve:http.hostname", "eve:http.url",
         "eve:ether.src_mac", "eve:ether.dest_mac", "eve:dns.rdata",
         "eve:flow.src_ip", "eve:flow.dest_ip", "eve:flow.src_port", "eve:flow.dest_port", "eve:direction",
         "eve:flow.start"]
_I = {p: i + 1 for i, p in enumerate(PATHS)}


def _jp(p: str) -> str:
    if p.startswith("eve:"):
        return "$." + p[4:]
    if p.endswith("[0]"):
        return f'$."{p[:-3]}"[0]'
    return f'$."{p}"'


def _e(p: str) -> str:
    return f"e[{_I[p]}]"


_HOSTLOGS = "('software', 'known_hosts', 'known_services', 'known_certs')"

# Epoch seconds, milliseconds, microseconds or nanoseconds; or an ISO 8601 string (any offset, or UTC if none).
TS_SQL = """CASE WHEN try_cast({s} AS DOUBLE) IS NOT NULL THEN to_timestamp(
                 CASE WHEN abs(try_cast({s} AS DOUBLE)) >= 1e17 THEN try_cast({s} AS DOUBLE) / 1e9
                      WHEN abs(try_cast({s} AS DOUBLE)) >= 1e14 THEN try_cast({s} AS DOUBLE) / 1e6
                      WHEN abs(try_cast({s} AS DOUBLE)) >= 1e11 THEN try_cast({s} AS DOUBLE) / 1e3
                      ELSE try_cast({s} AS DOUBLE) END)
            ELSE coalesce(try_cast({s} AS TIMESTAMPTZ),
                          try_strptime({s}, ['%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%d %H:%M:%S.%f%z']))
       END"""

EXTRACT_SQL = f"""
SELECT
  hash(coalesce({_e('uid')}, {_e('uids[0]')}, {_e('eve:flow_id')}, ''), coalesce({_e('fuid')}, {_e('id')}, ''), log_type,
       coalesce(epoch_us(ts), 0),
       CASE WHEN log_type = 'dns' THEN coalesce({_e('query')}, '') || '/' || coalesce(json_extract_string(j, '$.qtype'), '')
            WHEN log_type LIKE 'eve_%' THEN md5(raw) ELSE '' END,
       CASE WHEN coalesce({_e('uid')}, {_e('uids[0]')}, {_e('fuid')}, {_e('id')}, {_e('eve:flow_id')}) IS NULL THEN md5(raw) ELSE '' END) AS rk,
  ? AS file_id,
  CASE WHEN ts >= TIMESTAMPTZ '1990-01-01' AND ts < TIMESTAMPTZ '2100-01-01' THEN ts END AS ts,
  coalesce({_e('uid')}, {_e('uids[0]')}, {_e('eve:flow_id')}) AS uid,
  log_type,
  coalesce({_e('id.orig_h')}, {_e('eve:flow.src_ip')},
           CASE WHEN {_e('eve:direction')} = 'to_client' THEN {_e('eve:dest_ip')} ELSE {_e('eve:src_ip')} END, {_e('client_addr')}, {_e('src')}, {_e('tx_hosts[0]')},
           CASE WHEN log_type IN {_HOSTLOGS} THEN {_e('host')} END) AS orig_h,
  try_cast(coalesce({_e('id.orig_p')}, {_e('eve:flow.src_port')},
           CASE WHEN {_e('eve:direction')} = 'to_client' THEN {_e('eve:dest_port')} ELSE {_e('eve:src_port')} END) AS INTEGER) AS orig_p,
  coalesce({_e('id.resp_h')}, {_e('eve:flow.dest_ip')},
           CASE WHEN {_e('eve:direction')} = 'to_client' THEN {_e('eve:src_ip')} ELSE {_e('eve:dest_ip')} END, {_e('server_addr')}, {_e('dst')}, {_e('rx_hosts[0]')}) AS resp_h,
  try_cast(coalesce({_e('id.resp_p')}, {_e('eve:flow.dest_port')},
           CASE WHEN {_e('eve:direction')} = 'to_client' THEN {_e('eve:src_port')} ELSE {_e('eve:dest_port')} END, {_e('p')}, {_e('port_num')}, {_e('host_p')}) AS INTEGER) AS resp_p,
  lower(coalesce({_e('proto')}, {_e('port_proto')})) AS proto,
  coalesce({_e('service')}, {_e('eve:app_proto')}) AS service,
  try_cast(coalesce({_e('duration')}, {_e('eve:flow.age')}) AS DOUBLE) AS duration,
  try_cast(coalesce({_e('orig_bytes')}, {_e('eve:flow.bytes_toserver')}) AS BIGINT) AS orig_bytes,
  try_cast(coalesce({_e('resp_bytes')}, {_e('eve:flow.bytes_toclient')}) AS BIGINT) AS resp_bytes,
  coalesce({_e('conn_state')}, {_e('eve:flow.state')}) AS conn_state,
  {_e('history')} AS history,
  rtrim(CASE WHEN log_type = 'dns' THEN lower({_e('query')})
       WHEN log_type = 'eve_dns' THEN lower(coalesce({_e('eve:dns.rrname')}, {_e('eve:dns.queries[0].rrname')})) END, '.') AS query,
  list_transform(CASE WHEN log_type = 'dns' THEN try_cast(j->'$.answers' AS VARCHAR[])
       WHEN log_type = 'eve_dns' THEN coalesce(nullif(json_extract_string(j, '$.dns.answers[*].rdata'), []),
                                               CASE WHEN {_e('eve:dns.rdata')} IS NOT NULL THEN [{_e('eve:dns.rdata')}] END) END,
       lambda x: rtrim(lower(x), '.')) AS answers,
  rtrim(lower(coalesce({_e('server_name')}, {_e('eve:tls.sni')})), '.') AS server_name,
  CASE WHEN log_type NOT IN {_HOSTLOGS} THEN
    rtrim(regexp_replace(regexp_replace(lower(coalesce({_e('host')}, {_e('eve:http.hostname')})),
                                        '^\\[([0-9a-f:.]+)\\](:[0-9]+)?$', '\\1'),
                         '^([^:]*):[0-9]+$', '\\1'), '.') END AS host,
  coalesce({_e('uri')}, {_e('eve:http.url')}) AS uri,
  lower(coalesce({_e('mac')}, {_e('orig_l2_addr')}, {_e('eve:ether.src_mac')})) AS mac,
  lower(coalesce({_e('resp_l2_addr')}, {_e('eve:ether.dest_mac')})) AS resp_mac,
  lower({_e('host_name')}) AS hostname,
  raw
FROM (
  SELECT s.j, s.raw, g.log_type,
         json_extract_string(s.j, {[_jp(p) for p in PATHS]!r}) AS e,
         {TS_SQL.format(s="coalesce(json_extract_string(s.j, '$.ts'), json_extract_string(s.j, '$.flow.start'), json_extract_string(s.j, '$.timestamp'))")} AS ts
  FROM _nl_s s JOIN _nl_sig g ON g.sig = s.sig AND g.path IS NOT DISTINCT FROM s.path
)
"""


# ------------------------------------------------------------------ storing the original
def _safe_name(name: str) -> str:
    base = Path(name or "zeek.log").name
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base)[:80] or "zeek.log"
    return base[:-3] if base.endswith(".gz") else base


def _store(fh: BinaryIO, name: str) -> tuple[Path, str, int, str]:
    """Copy into the lake gzipped. Returns (path, sha256 of content, content bytes, first char)."""
    started = util.now()
    day = LAKE_DIR / started.strftime("%Y/%m/%d")
    day.mkdir(parents=True, exist_ok=True)
    part = day / f".{started.strftime('%H%M%S')}-{_safe_name(name)}.{time.time_ns()}.part"
    head = fh.read(2)
    fh.seek(0)
    h = hashlib.sha256()
    size = 0
    first = ""

    def feed(b: bytes) -> None:
        nonlocal size, first
        h.update(b)
        size += len(b)
        if size > MAX_UNCOMPRESSED:
            raise _TooBig(f"decompressed content exceeds the {MAX_UNCOMPRESSED >> 30} GiB limit")
        if not first:
            s = b.lstrip(b" \t\r\n\xef\xbb\xbf")
            if s:
                first = chr(s[0])

    try:
        if head == b"\x1f\x8b":
            with part.open("wb") as out:
                shutil.copyfileobj(fh, out, CHUNK)   # the compressed copy is bounded by the source size
            with gzip.open(part, "rb") as gz:
                while b := gz.read(CHUNK):
                    feed(b)
        else:
            with gzip.open(part, "wb", compresslevel=3) as out:
                while b := fh.read(CHUNK):
                    feed(b)
                    out.write(b)
    except BaseException:
        part.unlink(missing_ok=True)   # never leave a partial or bomb .part behind
        raise
    final = day / f"{started.strftime('%H%M%S')}-{h.hexdigest()[:12]}-{_safe_name(name)}.gz"
    part.replace(final)
    return final, h.hexdigest(), size, first


def _lake_rel(path: Path) -> str:
    """`path` relative to the lake (e.g. raw/netlog/2026/11/19/…gz); the bare file name if it is elsewhere."""
    try:
        return Path(path).resolve().relative_to(config.LAKE.resolve()).as_posix()
    except ValueError:
        return Path(path).name


# ------------------------------------------------------------------ import
def import_fileobj(fh: BinaryIO, name: str, origin: str = "api", match: bool = True) -> dict:
    """Import one Zeek JSON log. Synchronous: when it returns, devices and matching are done."""
    t0 = time.time()
    with util.LOCK:
        try:
            path, sha, size, first = _store(fh, name)
        except _TooBig as e:
            log.warning("netlog import %s rejected: %s", name, e)
            return util.jsonable({"name": name, "error": f"rejected: {e}", "rows": 0, "inserted": 0,
                                  "duplicate": False, "duplicates": 0, "warnings": [], "skipped_lines": 0,
                                  "log_types": {}, "seconds": round(time.time() - t0, 3)})
        prev = db.query("SELECT id, status FROM netlog_files WHERE id = ?", [sha])
        if prev and prev[0]["status"] == "ok":
            path.unlink(missing_ok=True)
            return {"file_id": sha, "name": name, "duplicate": True, "inserted": 0, "rows": 0,
                    "seconds": round(time.time() - t0, 3)}
        # The stored file's place in the lake, never the absolute path (it names the home folder; L5).
        res = {"file_id": sha, "name": name, "path": _lake_rel(path), "size": size, "duplicate": False}
        try:
            if not size or not first:
                raise ValueError("empty file")
            from . import sinkhole   # Pi-hole / AdGuard Home DNS logs, recognised by content (okf/data/netlog.md)
            kind = sinkhole.detect(path)
            if kind:
                res.update(sinkhole.load(path, sha, kind, size, _load, config.TMP_DIR))
                res["format"] = kind
            elif first == "#":
                raise ValueError("Zeek TSV logs are not supported; enable JSON output (LogAscii::use_json=T)")
            elif first not in ("{", "["):
                raise ValueError("not a Zeek JSON log (expected NDJSON objects or a JSON array), "
                                 "a Pi-hole query log or export, or an AdGuard Home query log")
            else:
                fmt = "array" if first == "[" else "ndjson"
                res.update(_load(path, sha, fmt))
                res["format"] = fmt
            status, err = "ok", None
        except Exception as e:  # keep the file record so the user sees why
            status, err = "error", f"{type(e).__name__}: {e}"[:500]
            res.update({"error": err, "rows": 0, "inserted": 0, "warnings": [], "skipped_lines": 0})
            log.warning("netlog import %s failed: %s", name, err)
        load_s = time.time() - t0
        with db._write_lock:
            db.cursor().execute(
                """INSERT OR REPLACE INTO netlog_files (id, name, path, origin, format, size, imported_at, rows, inserted,
                       duplicates, log_types, ts_min, ts_max, seconds, status, error, skipped, warnings)
                   VALUES (?, ?, ?, ?, ?, ?, now(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [sha, name, str(path), origin, res.get("format"), size, res.get("rows", 0), res.get("inserted", 0),
                 res.get("duplicates", 0), json.dumps(res.get("log_types", {})), res.get("ts_min"), res.get("ts_max"),
                 load_s, status, err, res.get("skipped_lines", 0), json.dumps(res.get("warnings") or [])])
        if status == "ok" and match and res.get("inserted"):
            from . import devices, intervals, matcher
            t1 = time.time()
            intervals.refresh()
            devices.rebuild()
            res["match"] = matcher.match_file(sha)
            res["match_seconds"] = round(time.time() - t1, 3)
        res["seconds"] = round(time.time() - t0, 3)
        with db._write_lock:
            db.cursor().execute("UPDATE netlog_files SET seconds = ? WHERE id = ?", [res["seconds"], sha])
        return util.jsonable(res)


def _load(path: Path, file_id: str, fmt: str) -> dict:
    jfmt = "array" if fmt == "array" else "newline_delimited"
    warnings: list[str] = []
    with db._write_lock:
        cur = db.cursor()
        try:
            cur.execute(f"""CREATE OR REPLACE TEMP TABLE _nl_s AS
                SELECT json AS j, json::VARCHAR AS raw,
                       CASE WHEN json_type(json) = 'OBJECT' THEN json_keys(json)::VARCHAR END AS sig,
                       coalesce(json_extract_string(json, '$._path'),
                                CASE WHEN json_exists(json, '$.event_type')
                                      AND (json_exists(json, '$.src_ip') OR json_exists(json, '$.dest_ip'))
                                     THEN 'eve_' || json_extract_string(json, '$.event_type') END) AS path
                FROM read_json_objects('{util.q(path)}', format='{jfmt}', compression='gzip',
                                       ignore_errors=true, maximum_object_size=67108864)""")
            total = cur.execute("SELECT count(*) FROM _nl_s").fetchone()[0]
            cur.execute("DELETE FROM _nl_s WHERE j IS NULL OR json_type(j) <> 'OBJECT'")
            rows = cur.execute("SELECT count(*) FROM _nl_s").fetchone()[0]
            skipped = total - rows
            if skipped:
                warnings.append(f"{skipped} line(s) were not JSON objects and were skipped")
            if not rows:
                raise ValueError("no JSON objects found" + (f" ({skipped} malformed line(s))" if skipped else ""))
            sigs = cur.execute("SELECT sig, path, count(*) FROM _nl_s GROUP BY ALL").fetchall()
            cur.execute("CREATE OR REPLACE TEMP TABLE _nl_sig (sig VARCHAR, path VARCHAR, log_type VARCHAR)")
            vals = [(s, p, classify(set(s[1:-1].split(", ")) if s and len(s) > 2 else set(), p)) for s, p, _ in sigs]
            cur.executemany("INSERT INTO _nl_sig VALUES (?, ?, ?)", vals)
            cur.execute(f"""CREATE OR REPLACE TEMP TABLE _nl_x AS SELECT * FROM ({EXTRACT_SQL})
                            QUALIFY row_number() OVER (PARTITION BY rk) = 1""", [file_id])
            _canonical_ips(cur)
            types = dict(cur.execute("SELECT log_type, count(*) FROM _nl_x GROUP BY 1 ORDER BY 2 DESC").fetchall())
            useful = cur.execute("""SELECT count(*) FROM _nl_x WHERE log_type <> 'unknown'
                                    OR orig_h IS NOT NULL OR resp_h IS NOT NULL""").fetchone()[0]
            if not useful:
                raise ValueError("not a Zeek or Suricata EVE log: no row has recognised fields "
                                 "(ts, uid, id.orig_h / id.resp_h, src_ip / dest_ip)")
            if types.get("unknown"):
                warnings.append(f"{types['unknown']} row(s) of unrecognised log type kept as 'unknown'")
            eve = sum(n for t, n in types.items() if t.startswith("eve_"))
            if eve:
                warnings.append(f"{eve} Suricata EVE record(s) mapped to netlog columns (log types eve_*)")
            bad_ts = cur.execute("SELECT count(*) FROM _nl_x WHERE ts IS NULL").fetchone()[0]
            if bad_ts:
                warnings.append(f"{bad_ts} row(s) have a missing or unparseable timestamp; they are kept but never match")
            inserted = cur.execute("INSERT INTO netlog SELECT x.* FROM _nl_x x ANTI JOIN netlog n ON n.rk = x.rk").fetchone()[0]
            tmin, tmax = cur.execute("SELECT min(ts), max(ts) FROM _nl_x").fetchone()
        finally:
            for t in ("_nl_s", "_nl_sig", "_nl_x"):
                cur.execute(f"DROP TABLE IF EXISTS {t}")
    return {"rows": int(rows), "inserted": int(inserted), "duplicates": int(rows - inserted), "log_types": types,
            "ts_min": tmin, "ts_max": tmax, "skipped_lines": int(skipped), "bad_ts": int(bad_ts),
            "warnings": warnings, "warning": "; ".join(warnings) or None}


def _canonical_ips(cur) -> None:
    """Rewrite IPv6 and IPv4-mapped addresses in _nl_x to canonical form (::ffff:a.b.c.d -> a.b.c.d,
    upper-case or zero-padded IPv6 -> RFC 5952), so equality, grouping and devices see one spelling."""
    cand = [r[0] for r in cur.execute("""
        SELECT DISTINCT ip FROM (SELECT orig_h AS ip FROM _nl_x UNION SELECT resp_h FROM _nl_x
                                 UNION SELECT unnest(answers) FROM _nl_x WHERE answers IS NOT NULL)
        WHERE ip LIKE '%:%'""").fetchall()]
    pairs = []
    for ip in cand:
        c = ipnum.canonical(ip)
        if c and c != ip:
            pairs.append((ip, c))
    if not pairs:
        return
    cur.execute("CREATE OR REPLACE TEMP TABLE _nl_canon (ip VARCHAR, canon VARCHAR)")
    cur.executemany("INSERT INTO _nl_canon VALUES (?, ?)", pairs)
    cur.execute("UPDATE _nl_x SET orig_h = c.canon FROM _nl_canon c WHERE _nl_x.orig_h = c.ip")
    cur.execute("UPDATE _nl_x SET resp_h = c.canon FROM _nl_canon c WHERE _nl_x.resp_h = c.ip")
    m = dict(pairs)
    rows = cur.execute("SELECT DISTINCT answers FROM _nl_x WHERE answers IS NOT NULL AND list_has_any(answers, ?)",
                       [list(m)]).fetchall()
    for (ans,) in rows:
        cur.execute("UPDATE _nl_x SET answers = ? WHERE answers = ?", [[m.get(a, a) for a in ans], ans])
    cur.execute("DROP TABLE _nl_canon")


# ------------------------------------------------------------------ bundles (tar, tar.gz, zip)
def _bundle_kind(fh: BinaryIO) -> str | None:
    head = fh.read(4)
    fh.seek(0)
    if head.startswith(b"PK\x03\x04"):
        return "zip"
    block = b""
    try:
        if head[:2] == b"\x1f\x8b":
            with gzip.GzipFile(fileobj=fh, mode="rb") as gz:
                block = gz.read(512)
        else:
            block = fh.read(512)
    except (OSError, EOFError):
        block = b""
    fh.seek(0)
    return "tar" if len(block) >= 262 and block[257:262] == b"ustar" else None


def import_any(fh: BinaryIO, name: str, origin: str = "api", match: bool = True) -> dict:
    """Import a log, or every log inside a tar, tar.gz or zip bundle (one result with `members`)."""
    kind = _bundle_kind(fh)
    if kind is None:
        return import_fileobj(fh, name, origin, match)
    import tarfile
    import zipfile
    members: list[dict] = []
    budget = 0

    def take(mf, label: str, declared: int) -> bool:
        """Import one member; returns False to stop the bundle (a cap was hit)."""
        nonlocal budget
        if len(members) >= MAX_BUNDLE_MEMBERS:
            members.append({"name": name, "error": f"archive has more than {MAX_BUNDLE_MEMBERS} members; stopped",
                            "rows": 0, "inserted": 0, "warnings": []})
            return False
        budget += max(0, declared)
        if budget > MAX_BUNDLE_UNCOMPRESSED:
            members.append({"name": name, "error": f"archive decompresses to more than {MAX_BUNDLE_UNCOMPRESSED >> 30} GiB; stopped",
                            "rows": 0, "inserted": 0, "warnings": []})
            return False
        if declared > MAX_UNCOMPRESSED:   # trust the header to reject early; _Seekable caps the real bytes too
            members.append({"name": label, "error": f"rejected: member exceeds the {MAX_UNCOMPRESSED >> 30} GiB limit",
                            "rows": 0, "inserted": 0, "warnings": []})
            return True
        sk = None
        try:
            sk = _Seekable(mf)
            members.append(import_fileobj(sk, label, origin, match))
        except _TooBig as e:
            members.append({"name": label, "error": f"rejected: {e}", "rows": 0, "inserted": 0, "warnings": []})
        finally:
            if sk is not None:
                sk.close()
        return True

    try:
        if kind == "zip":
            n_entries = _zip_entry_count(fh)
            if n_entries is None or n_entries > MAX_BUNDLE_MEMBERS:   # fail closed when indeterminate
                why = (f"has {n_entries} entries (limit {MAX_BUNDLE_MEMBERS})" if n_entries is not None
                       else "central directory could not be validated")
                return {"name": name, "bundle": "zip", "members": [], "rows": 0, "inserted": 0, "warnings": [],
                        "error": f"rejected: zip {why}"}
            with zipfile.ZipFile(fh) as zf:
                for zi in zf.infolist():
                    if zi.is_dir() or zi.file_size == 0 or _skip_member(zi.filename):
                        continue
                    with zf.open(zi) as mf:
                        if not take(mf, f"{name}/{zi.filename}", zi.file_size):
                            break
        else:
            reader, cleanup = _tar_fileobj(fh)   # decompress to a capped seekable temp; per-read cap in r:
            try:
                tf = tarfile.open(fileobj=reader, mode="r:")
                try:
                    seen = 0
                    while (ti := tf.next()) is not None:   # don't retain every header in memory
                        seen += 1
                        if seen > MAX_BUNDLE_MEMBERS:
                            members.append({"name": name, "error": f"archive has more than {MAX_BUNDLE_MEMBERS} members; stopped",
                                            "rows": 0, "inserted": 0, "warnings": []})
                            break
                        tf.members = []   # every entry (incl. skipped dirs/dotfiles) counts toward the cap
                        if not ti.isreg() or ti.size == 0 or _skip_member(ti.name):
                            continue
                        mf = tf.extractfile(ti)
                        if mf is not None and not take(mf, f"{name}/{ti.name}", ti.size):
                            break
                finally:
                    tf.close()
            finally:
                cleanup()
    except _TooBig as e:   # a bomb hit during archive parsing (e.g. a GNU/PAX long-name header)
        return {"name": name, "bundle": kind, "members": members, "rows": 0, "inserted": 0,
                "warnings": [], "error": f"rejected: {e}"}
    except (tarfile.TarError, zipfile.BadZipFile, OSError) as e:
        return {"name": name, "bundle": kind, "error": f"bad {kind} bundle: {e}", "rows": 0, "inserted": 0,
                "members": members, "warnings": []}
    types: dict = {}
    for m in members:
        for t, n in (m.get("log_types") or {}).items():
            types[t] = types.get(t, 0) + n
    ok = [m for m in members if not m.get("error")]
    return {"name": name, "bundle": kind, "members": members, "log_types": types,
            "rows": sum(m.get("rows") or 0 for m in members), "inserted": sum(m.get("inserted") or 0 for m in members),
            "duplicates": sum(m.get("duplicates") or 0 for m in members),
            "duplicate": bool(members) and all(m.get("duplicate") for m in members),
            "skipped_lines": sum(m.get("skipped_lines") or 0 for m in members),
            "warnings": [f"{m['name']}: {w}" for m in members for w in (m.get("warnings") or [])]
                        + [f"{m['name']}: {m['error']}" for m in members if m.get("error")],
            "error": None if ok or not members else ("no Zeek logs in the bundle" if not members else members[0].get("error"))}


def _skip_member(n: str) -> bool:
    base = n.rsplit("/", 1)[-1]
    return base.startswith(".") or "__MACOSX" in n


class _Seekable:
    """Spool a non-seekable member stream so _store can peek and rewind."""
    def __init__(self, f):
        import tempfile
        config.TMP_DIR.mkdir(parents=True, exist_ok=True)
        # spool on the lake's own drive (not the boot volume) and stop a member that expands unboundedly
        self._t = tempfile.SpooledTemporaryFile(max_size=8 << 20, dir=str(config.TMP_DIR))
        n = 0
        try:
            while b := f.read(CHUNK):
                n += len(b)
                if n > MAX_UNCOMPRESSED:
                    raise _TooBig(f"archive member exceeds the {MAX_UNCOMPRESSED >> 30} GiB limit")
                self._t.write(b)
        except BaseException:
            self._t.close()
            raise
        self._t.seek(0)

    def read(self, n=-1):
        return self._t.read(n)

    def seek(self, *a):
        return self._t.seek(*a)

    def close(self):
        try:
            self._t.close()
        except Exception:
            pass


# ------------------------------------------------------------------ watched inbox
# The folder is a setting (util.inbox_settings: OSINTHUB_INBOX, the saved folder, or <lake>/inbox/zeek), checked by
# filesystem identity (util.check_inbox_fd) when saved and again on every pass. A pass opens the folder once
# (O_NOFOLLOW), checks that open directory, and from then on works only relative to directory fds: subfolders are
# opened with O_NOFOLLOW under their parent's fd, files are read through an fd opened with O_NOFOLLOW, and a delete or
# a move to failed/ is unlinkat/renameat on the parent's fd, done only when the name still holds the very file that
# was read (same dev and inode). No path is resolved twice, so swapping a folder or a file for a link mid-scan cannot
# redirect a delete. By default (delete off) Night Desk only reads the folder. Reference: okf/data/netlog.md#inbox-folder
INBOX = util.default_inbox()      # the default folder (older callers and tests); the folder in effect: util.inbox_settings()
# Folders under the inbox that are never imported: Zeek's live `current/` directory (files still being written,
# plus stderr/stdout; often a link to the spool), and our own `failed/`.
INBOX_SKIP_DIRS = {"current", "failed"}
SETTLE_SECONDS = 5.0              # delete off: a file is read once it has not changed for this long (manual scans too)
DELETE_SETTLE_SECONDS = 120.0     # delete on: a file must be unchanged this long before it is imported and deleted
LEDGER_SQL = """
CREATE TABLE IF NOT EXISTS netlog_inbox_seen (
    folder    VARCHAR,                 -- the inbox folder this entry belongs to (resolved)
    path      VARCHAR,                 -- relative to folder
    size      BIGINT,
    mtime_ns  BIGINT,
    file_id   VARCHAR,                 -- netlog_files.id (sha256 of content), when it was read
    status    VARCHAR,                 -- ok | duplicate | error | notlog
    error     VARCHAR,
    seen_at   TIMESTAMPTZ,
    mode      VARCHAR,                 -- keep (delete off) | delete (delete on)
    st_mode   BIGINT,                  -- permissions: a chmod makes the file count as changed
    PRIMARY KEY (folder, path)
);
ALTER TABLE netlog_inbox_seen ADD COLUMN IF NOT EXISTS mode VARCHAR;
ALTER TABLE netlog_inbox_seen ADD COLUMN IF NOT EXISTS st_mode BIGINT;
"""
NOT_A_LOG = "not a log file"
READ_ERROR = "could not read the file"
UNSUPPORTED = "compressed with xz or bzip2, which Night Desk does not read: recompress it with gzip"
_scan_lock = threading.Lock()
_last_scan: list[dict] = []    # what the latest scan read, for a scan that had to wait for it
last_pass: dict = {}           # {folder, still_writing, not_logs, stopped} of the latest pass
_stopped: dict[str, str] = {}  # folder -> why its last pass stopped
_pruned_at = 0.0
_ledger_ready = False
LOG_KEYS = {"ts", "_path", "uid", "id.orig_h", "timestamp", "event_type", "src_ip", "QH", "T", "queries", "domain"}
_LOG_KEYS = re.compile(r'"(?:ts|_path|uid|id\.orig_h|timestamp|event_type|src_ip|QH|queries|domain)"\s*:')


def _ensure_ledger() -> None:
    global _ledger_ready
    if not _ledger_ready:
        db.execute(LEDGER_SQL)
        _ledger_ready = True


MAX_DEPTH = 64   # folder levels below the inbox that are walked; deeper ones are listed as "too deep, skipped"


class _Tree:
    """One walk of the inbox through directory fds, iterative (an explicit stack, at most MAX_DEPTH fds open, each
    closed as soon as its folder is done). `entries()` yields ("file", dir_fd, name, rel, lstat) for regular files and
    ("dir_done", parent_fd, name, rel, lstat) after a subfolder's contents; `links`, `unreadable` and `too_deep`
    collect what was skipped. Hidden entries, INBOX_SKIP_DIRS and links (except Zeek's `current`, skipped by design)
    are listed or skipped, never followed; a subfolder that is not the directory its name showed, or that is one of the
    lake's own folders (a bind mount), is not entered."""

    def __init__(self, root_fd: int):
        self.root_fd = root_fd
        self.links: list[str] = []
        self.unreadable: list[str] = []
        self.too_deep: list[str] = []
        self.protected = util.protected_idents()

    def _list(self, fd: int, prefix: str, files: list, subdirs: list) -> None:
        try:
            names = sorted(os.listdir(fd))
        except OSError:
            self.unreadable.append(prefix or "./")
            return
        for n in names:
            if n.startswith("."):
                continue
            try:
                st = os.stat(n, dir_fd=fd, follow_symlinks=False)
            except OSError:
                continue
            rel = prefix + n
            if stat.S_ISLNK(st.st_mode):
                if n not in INBOX_SKIP_DIRS:
                    self.links.append(rel)
            elif stat.S_ISDIR(st.st_mode):
                if n not in INBOX_SKIP_DIRS:
                    subdirs.append((n, st))
            elif stat.S_ISREG(st.st_mode):
                files.append((n, rel, st))

    def entries(self):
        # a frame: [fd, prefix, depth, pending subdirs, parent fd, name, lstat]
        stack: list[list] = []

        def push(fd, prefix, depth, parent, name, st):
            files: list = []
            subdirs: list = []
            self._list(fd, prefix, files, subdirs)
            subdirs.reverse()   # popped from the end: keeps name order
            stack.append([fd, prefix, depth, subdirs, parent, name, st])
            return files

        try:
            for n, rel, st in push(self.root_fd, "", 0, None, None, None):
                yield ("file", self.root_fd, n, rel, st)
            while stack:
                fd, prefix, depth, subdirs, parent, name, st = stack[-1]
                if not subdirs:
                    stack.pop()
                    if parent is not None:
                        os.close(fd)
                        yield ("dir_done", parent, name, prefix[:-1], st)
                    continue
                n, sst = subdirs.pop()
                if depth + 1 > MAX_DEPTH:
                    self.too_deep.append(prefix + n + "/")
                    continue
                try:
                    sub = os.open(n, util.DIR_FLAGS | util.NOFOLLOW, dir_fd=fd)
                except OSError:
                    self.unreadable.append(prefix + n + "/")
                    continue
                i = util.ident_of(os.fstat(sub))
                if i != util.ident_of(sst) or i in self.protected:
                    os.close(sub)   # swapped since it was listed, or one of the lake's own folders mounted here
                    continue
                for fn, rel, fst in push(sub, prefix + n + "/", depth + 1, fd, n, sst):
                    yield ("file", sub, fn, rel, fst)
        finally:
            for frame in stack:   # an abandoned walk still closes every fd it opened
                if frame[4] is not None:
                    os.close(frame[0])


def open_inbox(path: str) -> int:
    """The inbox folder opened (O_NOFOLLOW) and checked by identity; ValueError when it may not be scanned."""
    try:
        fd = os.open(path, util.DIR_FLAGS | util.NOFOLLOW)
    except OSError as e:
        raise ValueError(f"Night Desk cannot open the inbox folder ({e.strerror or e}).")
    try:
        util.check_inbox_fd(fd)
    except BaseException:
        os.close(fd)
        raise
    return fd


def log_kind(fh: BinaryIO | Path) -> str | None:
    """What the start of a file says it is: zip, tar, json (Zeek, Suricata EVE, AdGuard Home, Pi-hole API), zeek-tsv,
    pihole (a Pi-hole log), unsupported (xz, bzip2), or None for anything else (it is then never copied into the lake).
    Gzip is looked into. A file object is read from the start and rewound."""
    if isinstance(fh, Path):
        with fh.open("rb") as f:
            return log_kind(f)
    fh.seek(0)
    data = fh.read(65536)
    fh.seek(0)
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data.startswith(b"\xfd7zXZ\x00") or data.startswith(b"BZh"):
        return "unsupported"
    if data[:2] == b"\x1f\x8b":
        try:
            data = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data, 65536)
        except zlib.error:
            return None
    if len(data) >= 262 and data[257:262] == b"ustar":
        return "tar"
    text = data.decode("utf-8", "replace").lstrip("﻿ \t\r\n")
    if not text:
        return None
    if text[0] == "[":
        return "json"
    if text[0] == "{":   # a log record, not just any JSON (package.json, settings files)
        try:
            first = json.loads(text.split("\n", 1)[0])
        except ValueError:
            first = None
        if isinstance(first, dict):
            return "json" if LOG_KEYS.intersection(first) else None
        return "json" if _LOG_KEYS.search(text) else None
    if text.startswith("#separator") or text.startswith("#fields") or text.startswith("#path"):
        return "zeek-tsv"
    from . import sinkhole
    return "pihole" if sinkhole.detect_text(text) else None


def import_inbox_file(fh: BinaryIO, name: str) -> dict:
    """Import one inbox file from an already-open file (the fd the scan checked)."""
    return import_any(fh, name, origin="inbox")


def _ledger(folder: Path) -> dict[str, dict]:
    rows = db.query("SELECT * FROM netlog_inbox_seen WHERE folder = ?", [str(folder)])
    return {r["path"]: r for r in rows}


def _remember(folder: Path, rel: str, st: os.stat_result, res: dict, mode: str = "keep") -> None:
    status = res.get("status") or ("error" if res.get("error") else "duplicate" if res.get("duplicate") else "ok")
    db.execute("INSERT OR REPLACE INTO netlog_inbox_seen VALUES (?, ?, ?, ?, ?, ?, ?, now(), ?, ?)",
               [str(folder), rel, st.st_size, st.st_mtime_ns, res.get("file_id"), status, res.get("error"), mode,
                st.st_mode])


def _prune(folder: Path, present: set[str]) -> None:
    """Forget entries whose file is gone, so the ledger stays bounded: this folder's on every pass, other folders' (kept so
    switching back reads nothing again) at most hourly."""
    global _pruned_at
    gone = [p for p in _ledger(folder) if p not in present and not os.path.lexists(folder / p)]
    for i in range(0, len(gone), 500):
        db.execute("DELETE FROM netlog_inbox_seen WHERE folder = ? AND path IN (SELECT unnest(?))",
                   [str(folder), gone[i:i + 500]])
    if time.time() - _pruned_at > 3600:
        _pruned_at = time.time()
        rows = db.query("SELECT folder, path FROM netlog_inbox_seen WHERE folder <> ?", [str(folder)])
        for r in rows:
            if not os.path.lexists(os.path.join(r["folder"], r["path"])):
                db.execute("DELETE FROM netlog_inbox_seen WHERE folder = ? AND path = ?", [r["folder"], r["path"]])


def _unchanged(entry: dict | None, st: os.stat_result) -> bool:
    """Handled already and not changed since (size, mtime and permissions). A file that could not be read for lack of
    permission is always tried again (cheap: it fails at open)."""
    if not entry or entry["size"] != st.st_size or entry["mtime_ns"] != st.st_mtime_ns:
        return False
    if entry.get("st_mode") is not None and entry["st_mode"] != st.st_mode:
        return False
    return not (entry["status"] == "error" and (entry["error"] or "").startswith(READ_ERROR))


def _same(a: os.stat_result, b: os.stat_result) -> bool:
    return a.st_size == b.st_size and a.st_mtime_ns == b.st_mtime_ns


def _failed_dir(root_fd: int, rel_parent: list[str]) -> int:
    """failed/<subpath> opened under the inbox fd, each level created if missing and opened with O_NOFOLLOW."""
    fd = os.dup(root_fd)
    try:
        for part in ["failed", *rel_parent]:
            try:
                os.mkdir(part, dir_fd=fd)
            except FileExistsError:
                pass
            nxt = os.open(part, util.DIR_FLAGS | util.NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def scan_inbox(min_age: float | None = None) -> list[dict]:
    """Import every settled, new or changed log file under the inbox folder (subfolders included). Off (the default):
    the files stay exactly as they are and nothing is written into the folder. On: a file unchanged for
    DELETE_SETTLE_SECONDS is imported, and then removed (unlinkat) only if the name still holds the very file that was
    read; a log that failed is moved to failed/ (renameat). Files that are not logs are never copied, moved or deleted."""
    global _last_scan, last_pass
    waited = _scan_lock.locked()   # the watcher is scanning: what it imports counts as found by this scan too
    with _scan_lock:
        cfg = util.inbox_settings()   # read and checked under the lock: a folder saved meanwhile is the one scanned
        before = _last_scan if waited else []
        _last_scan = []
        last_pass = {"folder": cfg["path"], "still_writing": 0, "not_logs": 0, "stopped": cfg["problem"]}
        if cfg["problem"]:
            return before
        folder, delete = Path(cfg["path"]), cfg["delete_after_import"]
        settle = max(min_age if min_age is not None else SETTLE_SECONDS, DELETE_SETTLE_SECONDS if delete else 0)
        try:
            root_fd = open_inbox(str(folder))
        except ValueError as e:
            last_pass["stopped"] = _stopped[str(folder)] = str(e)
            return before
        _stopped.pop(str(folder), None)
        try:
            out = _scan_tree(folder, root_fd, delete, settle)
        finally:
            os.close(root_fd)
        _last_scan = out
        return before + out


def _scan_tree(folder: Path, root_fd: int, delete: bool, settle: float) -> list[dict]:
    _ensure_ledger()
    seen = _ledger(folder)
    tree = _Tree(root_fd)
    out: list[dict] = []
    present: set[str] = set()
    emptied: set[str] = set()   # subfolders a delete or move just emptied something from
    for kind, dir_fd, name, rel, st in tree.entries():
        if kind == "dir_done":
            if delete and rel in emptied:
                try:
                    os.rmdir(name, dir_fd=dir_fd)   # only if now empty; never follows a link
                    if "/" in rel:
                        emptied.add(rel.rsplit("/", 1)[0])
                except OSError:
                    pass
            continue
        present.add(rel)
        e = seen.get(rel)
        if _unchanged(e, st) and (not delete or e["mode"] == "delete"):
            continue  # handled already and not changed since. With delete on, a file kept while it was off is
            #           read once more (a duplicate then) so it can be deleted, or moved to failed/
        if time.time() - st.st_mtime < settle:
            last_pass["still_writing"] += 1
            continue
        try:
            fd = os.open(name, os.O_RDONLY | util.NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=dir_fd)
        except OSError as err:
            res = {"name": name, "error": f"{READ_ERROR}: {err.strerror or err}", "rows": 0, "inserted": 0}
            out.append(res)
            _remember(folder, rel, st, res, mode="delete" if delete else "keep")
            continue
        with os.fdopen(fd, "rb") as fh:
            fst = os.fstat(fh.fileno())
            if not stat.S_ISREG(fst.st_mode) or util.ident_of(fst) != util.ident_of(st):
                continue   # not the file that was listed (swapped meanwhile): left alone
            kind_ = log_kind(fh)
            if kind_ is None:   # not a log: never copied into the lake, never moved or deleted; listed quietly
                last_pass["not_logs"] += 1
                _remember(folder, rel, st, {"status": "notlog", "error": NOT_A_LOG}, mode="delete" if delete else "keep")
                continue
            if kind_ == "unsupported":   # a failure with a reason, but nothing is copied (and never moved or deleted)
                res = {"name": name, "error": UNSUPPORTED, "rows": 0, "inserted": 0}
                out.append(res)
                _remember(folder, rel, st, res, mode="delete" if delete else "keep")
                continue
            try:
                res = import_inbox_file(fh, name)
            except OSError as err:
                res = {"name": name, "error": f"{READ_ERROR}: {err.strerror or err}", "rows": 0, "inserted": 0}
            after = os.fstat(fh.fileno())
            out.append(res)
            if not _same(st, after):   # written to while it was read: read again once it settles
                last_pass["still_writing"] += 1
                continue
            if not delete:
                _remember(folder, rel, st, res)
                continue
            try:
                now = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(now.st_mode) or util.ident_of(now) != util.ident_of(fst):
                continue   # the name no longer holds the file that was read: delete or move nothing
            try:
                if res.get("error"):
                    parts = rel.split("/")[:-1]
                    dst = _failed_dir(tree.root_fd, parts)
                    try:
                        os.rename(name, name, src_dir_fd=dir_fd, dst_dir_fd=dst)
                    finally:
                        os.close(dst)
                    _remember(folder, f"failed/{rel}", st, res, mode="delete")
                else:
                    os.unlink(name, dir_fd=dir_fd)
                if "/" in rel:
                    emptied.add(rel.rsplit("/", 1)[0])
            except OSError as err:   # a read-only folder: remember it so it is not read again every pass
                log.warning("netlog inbox: could not %s %s: %s", "move" if res.get("error") else "delete", rel, err)
                _remember(folder, rel, st, res, mode="delete")
    _prune(folder, present)
    return out


def inbox_status(failed_limit: int = 50) -> dict:
    """What GET /api/netlog/inbox shows: the folder, the delete setting, and how many files are waiting, still being
    written, imported, failed, not logs, links skipped, and earlier failures in failed/ (names and errors only; never
    file contents)."""
    cfg = util.inbox_settings()
    folder = Path(cfg["path"])
    out = {**cfg, "waiting": 0, "writing": 0, "imported": 0, "failed": [], "failed_count": 0, "not_logs": [],
           "not_logs_count": 0, "links": [], "links_count": 0, "earlier_failed": 0, "too_deep": [], "too_deep_count": 0,
           "settle_seconds": DELETE_SETTLE_SECONDS if cfg["delete_after_import"] else SETTLE_SECONDS,
           "poll_seconds": util.settings().get("inbox_poll_seconds"), "docker": False}
    out["imported_total"] = db.query("SELECT count(*) AS n FROM netlog_files WHERE origin = 'inbox' AND status = 'ok'")[0]["n"]
    if cfg["problem"]:
        return out
    try:
        root_fd = open_inbox(str(folder))
    except ValueError as e:
        out["problem"] = str(e)
        return out
    try:
        if str(folder) in _stopped:
            out["problem"] = _stopped[str(folder)]
        _ensure_ledger()
        seen = _ledger(folder)
        failed, notlogs = [], []
        tree = _Tree(root_fd)
        now = time.time()
        for kind, _fd, _name, rel, st in tree.entries():
            if kind != "file":
                continue
            e = seen.get(rel)
            if e and e["size"] == st.st_size and e["mtime_ns"] == st.st_mtime_ns and (_unchanged(e, st) or e["status"] == "error"):
                if e["status"] == "error":
                    failed.append({"path": rel, "error": (e["error"] or "").replace("ValueError: ", ""), "moved": False})
                elif e["status"] == "notlog":
                    notlogs.append(rel)
                else:
                    out["imported"] += 1
            elif now - st.st_mtime < out["settle_seconds"]:
                out["writing"] += 1
            else:
                out["waiting"] += 1
        failed += [{"path": b, "error": "Night Desk cannot open this folder", "moved": False} for b in tree.unreadable]
        out["too_deep"] = tree.too_deep[:50]
        out["too_deep_count"] = len(tree.too_deep)
        out["links"] = tree.links[:50]
        out["links_count"] = len(tree.links)
        try:   # with delete on, failures move to failed/; v1.2 put its failures there too
            ffd = os.open("failed", util.DIR_FLAGS | util.NOFOLLOW, dir_fd=root_fd)
        except OSError:
            ffd = None
        if ffd is not None:
            try:
                for kind, _fd, _name, rel, _st in _Tree(ffd).entries():
                    if kind != "file":
                        continue
                    e = seen.get("failed/" + rel)
                    if e and e["status"] == "error":
                        failed.append({"path": "failed/" + rel, "error": (e["error"] or "").replace("ValueError: ", ""), "moved": True})
                    else:
                        out["earlier_failed"] += 1
            finally:
                os.close(ffd)
    finally:
        os.close(root_fd)
    out["failed_count"] = len(failed)
    out["failed"] = failed[:failed_limit]
    out["not_logs_count"] = len(notlogs)
    out["not_logs"] = notlogs[:50]
    return out
