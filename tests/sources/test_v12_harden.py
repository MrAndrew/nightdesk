"""v1.2 harden: upload memory (M4) and feed size caps (L3). No network: httpx MockTransport only.

    uv run --with pytest pytest tests/sources/test_v12_harden.py -q
"""
from __future__ import annotations

import asyncio
import gzip
import io
import json
import tracemalloc
import zlib
from pathlib import Path

from _lake import make_lake
LAKE = make_lake("harden-sources", disable="news,entities,ai")

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import config, db, scheduler  # noqa: E402
import osinthub.api as A  # noqa: E402
from osinthub.routing import net  # noqa: E402
from osinthub.sources import SOURCES, caps, upload  # noqa: E402

db.connect()
C = TestClient(A.app, base_url="http://localhost")
H = {"Origin": "http://localhost"}


# ================================================================== M4: upload
def _csv(n: int) -> bytes:
    nets = ("192.0.2.", "198.51.100.", "203.0.113.")
    return ("ip,title,severity,country\n" + "".join(f"{nets[i % 3]}{i % 254 + 1},host {i},0.5,US\n" for i in range(n))).encode()


def test_upload_reads_rows_in_batches_never_fetchall(monkeypatch, tmp_path):
    p = tmp_path / "rows.csv"
    p.write_bytes(_csv(12_000))
    calls = {"fetchmany": 0}
    real = upload.duckdb.connect

    class Spy:
        def __init__(self, con):
            self.con = con

        def __enter__(self):
            self.con.__enter__()
            return self

        def __exit__(self, *a):
            return self.con.__exit__(*a)

        def execute(self, *a, **k):
            cur = self.con.execute(*a, **k)
            outer = self

            class Cur:
                description = cur.description

                def fetchmany(self, n):
                    calls["fetchmany"] += 1
                    assert n <= upload.BATCH
                    return cur.fetchmany(n)

                def fetchall(self):
                    raise AssertionError("upload must not fetchall()")
            return Cur() if a and str(a[0]).lstrip().upper().startswith("SELECT") else outer

    monkeypatch.setattr(upload.duckdb, "connect", lambda *a, **k: Spy(real(*a, **k)))
    out = tmp_path / "rows.events.ndjson.gz"
    res = upload.ingest_to_ndjson(p, "t", str(p), out)
    assert res["kept"] == res["total"] == 12_000 and calls["fetchmany"] >= 3
    with gzip.open(out, "rt") as f:
        assert sum(1 for _ in f) == 12_000


def test_upload_events_are_a_generator(tmp_path):
    p = tmp_path / "rows.csv"
    p.write_bytes(_csv(10))
    it = upload.iter_events(p, "t")
    assert iter(it) is it                      # lazy: one event at a time, never a list of all rows
    assert next(it).ip == "192.0.2.1"


def test_upload_row_cap_keeps_the_first_rows_and_says_so(monkeypatch):
    monkeypatch.setattr(upload, "MAX_ROWS", 1_000)
    r = C.post("/api/upload", files={"file": ("big.csv", io.BytesIO(_csv(2_500)), "text/csv")},
               data={"label": "capped"}, headers=H)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["rows"] == 1_000 and d["kept"] == 1_000 and d["total"] == 2_500
    assert d["note"] == "Kept the first 1,000 of 2,500 rows: one upload holds at most 1,000 rows. Split the file to add the rest."
    assert db.query("SELECT count(*) AS n FROM events WHERE source = 'upload' AND list_contains(tags, 'capped')")[0]["n"] == 1_000


def test_upload_ip_list_is_streamed_and_capped(monkeypatch, tmp_path):
    monkeypatch.setattr(upload, "MAX_ROWS", 5)
    p = tmp_path / "list.txt"
    p.write_text("# x\n" + "".join(f"198.51.100.{i}\n" for i in range(1, 21)))
    monkeypatch.setattr(Path, "read_text", lambda *a, **k: (_ for _ in ()).throw(AssertionError("read whole file")))
    res = upload.ingest_to_ndjson(p, "l", None, tmp_path / "list.events.ndjson.gz", max_rows=upload.MAX_ROWS)
    assert (res["kept"], res["total"]) == (5, 20)


def test_upload_under_the_cap_has_no_note_and_no_absolute_path():
    r = C.post("/api/upload", files={"file": ("small.csv", io.BytesIO(_csv(3)), "text/csv")},
               data={"label": "small"}, headers=H)
    d = r.json()
    assert r.status_code == 200 and d["rows"] == 3 and "note" not in d
    assert "stored_at" not in d and d["file"].startswith("uploads/") and d["file"].endswith("-small.csv")
    assert str(LAKE) not in r.text and str(Path.home()) not in r.text
    assert (config.LAKE / d["file"]).exists()


def test_upload_byte_cap(monkeypatch):
    assert upload.MAX_BYTES == 64 << 20
    monkeypatch.setattr(upload, "MAX_BYTES", 1 << 20)
    r = C.post("/api/upload", files={"file": ("huge.csv", io.BytesIO(b"ip\n" + b"192.0.2.1\n" * 200_000), "text/csv")},
               data={"label": "huge"}, headers=H)
    assert r.status_code == 413 and "1 MB limit" in r.json()["detail"]
    assert not list((config.UPLOAD_DIR).rglob("*-huge.csv"))     # nothing left on disk


def test_empty_upload_loads_nothing():
    r = C.post("/api/upload", files={"file": ("empty.csv", io.BytesIO(b"ip,title\n"), "text/csv")},
               data={"label": "empty"}, headers=H)
    assert r.status_code == 200 and r.json()["rows"] == 0


# ================================================================== L3: feed size caps
class Chunks(httpx.AsyncByteStream):
    """A response body that arrives in pieces, like a real socket (not pre-read)."""

    def __init__(self, data: bytes, size: int = 16384):
        self.data, self.size = data, size

    async def __aiter__(self):
        for i in range(0, len(self.data), self.size):
            yield self.data[i:i + self.size]


def streamed(body: bytes, encoding: str | None = None, ctype="application/json"):
    hdrs = {"content-type": ctype}
    if encoding:
        hdrs["content-encoding"] = encoding
    return httpx.Response(200, headers=hdrs, stream=Chunks(body))


def _run(src, handler):
    async def go():
        scheduler._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            return await scheduler.run_batch(src)
        finally:
            await scheduler._client.aclose()
            scheduler._client = None
    old = config.OFFLINE
    config.OFFLINE = False
    try:
        return asyncio.run(go())
    finally:
        config.OFFLINE = old


def _stored(sid):
    n = db.query("SELECT count(*) AS n FROM events WHERE source = ?", [sid])[0]["n"]
    files = list((config.RAW_DIR / sid).rglob("*")) if (config.RAW_DIR / sid).exists() else []
    return n, [f for f in files if f.is_file()]


ZEROS_GZ = gzip.compress(b" " * (48 << 20), compresslevel=9)     # 48 MB of spaces, ~47 KB on the wire


def test_every_source_has_a_cap_and_caps_have_the_floor():
    for sid in SOURCES:
        if SOURCES[sid].mode == "stream":
            continue
        assert sid in caps.CAPS, f"{sid} has no size cap"
        assert caps.cap_for(sid) >= caps.FLOOR


def test_feed_over_cap_fails_the_run_and_stores_nothing():
    src = SOURCES["feodo_c2"]
    big = json.dumps([{"ip_address": "192.0.2.1", "port": 443, "pad": "x" * 2_000_000}]).encode()
    res = _run(src, lambda req: streamed(big))
    assert res["ok"] is False
    assert "feodotracker.abuse.ch sent more than 1 MB" in res["error"] and "stored nothing" in res["error"]
    assert _stored("feodo_c2") == (0, [])


def test_gzip_bomb_counts_decoded_bytes_and_stays_small_in_memory():
    src = SOURCES["et_compromised"]
    tracemalloc.start()
    res = _run(src, lambda req: streamed(ZEROS_GZ, "gzip", "text/plain"))
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert res["ok"] is False and "more than 1 MB" in res["error"]
    assert peak < 12 << 20, f"peak {peak >> 20} MB"     # never inflated whole (48 MB)
    assert _stored("et_compromised") == (0, [])


def test_double_gzip_bomb_is_stopped():
    async def go():
        cl = httpx.AsyncClient(transport=httpx.MockTransport(lambda req: streamed(gzip.compress(ZEROS_GZ), "gzip, gzip")))
        with pytest.raises(caps.TooLarge):
            await caps.get(cl, "https://lists.example/x", "tor_exits")
    tracemalloc.start()
    asyncio.run(go())
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert peak < 12 << 20


def test_rss_feed_over_cap_fails_the_run():
    src = SOURCES["security_news"]
    rss = b"<?xml version='1.0'?><rss version='2.0'><channel><title>t</title>" + b"<!-- pad -->" * 300_000 + b"</channel></rss>"
    res = _run(src, lambda req: streamed(rss, None, "application/rss+xml"))
    assert res["ok"] is False and "more than 2 MB" in res["error"]
    assert _stored("security_news")[0] == 0


def test_normal_gzip_and_deflate_responses_still_decode():
    body = json.dumps([{"ip_address": "192.0.2.9", "port": 8080, "status": "online", "malware": "Test",
                        "first_seen": "2026-11-01 10:00:00", "last_online": "2026-11-18", "country": "US",
                        "as_number": 64500, "as_name": "TEST"}]).encode()
    for enc, data in (("gzip", gzip.compress(body)), ("deflate", zlib.compress(body)),
                      ("deflate", zlib.compress(body)[2:-4])):          # raw deflate, as some servers send
        async def go(data=data, enc=enc):
            cl = httpx.AsyncClient(transport=httpx.MockTransport(lambda req: streamed(data, enc)))
            r = await caps.get(cl, "https://feodotracker.abuse.ch/x", "feodo_c2")
            return r
        r = asyncio.run(go())
        assert r.json()[0]["ip_address"] == "192.0.2.9" and "content-encoding" not in r.headers
    res = _run(SOURCES["feodo_c2"], lambda req: streamed(gzip.compress(body), "gzip"))
    assert res["ok"] is True and res["items"] == 1


def test_unsupported_encoding_is_refused():
    async def go():
        cl = httpx.AsyncClient(transport=httpx.MockTransport(lambda req: streamed(b"x", "br")))
        with pytest.raises(httpx.DecodingError):
            await caps.get(cl, "https://x.example/", "feodo_c2")
    asyncio.run(go())


def test_requests_ask_only_for_gzip_and_deflate():
    seen = []

    def h(req):
        seen.append(req.headers.get("accept-encoding"))
        return streamed(b"[]")
    asyncio.run(caps.get(httpx.AsyncClient(transport=httpx.MockTransport(h)), "https://x.example/", "feodo_c2"))
    assert seen == ["gzip, deflate"]


def test_epss_gzip_file_is_inflated_with_a_cap():
    with pytest.raises(caps.TooLarge, match="the EPSS file unpacks to more than 1 MB"):
        caps.inflate_capped(gzip.compress(b"a" * (3 << 20)), 1_000_000, "the EPSS file")
    assert caps.inflate_capped(gzip.compress(b"cve,epss\n"), 1_000_000, "x") == b"cve,epss\n"


def test_routing_download_is_capped_by_decoded_bytes(monkeypatch):
    monkeypatch.setattr(config, "OFFLINE", False)
    monkeypatch.setitem(caps.CAPS, "rpki_roas", 1_000_000)

    async def go():
        cl = httpx.AsyncClient(transport=httpx.MockTransport(lambda req: streamed(ZEROS_GZ, "gzip")))
        with pytest.raises(caps.TooLarge) as e:
            await net.get(cl, "https://rpki.example/rpki.json", sid="rpki_roas", budget=False)
        return e.value
    err = asyncio.run(go())
    assert "rpki.example sent more than 1 MB" in str(err)
    assert net.short_error(err, "rpki.example") == str(err)


def test_upload_loads_into_duckdb_in_parts(monkeypatch):
    calls = []
    real = db.load_events_ndjson
    monkeypatch.setattr(upload, "LOAD_ROWS", 400)
    monkeypatch.setattr(db, "load_events_ndjson", lambda p: calls.append(p) or real(p))
    r = C.post("/api/upload", files={"file": ("parts.csv", io.BytesIO(_csv(1_000)), "text/csv")},
               data={"label": "parts"}, headers=H)
    assert r.status_code == 200 and r.json()["rows"] == 1_000
    assert len(calls) == 3                                      # 400 + 400 + 200
    assert not list((config.TMP_DIR / "upload-parts").glob("*"))   # part files cleaned up


# ================================================================== round 2: every upload type, through the API
def _objs(n: int) -> list[dict]:
    nets = ("192.0.2.", "198.51.100.", "203.0.113.")
    return [{"ip": f"{nets[i % 3]}{i % 254 + 1}", "title": f"host {i}", "severity": 0.5, "country": "US",
             "first_seen": "2026-11-18T10:00:00Z"} for i in range(n)]


def _file(kind: str, n: int) -> tuple[str, bytes]:
    rows = _objs(n)
    if kind == "csv":
        return "f.csv", _csv(n)
    if kind == "json":
        return "f.json", json.dumps(rows).encode()
    if kind == "pretty":
        return "f.json", json.dumps(rows, indent=2).encode()
    if kind in ("ndjson", "jsonl"):
        return f"f.{kind}", "".join(json.dumps(r) + "\n" for r in rows).encode()
    if kind == "txt":
        return "f.txt", "".join(r["ip"] + "\n" for r in rows).encode()
    raise ValueError(kind)


def _post(name: str, data: bytes, label: str):
    return C.post("/api/upload", files={"file": (name, io.BytesIO(data), "application/octet-stream")},
                  data={"label": label}, headers=H)


@pytest.mark.parametrize("kind", ["csv", "json", "pretty", "ndjson", "jsonl", "txt"])
def test_every_upload_type_works(kind):
    name, data = _file(kind, 3 if kind != "txt" else 3)
    r = _post(name, data, f"t-{kind}")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["rows"] == 3 and d["kept"] == 3 and d["total"] == 3, d
    ev = db.query("SELECT ip, title FROM events WHERE source = 'upload' AND list_contains(tags, ?) ORDER BY ip", [f"t-{kind}"])
    assert [e["ip"] for e in ev] == ["192.0.2.1", "198.51.100.2", "203.0.113.3"]


def test_the_two_line_ndjson_from_the_review():
    r = _post("s.ndjson", b'{"ip":"192.0.2.7","title":"a"}\n{"ip":"198.51.100.9","title":"b"}\n', "t-review")
    assert r.status_code == 200 and r.json()["rows"] == 2, r.text


def test_ndjson_skips_a_broken_line_but_not_json_at_all_is_an_error():
    r = _post("b.ndjson", b'{"ip":"192.0.2.1"}\nnot json\n{"ip":"192.0.2.2"}\n', "t-broken")
    assert r.status_code == 200 and r.json()["rows"] == 2
    assert _post("c.json", b"ip,title\n192.0.2.1,x\n", "t-csv-as-json").status_code == 400
    assert _post("d.json", b'[{"ip": "192.0.2.1"}, {"ip": ', "t-cut").status_code == 400


def test_json_rows_are_streamed_not_parsed_whole(monkeypatch, tmp_path):
    p = tmp_path / "a.json"
    p.write_bytes(json.dumps(_objs(30_000)).encode())
    monkeypatch.setattr(upload, "JSON_READ", 4096)                 # many small reads
    monkeypatch.setattr(json, "loads", lambda *a, **k: (_ for _ in ()).throw(AssertionError("whole-file json.loads")))
    tracemalloc.start()
    n = sum(1 for _ in upload.iter_events(p, "s"))
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert n == 30_000 and peak < 4 << 20, peak


@pytest.mark.parametrize("kind", ["json", "ndjson"])
def test_json_upload_at_the_row_cap(kind):
    name, data = _file(kind, upload.MAX_ROWS + 1)
    r = _post(name, data, f"cap-{kind}")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["rows"] == upload.MAX_ROWS and d["total"] == upload.MAX_ROWS + 1 and "Kept the first 200,000 of 200,001" in d["note"]


# ================================================================== round 2: redirects are followed by hand
import threading  # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402

BOMB = gzip.compress(b"\0" * (96 << 20), compresslevel=9)            # 96 MB inflated, ~93 KB on the wire
SEEN: list[tuple[str, str | None, str]] = []


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", headers=()):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def do_GET(self):
        SEEN.append((self.path, self.headers.get("Authorization"), "GET"))
        p = self.path
        if p == "/redir-bomb":     # the evaluator's shape: a 302 whose own body is a gzip bomb
            return self._send(302, BOMB, [("Location", "/ok"), ("Content-Encoding", "gzip")])
        if p.startswith("/chain/"):
            n = int(p.rsplit("/", 1)[1])
            return self._send(302, BOMB, [("Location", f"/chain/{n - 1}" if n > 0 else "/ok"), ("Content-Encoding", "gzip")])
        if p == "/to-file":
            return self._send(302, b"", [("Location", "file:///etc/passwd")])
        if p == "/to-other-host":
            return self._send(302, b"", [("Location", f"http://localhost:{PORT}/ok")])
        if p == "/ok":
            return self._send(200, b'[{"ip_address": "192.0.2.9", "port": 443, "status": "online"}]', [("Content-Type", "application/json")])
        return self._send(404)

    def do_POST(self):
        SEEN.append((self.path, self.headers.get("Authorization"), "POST"))
        return self._send(302, b"", [("Location", "/ok")])


SRV = ThreadingHTTPServer(("127.0.0.1", 0), _H)
PORT = SRV.server_address[1]
threading.Thread(target=SRV.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{PORT}"


def _cl():
    return httpx.AsyncClient(follow_redirects=True, trust_env=False, timeout=10)   # like the scheduler's client


def _peak(coro):
    tracemalloc.start()
    try:
        out = asyncio.run(coro)
    finally:
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
    return out, peak


def test_redirect_body_bomb_is_never_read():
    async def go():
        async with _cl() as cl:
            return await caps.get(cl, f"{BASE}/redir-bomb", "feodo_c2")
    r, peak = _peak(go())
    assert r.status_code == 200 and r.json()[0]["ip_address"] == "192.0.2.9"
    assert peak < 8 << 20, f"peak {peak >> 20} MB: a 3xx body was inflated"


def test_redirect_chain_is_followed_up_to_five_hops():
    async def go(n):
        async with _cl() as cl:
            return await caps.get(cl, f"{BASE}/chain/{n}", "feodo_c2")
    (r, peak) = _peak(go(4))                       # 5 redirects, then the body
    assert r.status_code == 200 and peak < 8 << 20
    with pytest.raises(httpx.TooManyRedirects):
        asyncio.run(go(5))                         # 6 redirects


def test_redirect_rules_scheme_auth_and_method():
    async def go():
        async with _cl() as cl:
            with pytest.raises(httpx.UnsupportedProtocol):
                await caps.get(cl, f"{BASE}/to-file", "feodo_c2")
            SEEN.clear()
            r = await caps.get(cl, f"{BASE}/to-other-host", "feodo_c2", headers={"Authorization": "Bearer x"})
            assert r.status_code == 200
            assert SEEN == [("/to-other-host", "Bearer x", "GET"), ("/ok", None, "GET")]   # dropped for another origin
            SEEN.clear()
            r = await caps.get(cl, f"{BASE}/post", "threatfox", method="POST", json={"q": 1})
            assert r.status_code == 200 and [s[2] for s in SEEN] == ["POST", "GET"]
            r = await caps.get(cl, f"{BASE}/redir-bomb", "feodo_c2", follow_redirects=False)
            assert r.status_code == 302 and r.content == b"" and r.headers["location"] == "/ok"
    asyncio.run(go())


def test_source_run_through_the_scheduler_client_with_a_redirect_bomb(monkeypatch):
    src = SOURCES["feodo_c2"]
    monkeypatch.setattr(config, "OFFLINE", False)
    real = caps.get

    async def to_loopback(client, url, sid, **kw):   # the feed URL is replaced by the loopback bomb
        return await real(client, f"{BASE}/redir-bomb", sid, **kw)
    monkeypatch.setattr(caps, "get", to_loopback)

    async def go():
        scheduler._client = httpx.AsyncClient(follow_redirects=True, trust_env=False, timeout=10)
        try:
            return await scheduler.run_batch(src)
        finally:
            await scheduler._client.aclose()
            scheduler._client = None
    res, peak = _peak(go())
    assert res["ok"] is True and peak < 24 << 20, (res, peak >> 20)


def test_routing_download_follows_redirects_by_hand(monkeypatch):
    monkeypatch.setattr(config, "OFFLINE", False)

    async def go():
        async with _cl() as cl:
            return await net.get(cl, f"{BASE}/redir-bomb", sid="rpki_roas", budget=False)
    r, peak = _peak(go())
    assert r.status_code == 200 and peak < 8 << 20


def test_refdata_download_is_capped_and_follows_redirects_by_hand(monkeypatch, tmp_path):
    from osinthub.entities import refdata
    monkeypatch.setattr(refdata, "REF", tmp_path)
    monkeypatch.setattr(refdata, "FILES", {"tlds": ("tlds.txt", f"{BASE}/redir-bomb"), "psl": ("psl.dat", f"{BASE}/big")})
    monkeypatch.setattr(config, "OFFLINE", False)
    monkeypatch.setitem(caps.CAPS, "ref_psl", 1000)
    real = _H.do_GET

    def big(self):
        if self.path == "/big":
            return self._send(200, gzip.compress(b"x" * 50_000), [("Content-Encoding", "gzip")])
        return real(self)
    monkeypatch.setattr(_H, "do_GET", big)
    st = refdata.ensure()
    assert st["tlds"].startswith("downloaded") and (tmp_path / "tlds.txt").read_bytes().startswith(b'[{"ip_address"')
    assert st["psl"] == "failed: TooLarge" and not (tmp_path / "psl.dat").exists()


# ================================================================== lead fix after round 2: linear bad lines, big values
import time  # noqa: E402


def test_bad_ndjson_lines_cost_linear_time(tmp_path):
    # evaluator round 2, failure 1: 5 MB of "hello world" lines took 118 s (quadratic); v1.2 refused it in 0.1 s
    p = tmp_path / "bad.ndjson"
    p.write_bytes(b"hello world\n" * ((5 << 20) // 12))
    t0 = time.monotonic()
    with pytest.raises(ValueError):
        list(upload.iter_events(p, "bad"))
    assert time.monotonic() - t0 < 2
    q = tmp_path / "mixed.ndjson"   # a valid first line, then bad lines: skipped one by one, still linear
    q.write_bytes(b'{"ip": "192.0.2.1"}\n' + b"hello world\n" * ((5 << 20) // 12))
    t0 = time.monotonic()
    assert sum(1 for _ in upload.iter_events(q, "mixed")) == 1
    assert time.monotonic() - t0 < 2


def test_one_huge_value_is_one_row_as_in_v12(tmp_path):
    # evaluator round 2, failure 2: v1.2 kept these as rows; the 16 MB per-row limit is gone
    big = {"ip": "192.0.2.9", "blob": "x" * (20 << 20)}
    one = tmp_path / "one.json"
    one.write_text(json.dumps(big))
    assert sum(1 for _ in upload.iter_events(one, "one")) == 1
    pretty = tmp_path / "pretty.json"
    pretty.write_text(json.dumps({"data": _objs(2000)}, indent=2))
    assert sum(1 for _ in upload.iter_events(pretty, "pretty")) == 1
    arr = tmp_path / "arr.json"
    arr.write_text(json.dumps([big]))
    t0 = time.monotonic()
    assert sum(1 for _ in upload.iter_events(arr, "arr")) == 1
    assert time.monotonic() - t0 < 5
    nd = tmp_path / "three.ndjson"
    nd.write_text(json.dumps({"ip": "192.0.2.1"}) + "\n" + json.dumps(big) + "\n" + json.dumps({"ip": "192.0.2.2"}) + "\n")
    assert sum(1 for _ in upload.iter_events(nd, "three")) == 3


def test_a_broken_array_and_a_broken_object_are_refused_quickly(tmp_path):
    a = tmp_path / "a.json"
    a.write_text("[" + json.dumps(_objs(1))[1:-1] + ", {broken" + " " * (8 << 20))
    t0 = time.monotonic()
    with pytest.raises(ValueError):
        list(upload.iter_events(a, "a"))
    o = tmp_path / "o.json"
    o.write_text('{"ip": "192.0.2.1",\n "x": [1, 2,\n' + " " * (8 << 20))
    with pytest.raises(ValueError):
        list(upload.iter_events(o, "o"))
    assert time.monotonic() - t0 < 3


def _mock_redirects(seen: list):
    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((str(req.url), req.headers.get("authorization"), req.headers.get("x-api-key")))
        target = {"https://api.cloudflare.com/x": "http://api.cloudflare.com/y",
                  "http://a.example/x": "https://a.example:8443/y",
                  "https://api-pro.ransomware.live/v": "https://evil.example/y",
                  "http://b.example/x": "https://b.example/y",
                  "https://c.example/x": "/z"}.get(str(req.url))
        if target:
            return httpx.Response(302, headers={"location": target})
        return httpx.Response(200, content=b"ok")
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)


def test_redirects_never_carry_a_key_to_another_origin_or_over_a_downgrade():
    # evaluator round 2, failure 3
    async def go():
        seen: list = []
        async with _mock_redirects(seen) as cl:
            await caps.get(cl, "https://api.cloudflare.com/x", "cf_radar_bgp", headers={"Authorization": "Bearer SECRET"})
            assert seen[-1] == ("http://api.cloudflare.com/y", None, None)          # https -> http: dropped
            await caps.get(cl, "http://a.example/x", "cf_radar_bgp", headers={"Authorization": "Bearer SECRET"})
            assert seen[-1] == ("https://a.example:8443/y", None, None)             # another port: dropped
            await caps.get(cl, "https://api-pro.ransomware.live/v", "ransomware_live", headers={"X-API-KEY": "SECRET"})
            assert seen[-1] == ("https://evil.example/y", None, None)               # another host: X-API-KEY dropped
            await caps.get(cl, "http://b.example/x", "cf_radar_bgp", headers={"Authorization": "Bearer SECRET"})
            assert seen[-1] == ("https://b.example/y", "Bearer SECRET", None)       # http:80 -> https:443 upgrade: kept
            await caps.get(cl, "https://c.example/x", "ransomware_live", headers={"X-API-KEY": "SECRET"})
            assert seen[-1] == ("https://c.example/z", None, "SECRET")              # same origin: kept
    asyncio.run(go())


def test_same_origin_rule_matches_httpx():
    U = httpx.URL
    assert caps._same_origin(U("https://h.example/a"), U("https://h.example:443/b"))
    assert caps._same_origin(U("http://h.example/a"), U("https://h.example/b"))
    assert not caps._same_origin(U("https://h.example/a"), U("http://h.example/b"))
    assert not caps._same_origin(U("http://h.example:8080/a"), U("https://h.example/b"))
    assert not caps._same_origin(U("https://h.example/a"), U("https://other.example/b"))


@pytest.mark.parametrize("name", ["e.json", "e.ndjson"])
def test_an_empty_json_upload_has_no_rows_as_in_v12(name):
    # final check nit 1: v1.2 answered 200 with no rows
    for body in (b"", b"  \n\t\n"):
        r = _post(name, body, "t-empty")
        assert r.status_code == 200 and r.json()["rows"] == 0, r.text


# ================================================================== the Tranco top-sites list (online installs only)
def _tranco_client(monkeypatch, body: bytes):
    real = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(lambda req: httpx.Response(200, content=body)), **kw))


def _zip(text: str) -> bytes:
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("top-1m.csv", text)
    return buf.getvalue()


def test_tranco_keeps_the_first_20k_lines(monkeypatch, tmp_path):
    from osinthub.netlog import allowlist
    monkeypatch.setattr(config, "OFFLINE", False)
    monkeypatch.setattr(allowlist, "TRANCO_FILE", tmp_path / "tranco.txt")
    _tranco_client(monkeypatch, _zip("".join(f"{i},site{i}.example\n" for i in range(1, 25_001))))
    res = allowlist.ensure_tranco(force=True)
    assert res["ok"] and res["domains"] == allowlist.TRANCO_N
    assert (tmp_path / "tranco.txt").read_text().splitlines()[-1] == "20000,site20000.example"


def test_tranco_over_its_cap_stores_nothing(monkeypatch, tmp_path):
    from osinthub.netlog import allowlist
    monkeypatch.setattr(config, "OFFLINE", False)
    monkeypatch.setattr(allowlist, "TRANCO_FILE", tmp_path / "tranco.txt")
    monkeypatch.setitem(caps.CAPS, "ref_tranco", 1000)
    _tranco_client(monkeypatch, b"x" * 5000)
    res = allowlist.ensure_tranco(force=True)
    assert not res["ok"] and "TooLarge" in res["reason"]
    assert not (tmp_path / "tranco.txt").exists()


def test_tranco_one_endless_line_is_cut(monkeypatch, tmp_path):
    from osinthub.netlog import allowlist
    monkeypatch.setattr(config, "OFFLINE", False)
    monkeypatch.setattr(allowlist, "TRANCO_FILE", tmp_path / "tranco.txt")
    _tranco_client(monkeypatch, _zip("1," + "a" * 2_000_000))   # one 2 MB line, no newline
    res = allowlist.ensure_tranco(force=True)
    assert res["ok"]
    assert max(len(x) for x in (tmp_path / "tranco.txt").read_text().splitlines()) <= allowlist.TRANCO_LINE
