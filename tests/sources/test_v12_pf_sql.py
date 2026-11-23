"""Pre-public fix round, lane pf-sql: the upload parser (osinthub/sources/upload.py, okf/data/size-limits.md#uploads).

Rows past the 200,000-row cap are counted without building their events; NDJSON parses each line once (the first one
too); a JSON array is the file's one array: anything but white space after it (a second array too), a broken array
or a file that is not JSON is refused with a message that says what is wrong, quickly whatever the file holds; more
than 1 MB of white space before an array still reads it as an array.

    uv run --with pytest pytest tests/sources/test_v12_pf_sql.py -q
"""
from __future__ import annotations

import io
import json

from _lake import make_lake
LAKE = make_lake("pfsql-upload", disable="news,entities,ai")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from osinthub import db  # noqa: E402
import osinthub.api as A  # noqa: E402
from osinthub.sources import upload  # noqa: E402

db.connect()
C = TestClient(A.app, base_url="http://localhost")
H = {"Origin": "http://localhost"}
NETS = ("192.0.2.", "198.51.100.", "203.0.113.")


def ip(i: int) -> str:
    return f"{NETS[i % 3]}{i % 254 + 1}"


FILES = {
    "csv": ("rows.csv", lambda n: "ip,title\n" + "".join(f"{ip(i)},host {i}\n" for i in range(n))),
    "ndjson": ("rows.ndjson", lambda n: "".join(json.dumps({"ip": ip(i)}) + "\n" for i in range(n))),
    "array": ("rows.json", lambda n: json.dumps([{"ip": ip(i)} for i in range(n)])),
    "list": ("rows.txt", lambda n: "".join(ip(i) + "\n" for i in range(n))),
}


@pytest.fixture
def built(monkeypatch):
    """How many events were built."""
    n = {"events": 0}
    real = upload.Event

    def counting(*a, **k):
        n["events"] += 1
        return real(*a, **k)
    monkeypatch.setattr(upload, "Event", counting)
    return n


@pytest.mark.parametrize("kind", sorted(FILES))
def test_rows_past_the_cap_are_counted_without_building_events(kind, built, tmp_path):
    name, make = FILES[kind]
    p = tmp_path / name
    p.write_text(make(2_500))
    res = upload.ingest_to_ndjson(p, "t", None, tmp_path / "out.ndjson.gz", max_rows=1_000)
    assert (res["kept"], res["total"]) == (1_000, 2_500)
    assert built["events"] == 1_000


@pytest.mark.parametrize("kind", sorted(FILES))
def test_at_and_under_the_cap_every_row_is_kept(kind, built, tmp_path):
    name, make = FILES[kind]
    p = tmp_path / name
    for n, cap in ((1_000, 1_000), (999, 1_000), (5, 0)):
        p.write_text(make(n))
        res = upload.ingest_to_ndjson(p, "t", None, tmp_path / "out.ndjson.gz", max_rows=cap)
        assert (res["kept"], res["total"]) == (min(n, cap), n)


def test_a_null_row_past_the_cap_is_still_counted(tmp_path):
    p = tmp_path / "n.ndjson"
    p.write_text('{"ip": "192.0.2.1"}\nnull\nnull\n')
    res = upload.ingest_to_ndjson(p, "t", None, tmp_path / "out.ndjson.gz", max_rows=1)
    assert (res["kept"], res["total"]) == (1, 3)


def test_the_api_note_with_counted_rows(monkeypatch):
    monkeypatch.setattr(upload, "MAX_ROWS", 100)
    r = C.post("/api/upload", files={"file": ("big.ndjson", io.BytesIO(FILES["ndjson"][1](250).encode()), "application/json")},
               data={"label": "pfcap"}, headers=H)
    assert r.status_code == 200, r.text
    d = r.json()
    assert (d["rows"], d["kept"], d["total"]) == (100, 100, 250)
    assert d["note"].startswith("Kept the first 100 of 250 rows")


def test_ndjson_parses_every_line_once(monkeypatch, tmp_path):
    p = tmp_path / "once.ndjson"
    p.write_text('\n\n{"ip": "192.0.2.1"}\n{"ip": "192.0.2.2"}\nnot json\n\n{"ip": "192.0.2.3"}\n')
    seen = []
    real = json.loads
    monkeypatch.setattr(json, "loads", lambda s, *a, **k: seen.append(s.strip()) or real(s, *a, **k))
    assert [e.ip for e in upload.iter_events(p, "t")] == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    assert seen == ['{"ip": "192.0.2.1"}', '{"ip": "192.0.2.2"}', "not json", '{"ip": "192.0.2.3"}']


def test_white_space_after_the_array_across_read_chunks(monkeypatch, tmp_path):
    monkeypatch.setattr(upload, "JSON_READ", 64)
    p = tmp_path / "chunks.json"
    p.write_text(json.dumps([{"ip": ip(i)} for i in range(90)]) + " \n" * 500)
    assert [e.ip for e in upload.iter_events(p, "t")] == [ip(i) for i in range(90)]
    p.write_text(json.dumps([{"ip": ip(i)} for i in range(90)]) + " \n" * 500 + "[]")
    with pytest.raises(upload.UploadRefused, match="more after the closing ]"):
        list(upload.iter_events(p, "t"))


@pytest.mark.parametrize("text", ['[{"ip": "192.0.2.1"}] {"ip": "192.0.2.2"}', '[1, 2], [3]', '[1, 2]\nx', '[1]]',
                                  '[{"ip": "192.0.2.1"}][{"ip": "192.0.2.2"}]', '[1]\n[2]\n', '[] []',
                                  '["192.0.2.1", "host a"]\n["192.0.2.2", "host b"]\n'])
def test_other_text_after_an_array_is_refused_with_a_reason(text, tmp_path):
    p = tmp_path / "trail.json"
    p.write_text(text)
    with pytest.raises(upload.UploadRefused, match="more after the closing ]"):
        list(upload.iter_events(p, "t"))


@pytest.mark.parametrize("text,why", [('[{"ip": "192.0.2.1"}', "never closed"), ('[{"ip": }]', "not valid JSON"),
                                      ('{"a": 1,\n "b": }', "not valid JSON"),
                                      ('[1][2', "more after the closing ]")])
def test_the_api_says_why_a_file_is_refused(text, why):
    r = C.post("/api/upload", files={"file": ("bad.json", io.BytesIO(text.encode()), "application/json")},
               data={"label": "pfbad"}, headers=H)
    assert r.status_code == 400
    assert why in r.json()["detail"], r.text
    r = C.post("/api/upload", files={"file": ("trail.json", io.BytesIO(b'[1] {"a": 2}'), "application/json")},
               data={"label": "pfbad"}, headers=H)
    assert r.status_code == 400 and "Upload one JSON array" in r.json()["detail"], r.text


def test_more_than_a_megabyte_of_white_space_before_an_array(tmp_path):
    p = tmp_path / "ws.json"
    rows = [{"ip": ip(i)} for i in range(3)]
    p.write_text(" \n\t\r" * (700 << 10) + json.dumps(rows))     # 2.8 MB of white space, the array on one line
    assert p.stat().st_size > 2 * upload.JSON_READ
    assert [e.ip for e in upload.iter_events(p, "t")] == [ip(i) for i in range(3)]
    p.write_text(" " * (3 << 20) + "\n" + json.dumps(rows, indent=2) + "\n" + " \t" * (2 << 20))
    assert [e.ip for e in upload.iter_events(p, "t")] == [ip(i) for i in range(3)]


def test_more_than_a_megabyte_of_white_space_before_other_json(tmp_path):
    p = tmp_path / "ws.ndjson"
    p.write_text(" " * (2 << 20) + "\n" + '{"ip": "192.0.2.1"}\n{"ip": "192.0.2.2"}\n')
    assert [e.ip for e in upload.iter_events(p, "t")] == ["192.0.2.1", "192.0.2.2"]
    p.write_text("\n" * (2 << 20))
    assert list(upload.iter_events(p, "t")) == []


def test_upload_events_stay_a_lazy_generator(tmp_path):
    p = tmp_path / "lazy.json"
    p.write_text(json.dumps([{"ip": ip(i)} for i in range(10)]) + "garbage")
    it = upload.iter_events(p, "t")
    assert iter(it) is it and next(it).ip == ip(0)    # rows come before the trailer is seen
    with pytest.raises(upload.UploadRefused):
        list(it)


@pytest.mark.parametrize("name,text", [
    ("many empty arrays", "[]" * (8 << 20)),     # pf-sql round 1 spent ~5 s a MB here, quadratic per chunk
    ("many one-element arrays", "[1]" * (5 << 20)),
    ("one array, 15 MB of white space after it", "[1]" + (" " * 1023 + "\n") * (15 << 10)),
    ("one array of 1.5 million numbers", "[" + "1," * 1_500_000 + "1]"),
])
def test_json_arrays_parse_in_linear_time(name, text, tmp_path):
    """A guard, not a benchmark: each 3 to 16 MB file takes under half a second here (the 1.5 million numbers are
    counted past the cap); quadratic work in the buffer handling would take a minute or more."""
    import time
    p = tmp_path / "big.json"
    p.write_text(text)
    t = time.perf_counter()
    try:
        upload.ingest_to_ndjson(p, "t", None, tmp_path / "out.ndjson.gz", max_rows=100)
    except upload.UploadRefused:
        pass
    assert time.perf_counter() - t < 15, name
