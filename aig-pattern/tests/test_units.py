"""Модульные тесты ядра каждого микросервиса паттерна AIG."""

import io
import zipfile
from datetime import datetime, timedelta, timezone

from conftest import ROOT, load_service

SAMPLES = ROOT / "samples"


# ---------------------------------------------------------------- format-detector
def test_detector_known_and_unknown(tmp_path):
    d = load_service("format-detector", tmp_path)
    assert d.detect((SAMPLES / "supply_ok.csv").read_bytes())["format"] == "csv"
    assert d.detect((SAMPLES / "supply.jsonl").read_bytes())["format"] == "jsonl"
    assert d.detect(b"PAR1" + b"\x00" * 100)["format"] == "parquet"
    new = d.detect((SAMPLES / "supply_2026-07.csv").read_bytes())
    assert new["format"] == "UNKNOWN"
    assert (
        new["features"]["delimiter"] == "|"
        and new["features"]["encoding"] == "utf-8-sig"
    )
    cp = d.detect((SAMPLES / "supply_cp1251.csv").read_bytes())
    assert cp["features"]["encoding"] == "cp1251" and cp["features"]["delimiter"] == ";"
    junk = d.detect((SAMPLES / "garbage.bin").read_bytes())
    assert junk["format"] == "UNKNOWN" and junk["features"]["binary"] is True
    assert junk["features"]["entropy"] > 7.5


# ---------------------------------------------------------------- schema-registry
def test_registry_backward_policy(tmp_path):
    r = load_service("schema-registry", tmp_path)
    old = {"fields": {"id": "int", "v": "int"}, "optional": []}
    assert (
        r.check_backward(old, {"fields": {"id": "int", "v": "float"}, "optional": []})
        == []
    )
    assert r.check_backward(old, {"fields": {"id": "int"}, "optional": []})  # удаление
    assert r.check_backward(old, {"fields": {"id": "int", "v": "bool"}, "optional": []})
    assert r.check_backward(
        old, {"fields": {"id": "int", "v": "int", "c": "string"}, "optional": []}
    )  # не optional
    ok = {"fields": {"id": "int", "v": "int", "c": "string"}, "optional": ["c"]}
    assert r.check_backward(old, ok) == []


# ---------------------------------------------------------------- adapter-factory
def test_adapter_infer_and_convert(tmp_path, s3_mock):
    a = load_service("adapter-factory", tmp_path)
    blob = (SAMPLES / "supply_2026-07.csv").read_bytes()
    feats = {
        "family": "csv",
        "delimiter": "|",
        "encoding": "utf-8-sig",
        "has_header": True,
    }
    schema = a.infer_schema(blob.decode("utf-8-sig"), feats)
    assert schema["fields"] == {
        "date": "date",
        "well_id": "int",
        "volume_m3": "float",
        "approved": "bool",
        "comment": "string",
    }
    assert schema["optional"] == ["comment"]
    a.save_converter("cid-1", schema)
    a.CACHE.clear()  # имитация перезапуска пода
    data, good, bad = a.get_converter("cid-1")(blob)
    assert (good, bad) == (31, 0)
    assert b'"volume_m3": 474.45' in data.splitlines()[0]


# ---------------------------------------------------------------- security-service
def test_security_token_bucket(tmp_path, s3_mock):
    s = load_service("security-service", tmp_path)
    t0 = 1000.0
    assert all(s.take_token("u", t0) for _ in range(31))  # пакет BURST = 31
    assert s.take_token("u", t0) is False  # пакет исчерпан
    assert s.take_token("u", t0 + 6.0) is True  # 10 токенов/мин -> 1 за 6 с


def test_security_sanitize(tmp_path, s3_mock):
    s = load_service("security-service", tmp_path)
    assert s.sanitize(b"a,b\n1,2\n") is None
    assert s.sanitize(b"\x7fELF....")[0] == 415
    assert s.sanitize(b"MZ" + b"\x00" * 10)[0] == 415
    bomb = io.BytesIO()
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.csv", b"0" * 5_000_000)  # коэффициент сжатия ~1000
    assert s.sanitize(bomb.getvalue()) == (415, "zip bomb (compression ratio)")


def test_security_reaper_blocks_attacker(tmp_path, s3_mock):
    s = load_service("security-service", tmp_path)
    for i in range(3):
        s3_mock.create_multipart_upload(
            Bucket="raw", Key=f"contractor-07/t{i}/junk.csv"
        )
    future = datetime.now(timezone.utc) + timedelta(seconds=s.MPU_MAX_AGE + 1)
    aborted = s.reap_dangling_multiparts(now=future)
    assert len(aborted) == 3
    assert s3_mock.list_multipart_uploads(Bucket="raw").get("Uploads", []) == []
    assert s.is_blocked("contractor-07")  # 3 штрафа -> блокировка
