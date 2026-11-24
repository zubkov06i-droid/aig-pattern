"""Сценарии внутреннего нарушителя с низким потенциалом (ВМ1).

Каждый тест работает от своего субъекта: штрафы и блокировка одного
сценария не влияют на другие. Ожидаемые значения выведены из параметров
паттерна (ConfigMap aig-config, раздел 3.2): MPU_MAX_OPEN = 3,
STRIKES_TO_BLOCK = 3, MAX_ZIP_RATIO = 100, лимит шлюза 5 r/s, пакет 20 на IP.
"""

import io
import socket
import zipfile

import pytest

from .aigtest import VIA_GATEWAY, record, target_host
from gen_jwt import make_token

ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 1024


def zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


@pytest.mark.intruder
@pytest.mark.parametrize(
    "case, header",
    [
        ("без токена", {}),
        (
            "токен, подписанный чужим ключом",
            {
                "Authorization": "Bearer "
                + make_token("contractor-07", "uploader", "x" * 32)
            },
        ),
        ("просроченный токен", None),
    ],
)
def test_n1_authentication(client, token, case, header):
    if header is None:  # exp в прошлом: ttl < 0
        header = token("contractor", 10, ttl=-60)
    r = client.post("/ingest/a.csv", content=b"a,b\n1,2\n", headers=header)
    record(
        "Н1", f"аутентификация: {case}", "401", str(r.status_code), r.status_code == 401
    )
    assert r.status_code == 401


@pytest.mark.intruder
@pytest.mark.parametrize(
    "n, case, name, blob",
    [
        (
            11,
            "активное содержимое (<?php)",
            "evil.csv",
            b"id,cmd\n1,<?php system($_GET[c]); ?>\n",
        ),
        (12, "исполняемый файл ELF под видом CSV", "report.csv", ELF),
        (
            13,
            "zip-бомба (коэффициент сжатия > 100)",
            "data.zip",
            zip_bytes({"a.csv": b"0" * 10_000_000}),
        ),
        (
            14,
            "вложенный архив",
            "data.zip",
            zip_bytes({"inner.zip": zip_bytes({"a.csv": b"1,2\n"})}),
        ),
    ],
)
def test_n2_sanitization(client, token, n, case, name, blob):
    r = client.post(f"/ingest/{name}", content=blob, headers=token("contractor", n))
    ok = r.status_code == 415 and r.json()["status"] == "rejected"
    record(
        "Н2",
        f"санитизация: {case}",
        "415 rejected",
        f"{r.status_code} {r.json().get('status')}",
        ok,
    )
    assert ok


@pytest.mark.intruder
def test_n3_scenario_c2_multipart_flood(client, token):
    """Сценарий С2: висячие multipart-сессии -> лимит 3 сессий -> блокировка."""
    h = token("contractor", 20)
    codes = []
    for i in range(1, 9):
        r = client.post(f"/ingest-mpu/init/junk_{i}.csv", headers=h)
        codes.append(r.status_code)
        if r.status_code == 200:  # часть с «мусором», сессию не завершаем
            up = r.json()
            client.put(
                "/ingest-mpu/part",
                headers=h,
                content=b"\x00" * 1024,
                params={"key": up["key"], "upload_id": up["upload_id"], "n": 1},
            )
    expected = [200] * 3 + [429] * 3 + [403] * 2
    after = client.post("/ingest/ok.csv", content=b"a,b\n1,2\n", headers=h).status_code
    ok = codes == expected and after == 403
    record(
        "Н3",
        "С2: 8 multipart-сессий без завершения",
        f"{expected}, затем 403",
        f"{codes}, затем {after}",
        ok,
    )
    assert ok


@pytest.mark.intruder
@pytest.mark.gateway
@pytest.mark.parametrize(
    "path", ["/minio/health/live", "/raw/supply_ok.csv", "/metrics", "/health"]
)
def test_n4_gateway_closed_paths(client, path):
    if not VIA_GATEWAY:
        pytest.skip("только через шлюз")
    r = client.get(path)
    record(
        "Н4",
        f"обход шлюза: GET {path}",
        "404",
        str(r.status_code),
        r.status_code == 404,
    )
    assert r.status_code == 404


@pytest.mark.intruder
@pytest.mark.gateway
@pytest.mark.parametrize("port", [9000, 9001, 8001, 8002])
def test_n5_storage_and_services_not_exposed(port):
    """Прямое подключение к S3 API, консоли MinIO и сервисам с ВМ1 невозможно."""
    if not VIA_GATEWAY:
        pytest.skip("только на стенде")
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect((target_host(), port))
        result, ok = "соединение установлено", False
    except OSError as exc:
        result, ok = type(exc).__name__, True
    finally:
        s.close()
    record(
        "Н5",
        f"прямое подключение к {target_host()}:{port}",
        "нет соединения",
        result,
        ok,
    )
    assert ok


@pytest.mark.intruder
@pytest.mark.gateway
def test_n6_gateway_rate_limit(client, token):
    """Поток запросов с одного адреса: после пакета 20 шлюз отвечает 429."""
    if not VIA_GATEWAY:
        pytest.skip("только через шлюз")
    h = token("contractor", 30)
    codes = [
        client.get("/tickets/nonexistent", headers=h).status_code for _ in range(40)
    ]
    n429 = codes.count(429)
    record(
        "Н6",
        "40 запросов подряд с одного IP",
        "есть ответы 429 (limit_req)",
        f"429 x {n429}",
        n429 > 0,
    )
    assert n429 > 0
