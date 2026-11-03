"""Сквозной тест паттерна: все шесть сервисов запущены как отдельные процессы."""

import httpx
import pytest

import run_local
from conftest import ROOT
from gen_jwt import make_token

SAMPLES = ROOT / "samples"


@pytest.fixture(scope="module")
def stack():
    procs = run_local.start()
    yield httpx.Client(base_url="http://127.0.0.1:8001", timeout=60)
    run_local.stop(procs)


def auth(sub: str = "data-engineer-01") -> dict:
    return {
        "Authorization": "Bearer " + make_token(sub, "uploader", run_local.JWT_SECRET)
    }


@pytest.mark.parametrize(
    "name, status",
    [
        ("supply_ok.csv", "loaded"),
        ("supply_2026-07.csv", "adapted"),
        ("supply_cp1251.csv", "adapted"),
        ("garbage.bin", "quarantined"),
    ],
)
def test_contract_202(stack, name, status):
    r = stack.post(
        f"/ingest/{name}", content=(SAMPLES / name).read_bytes(), headers=auth()
    )
    assert r.status_code == 202 and r.json()["status"] == status
    t = stack.get(f"/tickets/{r.json()['ticket']}", headers=auth())
    assert t.json()["status"] == status
    assert (
        stack.get(f"/tickets/{r.json()['ticket']}", headers=auth("other")).status_code
        == 404
    )


def test_security_rejections(stack):
    assert stack.post("/ingest/a.csv", content=b"a,b\n1,2\n").status_code == 401
    r = stack.post(
        "/ingest/evil.csv", content=(SAMPLES / "evil.csv").read_bytes(), headers=auth()
    )
    assert r.status_code == 415


def test_scenario_c2_multipart_flood(stack):
    codes = [
        stack.post(
            f"/ingest-mpu/init/junk_{i}.csv", headers=auth("contractor-07")
        ).status_code
        for i in range(8)
    ]
    assert codes[:3] == [200, 200, 200]  # MPU_MAX_OPEN = 3
    assert 429 in codes and codes[-1] == 403  # лимит сессий, затем блокировка
