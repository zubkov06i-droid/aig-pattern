"""Сценарные тесты паттерна AIG на кластере Kubernetes (глава 4).

Тесты запускаются с клиентских ВМ стенда и обращаются к паттерну так же, как
настоящие пользователи, — только через шлюз https://aig.local:
    ВМ2 (легальный пользователь):  pytest -v -m user tests/cluster
    ВМ1 (нарушитель):              pytest -v -m intruder tests/cluster
Параметры задаются переменными окружения:
    AIG_URL         адрес шлюза (по умолчанию https://aig.local);
    AIG_JWT_SECRET  ключ подписи тестовых JWT (тестовый стенд играет роль IdP);
    AIG_PHASE       метка серии в отчёте: baseline (без атаки) или attack;
    AIG_GATEWAY     0 — обращение напрямую к ingest-api (локальная отладка).
Без AIG_JWT_SECRET тесты пропускаются, поэтому `pytest tests` в CI их не запускает.
"""

import time

import httpx
import pytest

from .aigtest import PHASE, RESULTS, RUN, SECRET, SERIES, URL, percentile
from gen_jwt import make_token


def pytest_collection_modifyitems(config, items):
    if SECRET:
        return
    skip = pytest.mark.skip(
        reason="AIG_JWT_SECRET не задан: кластерные тесты пропущены"
    )
    for item in items:
        if "tests/cluster" in str(item.fspath).replace("\\", "/"):
            item.add_marker(skip)


def pytest_configure(config):
    config.addinivalue_line("markers", "user: сценарии легального пользователя (ВМ2)")
    config.addinivalue_line("markers", "intruder: сценарии нарушителя (ВМ1)")
    config.addinivalue_line("markers", "gateway: проверки, требующие шлюза и Ingress")


@pytest.fixture(scope="session")
def client():
    with httpx.Client(base_url=URL, timeout=120, verify=False) as c:
        yield c


@pytest.fixture(scope="session")
def token():
    """Фабрика тестовых JWT: token('data-engineer') -> заголовки запроса."""

    def make(role: str, n: int = 0, **kw) -> dict:
        sub = f"{role}-{RUN}-{n}"
        return {"Authorization": "Bearer " + make_token(sub, "uploader", SECRET, **kw)}

    return make


def pytest_terminal_summary(terminalreporter):
    if not RESULTS:
        return
    lines = [
        f"Отчёт AIG: фаза {PHASE}, прогон {RUN}, {time.strftime('%Y-%m-%d %H:%M')}"
    ]
    for test_id, scenario, expected, actual, ok in RESULTS:
        mark = "ДА " if ok else "НЕТ"
        lines.append(
            f"{test_id:5} {mark} {scenario} | ожидалось: {expected} | факт: {actual}"
        )
    for name, rows in SERIES.items():
        lat = [r[2] for r in rows]
        statuses: dict[str, int] = {}
        for _, status, _ in rows:
            statuses[status] = statuses.get(status, 0) + 1
        lines.append(
            f"серия {name}: N={len(rows)}, исходы {statuses}, "
            f"латентность p50={percentile(lat, 0.5):.3f} с, "
            f"p95={percentile(lat, 0.95):.3f} с, "
            f"max={max(lat):.3f} с"
        )
    terminalreporter.write_sep("=", "итоговая таблица сценариев главы 4")
    for line in lines:
        terminalreporter.write_line(line)
    path = f"aig-report-{PHASE}-{RUN}.txt"
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    terminalreporter.write_line(f"отчёт сохранён в {path}")
