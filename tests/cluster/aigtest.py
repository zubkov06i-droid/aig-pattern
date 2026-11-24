"""Общие параметры и функции кластерных тестов AIG (для тестов и conftest)."""

import os
import socket
import uuid
from urllib.parse import urlparse

URL = os.getenv("AIG_URL", "https://aig.local")
SECRET = os.getenv("AIG_JWT_SECRET", "")
PHASE = os.getenv("AIG_PHASE", "baseline")
VIA_GATEWAY = os.getenv("AIG_GATEWAY", "1") == "1"
RUN = uuid.uuid4().hex[:6]  # уникальные субъекты: квоты прошлых прогонов не мешают

RESULTS: list[tuple[str, str, str, str, bool]] = []  # строки итоговой таблицы
SERIES: dict[str, list] = {}  # сырые данные серий загрузок для отчёта


def record(test_id: str, scenario: str, expected: str, actual: str, ok: bool) -> None:
    RESULTS.append((test_id, scenario, expected, actual, ok))


def target_host() -> str:
    """IP-адрес ВМ3, на который указывает имя шлюза."""
    return socket.gethostbyname(urlparse(URL).hostname)


def percentile(values: list[float], q: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, int(round(q * (len(s) - 1))))]
