"""Сценарии легального пользователя (ВМ2): проверка гипотезы об устранении УБИ.105.

Отказом в смысле УБИ.105 считается любой ответ, кроме 202 с исходом
loaded / adapted / quarantined: только эти исходы означают, что поставка
принята в обработку и у пользователя есть тикет.
"""

import itertools
import math
import os
import pathlib
import time

import pytest

from .aigtest import PHASE, SERIES, record

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"
ACCEPTED = {"loaded", "adapted", "quarantined"}

# Объём серии: при нуле отказов в N испытаниях вероятность отказа p не превышает
# p_max с доверием 1 - alpha, если (1 - p_max)^N <= alpha, т. е.
# N >= ln(alpha) / ln(1 - p_max) = ln 0,05 / ln 0,95 = 58,4 -> 59; берём 60.
ALPHA, P_MAX = 0.05, 0.05
N_MIN = math.ceil(math.log(ALPHA) / math.log(1 - P_MAX))  # = 59
N_SERIES = int(os.getenv("AIG_SERIES_N", "60"))
SUBJECTS = 2  # 60 = 2 x 30; 30 поставок на субъект < BURST = 31 токена квоты
PAUSE_S = 0.25  # 4 запроса/с < limit_req 5 r/s на IP шлюза: серия не упирается в лимит


def accepted(r) -> bool:
    return r.status_code == 202 and r.json().get("status") in ACCEPTED


DELIMS = {";": "semicolon", "|": "pipe", "\t": "tab"}


def new_dialects():
    """Поставки нового (неизвестного паттерну заранее) формата из supply_ok.csv.

    3 разделителя x 3 кодировки x 2 записи дробей = 18 диалектов CSV;
    исходный диалект (',', UTF-8, точка) исключён — он известен паттерну.
    """
    lines = (SAMPLES / "supply_ok.csv").read_text(encoding="utf-8").splitlines()
    rows = [line.split(",") for line in lines]
    for delim, enc, comma in itertools.product(
        DELIMS, ["utf-8", "utf-8-sig", "cp1251"], [False, True]
    ):
        out = []
        for i, row in enumerate(rows):  # строка 0 — заголовок
            cells = [c.replace(".", ",") if comma and i else c for c in row]
            out.append(delim.join(cells))
        name = f"{DELIMS[delim]}_{enc}_{'comma' if comma else 'dot'}"
        yield name, ("\r\n".join(out) + "\r\n").encode(enc)


@pytest.mark.user
@pytest.mark.parametrize("name", ["supply_ok.csv", "supply.jsonl"])
def test_u1_known_format_loaded(client, token, name):
    r = client.post(
        f"/ingest/{name}",
        content=(SAMPLES / name).read_bytes(),
        headers=token("data-engineer", 1),
    )
    ok = r.status_code == 202 and r.json()["status"] == "loaded"
    record(
        "У1",
        f"известный формат {name}",
        "202 loaded",
        f"{r.status_code} {r.json().get('status')}",
        ok,
    )
    assert ok


@pytest.mark.user
@pytest.mark.parametrize("name", ["supply_2026-07.csv", "supply_cp1251.csv"])
def test_u2_new_dialect_adapted(client, token, name):
    r = client.post(
        f"/ingest/{name}",
        content=(SAMPLES / name).read_bytes(),
        headers=token("data-engineer", 1),
    )
    body = r.json()
    ok = r.status_code == 202 and body["status"] == "adapted"
    record(
        "У2",
        f"новый диалект {name}",
        "202 adapted",
        f"{r.status_code} {body.get('status')}",
        ok,
    )
    assert ok


@pytest.mark.user
def test_u3_unknown_quarantined_with_ticket(client, token):
    h = token("data-engineer", 1)
    r = client.post(
        "/ingest/garbage.bin", content=(SAMPLES / "garbage.bin").read_bytes(), headers=h
    )
    body = r.json()
    t = client.get(f"/tickets/{body['ticket']}", headers=h)
    ok = (
        r.status_code == 202
        and body["status"] == "quarantined"
        and body.get("sla_hours") == 24
        and t.status_code == 200
        and t.json()["status"] == "quarantined"
    )
    actual = (
        f"{r.status_code} {body.get('status')}, SLA {body.get('sla_hours')} ч, "
        f"тикет {t.status_code}"
    )
    record(
        "У3",
        "неразбираемые данные garbage.bin",
        "202 quarantined, тикет, SLA 24 ч",
        actual,
        ok,
    )
    assert ok


@pytest.mark.user
def test_u4_multipart_new_format(client, token):
    h = token("data-engineer", 1)
    data = (SAMPLES / "supply_2026-07.csv").read_bytes()
    init = client.post("/ingest-mpu/init/supply_2026-07.csv", headers=h)
    assert init.status_code == 200
    up = init.json()
    part = client.put(
        "/ingest-mpu/part",
        headers=h,
        content=data,
        params={"key": up["key"], "upload_id": up["upload_id"], "n": 1},
    ).json()
    r = client.post(
        "/ingest-mpu/complete",
        headers=h,
        json={"key": up["key"], "upload_id": up["upload_id"], "parts": [part]},
    )
    ok = accepted(r)
    record(
        "У4",
        "multipart-загрузка нового формата",
        "202, тикет",
        f"{r.status_code} {r.json().get('status')}",
        ok,
    )
    assert ok


@pytest.mark.user
def test_u5_hypothesis_series(client, token):
    """Серия из N поставок новых диалектов: число отказов должно быть равно 0."""
    dialects = list(new_dialects())
    rows, refusals = [], []
    for i in range(N_SERIES):
        name, blob = dialects[i % len(dialects)]
        h = token("data-engineer-series", i % SUBJECTS)
        start = time.perf_counter()
        r = client.post(f"/ingest/s{i:03d}_{name}.csv", content=blob, headers=h)
        elapsed = time.perf_counter() - start
        if accepted(r):
            rows.append((name, r.json()["status"], elapsed))
        else:
            rows.append((name, f"ОТКАЗ {r.status_code}", elapsed))
            refusals.append((i, name, r.status_code, r.text[:120]))
        time.sleep(PAUSE_S)
    SERIES[f"У5 ({PHASE})"] = rows
    p_upper = 1 - ALPHA ** (1 / N_SERIES)  # верхняя граница p при нуле отказов
    record(
        "У5",
        f"серия N={N_SERIES} новых диалектов, фаза {PHASE}",
        "0 отказов",
        (
            f"0 отказов; p_отк <= {p_upper:.3f} при доверии {1 - ALPHA:.2f}"
            if not refusals
            else f"{len(refusals)} отказов: {refusals[:3]}"
        ),
        not refusals,
    )
    assert not refusals, refusals
