"""Длительная имитация сценария С2 для фазы «под атакой» (глава 4).

Нарушитель с ВМ1 в течение DURATION секунд непрерывно:
  * открывает multipart-сессии с «мусорными» частями и не завершает их;
  * после блокировки субъекта переходит к новому субъекту (новый JWT);
  * каждый пятый запрос — загрузка случайных двоичных данных (бинарный «мусор»).
Одновременно на ВМ2 выполняется серия легального пользователя
(AIG_PHASE=attack pytest -m user), которая не должна получить ни одного отказа.

    python scripts/attack_flood.py --url https://aig.local --secret <JWT> --insecure
"""

import argparse
import os
import time
from collections import Counter

import httpx

from gen_jwt import make_token

# 300 с = 20 опросов Prometheus с интервалом 15 с и окно [5m] правил оповещения
DURATION_S = 300


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="https://aig.local")
    ap.add_argument("--secret", required=True)
    ap.add_argument("--duration", type=int, default=DURATION_S)
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    codes, subject, sent = Counter(), 0, 0
    started = last_report = time.monotonic()
    with httpx.Client(base_url=a.url, timeout=30, verify=not a.insecure) as c:
        h = {
            "Authorization": "Bearer "
            + make_token(f"contractor-flood-{subject}", "uploader", a.secret)
        }
        while time.monotonic() - started < a.duration:
            sent += 1
            if sent % 5 == 0:
                r = c.post(
                    f"/ingest/junk_{sent}.bin", content=os.urandom(4096), headers=h
                )
            else:
                r = c.post(f"/ingest-mpu/init/junk_{sent}.csv", headers=h)
                if r.status_code == 200:
                    up = r.json()
                    c.put(
                        "/ingest-mpu/part",
                        headers=h,
                        content=os.urandom(1024),
                        params={"key": up["key"], "upload_id": up["upload_id"], "n": 1},
                    )
            codes[r.status_code] += 1
            if r.status_code == 403:  # субъект заблокирован — «новый» нарушитель
                subject += 1
                h = {
                    "Authorization": "Bearer "
                    + make_token(f"contractor-flood-{subject}", "uploader", a.secret)
                }
            if time.monotonic() - last_report >= 30:
                last_report = time.monotonic()
                print(
                    f"{int(last_report - started):4d} с: запросов {sent}, "
                    f"коды {dict(codes)}, "
                    f"заблокировано субъектов {subject}"
                )
    print(
        f"итог: запросов {sent}, коды {dict(codes)}, заблокировано субъектов {subject}"
    )


if __name__ == "__main__":
    main()
