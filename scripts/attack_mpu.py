"""Имитация сценария угрозы С2: массовое открытие multipart-сессий без завершения.

Нарушитель с низким потенциалом пользуется штатным API: открывает сессии
CreateMultipartUpload, грузит в них «мусорную» часть и не завершает их.
Ожидаемое поведение паттерна: после MPU_MAX_OPEN открытых сессий — 429,
после STRIKES_TO_BLOCK штрафов — 403 (субъект заблокирован), висячие
сессии прерываются security-service по таймеру (AbortMultipartUpload).

    python scripts/attack_mpu.py --url http://127.0.0.1:8001 --secret <JWT_SECRET> --n 10
"""

import argparse
import os
from collections import Counter

import httpx

from gen_jwt import make_token


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8001")
    ap.add_argument("--secret", required=True)
    ap.add_argument("--sub", default="contractor-07")
    ap.add_argument("--n", type=int, default=10)
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    h = {"Authorization": f"Bearer {make_token(a.sub, 'uploader', a.secret)}"}
    codes = Counter()
    with httpx.Client(base_url=a.url, timeout=30, verify=not a.insecure) as c:
        for i in range(1, a.n + 1):
            r = c.post(f"/ingest-mpu/init/junk_{i}.csv", headers=h)
            codes[r.status_code] += 1
            if r.status_code == 200:
                up = r.json()
                c.put(
                    "/ingest-mpu/part",
                    headers=h,
                    content=os.urandom(1024),
                    params={"key": up["key"], "upload_id": up["upload_id"], "n": 1},
                )
            print(f"сессия {i:3}: HTTP {r.status_code} {r.text[:90]}")
    print("итог по кодам ответа:", dict(codes))


if __name__ == "__main__":
    main()
