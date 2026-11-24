"""Демонстрация работы паттерна AIG: загрузка тестовых файлов и вывод ответов.

python scripts/demo.py --url http://127.0.0.1:8001 --secret <JWT_SECRET>   # локально
python scripts/demo.py --url https://aig.local --secret <JWT_SECRET> --insecure  # кластер
"""

import argparse
import json
import pathlib

import httpx

from gen_jwt import make_token

SAMPLES = pathlib.Path(__file__).resolve().parents[1] / "samples"
CASES = [
    ("supply_ok.csv", "известный формат CSV (',', UTF-8)", "loaded"),
    ("supply.jsonl", "известный формат JSON Lines", "loaded"),
    (
        "supply_2026-07.csv",
        "новый диалект: '|', UTF-8 BOM, десятичная запятая",
        "adapted",
    ),
    ("supply_cp1251.csv", "новый диалект: ';', кодировка cp1251", "adapted"),
    ("garbage.bin", "двоичный «мусор» неизвестного формата", "quarantined"),
    ("evil.csv", "активное содержимое (<?php)", "rejected"),
]


def upload_multipart(
    c: httpx.Client, token: str, path: pathlib.Path, part_size: int
) -> dict:
    h = {"Authorization": f"Bearer {token}"}
    init = c.post(f"/ingest-mpu/init/{path.name}", headers=h).json()
    data, parts = path.read_bytes(), []
    for n, off in enumerate(range(0, len(data), part_size), start=1):
        r = c.put(
            "/ingest-mpu/part",
            headers=h,
            content=data[off : off + part_size],
            params={"key": init["key"], "upload_id": init["upload_id"], "n": n},
        ).json()
        parts.append(r)
    return c.post(
        "/ingest-mpu/complete",
        headers=h,
        json={"key": init["key"], "upload_id": init["upload_id"], "parts": parts},
    ).json()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8001")
    ap.add_argument("--secret", required=True)
    ap.add_argument("--sub", default="data-engineer-01")
    ap.add_argument(
        "--insecure", action="store_true", help="самоподписанный TLS-сертификат"
    )
    a = ap.parse_args()
    token = make_token(a.sub, "uploader", a.secret)
    with httpx.Client(base_url=a.url, timeout=120, verify=not a.insecure) as c:
        for name, title, expected in CASES:
            r = c.post(
                f"/ingest/{name}",
                content=(SAMPLES / name).read_bytes(),
                headers={"Authorization": f"Bearer {token}"},
            )
            status = r.json().get("status")
            mark = "OK " if status == expected else "!! "
            print(
                f"{mark}{name:22} {title}\n    HTTP {r.status_code}: "
                f"{json.dumps(r.json(), ensure_ascii=False)}"
            )
        r = c.post(
            "/ingest/supply_ok.csv",
            content=b"x",
            headers={"Authorization": "Bearer bad"},
        )
        print(f"OK  без валидного JWT -> HTTP {r.status_code}")
        res = upload_multipart(
            c, token, SAMPLES / "supply_2026-07.csv", part_size=5 * 1024 * 1024
        )
        print(
            f"OK  multipart-загрузка нового формата -> {json.dumps(res, ensure_ascii=False)}"
        )


if __name__ == "__main__":
    main()
