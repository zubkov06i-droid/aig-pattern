"""Выпуск тестового JWT для обращения к паттерну AIG.

    python scripts/gen_jwt.py --sub data-engineer-01 --role uploader --secret <JWT_SECRET>
Секрет берётся из аргумента или из переменной окружения JWT_SECRET.
"""

import argparse
import os
import time

import jwt


def make_token(sub: str, role: str, secret: str, ttl: int = 3600) -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": sub, "role": role, "iat": now, "exp": now + ttl}, secret, "HS256"
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--sub", required=True)
    ap.add_argument("--role", default="uploader", choices=["uploader", "admin"])
    ap.add_argument("--ttl", type=int, default=3600)
    ap.add_argument("--secret", default=os.getenv("JWT_SECRET", ""))
    a = ap.parse_args()
    if not a.secret:
        raise SystemExit("укажите --secret или переменную JWT_SECRET")
    print(make_token(a.sub, a.role, a.secret, a.ttl))
