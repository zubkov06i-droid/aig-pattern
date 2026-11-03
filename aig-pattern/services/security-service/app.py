"""security-service — микросервис безопасности паттерна AIG (порт 8002).

Функции:
  * аутентификация по JWT (HS256) и проверка блокировки субъекта;
  * квотирование запросов по алгоритму «токен-бакет» на каждого пользователя;
  * санитизация содержимого (размер, исполняемые сигнатуры, zip-бомбы);
  * контроль multipart-сессий S3 API: лимит одновременно открытых сессий и
    принудительный AbortMultipartUpload «висячих» сессий (сценарий С2);
  * «штрафы» (strikes) и временная блокировка нарушителя, аудит в SQLite.
"""

import asyncio
import io
import os
import sqlite3
import threading
import time
import zipfile
from datetime import datetime, timezone

import jwt
from fastapi import Header, HTTPException, Request
from prometheus_client import Counter

from aig_common import create_app, env_float, env_int, get_logger, log_event, s3_client

SERVICE = "security-service"
app = create_app(SERVICE)
log = get_logger(SERVICE)

JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALG = "HS256"
RATE_PER_MIN = env_float("QUOTA_RATE_PER_MIN", 10)  # пополнение бакета, токенов/мин
BURST = env_float("QUOTA_BURST", 31)  # ёмкость бакета (пакет поставки)
MAX_SIZE = env_int("MAX_OBJECT_BYTES", 64 * 1024 * 1024)
MAX_ZIP_RATIO = env_float("MAX_ZIP_RATIO", 100)  # порог коэффициента сжатия
MPU_MAX_AGE = env_int("MPU_MAX_AGE_S", 600)  # время жизни multipart-сессии
MPU_MAX_OPEN = env_int("MPU_MAX_OPEN", 3)  # открытых сессий на пользователя
STRIKES_TO_BLOCK = env_int("STRIKES_TO_BLOCK", 3)
BLOCK_TTL = env_int("BLOCK_TTL_S", 3600)
REAP_PERIOD = env_int("REAP_PERIOD_S", 60)
RAW_BUCKET = os.getenv("RAW_BUCKET", "raw")
DB_PATH = os.getenv("DB_PATH", "/data/security.db")

ARCHIVE_EXT = (".zip", ".gz", ".tgz", ".7z", ".rar", ".bz2", ".xz")
REJECTED = Counter(
    "aig_security_rejections_total", "Отказы микросервиса безопасности", ["reason"]
)
MPU_ABORTED = Counter(
    "aig_mpu_aborted_total", "Принудительно прерванные multipart-сессии"
)
BLOCKS = Counter("aig_blocked_subjects_total", "Блокировки субъектов")

S3 = s3_client()
BUCKETS: dict[str, tuple[float, float]] = (
    {}
)  # sub -> (время последнего запроса, токены)
BUCKET_LOCK = threading.Lock()
DB_LOCK = threading.Lock()
DB = sqlite3.connect(DB_PATH, check_same_thread=False)
DB.executescript("""
    CREATE TABLE IF NOT EXISTS strikes(sub TEXT PRIMARY KEY, n INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS blocked(
        sub TEXT PRIMARY KEY, until REAL NOT NULL, reason TEXT);
    CREATE TABLE IF NOT EXISTS audit(
        ts REAL, sub TEXT, action TEXT, result TEXT, detail TEXT);
    """)


# ---------------------------------------------------------------- логика паттерна
def take_token(sub: str, now: float | None = None) -> bool:
    """Токен-бакет: True, если у пользователя есть токен на запрос."""
    now = time.monotonic() if now is None else now
    with BUCKET_LOCK:
        last, tokens = BUCKETS.get(sub, (now, BURST))
        tokens = min(BURST, tokens + (now - last) * RATE_PER_MIN / 60.0)
        if tokens < 1.0:
            BUCKETS[sub] = (now, tokens)
            return False
        BUCKETS[sub] = (now, tokens - 1.0)
        return True


def sanitize(blob: bytes) -> tuple[int, str] | None:
    """Санитизация содержимого. Возвращает (HTTP-код, причина) или None."""
    if len(blob) == 0:
        return 400, "empty object"
    if len(blob) > MAX_SIZE:
        return 413, "object too large"
    if blob.startswith(b"\x7fELF") or blob.startswith(b"MZ"):
        return 415, "executable payload"
    head = blob[:4096].lower()
    if b"<script" in head or b"<?php" in head:
        return 415, "active content"
    if blob.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                infos = zf.infolist()
                packed = sum(i.compress_size for i in infos) or 1
                unpacked = sum(i.file_size for i in infos)
                if unpacked / packed > MAX_ZIP_RATIO:
                    return 415, "zip bomb (compression ratio)"
                if any(i.filename.lower().endswith(ARCHIVE_EXT) for i in infos):
                    return 415, "nested archive"
        except zipfile.BadZipFile:
            return 415, "corrupted archive"
    return None


def strike(sub: str, reason: str) -> bool:
    """Начисляет штраф; при STRIKES_TO_BLOCK штрафах блокирует субъекта."""
    with DB_LOCK:
        row = DB.execute("SELECT n FROM strikes WHERE sub=?", (sub,)).fetchone()
        n = (row[0] if row else 0) + 1
        blocked = n >= STRIKES_TO_BLOCK
        if blocked:
            DB.execute(
                "INSERT OR REPLACE INTO blocked VALUES(?,?,?)",
                (sub, time.time() + BLOCK_TTL, reason),
            )
            n = 0
        DB.execute("INSERT OR REPLACE INTO strikes VALUES(?,?)", (sub, n))
        DB.commit()
    if blocked:
        BLOCKS.inc()
        log_event(log, "subject blocked", sub=sub, reason=reason, ttl_s=BLOCK_TTL)
    return blocked


def is_blocked(sub: str) -> bool:
    with DB_LOCK:
        row = DB.execute("SELECT until FROM blocked WHERE sub=?", (sub,)).fetchone()
    return bool(row and row[0] > time.time())


def reap_dangling_multiparts(now: datetime | None = None) -> list[dict]:
    """Прерывает multipart-сессии старше MPU_MAX_AGE и штрафует их владельцев."""
    now = now or datetime.now(timezone.utc)
    aborted = []
    for page in S3.get_paginator("list_multipart_uploads").paginate(Bucket=RAW_BUCKET):
        for mpu in page.get("Uploads", []):
            age = (now - mpu["Initiated"]).total_seconds()
            if age <= MPU_MAX_AGE:
                continue
            S3.abort_multipart_upload(
                Bucket=RAW_BUCKET, Key=mpu["Key"], UploadId=mpu["UploadId"]
            )
            sub = mpu["Key"].split("/", 1)[0]  # ключ имеет вид <sub>/<ticket>/<файл>
            MPU_ABORTED.inc()
            audit(sub, "mpu_abort", "aborted", mpu["Key"])
            strike(sub, "dangling multipart upload")
            aborted.append({"key": mpu["Key"], "sub": sub, "age_s": int(age)})
    return aborted


def open_multiparts(sub: str) -> int:
    resp = S3.list_multipart_uploads(Bucket=RAW_BUCKET, Prefix=f"{sub}/")
    return len(resp.get("Uploads", []))


# ---------------------------------------------------------------- служебные функции
def audit(sub: str, action: str, result: str, detail: str = "") -> None:
    with DB_LOCK:
        DB.execute(
            "INSERT INTO audit VALUES(?,?,?,?,?)",
            (time.time(), sub, action, result, detail),
        )
        DB.commit()
    log_event(log, "audit", sub=sub, action=action, result=result, detail=detail)


def authenticate(authorization: str) -> dict:
    """Проверяет JWT и блокировку; возвращает claims или поднимает 401/403."""
    if not authorization.startswith("Bearer "):
        REJECTED.labels("no_token").inc()
        raise HTTPException(401, "bearer token required")
    try:
        claims = jwt.decode(
            authorization[7:],
            JWT_SECRET,
            algorithms=[JWT_ALG],
            options={"require": ["sub", "exp"]},
        )
    except jwt.PyJWTError as exc:
        REJECTED.labels("bad_token").inc()
        raise HTTPException(401, f"invalid token: {type(exc).__name__}")
    if is_blocked(claims["sub"]):
        REJECTED.labels("blocked").inc()
        raise HTTPException(403, "subject is blocked")
    return claims


def deny(sub: str, action: str, code: int, reason: str, label: str):
    REJECTED.labels(label).inc()
    audit(sub, action, f"deny {code}", reason)
    raise HTTPException(code, reason)


# ---------------------------------------------------------------- эндпоинты
@app.post("/auth")
def auth(authorization: str = Header(default="")):
    """Только аутентификация (без квоты) — для частей multipart и тикетов."""
    claims = authenticate(authorization)
    return {"sub": claims["sub"], "role": claims.get("role", "uploader")}


@app.post("/check")
async def check(request: Request, authorization: str = Header(default="")):
    """Полная проверка загрузки: JWT -> блокировка -> квота -> санитизация."""
    claims = authenticate(authorization)
    sub = claims["sub"]
    if not take_token(sub):
        deny(sub, "ingest", 429, "quota exceeded", "quota")
    verdict = sanitize(await request.body())
    if verdict:
        strike(sub, verdict[1])
        deny(sub, "ingest", verdict[0], verdict[1], "sanitize")
    audit(sub, "ingest", "allow")
    return {"sub": sub, "decision": "allow"}


@app.post("/mpu/check")
def mpu_check(authorization: str = Header(default="")):
    """Разрешение на CreateMultipartUpload: квота и лимит открытых сессий."""
    sub = authenticate(authorization)["sub"]
    if not take_token(sub):
        deny(sub, "mpu_init", 429, "quota exceeded", "quota")
    if open_multiparts(sub) >= MPU_MAX_OPEN:
        strike(sub, "too many open multipart uploads")
        deny(sub, "mpu_init", 429, "too many open multipart uploads", "mpu_limit")
    audit(sub, "mpu_init", "allow")
    return {"sub": sub, "decision": "allow"}


@app.post("/mpu/reap")
def mpu_reap(authorization: str = Header(default="")):
    """Ручной запуск очистки (роль admin); штатно выполняется по таймеру."""
    if authenticate(authorization).get("role") != "admin":
        raise HTTPException(403, "admin role required")
    return {"aborted": reap_dangling_multiparts()}


@app.get("/blocked")
def blocked(authorization: str = Header(default="")):
    if authenticate(authorization).get("role") != "admin":
        raise HTTPException(403, "admin role required")
    with DB_LOCK:
        rows = DB.execute(
            "SELECT sub, until, reason FROM blocked WHERE until > ?", (time.time(),)
        ).fetchall()
    return [{"sub": s, "until": u, "reason": r} for s, u, r in rows]


async def reaper_loop():
    while True:
        await asyncio.sleep(REAP_PERIOD)
        try:
            aborted = await asyncio.to_thread(reap_dangling_multiparts)
            if aborted:
                log_event(log, "reaper run", aborted=len(aborted))
        except Exception as exc:  # сбой очистки не должен ронять сервис
            log_event(log, "reaper error", error=repr(exc))


@app.on_event("startup")
async def start_reaper():
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET is not set")
    asyncio.create_task(reaper_loop())
