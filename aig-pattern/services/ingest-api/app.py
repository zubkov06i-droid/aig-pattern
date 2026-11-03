"""ingest-api — оркестратор загрузки паттерна AIG (порт 8001).

Контракт: любой запрос, прошедший контроль безопасности, получает ответ
202 Accepted с тикетом и одним из статусов:
  loaded      — формат известен, объект записан в бакет raw;
  adapted     — формат был неизвестен, выполнена автоадаптация в canonical;
  quarantined — адаптация невозможна, объект в карантине, назначен SLA.
Отказ возможен только по решению security-service (401/403/413/415/429)
или при недоступности самого карантина (503, повторить позже).
Сервис не хранит состояния и масштабируется HPA.
"""

import asyncio
import os
import uuid

import httpx
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Header, Request
from fastapi.responses import JSONResponse
from prometheus_client import Counter
from pydantic import BaseModel

from aig_common import create_app, env_int, get_logger, log_event, s3_client

SERVICE = "ingest-api"
app = create_app(SERVICE)
log = get_logger(SERVICE)

SECURITY = os.getenv("SECURITY_URL", "http://security-service:8002")
DETECTOR = os.getenv("DETECTOR_URL", "http://format-detector:8003")
ADAPTER = os.getenv("ADAPTER_URL", "http://adapter-factory:8005")
QUARANTINE = os.getenv("QUARANTINE_URL", "http://quarantine-notifier:8006")
RAW_BUCKET = os.getenv("RAW_BUCKET", "raw")
HEAD_BYTES = env_int("HEAD_BYTES", 65536)
SLA_HOURS = env_int("SLA_HOURS", 24)
MAX_SIZE = env_int("MAX_OBJECT_BYTES", 64 * 1024 * 1024)
TIMEOUT = httpx.Timeout(float(os.getenv("CALL_TIMEOUT_S", "60")))

OUTCOMES = Counter("aig_ingest_outcomes_total", "Исходы обработки загрузок", ["status"])
S3 = s3_client()


class CompleteRequest(BaseModel):
    key: str
    upload_id: str
    parts: list[dict]  # [{"n": 1, "etag": "..."}, ...]


def answer(code: int, ticket: str, status: str, **extra) -> JSONResponse:
    OUTCOMES.labels(status).inc()
    log_event(log, "ingest outcome", ticket=ticket, status=status, code=code, **extra)
    return JSONResponse(
        status_code=code, content={"ticket": ticket, "status": status, **extra}
    )


def reason_of(resp: httpx.Response) -> str:
    try:
        return str(resp.json().get("detail", resp.text))
    except ValueError:
        return resp.text


async def set_status(
    c: httpx.AsyncClient, ticket: str, status: str, reason: str = ""
) -> None:
    await c.post(
        f"{QUARANTINE}/tickets/{ticket}/status",
        json={"status": status, "reason": reason},
    )


async def process(
    ticket: str,
    filename: str,
    blob: bytes,
    authorization: str,
    raw_key: str | None = None,
) -> JSONResponse:
    """Ядро оркестрации: проверка -> карантин -> идентификация -> адаптация."""
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        sec = await c.post(
            f"{SECURITY}/check", content=blob, headers={"Authorization": authorization}
        )
        if sec.status_code != 200:  # решение охраны
            return answer(sec.status_code, ticket, "rejected", reason=reason_of(sec))
        sub = sec.json()["sub"]
        try:  # копия до разбора
            q = await c.post(
                f"{QUARANTINE}/put",
                content=blob,
                params={"ticket": ticket, "sub": sub, "filename": filename},
            )
            q.raise_for_status()
        except httpx.HTTPError as exc:
            return answer(
                503, ticket, "retry_later", reason=f"quarantine unavailable: {exc!r}"
            )
        try:
            det = await c.post(
                f"{DETECTOR}/detect",
                content=blob[:HEAD_BYTES],
                headers={"X-Truncated": "1" if len(blob) > HEAD_BYTES else "0"},
            )
            det.raise_for_status()
            d = det.json()
            if d["format"] != "UNKNOWN":  # известный формат
                key = raw_key or f"{sub}/{ticket}/{filename}"
                await asyncio.to_thread(
                    S3.put_object,
                    Bucket=RAW_BUCKET,
                    Key=key,
                    Body=blob,
                    Metadata={"ticket": ticket, "format": d["format"]},
                )
                await set_status(c, ticket, "loaded")
                return answer(
                    202, ticket, "loaded", format=d["format"], key=f"{RAW_BUCKET}/{key}"
                )
            ad = await c.post(
                f"{ADAPTER}/adapt", json={"ticket": ticket, "features": d["features"]}
            )
            if ad.status_code == 200:  # автоадаптация удалась
                await set_status(c, ticket, "adapted")
                return answer(202, ticket, "adapted", **ad.json())
            reason = reason_of(ad)
        except (httpx.HTTPError, BotoCoreError, ClientError) as exc:
            # отказ компонента паттерна не превращается в отказ пользователю
            reason = f"internal error: {type(exc).__name__}"
        await set_status(c, ticket, "quarantined", reason)
        return answer(202, ticket, "quarantined", reason=reason, sla_hours=SLA_HOURS)


async def authenticate(
    c: httpx.AsyncClient, authorization: str
) -> tuple[str | None, httpx.Response]:
    r = await c.post(f"{SECURITY}/auth", headers={"Authorization": authorization})
    return (r.json()["sub"] if r.status_code == 200 else None), r


# ---------------------------------------------------------------- эндпоинты
@app.post("/ingest/{filename}")
async def ingest(
    filename: str, request: Request, authorization: str = Header(default="")
):
    """Загрузка объекта одним запросом (аналог S3 PutObject)."""
    return await process(
        str(uuid.uuid4()), filename, await request.body(), authorization
    )


@app.post("/ingest-mpu/init/{filename}")
async def mpu_init(filename: str, authorization: str = Header(default="")):
    """Начало multipart-загрузки (CreateMultipartUpload) с разрешения охраны."""
    ticket = str(uuid.uuid4())
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        r = await c.post(
            f"{SECURITY}/mpu/check", headers={"Authorization": authorization}
        )
    if r.status_code != 200:
        return answer(r.status_code, ticket, "rejected", reason=reason_of(r))
    key = f"{r.json()['sub']}/{ticket}/{filename}"
    up = await asyncio.to_thread(S3.create_multipart_upload, Bucket=RAW_BUCKET, Key=key)
    return {"ticket": ticket, "key": key, "upload_id": up["UploadId"]}


@app.put("/ingest-mpu/part")
async def mpu_part(
    key: str,
    upload_id: str,
    n: int,
    request: Request,
    authorization: str = Header(default=""),
):
    """Загрузка части (UploadPart); ключ обязан принадлежать владельцу токена."""
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        sub, r = await authenticate(c, authorization)
    if sub is None:
        return JSONResponse(status_code=r.status_code, content={"detail": reason_of(r)})
    if not key.startswith(f"{sub}/"):
        return JSONResponse(status_code=403, content={"detail": "foreign upload"})
    resp = await asyncio.to_thread(
        S3.upload_part,
        Bucket=RAW_BUCKET,
        Key=key,
        UploadId=upload_id,
        PartNumber=n,
        Body=await request.body(),
    )
    return {"n": n, "etag": resp["ETag"]}


@app.post("/ingest-mpu/complete")
async def mpu_complete(req: CompleteRequest, authorization: str = Header(default="")):
    """Завершение (CompleteMultipartUpload) и обработка объекта по общему пути."""
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        sub, r = await authenticate(c, authorization)
    if sub is None:
        return JSONResponse(status_code=r.status_code, content={"detail": reason_of(r)})
    if not req.key.startswith(f"{sub}/"):
        return JSONResponse(status_code=403, content={"detail": "foreign upload"})
    parts = [{"PartNumber": p["n"], "ETag": p["etag"]} for p in req.parts]
    await asyncio.to_thread(
        S3.complete_multipart_upload,
        Bucket=RAW_BUCKET,
        Key=req.key,
        UploadId=req.upload_id,
        MultipartUpload={"Parts": parts},
    )
    _, ticket, filename = req.key.split("/", 2)
    obj = await asyncio.to_thread(S3.get_object, Bucket=RAW_BUCKET, Key=req.key)
    if obj["ContentLength"] > MAX_SIZE:  # не читаем в память
        await asyncio.to_thread(S3.delete_object, Bucket=RAW_BUCKET, Key=req.key)
        return answer(413, ticket, "rejected", reason="object too large")
    blob = obj["Body"].read()
    result = await process(ticket, filename, blob, authorization, raw_key=req.key)
    if result.status_code >= 400:  # отвергнутое удаляется из raw
        await asyncio.to_thread(S3.delete_object, Bucket=RAW_BUCKET, Key=req.key)
    return result


@app.get("/tickets/{ticket}")
async def ticket_status(ticket: str, authorization: str = Header(default="")):
    """Статус тикета — только владельцу (или администратору)."""
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        sub, r = await authenticate(c, authorization)
        if sub is None:
            return JSONResponse(
                status_code=r.status_code, content={"detail": reason_of(r)}
            )
        t = await c.get(f"{QUARANTINE}/tickets/{ticket}")
    if t.status_code != 200 or (
        t.json()["sub"] != sub and r.json().get("role") != "admin"
    ):
        return JSONResponse(status_code=404, content={"detail": "ticket not found"})
    return t.json()
