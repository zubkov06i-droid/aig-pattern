"""quarantine-notifier — карантин и реестр тикетов (порт 8006).

Функции:
  * копия каждого поступившего объекта в бакет quarantine ДО начала разбора
    (запись в бакет разрешена только учётной записи этого сервиса);
  * реестр тикетов в SQLite: статус, причина, срок рассмотрения (SLA);
  * уведомление пользователя и администратора при помещении в карантин;
  * учёт открытых и просроченных тикетов (метрики для Grafana).
"""

import asyncio
import os
import sqlite3
import threading
import time

import httpx
from fastapi import HTTPException, Request
from prometheus_client import Counter, Gauge
from pydantic import BaseModel

from aig_common import create_app, env_int, get_logger, log_event, s3_client

SERVICE = "quarantine-notifier"
app = create_app(SERVICE)
log = get_logger(SERVICE)

QUARANTINE_BUCKET = os.getenv("QUARANTINE_BUCKET", "quarantine")
SLA_HOURS = env_int("SLA_HOURS", 24)
WEBHOOK_URL = os.getenv("NOTIFY_WEBHOOK_URL", "")  # необязательно: Telegram/SIEM-шлюз
STATUSES = {"received", "loaded", "adapted", "quarantined", "resolved"}

QUARANTINED = Counter("aig_quarantined_total", "Объекты, оставленные в карантине")
OPEN_TICKETS = Gauge("aig_quarantine_open", "Открытые карантинные тикеты")
OVERDUE = Gauge("aig_quarantine_sla_overdue", "Тикеты с нарушенным SLA")

S3 = s3_client()
LOCK = threading.Lock()
DB = sqlite3.connect(
    os.getenv("DB_PATH", "/data/quarantine.db"), check_same_thread=False
)
DB.execute("""CREATE TABLE IF NOT EXISTS tickets(
    ticket TEXT PRIMARY KEY, sub TEXT, filename TEXT, size INTEGER, status TEXT,
    reason TEXT, created REAL, sla_deadline REAL, updated REAL)""")


class StatusUpdate(BaseModel):
    status: str
    reason: str = ""


def notify(ticket: str, sub: str, reason: str, deadline: float) -> None:
    """Уведомление о карантине: событие в журнал (-> Loki/SIEM) и webhook."""
    event = {
        "ticket": ticket,
        "sub": sub,
        "reason": reason,
        "sla_deadline": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(deadline)),
    }
    log_event(log, "quarantine notification", **event)
    if WEBHOOK_URL:
        try:
            httpx.post(WEBHOOK_URL, json=event, timeout=5)
        except httpx.HTTPError as exc:  # уведомление не должно ломать приём
            log_event(log, "webhook failed", error=repr(exc))


@app.post("/put")
async def put(request: Request, ticket: str, sub: str, filename: str):
    """Копия объекта в карантин и регистрация тикета (до разбора формата)."""
    blob = await request.body()
    await asyncio.to_thread(
        S3.put_object,
        Bucket=QUARANTINE_BUCKET,
        Key=ticket,
        Body=blob,
        Metadata={"sub": sub, "filename": filename},
    )
    now = time.time()
    with LOCK:
        DB.execute(
            "INSERT OR REPLACE INTO tickets VALUES(?,?,?,?,?,?,?,?,?)",
            (ticket, sub, filename, len(blob), "received", "", now, None, now),
        )
        DB.commit()
    return {"ticket": ticket, "key": f"{QUARANTINE_BUCKET}/{ticket}"}


@app.post("/tickets/{ticket}/status")
def set_status(ticket: str, upd: StatusUpdate):
    if upd.status not in STATUSES:
        raise HTTPException(422, "unknown status")
    now = time.time()
    with LOCK:
        row = DB.execute("SELECT sub FROM tickets WHERE ticket=?", (ticket,)).fetchone()
        if row is None:
            raise HTTPException(404, "ticket not found")
        deadline = now + SLA_HOURS * 3600 if upd.status == "quarantined" else None
        DB.execute(
            "UPDATE tickets SET status=?, reason=?, sla_deadline=?, updated=? "
            "WHERE ticket=?",
            (upd.status, upd.reason, deadline, now, ticket),
        )
        DB.commit()
    if upd.status == "quarantined":
        QUARANTINED.inc()
        notify(ticket, row[0], upd.reason, deadline)
    return {"ticket": ticket, "status": upd.status, "sla_deadline": deadline}


@app.get("/tickets/{ticket}")
def get_ticket(ticket: str):
    with LOCK:
        row = DB.execute(
            "SELECT ticket, sub, filename, size, status, reason, created, "
            "sla_deadline FROM tickets WHERE ticket=?",
            (ticket,),
        ).fetchone()
    if row is None:
        raise HTTPException(404, "ticket not found")
    keys = [
        "ticket",
        "sub",
        "filename",
        "size",
        "status",
        "reason",
        "created",
        "sla_deadline",
    ]
    return dict(zip(keys, row))


@app.get("/tickets")
def list_tickets(status: str = "quarantined"):
    with LOCK:
        rows = DB.execute(
            "SELECT ticket, sub, filename, reason, sla_deadline FROM tickets "
            "WHERE status=? ORDER BY created",
            (status,),
        ).fetchall()
    return [
        dict(zip(["ticket", "sub", "filename", "reason", "sla_deadline"], r))
        for r in rows
    ]


def refresh_gauges() -> None:
    with LOCK:
        open_n, overdue_n = DB.execute(
            "SELECT COUNT(*), COALESCE(SUM(sla_deadline < ?), 0) FROM tickets "
            "WHERE status='quarantined'",
            (time.time(),),
        ).fetchone()
    OPEN_TICKETS.set(open_n)
    OVERDUE.set(overdue_n)


async def gauges_loop():
    while True:
        refresh_gauges()
        await asyncio.sleep(30)


@app.on_event("startup")
async def start_gauges():
    asyncio.create_task(gauges_loop())
