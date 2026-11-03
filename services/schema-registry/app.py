"""schema-registry — реестр схем и версий с проверкой совместимости (порт 8004).

Схема: {"fields": {"имя": "тип"}, "optional": ["имя", ...]},
типы: bool, int, float, date, string.
Политика BACKWARD: новая версия схемы обязана читать данные, записанные по
предыдущей версии: удалять поля нельзя, менять тип можно только на более
широкий, новое поле допускается только как необязательное.
Запись выполняется в одной транзакции SQLite (BEGIN IMMEDIATE), сервис
работает в одну реплику (режим leader-write).
"""

import json
import os
import sqlite3
import threading
import time

from fastapi import HTTPException
from prometheus_client import Counter
from pydantic import BaseModel

from aig_common import create_app, get_logger, log_event

SERVICE = "schema-registry"
app = create_app(SERVICE)
log = get_logger(SERVICE)

TYPES = {"bool", "int", "float", "date", "string"}
WIDENING = {
    ("bool", "int"),
    ("int", "float"),
    ("bool", "float"),
    ("bool", "string"),
    ("int", "string"),
    ("float", "string"),
    ("date", "string"),
}
REGISTERED = Counter("aig_schema_versions_total", "Зарегистрированные версии схем")
CONFLICTS = Counter("aig_schema_conflicts_total", "Отклонённые несовместимые схемы")

LOCK = threading.Lock()
DB = sqlite3.connect(
    os.getenv("DB_PATH", "/data/registry.db"),
    check_same_thread=False,
    isolation_level=None,
)
DB.execute("""CREATE TABLE IF NOT EXISTS schemas(
    subject TEXT, version INTEGER, schema TEXT, created REAL,
    PRIMARY KEY(subject, version))""")


class Schema(BaseModel):
    fields: dict[str, str]
    optional: list[str] = []


def check_backward(old: dict, new: dict) -> list[str]:
    """Возвращает список нарушений политики BACKWARD (пустой — совместимо)."""
    errors = []
    for name, old_type in old["fields"].items():
        new_type = new["fields"].get(name)
        if new_type is None:
            errors.append(f"field '{name}' removed")
        elif new_type != old_type and (old_type, new_type) not in WIDENING:
            errors.append(f"field '{name}': {old_type} -> {new_type} is not widening")
    for name in new["fields"]:
        if name not in old["fields"] and name not in new["optional"]:
            errors.append(f"new field '{name}' must be optional")
    return errors


def latest(subject: str):
    return DB.execute(
        "SELECT version, schema FROM schemas WHERE subject=? "
        "ORDER BY version DESC LIMIT 1",
        (subject,),
    ).fetchone()


@app.post("/subjects/{subject}/versions")
def register(subject: str, schema: Schema):
    new = schema.model_dump()
    new["optional"] = sorted(set(new["optional"]))
    bad_types = set(new["fields"].values()) - TYPES
    if bad_types:
        raise HTTPException(422, f"unknown types: {sorted(bad_types)}")
    with LOCK:
        DB.execute("BEGIN IMMEDIATE")  # атомарная регистрация версии
        try:
            row = latest(subject)
            version = 1
            if row:
                old = json.loads(row[1])
                if old == new:  # повторная регистрация — идемпотентно
                    DB.execute("COMMIT")
                    return {
                        "subject": subject,
                        "version": row[0],
                        "id": f"{subject}-v{row[0]}",
                    }
                errors = check_backward(old, new)
                if errors:
                    DB.execute("ROLLBACK")
                    CONFLICTS.inc()
                    log_event(
                        log, "incompatible schema", subject=subject, errors=errors
                    )
                    raise HTTPException(
                        409, {"message": "incompatible schema", "errors": errors}
                    )
                version = row[0] + 1
            DB.execute(
                "INSERT INTO schemas VALUES(?,?,?,?)",
                (subject, version, json.dumps(new, sort_keys=True), time.time()),
            )
            DB.execute("COMMIT")
        except HTTPException:
            raise
        except Exception:
            DB.execute("ROLLBACK")
            raise
    REGISTERED.inc()
    log_event(log, "schema registered", subject=subject, version=version)
    return {"subject": subject, "version": version, "id": f"{subject}-v{version}"}


@app.get("/subjects")
def subjects():
    return [
        r[0]
        for r in DB.execute("SELECT DISTINCT subject FROM schemas ORDER BY subject")
    ]


@app.get("/subjects/{subject}/versions/{version}")
def get_version(subject: str, version: str):
    if version == "latest":
        row = latest(subject)
    else:
        row = DB.execute(
            "SELECT version, schema FROM schemas WHERE subject=? AND version=?",
            (subject, int(version)),
        ).fetchone()
    if not row:
        raise HTTPException(404, "schema not found")
    return {"subject": subject, "version": row[0], "schema": json.loads(row[1])}
