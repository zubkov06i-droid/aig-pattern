"""adapter-factory — автоматическая адаптация к неизвестному формату (порт 8005).

Для объекта с меткой UNKNOWN (сейчас — новые диалекты CSV: другой разделитель,
кодировка UTF-8 BOM или cp1251, десятичная запятая):
  1) читает объект из бакета quarantine;
  2) выводит схему по выборке SAMPLE_ROWS строк (schema inference);
  3) регистрирует схему в schema-registry (проверка BACKWARD);
  4) строит конвертер в канонический формат JSON Lines и сохраняет его схему
     в SQLite (после перезапуска пода конвертер пересобирается);
  5) записывает результат в бакет canonical.
"""

import csv
import hashlib
import io
import json
import os
import re
import sqlite3
import threading

import httpx
from fastapi import HTTPException
from prometheus_client import Counter
from pydantic import BaseModel

from aig_common import create_app, env_float, env_int, get_logger, log_event, s3_client

SERVICE = "adapter-factory"
app = create_app(SERVICE)
log = get_logger(SERVICE)

REGISTRY_URL = os.getenv("REGISTRY_URL", "http://schema-registry:8004")
QUARANTINE_BUCKET = os.getenv("QUARANTINE_BUCKET", "quarantine")
CANONICAL_BUCKET = os.getenv("CANONICAL_BUCKET", "canonical")
SAMPLE_ROWS = env_int("SAMPLE_ROWS", 100)
MAX_BAD_RATIO = env_float("MAX_BAD_RATIO", 0.01)

INT_RE = re.compile(r"^[+-]?\d+$")
FLOAT_RE = re.compile(r"^[+-]?(\d+[.,]\d*|[.,]\d+)([eE][+-]?\d+)?$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ORDER = ["bool", "int", "float", "string"]  # решётка типов: bool < int < float < string
ADAPTED = Counter("aig_adaptations_total", "Результаты автоадаптации", ["result"])

S3 = s3_client()
CACHE: dict[str, callable] = {}  # кэш исполняемых конвертеров
DB_LOCK = threading.Lock()
DB = sqlite3.connect(os.getenv("DB_PATH", "/data/adapter.db"), check_same_thread=False)
DB.execute("CREATE TABLE IF NOT EXISTS converters(cid TEXT PRIMARY KEY, schema TEXT)")


class AdaptRequest(BaseModel):
    ticket: str
    features: dict


# ---------------------------------------------------------------- вывод схемы
def value_type(v: str) -> str | None:
    """Тип одного значения; None — пустое значение (поле необязательное)."""
    v = v.strip()
    if v == "":
        return None
    if v.lower() in ("true", "false"):
        return "bool"
    if INT_RE.match(v):
        return "int"
    if FLOAT_RE.match(v):
        return "float"
    if DATE_RE.match(v):
        return "date"
    return "string"


def join_types(a: str | None, b: str | None) -> str | None:
    """Наименьший общий тип двух типов по решётке."""
    if a is None or a == b:
        return b if a is None else a
    if b is None:
        return a
    if "date" in (a, b):
        return "string"
    return ORDER[max(ORDER.index(a), ORDER.index(b))]


def infer_schema(text: str, features: dict) -> dict:
    """Schema inference: заголовок + типы столбцов по первым SAMPLE_ROWS строкам."""
    rows = csv.reader(io.StringIO(text), delimiter=features["delimiter"])
    first = next(rows)
    header = (
        [h.strip() or f"col_{i + 1}" for i, h in enumerate(first)]
        if features.get("has_header", True)
        else [f"col_{i + 1}" for i in range(len(first))]
    )
    types: list[str | None] = [None] * len(header)
    optional = set()
    for n, row in enumerate(rows):
        if n >= SAMPLE_ROWS:
            break
        for i in range(len(header)):
            t = value_type(row[i]) if i < len(row) else None
            if t is None:
                optional.add(header[i])
            types[i] = join_types(types[i], t)
    fields = {h: (t or "string") for h, t in zip(header, types)}
    return {
        "fields": fields,
        "optional": sorted(optional),
        "source": {
            "delimiter": features["delimiter"],
            "encoding": features["encoding"],
            "has_header": features.get("has_header", True),
        },
    }


def subject_for(schema: dict) -> str:
    """Имя субъекта в реестре: отпечаток набора столбцов и диалекта."""
    src = schema["source"]
    key = f"{src['delimiter']}|{src['encoding']}|{src['has_header']}|" + "|".join(
        schema["fields"]
    )
    return "auto-" + hashlib.sha1(key.encode()).hexdigest()[:12]


# ---------------------------------------------------------------- конвертер
def cast(value: str, typ: str):
    v = value.strip()
    if v == "":
        return None
    if typ == "bool":
        return v.lower() == "true"
    if typ == "int":
        return int(v)
    if typ == "float":
        return float(v.replace(",", "."))
    return v  # date и string сохраняются строкой


def build_converter(schema: dict):
    """Строит функцию «байты источника -> (JSON Lines, строк, ошибок)»."""
    src, names, types = (
        schema["source"],
        list(schema["fields"]),
        list(schema["fields"].values()),
    )

    def convert(blob: bytes) -> tuple[bytes, int, int]:
        text = blob.decode(src["encoding"], errors="strict")
        reader = csv.reader(io.StringIO(text), delimiter=src["delimiter"])
        if src["has_header"]:
            next(reader, None)
        out, good, bad = io.StringIO(), 0, 0
        for row in reader:
            if not any(cell.strip() for cell in row):
                continue  # пустые строки пропускаются
            try:
                if len(row) != len(names):
                    raise ValueError("column count mismatch")
                rec = {n: cast(v, t) for n, t, v in zip(names, types, row)}
            except ValueError:
                bad += 1
                continue
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            good += 1
        return out.getvalue().encode("utf-8"), good, bad

    return convert


def save_converter(cid: str, schema: dict) -> None:
    with DB_LOCK:
        DB.execute(
            "INSERT OR REPLACE INTO converters VALUES(?,?)", (cid, json.dumps(schema))
        )
        DB.commit()


def get_converter(cid: str):
    """Конвертер из кэша; после рестарта пода — пересборка из схемы в SQLite."""
    if cid not in CACHE:
        with DB_LOCK:
            row = DB.execute(
                "SELECT schema FROM converters WHERE cid=?", (cid,)
            ).fetchone()
        if row is None:
            return None
        CACHE[cid] = build_converter(json.loads(row[0]))
    return CACHE[cid]


# ---------------------------------------------------------------- эндпоинт
def fail(reason: str, code: int = 422):
    ADAPTED.labels("failed").inc()
    raise HTTPException(code, reason)


@app.post("/adapt")
def adapt(req: AdaptRequest):
    f = req.features
    if f.get("family") != "csv":
        fail("automatic adaptation is not supported for this data")
    blob = S3.get_object(Bucket=QUARANTINE_BUCKET, Key=req.ticket)["Body"].read()
    try:
        text = blob.decode(f["encoding"])
    except (UnicodeDecodeError, LookupError):
        fail("cannot decode object with detected encoding")
    schema = infer_schema(text, f)
    subject = subject_for(schema)
    reg = httpx.post(
        f"{REGISTRY_URL}/subjects/{subject}/versions",
        json={"fields": schema["fields"], "optional": schema["optional"]},
        timeout=10,
    )
    if reg.status_code == 409:
        fail(f"schema conflict: {reg.json()['detail']['errors']}")
    reg.raise_for_status()
    cid = reg.json()["id"]
    if get_converter(cid) is None:
        save_converter(cid, schema)
    data, good, bad = get_converter(cid)(blob)
    if good == 0 or bad / (good + bad) > MAX_BAD_RATIO:
        fail(f"too many bad rows: {bad} of {good + bad}")
    key = f"{req.ticket}.jsonl"
    S3.put_object(
        Bucket=CANONICAL_BUCKET,
        Key=key,
        Body=data,
        ContentType="application/x-ndjson",
        Metadata={"schema-id": cid, "ticket": req.ticket},
    )
    ADAPTED.labels("adapted").inc()
    log_event(log, "adapted", ticket=req.ticket, schema_id=cid, rows=good, bad_rows=bad)
    return {
        "schema_id": cid,
        "converter_id": cid,
        "rows": good,
        "bad_rows": bad,
        "key": f"{CANONICAL_BUCKET}/{key}",
    }
