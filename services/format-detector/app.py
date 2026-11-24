"""format-detector — идентификация формата входных данных (порт 8003).

Сервис не хранит состояния и не имеет доступа к хранилищу: ingest-api
передаёт ему только первые HEAD_BYTES байт объекта. Порядок проверок:
  1) сигнатуры (магические байты) бинарных форматов;
  2) признак «двоичные / текстовые данные» и определение кодировки;
  3) структурная проба JSON / JSON Lines;
  4) структурная проба CSV с определением разделителя.
Если формат или его диалект не входит в каталог поддерживаемых ХБД,
возвращается метка UNKNOWN с вектором признаков для adapter-factory.
"""

import csv
import io
import json
import math
from collections import Counter as Freq

from fastapi import Request
from prometheus_client import Counter

from aig_common import create_app, env_int, get_logger, log_event

SERVICE = "format-detector"
app = create_app(SERVICE)
log = get_logger(SERVICE)

HEAD_BYTES = env_int("HEAD_BYTES", 65536)
CONTROL_RATIO_MAX = 0.05  # доля управляющих байтов, выше которой данные двоичные
SUPPORTED_MAGIC = {
    b"PAR1": "parquet",
    b"Obj\x01": "avro",
    b"ORC": "orc",
}  # грузятся в raw
CONTAINER_MAGIC = {
    b"\x1f\x8b": "gzip",
    b"PK\x03\x04": "zip",
    b"%PDF": "pdf",
}  # не табличные
CSV_SUPPORTED = {
    "delimiter": ",",
    "encoding": "utf-8",
}  # единственный штатный диалект CSV
DETECTED = Counter("aig_detected_total", "Результаты идентификации формата", ["format"])


def entropy(data: bytes) -> float:
    """Энтропия Шеннона, бит/байт (0 – константа, 8 – случайные данные)."""
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Freq(data).values()) if n else 0.0


def features_of(head: bytes) -> dict:
    control = sum(1 for b in head if b < 32 and b not in (9, 10, 13))
    return {
        "size_head": len(head),
        "entropy": round(entropy(head), 3),
        "control_ratio": round(control / max(len(head), 1), 4),
    }


def unknown(head: bytes, **extra) -> dict:
    return {
        "format": "UNKNOWN",
        "confidence": 0.0,
        "features": {**features_of(head), **extra},
    }


def decode_text(head: bytes) -> tuple[str | None, str | None]:
    """Возвращает (текст, кодировка) или (None, None) для двоичных данных."""
    feats = features_of(head)
    if b"\x00" in head or feats["control_ratio"] > CONTROL_RATIO_MAX:
        return None, None
    if head.startswith(b"\xef\xbb\xbf"):
        return head[3:].decode("utf-8", errors="ignore"), "utf-8-sig"
    try:
        return head.decode("utf-8"), "utf-8"
    except UnicodeDecodeError as exc:
        if exc.start >= len(head) - 3:  # обрезан последний многобайтный символ
            return head[: exc.start].decode("utf-8"), "utf-8"
        return head.decode("cp1251"), "cp1251"


def complete_lines(text: str, truncated: bool) -> list[str]:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return (
        lines[:-1] if truncated and len(lines) > 1 else lines
    )  # последняя строка обрезана


def probe_json(text: str, lines: list[str], truncated: bool) -> dict | None:
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        json.loads(text)
        return {"format": "json", "confidence": 0.95, "features": {}}
    except ValueError:
        pass
    try:
        if len(lines) >= 2 and all(json.loads(ln) is not None for ln in lines):
            return {
                "format": "jsonl",
                "confidence": 0.95,
                "features": {"rows_seen": len(lines)},
            }
    except ValueError:
        pass
    if truncated:  # начало корректного JSON больше 64 КБ
        return {"format": "json", "confidence": 0.6, "features": {"truncated": True}}
    return None


def probe_csv(lines: list[str]) -> dict | None:
    if len(lines) < 2:
        return None
    sample = "\n".join(lines[:200])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        return None
    rows = list(csv.reader(io.StringIO(sample), dialect))
    widths = {len(r) for r in rows}
    if len(widths) != 1 or len(rows[0]) < 2:
        return None
    try:
        has_header = csv.Sniffer().has_header(sample)
    except csv.Error:
        has_header = True
    return {
        "delimiter": dialect.delimiter,
        "ncols": len(rows[0]),
        "has_header": has_header,
    }


def detect(head: bytes, truncated: bool = False) -> dict:
    """Ядро идентификации: возвращает формат либо UNKNOWN с признаками."""
    for signature, fmt in SUPPORTED_MAGIC.items():  # шаг 1
        if head.startswith(signature):
            return {"format": fmt, "confidence": 0.99, "features": {}}
    for signature, fmt in CONTAINER_MAGIC.items():
        if head.startswith(signature):
            return unknown(head, container=fmt)
    text, encoding = decode_text(head)  # шаг 2
    if text is None:
        return unknown(head, binary=True)
    lines = complete_lines(text, truncated)
    found = probe_json(text, lines, truncated)  # шаг 3
    if found:
        return found
    csv_info = probe_csv(lines)  # шаг 4
    if csv_info:
        feats = {"family": "csv", "encoding": encoding, **csv_info}
        if csv_info["delimiter"] == CSV_SUPPORTED["delimiter"] and encoding == "utf-8":
            return {"format": "csv", "confidence": 0.9, "features": feats}
        return unknown(head, **feats)  # новый диалект CSV
    return unknown(head, encoding=encoding)


@app.post("/detect")
async def detect_endpoint(request: Request):
    body = await request.body()
    truncated = request.headers.get("X-Truncated", "0") == "1"
    result = detect(body[:HEAD_BYTES], truncated or len(body) > HEAD_BYTES)
    DETECTED.labels(result["format"]).inc()
    log_event(log, "detected", format=result["format"], confidence=result["confidence"])
    return result
