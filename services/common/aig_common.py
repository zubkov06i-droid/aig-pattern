"""Общий каркас микросервисов паттерна AIG.

Модуль копируется в образ каждого микросервиса и даёт:
  * журналы в формате JSON (одна строка = одно событие, удобно для Loki);
  * служебные эндпоинты /health (пробы Kubernetes) и /metrics (Prometheus);
  * счётчики и гистограмму латентности HTTP-запросов;
  * клиент S3 API для хранилища MinIO.
Логики паттерна здесь нет: это инфраструктурная обвязка.
"""

import json
import logging
import os
import sys
import time

import boto3
from botocore.config import Config
from fastapi import FastAPI, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

HTTP_REQUESTS = Counter(
    "aig_http_requests_total",
    "HTTP-запросы к микросервису",
    ["service", "path", "code"],
)
HTTP_LATENCY = Histogram(
    "aig_http_request_seconds",
    "Латентность обработки HTTP-запроса",
    ["service", "path"],
)


class JsonFormatter(logging.Formatter):
    """Форматирует запись журнала как одну JSON-строку."""

    def format(self, record: logging.LogRecord) -> str:
        data = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "service": record.name,
            "msg": record.getMessage(),
        }
        data.update(getattr(record, "fields", {}))
        return json.dumps(data, ensure_ascii=False)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))
        logger.propagate = False
    return logger


def log_event(logger: logging.Logger, msg: str, **fields) -> None:
    """Событие журнала с произвольными структурированными полями."""
    logger.info(msg, extra={"fields": fields})


def env_int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


def env_float(name: str, default: float) -> float:
    return float(os.getenv(name, str(default)))


def create_app(service: str) -> FastAPI:
    """Создаёт приложение FastAPI со служебными эндпоинтами и метриками."""
    app = FastAPI(title=service)

    @app.middleware("http")
    async def metrics_middleware(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        route = request.scope.get("route")
        path = route.path if route is not None else "unmatched"
        HTTP_REQUESTS.labels(service, path, str(response.status_code)).inc()
        HTTP_LATENCY.labels(service, path).observe(time.perf_counter() - start)
        return response

    @app.get("/health")
    def health():
        return {"status": "ok", "service": service}

    @app.get("/metrics")
    def metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


def s3_client():
    """Клиент S3 API (MinIO) с учётной записью конкретного микросервиса.

    Каждый сервис получает свои S3_ACCESS_KEY/S3_SECRET_KEY из Secret
    Kubernetes, права которых ограничены IAM-политикой MinIO (least privilege).
    """
    return boto3.client(
        "s3",
        endpoint_url=os.getenv("S3_ENDPOINT", "http://storage:9000") or None,
        aws_access_key_id=os.getenv("S3_ACCESS_KEY"),
        aws_secret_access_key=os.getenv("S3_SECRET_KEY"),
        region_name=os.getenv("S3_REGION", "us-east-1"),
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 3},
        ),
    )
