# AIG — Adaptive Ingestion Gateway

Паттерн безопасности против угрозы **УБИ.105** БДУ ФСТЭК России («отказ в загрузке входных данных
неизвестного формата хранилищем больших данных») на примере S3-совместимого ХБД MinIO.
Курсовая работа: Зубков И. А., КЕ-24-02, РГУ нефти и газа (НИУ) им. И. М. Губкина.

## Состав

| Сервис | Порт | Назначение |
|---|---|---|
| gateway (nginx) | 8080 | единственная точка входа, limit_req по IP и токену |
| ingest-api | 8001 | оркестратор: тикет, вызов сервисов, ответ 202 Accepted |
| security-service | 8002 | JWT, квоты «токен-бакет», санитизация, контроль multipart (сценарий С2) |
| format-detector | 8003 | идентификация формата по первым 64 КБ |
| schema-registry | 8004 | реестр схем, политика совместимости BACKWARD |
| adapter-factory | 8005 | вывод схемы, конвертер в JSON Lines, запись в canonical |
| quarantine-notifier | 8006 | карантин, тикеты с SLA 24 ч, уведомления |
| storage (MinIO) | 9000 | бакеты raw / canonical / quarantine |

## Быстрый старт без Docker (Windows, PowerShell)

```powershell
python -m venv .venv               # нужен Python 3.10+ (рекомендуется 3.12)
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
pytest -q tests                       # 12 тестов
python scripts/run_local.py           # окно 1: все сервисы + эмулятор S3
python scripts/demo.py --secret local-dev-secret-0123456789abcdef0123456789   # окно 2
python scripts/attack_mpu.py --secret local-dev-secret-0123456789abcdef0123456789
```

## Docker Compose

```powershell
copy .env.example .env                # замените пароли
docker compose up -d --build
python scripts/demo.py --url http://127.0.0.1:8080 --secret <JWT_SECRET из .env>
```

## Kubernetes (minikube)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\deploy-minikube.ps1
# hosts: 127.0.0.1 aig.local ; в отдельном окне (от администратора): minikube tunnel
python scripts/demo.py --url https://aig.local --secret <JWT_SECRET> --insecure
kubectl -n aig get pods
```

Подробное описание работы кода — в файле «Документация к программному коду паттерна AIG».
