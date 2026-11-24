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

## Глава 4: мониторинг и тесты на стенде из трёх ВМ

```bash
# ВМ3: контур мониторинга (Prometheus, Loki + promtail, Grafana)
kubectl apply -f k8s/monitoring/00-namespace.yaml
kubectl -n aig-monitoring create secret generic grafana-admin --from-literal=admin-password="$(openssl rand -hex 12)"
kubectl apply -k k8s/monitoring
kubectl -n aig-monitoring port-forward --address 0.0.0.0 svc/grafana 3000:3000   # http://192.168.56.13:3000
# ВМ2 (легальный пользователь) и ВМ1 (нарушитель), после ansible-playbook ... --limit aig_clients
cd /opt/aig-client && source .venv/bin/activate && source aig.env
pytest -v -m user tests/cluster                      # ВМ2, фаза baseline
python scripts/attack_flood.py --url $AIG_URL --secret $AIG_JWT_SECRET --insecure   # ВМ1
AIG_PHASE=attack pytest -v -m user tests/cluster     # ВМ2 одновременно с атакой
pytest -v -m intruder tests/cluster                  # ВМ1
```

Ingress публикуется на адресе ВМ3 правилами DNAT (`ansible/files/aig-ingress-dnat.sh`), чтобы
шлюз видел настоящий IP клиента и лимит «на IP» различал ВМ1 и ВМ2.

Подробное описание работы кода — в файле «Документация к программному коду паттерна AIG».
