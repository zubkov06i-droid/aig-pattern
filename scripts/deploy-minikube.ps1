# Развёртывание паттерна AIG в локальном кластере minikube (Windows PowerShell).
# Запуск из корня проекта:  powershell -ExecutionPolicy Bypass -File scripts\deploy-minikube.ps1
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

if (-not (Test-Path .env)) {
    Copy-Item .env.example .env
    Write-Host "Создан файл .env - замените в нём пароли и запустите скрипт ещё раз"; exit 1
}

# 1. Кластер: драйвер Docker, CNI Calico (поддерживает NetworkPolicy), Ingress, metrics-server
minikube start --driver=docker --cni=calico --cpus=4 --memory=6144
minikube addons enable ingress
minikube addons enable metrics-server

# 2. Сборка образов прямо в Docker внутри minikube (реестр не нужен)
& minikube -p minikube docker-env --shell powershell | Invoke-Expression
$images = [ordered]@{
    "ingest-api" = "aig/ingest:1.0";        "security-service" = "aig/security:1.0"
    "format-detector" = "aig/detector:1.0"; "schema-registry" = "aig/registry:1.0"
    "adapter-factory" = "aig/adapter:1.0";  "quarantine-notifier" = "aig/quarantine:1.0"
    "minio-init" = "aig/minio-init:1.0"
}
foreach ($svc in $images.Keys) { docker build --build-arg SERVICE=$svc -t $images[$svc] services }

# 3. Пространство имён и секреты (секреты в git не хранятся)
kubectl apply -f k8s/00-namespace.yaml
kubectl -n aig create secret generic aig-secrets --from-env-file=.env --dry-run=client -o yaml | kubectl apply -f -
python scripts/make_tls.py
kubectl -n aig create secret tls aig-tls --cert=tls/tls.crt --key=tls/tls.key --dry-run=client -o yaml | kubectl apply -f -

# 4. Манифесты паттерна и ожидание готовности
kubectl apply -k k8s
kubectl -n aig wait --for=condition=complete job/minio-init --timeout=300s
kubectl -n aig rollout status deployment/ingest-api --timeout=300s
kubectl -n aig get pods,svc,ingress,networkpolicy,hpa

Write-Host ""
Write-Host "Готово. Добавьте в C:\Windows\System32\drivers\etc\hosts строку:  127.0.0.1 aig.local"
Write-Host "и в отдельном окне PowerShell (от администратора) запустите:  minikube tunnel"
