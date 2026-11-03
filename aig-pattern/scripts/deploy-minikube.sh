#!/usr/bin/env bash
# Развёртывание паттерна AIG в minikube (Linux / macOS / Git Bash)
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { cp .env.example .env; echo "Создан .env — замените пароли и запустите снова"; exit 1; }
minikube start --driver=docker --cni=calico --cpus=4 --memory=6144
minikube addons enable ingress
minikube addons enable metrics-server
eval "$(minikube -p minikube docker-env)"
for pair in ingest-api:ingest security-service:security format-detector:detector \
            schema-registry:registry adapter-factory:adapter quarantine-notifier:quarantine \
            minio-init:minio-init; do
  docker build --build-arg SERVICE="${pair%%:*}" -t "aig/${pair##*:}:1.0" services
done
kubectl apply -f k8s/00-namespace.yaml
kubectl -n aig create secret generic aig-secrets --from-env-file=.env --dry-run=client -o yaml | kubectl apply -f -
python3 scripts/make_tls.py
kubectl -n aig create secret tls aig-tls --cert=tls/tls.crt --key=tls/tls.key --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -k k8s
kubectl -n aig wait --for=condition=complete job/minio-init --timeout=300s
kubectl -n aig rollout status deployment/ingest-api --timeout=300s
kubectl -n aig get pods,svc,ingress,networkpolicy,hpa
