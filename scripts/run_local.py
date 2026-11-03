"""Запуск всех микросервисов AIG локально, без Docker (для отладки и pytest).

Вместо MinIO поднимается эмулятор S3 API moto (pip install "moto[server]").
    python scripts/run_local.py          # Ctrl+C — остановка
Сервисы слушают 127.0.0.1:8001…8006, S3-эмулятор — 127.0.0.1:9000.
"""

import os
import pathlib
import signal
import subprocess
import sys
import time

import boto3
import httpx

ROOT = pathlib.Path(__file__).resolve().parents[1]
STATE = ROOT / ".local"
SERVICES = {
    "ingest-api": 8001,
    "security-service": 8002,
    "format-detector": 8003,
    "schema-registry": 8004,
    "adapter-factory": 8005,
    "quarantine-notifier": 8006,
}
JWT_SECRET = "local-dev-secret-0123456789abcdef0123456789"


def base_env() -> dict:
    env = dict(os.environ)
    env.update(
        {
            "JWT_SECRET": JWT_SECRET,
            "S3_ENDPOINT": "http://127.0.0.1:9000",
            "S3_ACCESS_KEY": "test",
            "S3_SECRET_KEY": "test",
            "SECURITY_URL": "http://127.0.0.1:8002",
            "DETECTOR_URL": "http://127.0.0.1:8003",
            "REGISTRY_URL": "http://127.0.0.1:8004",
            "ADAPTER_URL": "http://127.0.0.1:8005",
            "QUARANTINE_URL": "http://127.0.0.1:8006",
            "PYTHONPATH": str(ROOT / "services" / "common"),
        }
    )
    return env


def start() -> list[subprocess.Popen]:
    STATE.mkdir(exist_ok=True)
    for db in STATE.glob("*.db"):
        db.unlink()
    env = base_env()
    procs = [
        subprocess.Popen(
            [sys.executable, "-m", "moto.server", "-p", "9000"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    ]
    for _ in range(50):
        try:
            httpx.get("http://127.0.0.1:9000", timeout=1)
            break
        except httpx.HTTPError:
            time.sleep(0.2)
    s3 = boto3.client(
        "s3",
        endpoint_url="http://127.0.0.1:9000",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    for bucket in ("raw", "canonical", "quarantine"):
        s3.create_bucket(Bucket=bucket)
    for name, port in SERVICES.items():
        senv = dict(env, DB_PATH=str(STATE / f"{name}.db"), REAP_PERIOD_S="3600")
        log = open(STATE / f"{name}.log", "w")
        procs.append(
            subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "app:app",
                    "--port",
                    str(port),
                    "--no-access-log",
                ],
                cwd=ROOT / "services" / name,
                env=senv,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        )
    for port in SERVICES.values():
        for _ in range(100):
            try:
                if (
                    httpx.get(f"http://127.0.0.1:{port}/health", timeout=1).status_code
                    == 200
                ):
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        else:
            stop(procs)
            raise RuntimeError(
                f"service on port {port} did not start, see .local/*.log"
            )
    return procs


def stop(procs: list[subprocess.Popen]) -> None:
    for p in procs:
        p.terminate()
    for p in procs:
        p.wait(timeout=10)


if __name__ == "__main__":
    running = start()
    print("AIG запущен: ingest-api http://127.0.0.1:8001 (Ctrl+C — остановка)")
    print(f"JWT_SECRET для scripts/gen_jwt.py: {JWT_SECRET}")
    try:
        signal.pause() if hasattr(signal, "pause") else input()
    except KeyboardInterrupt:
        pass
    finally:
        stop(running)
