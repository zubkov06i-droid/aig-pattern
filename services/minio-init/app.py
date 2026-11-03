"""minio-init — однократная инициализация ХБД MinIO (Job Kubernetes).

  * создаёт бакеты raw, canonical, quarantine;
  * включает версионирование canonical (аудит изменений канонических данных);
  * задаёт Lifecycle: raw — 30 дней, quarantine — 90 дней;
  * создаёт учётные записи микросервисов и IAM-политики минимальных привилегий:
      aig-ingest-sa     — запись/чтение/multipart в raw;
      aig-security-sa   — просмотр и прерывание multipart-сессий raw;
      aig-quarantine-sa — ЕДИНСТВЕННАЯ учётная запись с правом записи в quarantine;
      aig-adapter-sa    — чтение quarantine, запись canonical.
Повторный запуск безопасен (идемпотентен).
"""

import json
import os
import tempfile
import time

from minio import Minio
from minio.commonconfig import ENABLED, Filter
from minio.credentials import StaticProvider
from minio.lifecycleconfig import Expiration, LifecycleConfig, Rule
from minio.minioadmin import MinioAdmin
from minio.versioningconfig import VersioningConfig

ENDPOINT = os.getenv("MINIO_ENDPOINT", "storage:9000")
ROOT_USER, ROOT_PASSWORD = (
    os.environ["MINIO_ROOT_USER"],
    os.environ["MINIO_ROOT_PASSWORD"],
)
EXPIRY = {
    "raw": int(os.getenv("RAW_EXPIRY_DAYS", "30")),
    "quarantine": int(os.getenv("QUARANTINE_EXPIRY_DAYS", "90")),
}

POLICIES = {
    "aig-ingest-sa": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject",
                "s3:AbortMultipartUpload",
                "s3:ListMultipartUploadParts",
            ],
            "Resource": ["arn:aws:s3:::raw/*"],
        }
    ],
    "aig-security-sa": [
        {
            "Effect": "Allow",
            "Action": ["s3:ListBucketMultipartUploads"],
            "Resource": ["arn:aws:s3:::raw"],
        },
        {
            "Effect": "Allow",
            "Action": ["s3:AbortMultipartUpload"],
            "Resource": ["arn:aws:s3:::raw/*"],
        },
    ],
    "aig-quarantine-sa": [
        {
            "Effect": "Allow",
            "Action": ["s3:PutObject"],
            "Resource": ["arn:aws:s3:::quarantine/*"],
        }
    ],
    "aig-adapter-sa": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::quarantine/*"],
        },
        {
            "Effect": "Allow",
            "Action": ["s3:PutObject"],
            "Resource": ["arn:aws:s3:::canonical/*"],
        },
    ],
}


def wait_ready(client: Minio, attempts: int = 30) -> None:
    for _ in range(attempts):
        try:
            client.list_buckets()
            return
        except Exception:
            time.sleep(2)
    raise RuntimeError("MinIO is not reachable")


def main() -> None:
    client = Minio(ENDPOINT, ROOT_USER, ROOT_PASSWORD, secure=False)
    admin = MinioAdmin(ENDPOINT, StaticProvider(ROOT_USER, ROOT_PASSWORD), secure=False)
    wait_ready(client)
    for bucket in ("raw", "canonical", "quarantine"):
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
    client.set_bucket_versioning("canonical", VersioningConfig(ENABLED))
    for bucket, days in EXPIRY.items():
        rule = Rule(
            ENABLED,
            rule_filter=Filter(prefix=""),
            rule_id=f"{bucket}-expiry",
            expiration=Expiration(days=days),
        )
        client.set_bucket_lifecycle(bucket, LifecycleConfig([rule]))
    for user, statements in POLICIES.items():
        secret = os.environ[user.upper().replace("-", "_") + "_SECRET"]
        admin.user_add(user, secret)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"Version": "2012-10-17", "Statement": statements}, fh)
        admin.policy_add(user + "-policy", fh.name)
        try:
            admin.attach_policy([user + "-policy"], user=user)
        except Exception as exc:  # политика уже привязана — не ошибка
            print(f"attach {user}: {exc}")
        print(f"user {user}: policy {user}-policy")
    print("minio-init: done")


if __name__ == "__main__":
    main()
