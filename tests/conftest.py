"""Общие фикстуры pytest: загрузка модулей сервисов и эмулятор S3 (moto)."""

import importlib.util
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "common"))
sys.path.insert(0, str(ROOT / "scripts"))


def load_service(name: str, tmp_path: pathlib.Path):
    """Импортирует services/<name>/app.py как отдельный модуль."""
    os.environ.update(
        {
            "DB_PATH": str(tmp_path / f"{name}.db"),
            "JWT_SECRET": "test-secret-0123456789abcdef0123456789",
            "S3_ENDPOINT": "",
            "S3_ACCESS_KEY": "t",
            "S3_SECRET_KEY": "t",
        }
    )
    import aig_common
    from prometheus_client import REGISTRY

    keep = {aig_common.HTTP_REQUESTS, aig_common.HTTP_LATENCY}
    for collector, names in list(REGISTRY._collector_to_names.items()):
        if collector not in keep and any(n.startswith("aig_") for n in names):
            REGISTRY.unregister(collector)  # повторный импорт модуля в другом тесте
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), ROOT / "services" / name / "app.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def s3_mock():
    from moto import mock_aws

    with mock_aws():
        import boto3

        s3 = boto3.client("s3", region_name="us-east-1")
        for bucket in ("raw", "canonical", "quarantine"):
            s3.create_bucket(Bucket=bucket)
        yield s3
