"""Every setting must reach the API container, and every variable passed to it must be used."""

import re
from pathlib import Path

import yaml

from app.core.config import Settings

ROOT = Path(__file__).resolve().parents[3]
# app_name is a constant. The blockchain settings arrive with Phase 7.
NOT_PASSED = {
    "APP_NAME",
    "BLOCKCHAIN_RPC_URL",
    "BLOCKCHAIN_CONTRACT_ADDRESS",
    "BLOCKCHAIN_PRIVATE_KEY",
}
SETTINGS = {name.upper() for name in Settings.model_fields}


def _api_service() -> dict:
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))["services"][
        "api"
    ]


def test_every_setting_is_passed_to_the_api():
    assert SETTINGS - NOT_PASSED - set(_api_service()["environment"]) == set()


def test_every_variable_passed_to_the_api_is_a_setting():
    assert set(_api_service()["environment"]) - SETTINGS == set()


def test_env_example_documents_every_setting():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    documented = set(re.findall(r"^([A-Z][A-Z0-9_]*)=", text, re.M))
    assert SETTINGS - {"APP_NAME"} - documented == set()


def test_models_are_mounted_read_only_at_the_configured_path():
    service = _api_service()
    assert "./ml/models:/app/ml/models:ro" in service["volumes"]
    assert service["environment"]["MODEL_PATH"] == "/app/ml/models"


def test_api_container_gets_no_docker_socket():
    assert not any("docker.sock" in volume for volume in _api_service()["volumes"])


def test_image_installs_the_pinned_ml_packages():
    dockerfile = (ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")
    assert "-r requirements-ml.txt" in dockerfile
