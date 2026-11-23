"""GET /api/v1/limits: read-only submission limits for the UI."""

from fastapi.testclient import TestClient

from app.core.config import Settings, get_settings
from app.main import create_app


def _get(path="/api/v1/limits", method="get", **overrides):
    app = create_app()
    settings = Settings(_env_file=None, **overrides)
    app.dependency_overrides[get_settings] = lambda: settings
    return getattr(TestClient(app, raise_server_exceptions=False), method)(path)


def test_limits_reports_configured_values():
    resp = _get(max_upload_mb=7, max_artifact_size_mb=9, max_artifact_files=123)
    assert resp.status_code == 200
    body = resp.json()
    assert body["max_upload_mb"] == 7
    assert body["max_artifact_size_mb"] == 9
    assert body["max_artifact_files"] == 123
    assert body["upload_extensions"] == [".zip"]
    assert body["allowed_hosts"] == {"software": ["github.com"], "model": ["huggingface.co"]}
    assert body["artifact_types"] == {
        "software": ["software"],
        "model": ["model", "lora", "dataset"],
    }
    assert body["max_revision_length"] > 0
    assert body["max_url_length"] > 0


def test_limits_reports_optional_layers():
    body = _get(sandbox_provider="mock", blockchain_provider="disabled").json()
    assert body["sandbox_provider"] == "mock"
    assert body["blockchain_provider"] == "disabled"
    assert body["blockchain_anchor_on_scan"] is False


def test_limits_exposes_no_secrets_or_endpoints():
    resp = _get(blockchain_private_key="0x" + "ab" * 32, nvd_api_key="secret-key")
    text = resp.text
    assert "ab" * 32 not in text
    assert "secret-key" not in text
    assert "8545" not in text
    assert "database" not in text.lower()
    assert "workspace" not in text.lower()


def test_limits_is_read_only():
    assert _get(method="post").status_code == 405
