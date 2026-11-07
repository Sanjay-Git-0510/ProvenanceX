import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_defaults_load():
    s = Settings(_env_file=None)
    assert s.max_artifact_size_mb > 0
    assert s.sandbox_timeout_seconds > 0


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("MAX_ARTIFACT_SIZE_MB", "5")
    monkeypatch.setenv("LOG_LEVEL", "debug")
    monkeypatch.setenv("CORS_ORIGINS", "http://a.test, http://b.test")
    s = Settings(_env_file=None)
    assert s.max_artifact_size_mb == 5
    assert s.log_level == "DEBUG"
    assert s.cors_origins == ["http://a.test", "http://b.test"]


@pytest.mark.parametrize(
    ("var", "value"),
    [("MAX_ARTIFACT_SIZE_MB", "0"), ("SANDBOX_TIMEOUT_SECONDS", "-1"), ("LOG_LEVEL", "LOUD")],
)
def test_invalid_values_rejected(monkeypatch, var, value):
    monkeypatch.setenv(var, value)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_private_key_not_in_repr(monkeypatch):
    monkeypatch.setenv("BLOCKCHAIN_PRIVATE_KEY", "0xnotarealkey")
    assert "0xnotarealkey" not in repr(Settings(_env_file=None))
