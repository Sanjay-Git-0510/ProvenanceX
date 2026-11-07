"""Application settings loaded from environment variables (and an optional .env file)."""

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """Central runtime configuration.

    Risk fusion weights and policy thresholds are intentionally NOT here; they live in
    app/risk/policy_config.py (Phase 6) as research parameters.
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "ProvenanceX"
    app_env: str = "development"
    log_level: str = "INFO"
    scanner_version: str = "0.1.0"

    database_url: str = "postgresql+psycopg://provenancex:provenancex@localhost:5432/provenancex"

    workspace_root: Path = Path("./workspace")
    max_artifact_size_mb: int = Field(default=200, gt=0)
    max_artifact_files: int = Field(default=20000, gt=0)

    osv_api_base: str = "https://api.osv.dev"
    nvd_api_key: str = ""

    sandbox_timeout_seconds: int = Field(default=60, gt=0)
    model_path: Path = Path("./ml/models")

    blockchain_rpc_url: str = "http://localhost:8545"
    blockchain_contract_address: str = ""
    blockchain_private_key: str = Field(default="", repr=False)

    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:5173"]

    @field_validator("log_level")
    @classmethod
    def _normalize_log_level(cls, value: str) -> str:
        value = value.upper()
        if value not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"invalid log level: {value}")
        return value

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        # Allow a comma-separated string in env vars.
        if isinstance(value, str):
            return [v.strip() for v in value.split(",") if v.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
