"""Application settings loaded from environment variables (and an optional .env file)."""

from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

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
    max_upload_mb: int = Field(default=100, gt=0)
    max_compression_ratio: float = Field(default=100.0, gt=1)
    git_clone_timeout_seconds: int = Field(default=120, gt=0)

    # --- SBOM (Phase 2). "mock" serves a recorded fixture SBOM tagged source="mock".
    sbom_provider: Literal["syft", "mock"] = "syft"
    syft_path: str = "syft"
    syft_timeout_seconds: int = Field(default=300, gt=0)
    max_sbom_mb: int = Field(default=50, gt=0)
    max_sbom_components: int = Field(default=50000, gt=0)

    # --- Vulnerability intelligence (Phase 2). "mock" serves recorded OSV data, source="mock".
    vuln_provider: Literal["osv", "mock"] = "osv"
    osv_api_base: str = "https://api.osv.dev"
    osv_timeout_seconds: float = Field(default=20.0, gt=0)
    osv_max_detail_lookups: int = Field(default=500, gt=0)
    nvd_enabled: bool = True
    nvd_api_base: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str = Field(default="", repr=False)
    nvd_timeout_seconds: float = Field(default=20.0, gt=0)
    nvd_max_lookups: int = Field(default=10, ge=0)
    http_max_retries: int = Field(default=2, ge=0, le=5)
    http_max_response_mb: int = Field(default=10, gt=0)

    # --- Hugging Face model ingestion (Phase 3). "mock" serves a synthetic benign fixture
    # repo tagged source="mock". No HF token is used: only public, non-gated repos.
    hf_provider: Literal["hf", "mock"] = "hf"
    hf_timeout_seconds: float = Field(default=30.0, gt=0)
    hf_download_timeout_seconds: int = Field(default=600, gt=0)
    hf_max_file_mb: int = Field(default=64, gt=0)
    hf_max_files: int = Field(default=2000, gt=0)
    # --- Model analysis limits (Phase 3, parse-only)
    pickle_max_mb: int = Field(default=64, gt=0)
    pickle_max_opcodes: int = Field(default=2_000_000, gt=0)
    model_card_max_kb: int = Field(default=256, gt=0)

    # --- Static analysis budgets (Phase 4, parse-only)
    static_max_files: int = Field(default=5000, gt=0)
    static_max_file_kb: int = Field(default=1024, gt=0)
    static_max_total_mb: int = Field(default=64, gt=0)
    static_max_findings: int = Field(default=500, gt=0)
    # Research parameter: a share of MAX_COMPRESSION_RATIO that counts as "near the limit".
    static_archive_ratio_warn_fraction: float = Field(default=0.8, gt=0, le=1)

    # --- Sandbox (Phase 4). "disabled" is the default. "mock" returns a synthetic bundle
    # tagged source="mock". "docker" needs the API on the host, with Docker available.
    # The network mode and other hardening flags are deliberately not settings.
    sandbox_provider: Literal["disabled", "docker", "mock"] = "disabled"
    sandbox_docker_path: str = "docker"
    sandbox_image: str = "provenancex-sandbox:0.1.0"
    sandbox_timeout_seconds: int = Field(default=60, gt=0)
    sandbox_host_grace_seconds: int = Field(default=15, gt=0)
    sandbox_memory_mb: int = Field(default=512, gt=0)
    sandbox_cpus: float = Field(default=1.0, gt=0)
    sandbox_pids_limit: int = Field(default=128, gt=0)
    sandbox_tmp_mb: int = Field(default=64, gt=0)
    sandbox_trace_tmp_mb: int = Field(default=32, gt=0)
    sandbox_max_stderr_kb: int = Field(default=1024, gt=0)
    # Limits are per container, so this caps the total. Applies per API process.
    sandbox_max_concurrent: int = Field(default=2, gt=0)
    sandbox_queue_timeout_seconds: int = Field(default=300, gt=0)
    # Traces are untrusted: parser caps.
    sandbox_max_trace_mb: int = Field(default=16, gt=0)
    sandbox_max_trace_lines: int = Field(default=200_000, gt=0)
    # Research parameters: resource_spike thresholds, as shares of the sandbox limits.
    sandbox_spike_memory_fraction: float = Field(default=0.9, gt=0, le=1)
    sandbox_spike_pids_fraction: float = Field(default=0.9, gt=0, le=1)
    sandbox_spike_cpu_fraction: float = Field(default=0.9, gt=0, le=1)
    sandbox_spike_cpu_min_intervals: int = Field(default=3, gt=0)
    model_path: Path = Path("./ml/models")

    # --- Blockchain (Phase 7). "disabled" is the default. "mock" is an in-memory ledger tagged
    # source="mock", and is never a fallback. "web3" accepts only a local chain.
    blockchain_provider: Literal["disabled", "web3", "mock"] = "disabled"
    blockchain_anchor_on_scan: bool = False
    blockchain_timeout_seconds: float = Field(default=30.0, gt=0)
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
