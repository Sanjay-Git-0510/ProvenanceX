"""Application settings loaded from environment variables (and an optional .env file)."""

from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
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
    # Use the real-world software model (MODEL_PATH/realworld/software) for software scans, but
    # only when its digests verify and its quality gates pass; otherwise the synthetic models or
    # the rule-based result are used and the reason is stated. False never tries it.
    realworld_models_enabled: bool = True

    # --- Content analysis (master prompt Phase 1). Every step that reads untrusted artifact
    # content (extraction, tree hashing, manifests, Syft, AI-BOM, pickle/safetensors parsing,
    # static analysis) runs in a disposable analyzer container. There is no "disabled" value
    # and no host fallback: without a working analyzer the scan fails with
    # sandbox_unavailable. "inprocess_test" runs the same worker code in-process and is
    # refused unless APP_ENV=test inside a pytest run.
    analyzer_provider: Literal["docker", "inprocess_test"] = "docker"
    analyzer_docker_path: str = "docker"
    analyzer_image: str = "provenancex-analyzer:0.1.0"
    analyzer_timeout_seconds: int = Field(default=600, gt=0)
    analyzer_extract_timeout_seconds: int = Field(default=300, gt=0)
    analyzer_host_grace_seconds: int = Field(default=15, gt=0)
    # tmpfs pages count toward the memory limit, so keep this well above the tmpfs sizes.
    analyzer_memory_mb: int = Field(default=1536, gt=0)
    analyzer_cpus: float = Field(default=1.0, gt=0)
    analyzer_pids_limit: int = Field(default=128, gt=0)
    analyzer_tmp_mb: int = Field(default=256, gt=0)
    # Cap on the JSON envelope a worker returns (audit finding M3). The SBOM is no longer inside
    # it: it is a separate frame capped by MAX_SBOM_MB and parsed in a child process.
    analyzer_max_output_mb: int = Field(default=12, gt=0, le=64)
    analyzer_persist_timeout_seconds: int = Field(default=120, gt=0)
    # The separate Syft container (audit finding M4): Syft's own timeout plus start-up.
    analyzer_sbom_timeout_seconds: int = Field(default=360, gt=0)
    analyzer_max_stderr_kb: int = Field(default=256, gt=0)
    # How the per-scan workspace reaches the analyzer: "bind" (the runner runs on the host,
    # WORKSPACE_ROOT is a host path) or "volume" (the runner runs in Compose and the
    # workspace is the named volume ANALYZER_WORKSPACE_VOLUME, mounted with volume-subpath).
    analyzer_workspace_mount: Literal["bind", "volume"] = "bind"
    analyzer_workspace_volume: str = "provenancex_workspace"
    # Label value that scopes orphan cleanup to this deployment. Analyzer containers are
    # labelled with it, and the runner only ever removes containers carrying its own value,
    # so another Compose project on the same daemon is never touched. Empty: the volume name.
    analyzer_instance: str = Field(default="", max_length=63, pattern=r"^[A-Za-z0-9_.-]*$")
    # Extra CPU seconds above cpus x timeout before RLIMIT_CPU stops the worker.
    analyzer_cpu_grace_seconds: int = Field(default=30, ge=0)

    # --- Staging storage (Milestone B, audit finding L1). Every artifact tree is written into
    # its own Docker volume backed by a size-limited tmpfs, so the kernel enforces the cap.
    # tmpfs lives in RAM: new volumes are admitted only while this deployment's staging volumes
    # stay within STAGING_TOTAL_MB; otherwise the scan waits up to STAGING_WAIT_SECONDS.
    staging_mb: int = Field(default=512, gt=0)
    staging_total_mb: int = Field(default=1536, gt=0)
    staging_wait_seconds: int = Field(default=300, ge=0)
    # Persistent workspace budget: the kept trees of finished scans (needed by /verify). Before a
    # new tree is persisted, the oldest finished scans' trees are pruned until it fits.
    workspace_max_total_mb: int = Field(default=4096, gt=0)
    # The untrusted SBOM is parsed in a child process with this address-space limit.
    sbom_parse_memory_mb: int = Field(default=768, ge=128)
    sbom_parse_timeout_seconds: int = Field(default=120, gt=0)

    # --- Isolated fetcher (Milestone B, audit finding H1). GitHub and Hugging Face downloads
    # run in a per-scan fetcher container with no Docker socket and no secrets, on an internal
    # Docker network whose only exit is the egress proxy. "inprocess_test" runs the same worker
    # code in-process and is refused unless APP_ENV=test inside a pytest run.
    fetcher_provider: Literal["docker", "inprocess_test"] = "docker"
    fetcher_image: str = "provenancex-fetcher:0.1.0"
    fetcher_network: str = Field(
        default="provenancex_fetch", pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$"
    )
    fetcher_proxy_url: str = Field(
        default="http://egress-proxy:3128", pattern=r"^http://[a-z0-9.-]+:[0-9]{2,5}$"
    )
    fetcher_memory_mb: int = Field(default=1024, gt=0)
    fetcher_cpus: float = Field(default=1.0, gt=0)
    fetcher_pids_limit: int = Field(default=64, gt=0)
    fetcher_tmp_mb: int = Field(default=64, gt=0)
    fetcher_setup_seconds: int = Field(default=30, gt=0)
    fetcher_host_grace_seconds: int = Field(default=15, gt=0)
    fetcher_max_output_mb: int = Field(default=8, gt=0, le=32)
    fetcher_max_concurrent: int = Field(default=2, gt=0)
    fetcher_wait_seconds: int = Field(default=300, ge=0)
    # Exact host names the egress proxy and the fetcher allow (no wildcards). The proxy reads
    # the same list from its own environment (EGRESS_ALLOWED_HOSTS).
    egress_allowed_hosts: Annotated[list[str], NoDecode] = [
        "github.com",
        "huggingface.co",
        "us.aws.cdn.hf.co",
        "cas-bridge.xethub.hf.co",
    ]

    # --- Scan dispatch. "runner": the API only queues; the scan-runner service claims and
    # runs scans. "inline_test" runs the pipeline in an API background task and is refused
    # outside APP_ENV=test.
    scan_dispatch: Literal["runner", "inline_test"] = "runner"
    runner_poll_seconds: float = Field(default=2.0, gt=0)
    # Ownership of a running scan (app/pipeline/ownership.py). The owning runner renews the
    # heartbeat every RUNNER_HEARTBEAT_SECONDS; a RUNNING scan with no heartbeat for
    # RUNNER_STALE_SECONDS is failed as runner_interrupted and its claim token replaced, so the
    # old runner can no longer write to it. A scan claimed more than RUNNER_MAX_SCAN_SECONDS ago
    # is failed even if its heartbeat is fresh (a hung pipeline). Compose sets the runner's
    # stop_grace_period from RUNNER_MAX_SCAN_SECONDS.
    runner_heartbeat_seconds: float = Field(default=10.0, gt=0)
    runner_stale_seconds: int = Field(default=120, gt=0)
    runner_max_scan_seconds: int = Field(default=1800, gt=0)
    # How often an idle runner recovers stale claims and removes orphaned analyzer containers.
    runner_reconcile_seconds: float = Field(default=30.0, gt=0)
    # Identity recorded on claims. Must be unique per runner replica; empty: the hostname
    # (in Compose, the container id, which survives a restart of the same container).
    runner_id: str = Field(default="", max_length=128)
    # Watchdog (app/runner/watchdog.py): a sandbox step still running this long after its own
    # deadline, or a scan past RUNNER_MAX_SCAN_SECONDS, is failed by the runner itself, its
    # containers are removed, and the process exits so Compose restarts it.
    runner_watchdog_grace_seconds: int = Field(default=60, gt=0)
    runner_watchdog_exit_seconds: int = Field(default=30, gt=0)

    # --- Verification jobs (Milestone C1, audit finding M5). POST /verify only queues a job;
    # the scan-runner re-hashes the kept evidence in a read-only `rehash` analyzer container and
    # compares it with the anchor and the chain. One active job per scan (database-enforced);
    # beyond VERIFY_MAX_PENDING queued jobs the API answers 429. A job running longer than
    # VERIFY_MAX_SECONDS, or whose heartbeat stops, is failed and answers UNKNOWN.
    verify_rehash_timeout_seconds: int = Field(default=300, gt=0)
    verify_max_seconds: int = Field(default=600, gt=0)
    verify_max_pending: int = Field(default=50, gt=0, le=10000)

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

    @property
    def analyzer_instance_label(self) -> str:
        return self.analyzer_instance or self.analyzer_workspace_volume

    @model_validator(mode="after")
    def _runner_timing(self) -> "Settings":
        # Three missed heartbeats before a claim can be declared stale, so a slow database
        # round trip never fails a healthy scan.
        if self.runner_stale_seconds < 3 * self.runner_heartbeat_seconds:
            raise ValueError("RUNNER_STALE_SECONDS must be at least 3 x RUNNER_HEARTBEAT_SECONDS")
        # A legitimate scan with every sandbox step at its limit must fit in the ceiling:
        # fetch or extract, then analyze, then persist.
        analyzer_budget = (
            max(
                self.analyzer_extract_timeout_seconds,
                self.fetch_timeout_seconds("github"),
                self.fetch_timeout_seconds("huggingface"),
            )
            + self.analyzer_timeout_seconds
            + self.analyzer_sbom_timeout_seconds
            + self.analyzer_persist_timeout_seconds
            + 3 * self.analyzer_host_grace_seconds
            + self.fetcher_host_grace_seconds
        )
        if self.analyzer_sbom_timeout_seconds < self.syft_timeout_seconds + 30:
            raise ValueError(
                "ANALYZER_SBOM_TIMEOUT_SECONDS must exceed SYFT_TIMEOUT_SECONDS by at least 30s"
            )
        if self.verify_max_seconds < self.verify_rehash_timeout_seconds + 2 * (
            self.analyzer_host_grace_seconds
        ):
            raise ValueError(
                "VERIFY_MAX_SECONDS must cover VERIFY_REHASH_TIMEOUT_SECONDS plus its grace"
            )
        if self.runner_max_scan_seconds < analyzer_budget:
            raise ValueError(
                "RUNNER_MAX_SCAN_SECONDS must cover the fetch, analyzer and persist time limits "
                f"plus their grace ({analyzer_budget}s)"
            )
        return self

    def fetch_timeout_seconds(self, source: str) -> int:
        """In-container deadline of one fetch: the source's own budget plus setup time."""
        budget = (
            self.git_clone_timeout_seconds
            if source == "github"
            else self.hf_download_timeout_seconds
        )
        return budget + self.fetcher_setup_seconds

    @model_validator(mode="after")
    def _storage_budgets(self) -> "Settings":
        if self.staging_mb < self.max_artifact_size_mb:
            raise ValueError("STAGING_MB must be at least MAX_ARTIFACT_SIZE_MB")
        if self.staging_total_mb < self.staging_mb:
            raise ValueError("STAGING_TOTAL_MB must be at least STAGING_MB")
        # tmpfs pages are charged to the memory cgroup of the container that writes them.
        if self.fetcher_memory_mb <= self.staging_mb:
            raise ValueError("FETCHER_MEMORY_MB must be larger than STAGING_MB")
        if self.analyzer_memory_mb <= self.staging_mb:
            raise ValueError("ANALYZER_MEMORY_MB must be larger than STAGING_MB")
        if self.workspace_max_total_mb < self.max_artifact_size_mb:
            raise ValueError("WORKSPACE_MAX_TOTAL_MB must be at least MAX_ARTIFACT_SIZE_MB")
        for host in self.egress_allowed_hosts:
            if (
                not host
                or "*" in host
                or not all(part and part.replace("-", "").isalnum() for part in host.split("."))
            ):
                raise ValueError(f"EGRESS_ALLOWED_HOSTS has an invalid host name: {host!r}")
        return self

    @model_validator(mode="after")
    def _test_only_modes(self) -> "Settings":
        if self.app_env != "test":
            if self.analyzer_provider == "inprocess_test":
                raise ValueError(
                    "ANALYZER_PROVIDER=inprocess_test is allowed only with APP_ENV=test"
                )
            if self.fetcher_provider == "inprocess_test":
                raise ValueError(
                    "FETCHER_PROVIDER=inprocess_test is allowed only with APP_ENV=test"
                )
            if self.scan_dispatch == "inline_test":
                raise ValueError("SCAN_DISPATCH=inline_test is allowed only with APP_ENV=test")
        return self

    @field_validator("cors_origins", "egress_allowed_hosts", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        # Allow a comma-separated string in env vars.
        if isinstance(value, str):
            return [v.strip() for v in value.split(",") if v.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
