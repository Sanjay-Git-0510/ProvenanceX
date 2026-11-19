"""The JSON contract between the scan-runner (host) and the analyzer worker (container).

The request is trusted (the runner writes it). The result is untrusted: code in the container
parsed attacker-controlled bytes, so the runner caps its size before decoding, then validates
it against these models (unknown fields are rejected) before anything is stored.
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.sandbox_worker.exitcodes import EXIT_CPU_LIMIT, EXIT_DEADLINE  # noqa: F401 - re-export

REQUEST_FORMAT = "provenancex-analyzer-request-v1"
RESULT_FORMAT = "provenancex-analyzer-result-v1"

Mode = Literal["extract", "analyze"]
Kind = Literal["software", "model"]

_HEX64 = r"^[0-9a-f]{64}$"
MAX_LIST = 200_000
MAX_PATH = 4096


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------- request
class WorkerLimits(_Strict):
    max_artifact_size_mb: int = Field(gt=0)
    max_artifact_files: int = Field(gt=0)
    max_compression_ratio: float = Field(gt=1)
    max_sbom_mb: int = Field(gt=0)
    max_sbom_components: int = Field(gt=0)
    syft_timeout_seconds: int = Field(gt=0)
    pickle_max_mb: int = Field(gt=0)
    pickle_max_opcodes: int = Field(gt=0)
    model_card_max_kb: int = Field(gt=0)
    static_max_files: int = Field(gt=0)
    static_max_file_kb: int = Field(gt=0)
    static_max_total_mb: int = Field(gt=0)
    static_max_findings: int = Field(gt=0)
    static_archive_ratio_warn_fraction: float = Field(gt=0, le=1)


class RemoteOnlyIn(_Strict):
    path: str = Field(max_length=MAX_PATH)
    size: int = Field(ge=0)
    remote_sha256: str | None = Field(default=None, max_length=64)
    skip_reason: str = Field(max_length=512)


class ModelContextIn(_Strict):
    name: str = Field(max_length=255)
    artifact_type: str = Field(max_length=32)
    source: str = Field(max_length=32)
    source_url: str | None = Field(default=None, max_length=2048)
    repo_id: str | None = Field(default=None, max_length=256)
    commit_sha: str | None = Field(default=None, max_length=64)
    remote_only: list[RemoteOnlyIn] = Field(default_factory=list, max_length=MAX_LIST)
    remote_hashes: dict[str, str | None] = Field(default_factory=dict)
    api_card_data: dict[str, Any] | None = None
    api_meta: dict[str, Any] = Field(default_factory=dict)


class WorkerRequest(_Strict):
    format: Literal["provenancex-analyzer-request-v1"] = REQUEST_FORMAT
    mode: Mode
    kind: Kind
    has_upload: bool
    revision_requested: str | None = Field(default=None, max_length=255)
    sbom_provider: Literal["syft", "mock"] = "syft"
    limits: WorkerLimits
    model_context: ModelContextIn | None = None


# --------------------------------------------------------------------------- result
class SectionError(_Strict):
    code: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    message: str = Field(max_length=2000)
    details: Any = None


class TreeOut(_Strict):
    sha256: str = Field(pattern=_HEX64)
    file_count: int = Field(ge=0)
    total_bytes: int = Field(ge=0)


class ManifestOut(_Strict):
    path: str = Field(max_length=MAX_PATH)
    ecosystem: str = Field(max_length=64)
    kind: str = Field(max_length=64)


class ProjectPackageOut(_Strict):
    ecosystem: str = Field(max_length=64)
    name: str = Field(max_length=512)
    version: str | None = Field(default=None, max_length=256)
    manifest: str = Field(max_length=MAX_PATH)


class SbomOut(_Strict):
    raw: str
    source: Literal["syft", "mock"]
    tool_name: str = Field(max_length=128)
    tool_version: str | None = Field(default=None, max_length=128)
    format: str = Field(max_length=64)


class AnalysisOut(_Strict):
    tree: TreeOut
    file_paths: list[str] = Field(max_length=MAX_LIST)
    manifests: list[ManifestOut] = Field(default_factory=list, max_length=MAX_LIST)
    manifests_truncated: bool = False
    project_packages: list[ProjectPackageOut] = Field(default_factory=list, max_length=64)
    sbom_provider: str | None = Field(default=None, max_length=32)
    sbom: SbomOut | None = None
    sbom_error: SectionError | None = None
    aibom: dict[str, Any] | None = None
    aibom_error: SectionError | None = None
    static: dict[str, Any] | None = None
    static_error: SectionError | None = None
    config_sha256: str | None = Field(default=None, pattern=_HEX64)
    config_sha256_error: SectionError | None = None
    declared_versions: dict[str, str] | None = None
    declared_versions_error: SectionError | None = None

    @model_validator(mode="after")
    def _paths_bounded(self) -> "AnalysisOut":
        if any(len(p) > MAX_PATH for p in self.file_paths):
            raise ValueError("file path too long")
        if self.declared_versions is not None and len(self.declared_versions) > 64:
            raise ValueError("too many declared versions")
        return self


class WorkerResult(_Strict):
    format: Literal["provenancex-analyzer-result-v1"] = RESULT_FORMAT
    mode: Mode
    status: Literal["ok", "error"]
    isolation_mode: Literal["container", "inprocess_test"]
    isolation: dict[str, bool] = Field(max_length=32)
    error: SectionError | None = None
    analysis: AnalysisOut | None = None

    @model_validator(mode="after")
    def _consistent(self) -> "WorkerResult":
        if self.status == "error":
            if self.error is None or self.analysis is not None:
                raise ValueError("an error result carries exactly one error and no analysis")
        else:
            if self.error is not None:
                raise ValueError("an ok result carries no error")
            if (self.mode == "analyze") != (self.analysis is not None):
                raise ValueError("only an ok analyze result carries an analysis")
        return self
