"""The JSON contract between the scan-runner and the fetcher worker (container).

The request is trusted (the runner writes it). The result is untrusted: the fetcher talked to the
internet and parsed Hub JSON and git objects. The runner caps its size (framing), checks its
structural JSON budget, then validates it against these strict models (unknown fields refused,
booleans strict) before anything is used. The runner never reads the downloaded files.
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

REQUEST_FORMAT = "provenancex-fetch-request-v1"
RESULT_FORMAT = "provenancex-fetch-result-v1"

Source = Literal["github", "huggingface"]
_SHA = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
_HEX64 = r"^[0-9a-f]{64}$"
_HEX40 = r"^[0-9a-f]{40}$"
MAX_FILES = 200_000
MAX_PATH = 4096
FILE_STATUSES = ("pending", "downloaded", "skipped", "rejected", "integrity_mismatch", "failed")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------- request
class FetchLimits(_Strict):
    max_total_bytes: int = Field(gt=0)
    max_files: int = Field(gt=0)
    max_file_bytes: int = Field(gt=0)
    timeout_seconds: int = Field(gt=0)
    hf_api_timeout_seconds: float = Field(gt=0)
    http_max_retries: int = Field(ge=0, le=5)
    max_api_bytes: int = Field(gt=0)


class FetchRequest(_Strict):
    format: Literal["provenancex-fetch-request-v1"] = REQUEST_FORMAT
    source: Source
    url: str = Field(max_length=2048)
    revision: str | None = Field(default=None, max_length=255)
    hf_provider: Literal["hf", "mock"] = "hf"
    # The egress proxy. Always set for the container; None only in the in-process test fetcher.
    proxy_url: str | None = Field(default=None, pattern=r"^http://[a-z0-9.-]+:[0-9]{2,5}$")
    allowed_hosts: list[str] = Field(max_length=32)
    user_agent: str = Field(max_length=128)
    limits: FetchLimits


# --------------------------------------------------------------------------- result
class SectionError(_Strict):
    code: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    message: str = Field(max_length=2000)
    details: Any = None


class HfFileOut(_Strict):
    path: str = Field(max_length=MAX_PATH)
    size: int = Field(ge=0)
    lfs: StrictBool
    lfs_sha256: str | None = Field(default=None, pattern=_HEX64)
    git_oid: str | None = Field(default=None, pattern=_HEX40)
    downloaded: StrictBool
    local_sha256: str | None = Field(default=None, pattern=_HEX64)
    hash_verified: StrictBool | None = None
    status: Literal["pending", "downloaded", "skipped", "rejected", "integrity_mismatch", "failed"]
    reason: str | None = Field(default=None, max_length=512)


class HfOut(_Strict):
    source: Literal["huggingface", "mock"]
    repo_id: str = Field(max_length=256)
    repo_type: Literal["model", "dataset"]
    files: list[HfFileOut] = Field(max_length=MAX_FILES)
    meta: dict[str, Any] = Field(default_factory=dict)
    card_data: dict[str, Any] | None = None
    warnings: list[str] = Field(default_factory=list, max_length=100)


class GitOut(_Strict):
    commit_sha: str = Field(pattern=_SHA)
    revision: str | None = Field(default=None, max_length=255)


class FetchResult(_Strict):
    format: Literal["provenancex-fetch-result-v1"] = RESULT_FORMAT
    status: Literal["ok", "error"]
    isolation_mode: Literal["container", "inprocess_test"]
    isolation: dict[str, StrictBool] = Field(max_length=32)
    source: Source
    error: SectionError | None = None
    commit_sha: str | None = Field(default=None, pattern=_SHA)
    git: GitOut | None = None
    hf: HfOut | None = None
    # What the fetcher wrote into the staging volume (regular files only).
    file_count: int | None = Field(default=None, ge=0)
    total_bytes: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _consistent(self) -> "FetchResult":
        if self.status == "error":
            if self.error is None or self.git is not None or self.hf is not None:
                raise ValueError("an error result carries exactly one error and no evidence")
            return self
        if self.error is not None or self.commit_sha is None:
            raise ValueError("an ok result carries a commit and no error")
        if self.source == "github" and (self.git is None or self.hf is not None):
            raise ValueError("a GitHub result carries git evidence only")
        if self.source == "huggingface" and (self.hf is None or self.git is not None):
            raise ValueError("a Hugging Face result carries Hub evidence only")
        if self.git is not None and self.git.commit_sha != self.commit_sha:
            raise ValueError("commit mismatch")
        return self
