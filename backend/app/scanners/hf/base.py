"""Hugging Face provider interface and normalized results."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from app.security.url_validation import HfRepo


@dataclass(frozen=True)
class HfFetchLimits:
    max_total_bytes: int
    max_file_bytes: int  # LFS files above this are listed but not downloaded
    max_files: int
    timeout_seconds: int  # overall download budget


@dataclass
class HfFile:
    """One file from the repository listing and what happened to it."""

    path: str
    size: int
    git_oid: str | None  # git blob SHA-1 (non-LFS) or pointer SHA-1
    lfs_sha256: str | None  # SHA-256 of the real content for LFS files
    downloaded: bool = False
    local_sha256: str | None = None
    hash_verified: bool | None = None
    status: str = "pending"  # downloaded | skipped | rejected | integrity_mismatch | failed
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "lfs": self.lfs_sha256 is not None,
            "lfs_sha256": self.lfs_sha256,
            "git_oid": self.git_oid,
            "downloaded": self.downloaded,
            "local_sha256": self.local_sha256,
            "hash_verified": self.hash_verified,
            "status": self.status,
            "reason": self.reason,
        }


@dataclass
class HfFetchResult:
    source: str  # "huggingface" | "mock"
    repo: HfRepo
    commit_sha: str
    files: list[HfFile]
    meta: dict[str, Any] = field(default_factory=dict)  # author, tags, library_name, ...
    card_data: dict[str, Any] | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def downloaded(self) -> list[HfFile]:
        return [f for f in self.files if f.downloaded]

    def counts(self) -> dict[str, int]:
        statuses: dict[str, int] = {}
        for f in self.files:
            statuses[f.status] = statuses.get(f.status, 0) + 1
        return {
            "listed": len(self.files),
            "downloaded": len(self.downloaded),
            "bytes_listed": sum(f.size for f in self.files),
            "bytes_downloaded": sum(f.size for f in self.downloaded),
            **{f"status_{k}": v for k, v in sorted(statuses.items())},
        }


class HfProvider(Protocol):
    name: str

    def fetch(
        self, repo: HfRepo, revision: str | None, dest: Path, limits: HfFetchLimits
    ) -> HfFetchResult:
        """Resolve the revision, list files, and download the allowed ones into `dest`.

        Raises AppError (hf_access_denied | hf_not_found | hf_unavailable | hf_error).
        """
        ...
