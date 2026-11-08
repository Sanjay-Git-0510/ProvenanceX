"""SBOM provider interface."""

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class SbomResult:
    """Raw SBOM bytes as produced by a provider, before parsing."""

    raw: bytes
    source: str  # "syft" | "mock"
    tool_name: str
    tool_version: str | None
    format: str = "cyclonedx-json"


class SbomProvider(Protocol):
    name: str

    def generate(self, src_dir: Path, work_dir: Path) -> SbomResult:
        """Produce a CycloneDX JSON SBOM for `src_dir`.

        `work_dir` is a trusted scratch directory (never inside `src_dir`).
        Raises AppError with an SBOM_* code on failure.
        """
        ...
