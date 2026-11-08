"""Sandbox provider interface."""

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import UUID


@dataclass(frozen=True)
class SandboxRequest:
    scan_id: UUID
    src_dir: Path
    workspace_root: Path
    kind: str  # software | model


@dataclass(frozen=True)
class SandboxRun:
    raw: bytes | None  # None: no complete bundle was received
    timed_out: bool
    source: str  # "sandbox" | "mock"


class SandboxProvider(Protocol):
    name: str

    def run(self, request: SandboxRequest) -> SandboxRun:
        """Run the fixed targets for a scan.

        Raises AppError (sandbox_unavailable | sandbox_refused | sandbox_failed |
        sandbox_trace_error).
        """
        ...
