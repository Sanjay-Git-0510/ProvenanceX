"""The ContentAnalyzer interface, the worker request builder and output validation.

`ContentAnalyzer.extract` / `.analyze` are the only ways the pipeline reaches artifact content.
There is deliberately no "disabled" analyzer: if no sandbox can run, the call raises
sandbox_unavailable and the scan fails. Nothing falls back to processing on the host.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from pydantic import ValidationError

from app.analysis.framing import FrameError, check_json_budget
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.pipeline.workspace import Workspace
from app.sandbox_worker.protocol import (
    AnalysisOut,
    Kind,
    Mode,
    ModelContextIn,
    WorkerLimits,
    WorkerRequest,
    WorkerResult,
)

logger = logging.getLogger(__name__)


# Structural budget for the JSON envelope (app/analysis/framing.py, audit finding M3). Generous
# for real results (a 20,000-file tree, a 2,000-file AI-BOM, 500 static findings), but it caps
# how many Python objects a hostile envelope can expand into.
ENVELOPE_MAX_CONTAINERS = 200_000
ENVELOPE_MAX_ITEMS = 2_000_000
ENVELOPE_MAX_DEPTH = 64
# The raw SBOM frame the runner receives is spooled here (the scan's own workspace), never
# held in memory, and parsed later in a memory-limited child process.
SBOM_INCOMING = ".sbom-incoming.cdx.json"


@dataclass(frozen=True)
class AnalysisJob:
    scan_id: UUID
    workspace: Workspace
    kind: Kind
    has_upload: bool
    revision_requested: str | None = None
    model_context: dict[str, Any] | None = None
    # The per-scan tmpfs staging volume (app/analysis/staging.py) that holds the artifact tree.
    # None only for the in-process test executor, which uses workspace/src directly.
    staging_volume: str | None = None

    @property
    def sbom_path(self) -> Path:
        return self.workspace.root / SBOM_INCOMING


@dataclass
class AnalyzerRun:
    """What one sandbox run produced, plus the facts recorded on Scan.sandbox."""

    result: WorkerResult
    record: dict[str, Any] = field(default_factory=dict)

    @property
    def analysis(self) -> AnalysisOut:
        if self.result.analysis is None:  # guaranteed by WorkerResult for ok analyze results
            raise AppError(ErrorCode.ANALYZER_OUTPUT_INVALID, "Analyzer returned no analysis", 502)
        return self.result.analysis


class ContentAnalyzer(Protocol):
    name: str

    def run(self, job: AnalysisJob, mode: Mode) -> AnalyzerRun:
        """Run one sandboxed mode. Raises AppError (sandbox_* codes) when no result exists."""
        ...


def build_request(settings: Settings, job: AnalysisJob, mode: Mode) -> WorkerRequest:
    limits = WorkerLimits(
        max_artifact_size_mb=settings.max_artifact_size_mb,
        max_artifact_files=settings.max_artifact_files,
        max_compression_ratio=settings.max_compression_ratio,
        max_sbom_mb=settings.max_sbom_mb,
        max_sbom_components=settings.max_sbom_components,
        syft_timeout_seconds=settings.syft_timeout_seconds,
        pickle_max_mb=settings.pickle_max_mb,
        pickle_max_opcodes=settings.pickle_max_opcodes,
        model_card_max_kb=settings.model_card_max_kb,
        static_max_files=settings.static_max_files,
        static_max_file_kb=settings.static_max_file_kb,
        static_max_total_mb=settings.static_max_total_mb,
        static_max_findings=settings.static_max_findings,
        static_archive_ratio_warn_fraction=settings.static_archive_ratio_warn_fraction,
    )
    ctx = ModelContextIn.model_validate(job.model_context) if job.model_context else None
    return WorkerRequest(
        mode=mode,
        kind=job.kind,
        has_upload=job.has_upload,
        revision_requested=job.revision_requested,
        sbom_provider=settings.sbom_provider,
        limits=limits,
        model_context=ctx,
    )


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite number {value} is not allowed")


def parse_worker_output(raw: bytes, max_bytes: int, expected_mode: Mode) -> WorkerResult:
    """Decode and validate the untrusted JSON envelope. Raises analyzer_output_invalid.

    `raw` is the envelope frame only (the framing layer already removed the SBOM frame).
    """

    def invalid(reason: str) -> AppError:
        return AppError(
            ErrorCode.ANALYZER_OUTPUT_INVALID,
            "The analyzer returned output that failed validation; it was discarded",
            502,
            {"reason": reason},
        )

    if not raw:
        raise invalid("empty output")
    if len(raw) > max_bytes:
        raise invalid("output exceeds the size limit")
    try:
        check_json_budget(
            raw,
            max_containers=ENVELOPE_MAX_CONTAINERS,
            max_items=ENVELOPE_MAX_ITEMS,
            max_depth=ENVELOPE_MAX_DEPTH,
        )
    except FrameError as exc:
        raise invalid(str(exc)) from exc
    try:
        data = json.loads(raw, parse_constant=_reject_constant)
    except (ValueError, RecursionError, UnicodeDecodeError) as exc:
        raise invalid("output is not valid JSON") from exc
    try:
        result = WorkerResult.model_validate(data)
    except ValidationError as exc:
        logger.warning("Analyzer output failed schema validation: %s", exc.error_count())
        raise invalid("output does not match the result schema") from exc
    if result.mode != expected_mode:
        raise invalid("output is for a different mode")
    return result


def raise_if_error(run: AnalyzerRun) -> None:
    """Turn a worker error result into the AppError the pipeline records on the scan."""
    err = run.result.error
    if run.result.status != "error" or err is None:
        return
    known = {str(c) for c in ErrorCode}
    code = err.code if err.code in known else str(ErrorCode.INTERNAL_ERROR)
    raise AppError(code, err.message, 400 if code != ErrorCode.INTERNAL_ERROR else 500, err.details)


def section_to_error(err: Any) -> AppError:
    """A per-section error from the worker, re-raised inside the matching host stage."""
    known = {str(c) for c in ErrorCode}
    code = err.code if err.code in known else str(ErrorCode.INTERNAL_ERROR)
    return AppError(code, err.message, 502, err.details)
