"""Pipeline step 10 (optional): dynamic analysis in a disposable sandbox.

The raw trace stays off-chain at <workspace>/sandbox/trace.json (mode 0600); only its
SHA-256 is recorded. When no behavior was observed for any reason, the features are None
rather than 0. A sandbox failure never fails the scan, and a mock is never a fallback.

`partial` means the evidence cannot be trusted as complete (see `incomplete_reasons`).
Observed code can stop or alter its own trace, so a killed tracer or malformed lines must
never read as a quiet, completed run. Phase 6 must treat `error` and `partial` as "not
evaluated / lower confidence", never as quiet.
"""

import hashlib
import os
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.models import Scan
from app.pipeline.stages import StageStatus, execute_stage, skip_stage
from app.pipeline.workspace import MB, Workspace
from app.scanners.sandbox.base import SandboxProvider, SandboxRequest
from app.scanners.sandbox.behavior_findings import behavior_finding, build_behavior_signals
from app.scanners.sandbox.telemetry import (
    SpikeThresholds,
    TelemetryResult,
    TraceLimits,
    parse_trace_bundle,
)

STAGE = "sandbox"
TRACE_DIR = "sandbox"
TRACE_FILENAME = "trace.json"
# strace re-raises a fatal signal on itself, so -9 can also appear as 128 + 9.
KILLED_EXIT_CODES = frozenset({-9, 137})
NO_TRACE_LIMITATION = "The sandbox hit its deadline before returning a trace; nothing was observed."


def _incomplete_reasons(result: TelemetryResult) -> list[str]:
    reasons: list[str] = []
    if result.meta["timed_out"]:
        reasons.append("the run timed out")
    if result.truncated:
        reasons.append("the trace was cut off at its size or line limit")
    if result.features["syscall_count"] is None:
        reasons.append("no syscalls were recorded")
    killed = [t for t in result.meta["targets"] if t["exit_code"] in KILLED_EXIT_CODES]
    if killed:
        reasons.append(
            f"{len(killed)} target(s) were killed (exit -9), so tracing may have stopped early"
        )
    malformed = result.features["malformed_line_count"]
    if malformed:
        reasons.append(f"{malformed} malformed trace line(s): the trace may have been altered")
    return reasons


def _store_trace(root: Path, raw: bytes) -> str:
    directory = root / TRACE_DIR
    directory.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(directory / TRACE_FILENAME, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(raw)
    return f"{TRACE_DIR}/{TRACE_FILENAME}"


def run_sandbox_stage(
    session: Session,
    scan_id: UUID,
    workspace: Workspace,
    settings: Settings,
    provider: SandboxProvider | None,
    kind: str,
) -> dict[str, Any] | None:
    if provider is None:
        skip_stage(session, scan_id, STAGE, "sandbox disabled (SANDBOX_PROVIDER=disabled)")
        return None
    limits = TraceLimits(
        max_bytes=settings.sandbox_max_trace_mb * MB,
        max_lines=settings.sandbox_max_trace_lines,
    )
    thresholds = SpikeThresholds(
        memory_fraction=settings.sandbox_spike_memory_fraction,
        pids_fraction=settings.sandbox_spike_pids_fraction,
        cpu_fraction=settings.sandbox_spike_cpu_fraction,
        cpu_min_intervals=settings.sandbox_spike_cpu_min_intervals,
    )

    def body(scan: Scan) -> tuple[dict[str, Any] | None, StageStatus, dict[str, Any]]:
        run = provider.run(SandboxRequest(scan.id, workspace.src_dir, workspace.root.parent, kind))
        source = "mock" if run.source == "mock" else "sandbox"
        common = {"source": source, "is_mock": source == "mock"}
        if run.raw is None:
            return (
                None,
                StageStatus.PARTIAL,
                {
                    **common,
                    "features": None,
                    "timed_out": run.timed_out,
                    "incomplete_reasons": [NO_TRACE_LIMITATION],
                    "limitations": [NO_TRACE_LIMITATION],
                },
            )
        result = parse_trace_bundle(run.raw, limits, thresholds)
        trace_file = _store_trace(workspace.root, run.raw)
        signals = build_behavior_signals(result)
        session.add_all(
            behavior_finding(scan.id, source, s, synthetic=result.synthetic) for s in signals
        )
        reasons = _incomplete_reasons(result)
        status = StageStatus.PARTIAL if reasons else StageStatus.COMPLETED
        fields = {
            **common,
            "features": result.features,
            "timed_out": result.meta["timed_out"],
            "truncated": result.truncated,
            "incomplete_reasons": reasons,
            "synthetic": result.synthetic,
            "exit_code": result.meta["exit_code"],
            "duration_seconds": result.meta["duration_seconds"],
            "targets": result.meta["targets"],
            "spike_reasons": result.spike_reasons,
            "trace_file": trace_file,
            "trace_sha256": hashlib.sha256(run.raw).hexdigest(),
            "counts": {"findings": len(signals)},
            "limitations": result.limitations,
        }
        return result.features, status, fields

    return execute_stage(session, scan_id, STAGE, body, provider=provider.name)
