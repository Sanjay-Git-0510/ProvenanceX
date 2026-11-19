"""Analyzer container entry point:
`python -B -m app.sandbox_worker --deadline S --cpu-seconds C --mode MODE`
(MODE: extract, analyze, sbom, persist, rehash or hold).

Reads one WorkerRequest (JSON) from stdin, runs the isolation self-check, then the requested
mode against the fixed mount points, and writes exactly one framed result on stdout
(app/analysis/framing.py): a JSON envelope (WorkerResult) and, for a software analysis, the raw
SBOM as its own frame. It exits 0 whenever it wrote a result, including an error result; any
other exit means the run failed (for example, the kernel killed it at the memory limit).

Self-imposed limits (audit finding M1): see app/sandbox_worker/supervise.py. Only the standard
library is imported before the deadline is armed; the analysis code (pydantic, parsers, Syft
wrapper) is imported by the child, inside the deadline.
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from app.analysis.framing import write_frames
from app.sandbox_worker.supervise import CPU_HARD_MARGIN_SECONDS, positive, supervise

__all__ = ["CPU_HARD_MARGIN_SECONDS", "main", "run", "supervise"]

# Fixed mount points. They are not taken from the request.
ARTIFACT_DIR = Path("/artifact")  # analyze, persist: the staging tree, read-only
INPUT_UPLOAD = Path("/input/upload.zip")  # extract and analyze: the raw upload, read-only
EVIDENCE_DIR = Path("/evidence")  # rehash: the scan's whole workspace, read-only
OUT_SRC = Path("/out/src")  # extract: the staging volume; persist: the workspace src (writable)
SCRATCH = Path("/tmp")  # noqa: S108 - size-limited noexec tmpfs
SBOM_FILE = SCRATCH / "px-sbom.cdx.json"
MAX_REQUEST_BYTES = 4 * 1024 * 1024


def _emit(result: dict[str, Any], sbom: Path | None = None) -> None:
    envelope = json.dumps(result, allow_nan=False, separators=(",", ":")).encode()
    out = sys.stdout.buffer
    if sbom is not None and sbom.is_file():
        with sbom.open("rb") as fh:
            write_frames(out, envelope, fh)
    else:
        write_frames(out, envelope)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deadline", type=positive, default=None)
    parser.add_argument("--cpu-seconds", type=positive, default=None)
    parser.add_argument(
        "--mode", choices=("extract", "analyze", "sbom", "persist", "rehash", "hold"), required=True
    )
    args = parser.parse_args(argv)
    if args.deadline is not None:
        code = supervise(args.deadline, args.cpu_seconds)
        if code is not None:
            return code
    return run(args.mode)


def hold() -> int:
    """Keep the staging volume mounted. Reads nothing; stops at the supervisor's deadline."""
    from app.sandbox_worker.selfcheck import ANALYZER_CHECKS, is_isolated, isolation_report

    if not is_isolated(isolation_report(), ANALYZER_CHECKS):
        return 3  # the runner sees the holder stop and fails the scan
    while True:
        time.sleep(3600)


def run(mode: str) -> int:
    if mode == "hold":
        return hold()
    # Imported here, after the deadline is armed (see the module docstring).
    from app.sandbox_worker.collect import (
        run_analyze,
        run_extract,
        run_persist,
        run_rehash,
        run_sbom,
        section_error,
    )
    from app.sandbox_worker.protocol import RESULT_FORMAT, WorkerRequest
    from app.sandbox_worker.selfcheck import (
        ANALYZER_CHECKS,
        failed_checks,
        is_isolated,
        isolation_report,
    )

    report = isolation_report()
    base: dict[str, Any] = {
        "format": RESULT_FORMAT,
        "mode": mode,
        "isolation_mode": "container",
        "isolation": report,
    }
    if not is_isolated(report, ANALYZER_CHECKS):
        _emit(
            {
                **base,
                "status": "error",
                "error": {
                    "code": "sandbox_refused",
                    "message": "The analyzer container is not isolated; nothing was analyzed",
                    "details": {"failed_checks": failed_checks(report, ANALYZER_CHECKS)},
                },
            }
        )
        return 0

    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("request too large")
        request = WorkerRequest.model_validate_json(raw)
        if request.mode != mode:
            raise ValueError("request mode does not match --mode")
        if mode == "extract":
            run_extract(request, INPUT_UPLOAD, OUT_SRC)
            _emit({**base, "status": "ok"})
        elif mode == "persist":
            persisted = run_persist(request, ARTIFACT_DIR, OUT_SRC)
            _emit({**base, "status": "ok", "persisted": persisted})
        elif mode == "rehash":
            _emit({**base, "status": "ok", "rehash": run_rehash(request, EVIDENCE_DIR)})
        elif mode == "sbom":
            # Syft alone, in its own container (audit finding M4); the SBOM is its own frame.
            sbom_run = run_sbom(request, ARTIFACT_DIR, SCRATCH, sbom_out=SBOM_FILE)
            sbom = SBOM_FILE if sbom_run.get("sbom") is not None else None
            _emit({**base, "status": "ok", "sbom_run": sbom_run}, sbom)
        else:
            analysis = run_analyze(request, ARTIFACT_DIR, INPUT_UPLOAD, SCRATCH)
            _emit({**base, "status": "ok", "analysis": analysis})
    except Exception as exc:  # noqa: BLE001 - reported as a structured error result
        _emit({**base, "status": "error", "error": section_error(exc)})
    return 0


if __name__ == "__main__":
    sys.exit(main())
