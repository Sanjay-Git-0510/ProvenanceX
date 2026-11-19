"""Test-only executor: runs the same worker code in-process and validates its output exactly
like the Docker path does (framed output, size caps, JSON budget, schema, SBOM frame checks).

It refuses to exist outside a pytest run with APP_ENV=test, and the worker entry points refuse
to run outside `inprocess_test_context()`. It isolates nothing, and its results say so:
isolation_mode="inprocess_test". There is no staging volume here: the workspace's src directory
plays its role, so `persist` only re-hashes it. The live Docker path is covered by the
`sandbox`-marked tests.
"""

import io
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from app.analysis.base import AnalysisJob, AnalyzerRun, build_request, parse_worker_output
from app.analysis.docker_analyzer import DockerAnalyzer
from app.analysis.framing import FrameDecoder, FrameError, write_frames
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.pipeline.workspace import MB
from app.sandbox_worker.collect import (
    rehash_tree,
    run_analyze,
    run_extract,
    run_rehash,
    run_sbom,
    section_error,
)
from app.sandbox_worker.protocol import RESULT_FORMAT, Mode
from app.scanners.sbom.base import SbomProvider
from app.scanners.sbom.syft import SyftProvider
from app.security.sandbox_guard import inprocess_test_context, running_under_pytest


class InProcessTestAnalyzer:
    name = "inprocess_test"

    def __init__(self, settings: Settings, *, sbom_provider: SbomProvider | None = None) -> None:
        if settings.app_env != "test" or not running_under_pytest():
            raise AppError(
                ErrorCode.SANDBOX_REFUSED,
                "The in-process analyzer is available only inside the test suite",
                500,
            )
        self.settings = settings
        # Lets tests inject failing or recorded SBOMs. With none, a test that selects Syft gets
        # its configured SYFT_PATH (the container always uses the image's own Syft).
        if sbom_provider is None and settings.sbom_provider == "syft":
            sbom_provider = SyftProvider(
                settings.syft_path, settings.syft_timeout_seconds, settings.max_sbom_mb * MB
            )
        self.sbom_provider = sbom_provider
        self.max_output = settings.analyzer_max_output_mb * MB
        self.max_sbom = settings.max_sbom_mb * MB

    # No staging volume or holder in-process.
    def start_holder(self, job: AnalysisJob) -> dict[str, Any]:  # noqa: ARG002
        return {"mode": "hold", "provider": self.name, "runtime_verified": False, "status": "ok"}

    def stop_holder(self, job: AnalysisJob) -> None:
        return None

    def holder_running(self, job: AnalysisJob) -> bool:  # noqa: ARG002
        return True

    def run(self, job: AnalysisJob, mode: Mode) -> AnalyzerRun:
        request = build_request(self.settings, job, mode)
        base = {
            "format": RESULT_FORMAT,
            "mode": mode,
            "isolation_mode": "inprocess_test",
            "isolation": {},
        }
        ws = job.workspace
        if mode == "sbom":
            job.sbom_path.unlink(missing_ok=True)
        with tempfile.TemporaryDirectory(prefix="px-scratch-") as scratch:
            sbom_tmp = Path(scratch) / "sbom.cdx.json"
            with inprocess_test_context():
                try:
                    if mode == "extract":
                        run_extract(request, ws.upload_path, ws.src_dir)
                        out = {**base, "status": "ok"}
                    elif mode == "sbom":
                        sbom_run = run_sbom(
                            request,
                            ws.src_dir,
                            Path(scratch),
                            sbom_out=sbom_tmp,
                            sbom_provider=self.sbom_provider,
                        )
                        out = {**base, "status": "ok", "sbom_run": sbom_run}
                    elif mode == "rehash":
                        out = {**base, "status": "ok", "rehash": run_rehash(request, ws.root)}
                    elif mode == "persist":
                        persisted = rehash_tree(request, ws.src_dir)
                        out = {**base, "status": "ok", "persisted": persisted}
                    else:
                        work = Path(scratch) / "work"
                        work.mkdir()
                        analysis = run_analyze(request, ws.src_dir, ws.upload_path, work)
                        out = {**base, "status": "ok", "analysis": analysis}
                except Exception as exc:  # noqa: BLE001 - mirrors the container entry point
                    out = {**base, "status": "error", "error": section_error(exc)}
            framed = io.BytesIO()
            envelope = json.dumps(out, allow_nan=False).encode()
            sbom_present = (out.get("sbom_run") or {}).get("sbom") is not None
            if sbom_present and sbom_tmp.is_file():
                with sbom_tmp.open("rb") as fh:
                    write_frames(framed, envelope, fh)
            else:
                write_frames(framed, envelope)
        return self._decode(job, mode, framed.getvalue())

    def _decode(self, job: AnalysisJob, mode: Mode, raw: bytes) -> AnalyzerRun:
        handles: list[Any] = []

        def open_sbom() -> Any:
            fd = os.open(job.sbom_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            handle = os.fdopen(fd, "wb")
            handles.append(handle)
            return handle

        decoder = FrameDecoder(
            max_envelope=self.max_output,
            max_sbom=self.max_sbom,
            open_sbom=open_sbom if mode == "sbom" else None,
        )
        ok = False
        try:
            try:
                decoder.feed(raw)
                envelope = decoder.finish()
            except FrameError as exc:
                raise AppError(
                    ErrorCode.ANALYZER_OUTPUT_INVALID,
                    "The analyzer returned output that failed validation; it was discarded",
                    502,
                    {"reason": str(exc)},
                ) from exc
            for handle in handles:
                handle.close()
            result = parse_worker_output(envelope, self.max_output, mode)
            DockerAnalyzer._check_sbom(result, decoder)
            ok = True
        finally:
            for handle in handles:
                handle.close()
            if not ok and mode == "sbom":
                job.sbom_path.unlink(missing_ok=True)
        record = {"mode": mode, "provider": self.name, "runtime_verified": False}
        return AnalyzerRun(result=result, record=record)
