"""Test-only executor: runs the same worker code in-process and validates its output exactly
like the Docker path does (JSON round trip, size cap, schema).

It refuses to exist outside a pytest run with APP_ENV=test, and the worker entry points refuse
to run outside `inprocess_test_context()`. It isolates nothing, and its results say so:
isolation_mode="inprocess_test". It exists so the 2,600-test suite can exercise the pipeline
without Docker; the live Docker path is covered by the `sandbox`-marked tests.
"""

import json
import tempfile
from pathlib import Path

from app.analysis.base import AnalysisJob, AnalyzerRun, build_request, parse_worker_output
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.pipeline.workspace import MB
from app.sandbox_worker.collect import run_analyze, run_extract, section_error
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
        self.max_output = settings.analyzer_max_output_mb * 1024 * 1024

    def run(self, job: AnalysisJob, mode: Mode) -> AnalyzerRun:
        request = build_request(self.settings, job, mode)
        base = {
            "format": RESULT_FORMAT,
            "mode": mode,
            "isolation_mode": "inprocess_test",
            "isolation": {},
        }
        ws = job.workspace
        with inprocess_test_context():
            try:
                if mode == "extract":
                    run_extract(request, ws.upload_path, ws.src_dir)
                    out = {**base, "status": "ok"}
                else:
                    with tempfile.TemporaryDirectory(prefix="px-scratch-") as scratch:
                        analysis = run_analyze(
                            request,
                            ws.src_dir,
                            ws.upload_path,
                            Path(scratch),
                            sbom_provider=self.sbom_provider,
                        )
                    out = {**base, "status": "ok", "analysis": analysis}
            except Exception as exc:  # noqa: BLE001 - mirrors the container entry point
                out = {**base, "status": "error", "error": section_error(exc)}
        raw = json.dumps(out, allow_nan=False).encode()
        result = parse_worker_output(raw, self.max_output, mode)
        record = {"mode": mode, "provider": self.name, "runtime_verified": False}
        return AnalyzerRun(result=result, record=record)
