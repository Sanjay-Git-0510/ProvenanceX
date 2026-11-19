"""Test-only fetcher: runs the same worker code (app/fetch_worker/run.py) in-process.

It refuses to exist outside a pytest run with APP_ENV=test, and the download entry points
refuse to run outside `inprocess_test_context()`. It isolates nothing and its results say so
(isolation_mode="inprocess_test"). Its output goes through the same framing, JSON budget and
schema validation as the container's. The staging area is the workspace's src directory.

Tests inject an HF provider (`hf_provider`) and patch `clone_repository` in this module to
avoid real network access; the live Docker path is covered by the `sandbox`-marked tests.
"""

import io
import json
from typing import Any

from app.analysis.framing import FrameDecoder, FrameError, write_frames
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.fetch.base import FetchJob, FetchRun, build_fetch_request, parse_fetch_output
from app.fetch_worker.errors import section_error
from app.fetch_worker.protocol import RESULT_FORMAT
from app.fetch_worker.run import run_fetch
from app.pipeline.workspace import MB
from app.scanners.git_fetch import clone_repository
from app.scanners.hf.base import HfProvider
from app.security.sandbox_guard import inprocess_test_context, running_under_pytest


def _clone(*args: Any, **kwargs: Any) -> Any:
    # Looked up at call time so tests can monkeypatch `app.fetch.inprocess.clone_repository`.
    return clone_repository(*args, **kwargs)


class InProcessTestFetcher:
    name = "inprocess_test"

    def __init__(
        self,
        settings: Settings,
        *,
        hf_provider: HfProvider | None = None,
        hf_from_settings: bool = True,
    ) -> None:
        if settings.app_env != "test" or not running_under_pytest():
            raise AppError(
                ErrorCode.SANDBOX_REFUSED,
                "The in-process fetcher is available only inside the test suite",
                500,
            )
        self.settings = settings
        self.hf_provider = hf_provider
        # Hand-built test providers pass hf_from_settings=False: a missing HF provider then
        # fails as hf_unavailable instead of silently using the mock.
        self.hf_from_settings = hf_from_settings
        self.max_output = settings.fetcher_max_output_mb * MB

    def run(self, job: FetchJob) -> FetchRun:
        request = build_fetch_request(self.settings, job, proxy=False)
        base: dict[str, Any] = {
            "format": RESULT_FORMAT,
            "isolation_mode": "inprocess_test",
            "isolation": {},
            "source": job.source,
        }
        hf_provider = self.hf_provider
        if job.source == "huggingface" and hf_provider is None:
            if self.hf_from_settings and self.settings.hf_provider == "mock":
                from app.scanners.hf.mock import MockHfProvider

                hf_provider = MockHfProvider()
            else:
                out = {
                    **base,
                    "status": "error",
                    "error": {
                        "code": str(ErrorCode.HF_UNAVAILABLE),
                        "message": "No Hugging Face provider is configured",
                        "details": None,
                    },
                }
                return self._decode(job, out)
        with inprocess_test_context():
            try:
                fields = run_fetch(
                    request,
                    job.workspace.src_dir,
                    hf_provider=hf_provider,
                    clone=lambda *a, **k: _clone(*a, **k),
                )
                out = {**base, "status": "ok", **fields}
            except AppError as exc:
                out = {**base, "status": "error", "error": section_error(exc)}
        return self._decode(job, out)

    def _decode(self, job: FetchJob, out: dict[str, Any]) -> FetchRun:
        framed = io.BytesIO()
        write_frames(framed, json.dumps(out, allow_nan=False, default=str).encode())
        decoder = FrameDecoder(max_envelope=self.max_output, max_sbom=0)
        try:
            decoder.feed(framed.getvalue())
            envelope = decoder.finish()
        except FrameError as exc:
            raise AppError(
                ErrorCode.FETCH_OUTPUT_INVALID, "Invalid fetcher output", 502, {"reason": str(exc)}
            ) from exc
        result = parse_fetch_output(envelope, self.max_output, job.source)
        return FetchRun(
            result=result,
            record={"mode": "fetch", "provider": self.name, "runtime_verified": False},
        )
