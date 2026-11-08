"""Syft CLI adapter: produces a CycloneDX JSON SBOM for an extracted artifact directory.

Safety notes:
- Syft only reads files. It never runs package code or install scripts.
- It runs as an argv list (no shell), with a hard timeout and an output-size cap.
- cwd is the trusted workspace directory, NOT the untrusted source directory, so a
  `.syft.yaml` planted in the artifact is never loaded as configuration.
- Online enrichment (`--enrich`) stays off, and the update check and remote license
  lookups are disabled through the environment, so scanning makes no network calls.
- The environment is reduced to an explicit allowlist, so app secrets (DB URL,
  NVD key, chain key) are not passed to the subprocess.
"""

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path

from app.core.errors import AppError, ErrorCode
from app.scanners.sbom.base import SbomResult

logger = logging.getLogger(__name__)

OUTPUT_NAME = "sbom.syft.cdx.json"
_VERSION_TIMEOUT_SECONDS = 15
_STDERR_TAIL = 2000

_SYFT_ENV = {
    "SYFT_CHECK_FOR_APP_UPDATE": "false",
    "SYFT_JAVA_USE_NETWORK": "false",
    "SYFT_GOLANG_SEARCH_REMOTE_LICENSES": "false",
    "SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES": "false",
    "SYFT_PYTHON_SEARCH_REMOTE_LICENSES": "false",
    "SYFT_LOG_LEVEL": "error",
}
_PASSTHROUGH_ENV = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL")


def _subprocess_env() -> dict[str, str]:
    env = {k: os.environ[k] for k in _PASSTHROUGH_ENV if k in os.environ}
    env.update(_SYFT_ENV)
    return env


class SyftProvider:
    name = "syft"

    def __init__(self, syft_path: str, timeout_seconds: int, max_output_bytes: int) -> None:
        self.syft_path = syft_path
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    def _binary(self) -> str:
        resolved = shutil.which(self.syft_path)
        if resolved is None:
            raise AppError(
                ErrorCode.SBOM_TOOL_UNAVAILABLE,
                "Syft is not installed or not on PATH; SBOM generation unavailable",
                503,
                {"syft_path": self.syft_path},
            )
        return resolved

    def version(self) -> str | None:
        """Best-effort Syft version string. Returns None if the version cannot be read."""
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, resolved binary, no shell
                [self._binary(), "version", "-o", "json"],
                capture_output=True,
                timeout=_VERSION_TIMEOUT_SECONDS,
                env=_subprocess_env(),
                check=False,
            )
            if proc.returncode == 0:
                return str(json.loads(proc.stdout).get("version") or "") or None
        except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
            logger.warning("Could not read Syft version: %s", exc)
        return None

    def generate(self, src_dir: Path, work_dir: Path) -> SbomResult:
        binary = self._binary()
        src_dir = src_dir.resolve()
        work_dir = work_dir.resolve()
        if work_dir == src_dir or work_dir.is_relative_to(src_dir):
            raise AppError(ErrorCode.WORKSPACE_ERROR, "SBOM work dir must be outside source", 500)
        out_path = work_dir / OUTPUT_NAME
        out_path.unlink(missing_ok=True)

        argv = [
            binary,
            "scan",
            f"dir:{src_dir}",
            "-o",
            f"cyclonedx-json={out_path}",
            "--quiet",
            "--exclude",
            "./.git/**",
        ]
        logger.info("Running Syft on %s", src_dir)
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, resolved binary, no shell
                argv,
                cwd=work_dir,
                capture_output=True,
                timeout=self.timeout_seconds,
                env=_subprocess_env(),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            out_path.unlink(missing_ok=True)
            raise AppError(
                ErrorCode.SBOM_TIMEOUT,
                "Syft did not finish within the time limit",
                504,
                {"timeout_seconds": self.timeout_seconds},
            ) from exc
        except OSError as exc:
            raise AppError(
                ErrorCode.SBOM_TOOL_UNAVAILABLE, "Syft could not be started", 503
            ) from exc

        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", "replace")[-_STDERR_TAIL:]
            out_path.unlink(missing_ok=True)
            raise AppError(
                ErrorCode.SBOM_FAILED,
                "Syft exited with an error",
                502,
                {"returncode": proc.returncode, "stderr_tail": stderr},
            )
        if not out_path.is_file():
            raise AppError(ErrorCode.SBOM_FAILED, "Syft produced no SBOM output", 502)
        size = out_path.stat().st_size
        if size > self.max_output_bytes:
            out_path.unlink(missing_ok=True)
            raise AppError(
                ErrorCode.SBOM_TOO_LARGE,
                "SBOM output exceeds the size limit",
                413,
                {"size_bytes": size, "max_bytes": self.max_output_bytes},
            )
        raw = out_path.read_bytes()
        out_path.unlink(missing_ok=True)
        return SbomResult(raw=raw, source="syft", tool_name="syft", tool_version=self.version())
