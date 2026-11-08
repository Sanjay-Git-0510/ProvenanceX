"""Runs the fixed sandbox targets in a disposable Docker container.

The Docker CLI runs as an argv list (no shell), with an allowlisted environment. The
command is built and then independently verified in hardening.py. The trace bundle comes
back over the container's stdout. Stdout and stderr are both read with byte caps and a
host deadline, because code in the container can write to both. A `docker rm -f` always
runs afterwards. Concurrent runs are limited per API process.
"""

import logging
import os
import selectors
import shutil
import subprocess
import threading
import time
from collections.abc import Callable

from app.core.errors import AppError, ErrorCode
from app.scanners.sandbox.base import SandboxRequest, SandboxRun
from app.scanners.sandbox.hardening import (
    SandboxLimits,
    SandboxSpec,
    assert_hardened,
    build_docker_argv,
    resolve_artifact_source,
)

logger = logging.getLogger(__name__)

_PASSTHROUGH_ENV = (
    "PATH",
    "HOME",
    "DOCKER_HOST",
    "DOCKER_CONFIG",
    "DOCKER_CONTEXT",
    "XDG_RUNTIME_DIR",
    "TMPDIR",
)
_COMMAND_TIMEOUT_SECONDS = 20
_READ_CHUNK = 65536
_POLL_SECONDS = 0.2
_DOCKER_ERROR_RETURN_CODES = frozenset({125, 126, 127})
_STDERR_LOG_BYTES = 2000
DEFAULT_MAX_STDERR_BYTES = 1024 * 1024
DEFAULT_MAX_CONCURRENT = 2
DEFAULT_QUEUE_TIMEOUT_SECONDS = 300.0

# Providers are built per request, so the slots must outlive any one instance.
_slots_lock = threading.Lock()
_slots: dict[int, threading.BoundedSemaphore] = {}


def _concurrency_slots(limit: int) -> threading.BoundedSemaphore:
    with _slots_lock:
        return _slots.setdefault(limit, threading.BoundedSemaphore(limit))


def _unavailable(message: str) -> AppError:
    return AppError(ErrorCode.SANDBOX_UNAVAILABLE, message, 503)


def _docker_env() -> dict[str, str]:
    return {k: os.environ[k] for k in _PASSTHROUGH_ENV if k in os.environ}


class DockerSandboxProvider:
    name = "docker"

    def __init__(
        self,
        docker_path: str,
        image: str,
        limits: SandboxLimits,
        max_trace_bytes: int,
        grace_seconds: int,
        clock: Callable[[], float] = time.monotonic,
        *,
        max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        queue_timeout_seconds: float = DEFAULT_QUEUE_TIMEOUT_SECONDS,
    ) -> None:
        self.docker_path = docker_path
        self.image = image
        self.limits = limits
        self.max_trace_bytes = max_trace_bytes
        self.grace_seconds = grace_seconds
        self.clock = clock
        self.max_stderr_bytes = max_stderr_bytes
        self.max_concurrent = max_concurrent
        self.queue_timeout_seconds = queue_timeout_seconds

    def _short(self, *args: str) -> int | None:
        """Run a short docker command. Returns its exit code, or None if it could not run."""
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [self.docker_path, *args],
                env=_docker_env(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=_COMMAND_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("docker %s failed: %s", args[0], exc.__class__.__name__)
            return None
        return done.returncode

    def _resolve_docker(self) -> str:
        resolved = shutil.which(self.docker_path)
        if resolved is None:
            raise _unavailable("Docker is not available to the API process")
        return resolved

    def _require_image(self) -> None:
        if self._short("image", "inspect", self.image) != 0:
            raise _unavailable("Docker is not running, or the sandbox image has not been built")

    def _kill(self, name: str, proc: subprocess.Popen[bytes]) -> None:
        self._short("kill", name)
        if proc.poll() is None:
            proc.kill()
        proc.wait()

    def _over_limit(
        self, proc: subprocess.Popen[bytes], name: str, stream_name: str, limit: int
    ) -> AppError:
        self._kill(name, proc)
        return AppError(
            ErrorCode.SANDBOX_TRACE_ERROR,
            f"Sandbox {stream_name} exceeds the size limit",
            502,
            {"max_bytes": limit},
        )

    def _read_capped(
        self, proc: subprocess.Popen[bytes], name: str, deadline: float
    ) -> tuple[bytes | None, bytes, bool]:
        """Read stdout and stderr to EOF. Returns (stdout, start of stderr, timed out)."""
        assert proc.stdout is not None and proc.stderr is not None  # noqa: S101 - PIPEs
        stdout_chunks: list[bytes] = []
        stdout_total = stderr_total = 0
        stderr_head = b""
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            selector.register(proc.stderr, selectors.EVENT_READ)
            while selector.get_map():
                if self.clock() > deadline:
                    self._kill(name, proc)
                    return None, stderr_head, True
                for key, _ in selector.select(timeout=_POLL_SECONDS):
                    chunk = os.read(key.fd, _READ_CHUNK)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif key.fileobj is proc.stdout:
                        stdout_total += len(chunk)
                        if stdout_total > self.max_trace_bytes:
                            raise self._over_limit(proc, name, "trace", self.max_trace_bytes)
                        stdout_chunks.append(chunk)
                    else:
                        stderr_total += len(chunk)
                        if stderr_total > self.max_stderr_bytes:
                            raise self._over_limit(proc, name, "stderr", self.max_stderr_bytes)
                        stderr_head = (stderr_head + chunk)[:_STDERR_LOG_BYTES]
        return b"".join(stdout_chunks), stderr_head, False

    def _execute(self, argv: list[str], name: str) -> SandboxRun:
        deadline = self.clock() + self.limits.timeout_seconds + self.grace_seconds
        try:
            proc = subprocess.Popen(  # noqa: S603 - verified by assert_hardened
                argv,
                env=_docker_env(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:
            raise _unavailable("Docker could not be started") from exc
        try:
            assert proc.stdout is not None and proc.stderr is not None  # noqa: S101 - PIPEs
            with proc.stdout, proc.stderr:
                raw, stderr_head, timed_out = self._read_capped(proc, name, deadline)
            if timed_out:
                logger.warning("Sandbox %s hit the host deadline", name)
                return SandboxRun(None, True, "sandbox")
            remaining = max(1.0, deadline - self.clock())
            try:
                code = proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                self._kill(name, proc)
                return SandboxRun(None, True, "sandbox")
        finally:
            if proc.poll() is None:
                self._kill(name, proc)
        if code in _DOCKER_ERROR_RETURN_CODES:
            logger.warning(
                "docker run failed (%s): %s", code, stderr_head.decode("utf-8", "replace")
            )
            raise AppError(ErrorCode.SANDBOX_FAILED, "The sandbox could not be started", 502)
        if not raw:
            raise AppError(
                ErrorCode.SANDBOX_TRACE_ERROR,
                "The sandbox did not return a trace",
                502,
                {"exit_code": code},
            )
        return SandboxRun(raw, False, "sandbox")

    def run(self, request: SandboxRequest) -> SandboxRun:
        docker = self._resolve_docker()
        self._require_image()
        source, uid, gid = resolve_artifact_source(request.src_dir, request.workspace_root)
        spec = SandboxSpec(
            scan_id=request.scan_id,
            image=self.image,
            src_dir=source,
            uid=uid,
            gid=gid,
            kind=request.kind,
            limits=self.limits,
        )
        argv = build_docker_argv(docker, spec)
        assert_hardened(argv)
        slots = _concurrency_slots(self.max_concurrent)
        if not slots.acquire(timeout=self.queue_timeout_seconds):
            raise _unavailable("Too many sandbox runs are in progress; this run was not started")
        try:
            return self._execute(argv, spec.name)
        finally:
            slots.release()
            # Also covers a killed `docker run` client whose container is still present.
            self._short("rm", "-f", spec.name)
