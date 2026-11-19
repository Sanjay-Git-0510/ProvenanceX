"""Runs the analyzer worker in a disposable, hardened Docker container (one per mode per scan).

Sequence for every run:
  docker rm -f (stale)  ->  docker create (argv checked by assert_create_hardened)
  ->  docker inspect (verify_runtime_config)  ->  docker start --attach --interactive
  ->  request JSON on stdin, capped stdout/stderr under a host deadline
  ->  docker inspect State (OOM kill, exit code)  ->  docker rm -f   (always, in `finally`)

If the runner dies and the `finally` never runs (SIGKILL), the container still stops on its
own: the worker enforces the in-container deadline and CPU-time limit passed in its command.
The leftover is labelled with its deployment instance, scan id and claim token, and the next
reconciliation pass removes it (app/analysis/reconcile.py). If this runner's claim on the scan
is lost mid-run (stale recovery took the scan), the run is stopped and the container removed.

The Docker CLI runs as an argv list (no shell) with an allowlisted environment. Every failure
raises a sandbox_* AppError. There is no fallback: the caller fails the scan.
"""

import json
import logging
import os
import selectors
import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.analysis.base import AnalysisJob, AnalyzerRun, build_request, parse_worker_output
from app.analysis.hardening import (
    ARTIFACT_DST,
    INPUT_DST,
    NO_CLAIM,
    OUT_DST,
    AnalyzerLimits,
    AnalyzerSpec,
    MountKind,
    MountSpec,
    assert_create_hardened,
    build_create_argv,
    refuse,
    resolve_workspace_dir,
    verify_runtime_config,
)
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.pipeline.ownership import ClaimLost, current_claim
from app.sandbox_worker.protocol import EXIT_CPU_LIMIT, EXIT_DEADLINE, Mode
from app.sandbox_worker.selfcheck import is_isolated

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
_COMMAND_TIMEOUT_SECONDS = 30
_MAX_INSPECT_BYTES = 1024 * 1024
_READ_CHUNK = 65536
_POLL_SECONDS = 0.2
_STDERR_LOG_BYTES = 2000
_DOCKER_ERROR_RETURN_CODES = frozenset({125, 126, 127})
_OOM_EXIT_CODES = frozenset({137, -9})


def _docker_env() -> dict[str, str]:
    return {k: os.environ[k] for k in _PASSTHROUGH_ENV if k in os.environ}


def unavailable(message: str) -> AppError:
    return AppError(ErrorCode.SANDBOX_UNAVAILABLE, message, 503)


def failed(message: str, details: dict[str, Any]) -> AppError:
    return AppError(ErrorCode.SANDBOX_FAILED, message, 502, details)


class DockerAnalyzer:
    name = "docker"

    def __init__(
        self,
        settings: Settings,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self.docker_path = settings.analyzer_docker_path
        self.image = settings.analyzer_image
        self.mount_kind: MountKind = settings.analyzer_workspace_mount
        self.volume = settings.analyzer_workspace_volume
        self.max_output = settings.analyzer_max_output_mb * 1024 * 1024
        self.max_stderr = settings.analyzer_max_stderr_kb * 1024
        self.grace = settings.analyzer_host_grace_seconds
        self.clock = clock
        self._cancel_scan: Any = None

    # ------------------------------------------------------------------ docker CLI helpers
    def _capture(
        self, args: list[str], limit: int = _MAX_INSPECT_BYTES
    ) -> tuple[int | None, bytes]:
        """Run a short docker command. Returns (exit code or None, capped stdout)."""
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [self.docker_path, *args],
                env=_docker_env(),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=_COMMAND_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("docker %s failed: %s", args[0], exc.__class__.__name__)
            return None, b""
        if done.returncode != 0 and done.stderr:
            logger.warning(
                "docker %s: %s", args[0], done.stderr[:_STDERR_LOG_BYTES].decode("utf-8", "replace")
            )
        return done.returncode, done.stdout[:limit]

    def _remove(self, name: str) -> None:
        self._capture(["rm", "-f", name])

    def _limits(self, mode: Mode) -> AnalyzerLimits:
        s = self.settings
        timeout = (
            s.analyzer_extract_timeout_seconds if mode == "extract" else s.analyzer_timeout_seconds
        )
        return AnalyzerLimits(
            timeout_seconds=timeout,
            memory_mb=s.analyzer_memory_mb,
            cpus=s.analyzer_cpus,
            pids=s.analyzer_pids_limit,
            tmp_mb=s.analyzer_tmp_mb,
            cpu_grace_seconds=s.analyzer_cpu_grace_seconds,
        )

    def _mount(
        self, path: Path, job: AnalysisJob, target: str, subdir: str, read_only: bool
    ) -> tuple[MountSpec, int, int]:
        resolved, uid, gid = resolve_workspace_dir(
            path, Path(self.settings.workspace_root), job.scan_id
        )
        source = str(resolved) if self.mount_kind == "bind" else self.volume
        return MountSpec(self.mount_kind, source, target, subdir, read_only, job.scan_id), uid, gid

    def _spec(self, job: AnalysisJob, mode: Mode) -> AnalyzerSpec:
        ws = job.workspace
        wanted: list[tuple[Path, str, str, bool]] = []
        if mode == "extract":
            wanted = [(ws.input_dir, INPUT_DST, "input", True), (ws.src_dir, OUT_DST, "src", False)]
        else:
            wanted = [(ws.src_dir, ARTIFACT_DST, "src", True)]
            if job.has_upload:
                wanted.append((ws.input_dir, INPUT_DST, "input", True))
        mounts, owners = [], set()
        for path, target, subdir, ro in wanted:
            mount, uid, gid = self._mount(path, job, target, subdir, ro)
            mounts.append(mount)
            owners.add((uid, gid))
        if len(owners) != 1:
            raise refuse("Workspace directories have different owners")
        uid, gid = owners.pop()
        claim = current_claim()
        return AnalyzerSpec(
            job.scan_id,
            mode,
            self.image,
            uid,
            gid,
            tuple(mounts),
            self._limits(mode),
            instance=self.settings.analyzer_instance_label,
            claim_token=str(claim.token) if claim and claim.scan_id == job.scan_id else NO_CLAIM,
        )

    @staticmethod
    def _check_claim(job: AnalysisJob) -> None:
        claim = current_claim()
        if claim is not None and claim.scan_id == job.scan_id and claim.lost.is_set():
            raise ClaimLost(job.scan_id)

    # ------------------------------------------------------------------ run
    def _preflight(self) -> str:
        docker = shutil.which(self.docker_path)
        if docker is None:
            raise unavailable(
                "Docker is not available to the scan runner; the artifact was not processed"
            )
        code, _ = self._capture(["version", "--format", "{{.Server.APIVersion}}"])
        if code != 0:
            raise unavailable(
                "The Docker daemon is not reachable from the scan runner (not running, or no "
                "permission on the Docker socket); the artifact was not processed"
            )
        code, _ = self._capture(["image", "inspect", "--format", "{{.Id}}", self.image])
        if code != 0:
            raise unavailable(
                "The analyzer image has not been built (make analyzer-image); "
                "the artifact was not processed"
            )
        return docker

    def _read_capped(
        self,
        proc: subprocess.Popen[bytes],
        deadline: float,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> tuple[bytes, bytes, bool]:
        """Read stdout and stderr to EOF. Returns (stdout, start of stderr, timed out).

        Raises ClaimLost if `cancelled()` turns true (the caller's finally kills the container).
        """
        assert proc.stdout is not None and proc.stderr is not None  # noqa: S101 - PIPEs
        out: list[bytes] = []
        out_total = err_total = 0
        err_head = b""
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            selector.register(proc.stderr, selectors.EVENT_READ)
            while selector.get_map():
                if self.clock() > deadline:
                    return b"".join(out), err_head, True
                if cancelled():
                    raise ClaimLost(self._cancel_scan)
                for key, _ in selector.select(timeout=_POLL_SECONDS):
                    chunk = os.read(key.fd, _READ_CHUNK)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif key.fileobj is proc.stdout:
                        out_total += len(chunk)
                        if out_total > self.max_output:
                            raise AppError(
                                ErrorCode.ANALYZER_OUTPUT_INVALID,
                                "The analyzer output exceeds the size limit; it was discarded",
                                502,
                                {"max_bytes": self.max_output},
                            )
                        out.append(chunk)
                    else:
                        err_total += len(chunk)
                        if err_total > self.max_stderr:
                            raise AppError(
                                ErrorCode.ANALYZER_OUTPUT_INVALID,
                                "The analyzer error output exceeds the size limit",
                                502,
                                {"max_bytes": self.max_stderr},
                            )
                        err_head = (err_head + chunk)[:_STDERR_LOG_BYTES]
        return b"".join(out), err_head, False

    def _attach(self, spec: AnalyzerSpec, request: bytes) -> tuple[bytes, bytes, bool, float]:
        deadline = self.clock() + spec.limits.timeout_seconds + self.grace
        claim = current_claim()
        self._cancel_scan = spec.scan_id

        def cancelled() -> bool:
            return claim is not None and claim.scan_id == spec.scan_id and claim.lost.is_set()

        started = self.clock()
        try:
            proc = subprocess.Popen(  # noqa: S603 - fixed argv; the container was verified
                [self.docker_path, "start", "--attach", "--interactive", spec.name],
                env=_docker_env(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:
            raise unavailable("Docker could not be started") from exc

        def feed() -> None:
            assert proc.stdin is not None  # noqa: S101 - PIPE
            try:
                proc.stdin.write(request)
            except OSError:
                pass  # the container exited early; its result says why
            finally:
                try:
                    proc.stdin.close()
                except OSError:
                    pass

        writer = threading.Thread(target=feed, daemon=True)
        writer.start()
        try:
            assert proc.stdout is not None and proc.stderr is not None  # noqa: S101 - PIPEs
            with proc.stdout, proc.stderr:
                raw, err_head, timed_out = self._read_capped(proc, deadline, cancelled)
            if not timed_out:
                try:
                    proc.wait(timeout=max(1.0, deadline - self.clock()))
                except subprocess.TimeoutExpired:
                    timed_out = True
        finally:
            if proc.poll() is None:
                self._capture(["kill", spec.name])
                proc.kill()
                proc.wait()
            writer.join(timeout=5)
        return raw, err_head, timed_out, self.clock() - started

    def _state(self, name: str) -> dict[str, Any]:
        code, raw = self._capture(["inspect", "--format", "{{json .State}}", name])
        if code != 0:
            return {}
        try:
            state = json.loads(raw)
        except ValueError:
            return {}
        return state if isinstance(state, dict) else {}

    def run(self, job: AnalysisJob, mode: Mode) -> AnalyzerRun:
        docker = self._preflight()
        spec = self._spec(job, mode)
        argv = build_create_argv(docker, spec)
        assert_create_hardened(argv)
        request = build_request(self.settings, job, mode).model_dump_json().encode()
        base = {"mode": mode, "provider": self.name, "image": self.image, "container": spec.name}

        self._check_claim(job)
        self._remove(spec.name)  # a leftover from a crashed runner
        try:
            code, _ = self._capture(argv[1:])
            if code is None:
                raise unavailable("Docker did not respond; the artifact was not processed")
            if code != 0:
                raise failed(
                    "The analyzer container could not be created", {**base, "exit_code": code}
                )
            code, raw_inspect = self._capture(["inspect", spec.name])
            try:
                inspected = json.loads(raw_inspect) if code == 0 else None
            except ValueError:
                inspected = None
            runtime = verify_runtime_config(inspected, spec)

            raw, err_head, timed_out, duration = self._attach(spec, request)
            state = self._state(spec.name)
            exit_code = state.get("ExitCode")
            # The worker stopped itself at its in-container deadline.
            timed_out = timed_out or exit_code == EXIT_DEADLINE
            record = {
                **base,
                "runtime_verified": True,
                "runtime": runtime,
                "exit_code": exit_code,
                "oom_killed": bool(state.get("OOMKilled")),
                "timed_out": timed_out,
                "duration_seconds": round(duration, 3),
            }
            if err_head:
                logger.warning(
                    "Analyzer %s stderr: %s", spec.name, err_head.decode("utf-8", "replace")
                )
            if timed_out:
                raise failed(
                    f"The analyzer exceeded its {spec.limits.timeout_seconds}s time limit "
                    "and was stopped",
                    {"mode": mode, "timed_out": True},
                )
            if record["oom_killed"] or exit_code in _OOM_EXIT_CODES:
                raise failed(
                    f"The analyzer exceeded its {spec.limits.memory_mb} MB memory limit "
                    "and was stopped",
                    {"mode": mode, "oom_killed": True},
                )
            if exit_code == EXIT_CPU_LIMIT:
                raise failed(
                    f"The analyzer exceeded its {spec.limits.cpu_seconds}s CPU-time limit "
                    "and was stopped",
                    {"mode": mode, "cpu_limited": True},
                )
            if exit_code in _DOCKER_ERROR_RETURN_CODES:
                raise failed(
                    "The analyzer container could not be started",
                    {"mode": mode, "exit_code": exit_code},
                )
            if exit_code != 0:
                raise failed(
                    "The analyzer exited abnormally", {"mode": mode, "exit_code": exit_code}
                )

            result = parse_worker_output(raw, self.max_output, mode)
            if result.isolation_mode != "container" or not is_isolated(result.isolation):
                failed_checks = sorted(k for k, v in result.isolation.items() if not v)
                raise refuse(
                    "The analyzer reported that it was not isolated; its output was discarded",
                    {"failed_checks": failed_checks},
                )
            record["isolation"] = result.isolation
            return AnalyzerRun(result=result, record=record)
        finally:
            self._remove(spec.name)
