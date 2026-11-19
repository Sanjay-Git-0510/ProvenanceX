"""Runs the analyzer worker in a disposable, hardened Docker container (one per mode per scan).

Sequence for every run:
  docker rm -f (stale)  ->  docker create (argv checked by assert_create_hardened)
  ->  docker inspect (verify_runtime_config, including the L3 checks)
  ->  docker start --attach --interactive
  ->  request JSON on stdin; framed stdout decoded incrementally under a host deadline
      (envelope kept in memory up to ANALYZER_MAX_OUTPUT_MB; SBOM frame streamed to a file)
  ->  docker inspect State (OOM kill, exit code)  ->  docker rm -f   (always, in `finally`)

Modes and mounts (app/analysis/hardening.py): every mode works on the scan's kernel-capped tmpfs
staging volume (app/analysis/staging.py). A `hold` container keeps that volume mounted for the
whole scan, because Docker unmounts a tmpfs volume, and its data is lost, as soon as no container
uses it. The holder reads nothing and stops by itself at its in-container deadline.

If the runner dies and the `finally` never runs (SIGKILL), the containers still stop on their own
(in-container deadline and CPU-time limit) and the reconciler removes them. If this runner's claim
on the scan is lost mid-run, the run is stopped and the container removed.

The Docker CLI runs as an argv list (no shell) with an allowlisted environment. Every failure
raises a sandbox_* AppError. There is no fallback: the caller fails the scan.
"""

import hashlib
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
from typing import Any, BinaryIO

from app.analysis.base import AnalysisJob, AnalyzerRun, build_request, parse_worker_output
from app.analysis.docker_cli import docker_env
from app.analysis.framing import FrameDecoder, FrameError
from app.analysis.hardening import (
    ARTIFACT_DST,
    EVIDENCE_DST,
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
from app.core.bounded import printable_excerpt
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.pipeline.ownership import ClaimLost, current_claim
from app.sandbox_worker.protocol import EXIT_CPU_LIMIT, EXIT_DEADLINE, Mode
from app.sandbox_worker.selfcheck import ANALYZER_CHECKS, failed_checks, is_isolated

logger = logging.getLogger(__name__)

_COMMAND_TIMEOUT_SECONDS = 30
_MAX_INSPECT_BYTES = 1024 * 1024
_READ_CHUNK = 65536
_POLL_SECONDS = 0.2
_STDERR_LOG_BYTES = 2000
_DOCKER_ERROR_RETURN_CODES = frozenset({125, 126, 127})
_OOM_EXIT_CODES = frozenset({137, -9})
MB = 1024 * 1024
# The holder only sleeps: tiny limits.
HOLD_MEMORY_MB = 48
HOLD_CPUS = 0.1
HOLD_PIDS = 8
HOLD_TMP_MB = 1


def _docker_env() -> dict[str, str]:
    return docker_env()


def unavailable(message: str) -> AppError:
    return AppError(ErrorCode.SANDBOX_UNAVAILABLE, message, 503)


def failed(message: str, details: dict[str, Any]) -> AppError:
    return AppError(ErrorCode.SANDBOX_FAILED, message, 502, details)


def output_invalid(reason: str, details: dict[str, Any] | None = None) -> AppError:
    return AppError(
        ErrorCode.ANALYZER_OUTPUT_INVALID,
        "The analyzer returned output that failed validation; it was discarded",
        502,
        {"reason": reason, **(details or {})},
    )


class ContainerCli:
    """Docker CLI plumbing shared by the analyzer and the fetcher runners."""

    docker_path: str
    max_output: int
    max_stderr: int
    clock: Callable[[], float]

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
                "docker %s: %s", args[0], printable_excerpt(done.stderr[:_STDERR_LOG_BYTES])
            )
        return done.returncode, done.stdout[:limit]

    def _remove(self, name: str) -> None:
        self._capture(["rm", "-f", name])

    def _inspect(self, name: str) -> Any:
        code, raw = self._capture(["inspect", name])
        try:
            return json.loads(raw) if code == 0 else None
        except ValueError:
            return None

    def _state(self, name: str) -> dict[str, Any]:
        code, raw = self._capture(["inspect", "--format", "{{json .State}}", name])
        if code != 0:
            return {}
        try:
            state = json.loads(raw)
        except ValueError:
            return {}
        return state if isinstance(state, dict) else {}

    def _read_frames(
        self,
        proc: subprocess.Popen[bytes],
        deadline: float,
        decoder: FrameDecoder,
        cancelled: Callable[[], bool],
        cancel_scan: Any,
    ) -> tuple[bytes, bool]:
        """Feed stdout to `decoder` until EOF. Returns (start of stderr, timed out).

        Raises analyzer_output_invalid for malformed or oversized frames, and ClaimLost if
        `cancelled()` turns true (the caller's finally kills the container).
        """
        assert proc.stdout is not None and proc.stderr is not None  # noqa: S101 - PIPEs
        err_total = 0
        err_head = b""
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            selector.register(proc.stderr, selectors.EVENT_READ)
            while selector.get_map():
                if self.clock() > deadline:
                    return err_head, True
                if cancelled():
                    raise ClaimLost(cancel_scan)
                for key, _ in selector.select(timeout=_POLL_SECONDS):
                    chunk = os.read(key.fd, _READ_CHUNK)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif key.fileobj is proc.stdout:
                        try:
                            decoder.feed(chunk)
                        except FrameError as exc:
                            raise output_invalid(str(exc)) from exc
                    else:
                        err_total += len(chunk)
                        if err_total > self.max_stderr:
                            raise AppError(
                                ErrorCode.ANALYZER_OUTPUT_INVALID,
                                "The sandbox error output exceeds the size limit",
                                502,
                                {"max_bytes": self.max_stderr},
                            )
                        err_head = (err_head + chunk)[:_STDERR_LOG_BYTES]
        return err_head, False

    def _attach(
        self,
        name: str,
        scan_id: Any,
        timeout_seconds: int,
        grace: int,
        request: bytes,
        decoder: FrameDecoder,
        step: str,
    ) -> tuple[bytes, bool, float]:
        """Start the created container attached, feed `request`, decode its framed stdout."""
        deadline = self.clock() + timeout_seconds + grace
        claim = current_claim()

        def cancelled() -> bool:
            return claim is not None and claim.scan_id == scan_id and claim.lost.is_set()

        if claim is not None and claim.scan_id == scan_id:
            claim.steps.begin(step, timeout_seconds + grace)
        started = self.clock()
        try:
            proc = subprocess.Popen(  # noqa: S603 - fixed argv; the container was verified
                [self.docker_path, "start", "--attach", "--interactive", name],
                env=_docker_env(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:
            if claim is not None:
                claim.steps.end()
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
                err_head, timed_out = self._read_frames(proc, deadline, decoder, cancelled, scan_id)
            if not timed_out:
                try:
                    proc.wait(timeout=max(1.0, deadline - self.clock()))
                except subprocess.TimeoutExpired:
                    timed_out = True
        finally:
            if proc.poll() is None:
                self._capture(["kill", name])
                proc.kill()
                proc.wait()
            writer.join(timeout=5)
            if claim is not None and claim.scan_id == scan_id:
                claim.steps.end()
        return err_head, timed_out, self.clock() - started


class DockerAnalyzer(ContainerCli):
    name = "docker"
    uses_staging = True

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
        self.max_output = settings.analyzer_max_output_mb * MB
        self.max_sbom = settings.max_sbom_mb * MB
        self.max_stderr = settings.analyzer_max_stderr_kb * 1024
        self.grace = settings.analyzer_host_grace_seconds
        self.clock = clock

    # ------------------------------------------------------------------ specs
    def _limits(self, mode: Mode) -> AnalyzerLimits:
        s = self.settings
        if mode == "hold":
            return AnalyzerLimits(
                timeout_seconds=s.runner_max_scan_seconds + s.runner_stale_seconds,
                memory_mb=HOLD_MEMORY_MB,
                cpus=HOLD_CPUS,
                pids=HOLD_PIDS,
                tmp_mb=HOLD_TMP_MB,
                cpu_grace_seconds=s.analyzer_cpu_grace_seconds,
            )
        timeout = {
            "extract": s.analyzer_extract_timeout_seconds,
            "persist": s.analyzer_extract_timeout_seconds,
            "rehash": s.verify_rehash_timeout_seconds,
            "sbom": s.analyzer_sbom_timeout_seconds,
        }.get(mode, s.analyzer_timeout_seconds)
        return AnalyzerLimits(
            timeout_seconds=timeout,
            memory_mb=s.analyzer_memory_mb,
            cpus=s.analyzer_cpus,
            pids=s.analyzer_pids_limit,
            tmp_mb=s.analyzer_tmp_mb,
            cpu_grace_seconds=s.analyzer_cpu_grace_seconds,
        )

    def workspace_owner(self, job: AnalysisJob) -> tuple[int, int]:
        """The uid/gid every sandbox container of this scan runs as (never 0)."""
        _, uid, gid = resolve_workspace_dir(
            job.workspace.src_dir, Path(self.settings.workspace_root), job.scan_id
        )
        return uid, gid

    def _mount(
        self, path: Path, job: AnalysisJob, target: str, subdir: str, read_only: bool
    ) -> tuple[MountSpec, int, int]:
        resolved, uid, gid = resolve_workspace_dir(
            path, Path(self.settings.workspace_root), job.scan_id
        )
        source = str(resolved) if self.mount_kind == "bind" else self.volume
        if subdir == "scan":
            spec = MountSpec(self.mount_kind, source, target, "scan", True, job.scan_id)  # type: ignore[arg-type]
            return spec, uid, gid
        return (
            MountSpec(self.mount_kind, source, target, subdir, read_only, job.scan_id),  # type: ignore[arg-type]
            uid,
            gid,
        )

    def _staging(self, job: AnalysisJob, target: str, read_only: bool) -> MountSpec:
        if not job.staging_volume:
            raise refuse("No staging volume for this scan; the analyzer never writes elsewhere")
        return MountSpec("volume", job.staging_volume, target, "staging", read_only, job.scan_id)

    def _spec(self, job: AnalysisJob, mode: Mode) -> AnalyzerSpec:
        ws = job.workspace
        workspace: list[tuple[Path, str, str, bool]] = []
        staging: list[MountSpec] = []
        if mode == "extract":
            workspace = [(ws.input_dir, INPUT_DST, "input", True)]
            staging = [self._staging(job, OUT_DST, False)]
        elif mode == "sbom":
            staging = [self._staging(job, ARTIFACT_DST, True)]
        elif mode == "analyze":
            staging = [self._staging(job, ARTIFACT_DST, True)]
            if job.has_upload:
                workspace = [(ws.input_dir, INPUT_DST, "input", True)]
        elif mode == "persist":
            staging = [self._staging(job, ARTIFACT_DST, True)]
            workspace = [(ws.src_dir, OUT_DST, "src", False)]
        elif mode == "rehash":
            # The kept evidence only, read-only. No staging volume and no upload is involved.
            workspace = [(ws.root, EVIDENCE_DST, "scan", True)]
        else:  # hold
            staging = [self._staging(job, ARTIFACT_DST, True)]
        # rehash must still run when src/ is gone (a deleted tree answers UNKNOWN), so its owner
        # comes from the scan directory it mounts.
        mounts, owners = [], set() if mode == "rehash" else {self.workspace_owner(job)}
        for path, target, subdir, ro in workspace:
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
            tuple([*staging, *mounts]),
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

    def _create_verified(self, docker: str, spec: AnalyzerSpec, base: dict[str, Any]) -> dict:
        argv = build_create_argv(docker, spec)
        assert_create_hardened(
            argv, workspace_root=str(Path(self.settings.workspace_root).resolve())
        )
        self._remove(spec.name)  # a leftover from a crashed runner
        code, _ = self._capture(argv[1:])
        if code is None:
            raise unavailable("Docker did not respond; the artifact was not processed")
        if code != 0:
            raise failed("The analyzer container could not be created", {**base, "exit_code": code})
        return verify_runtime_config(self._inspect(spec.name), spec)

    # ------------------------------------------------------------------ holder
    def start_holder(self, job: AnalysisJob) -> dict[str, Any]:
        """Start the container that keeps the scan's tmpfs staging volume mounted."""
        docker = self._preflight()
        self._check_claim(job)
        spec = self._spec(job, "hold")
        base = {"mode": "hold", "provider": self.name, "image": self.image, "container": spec.name}
        try:
            runtime = self._create_verified(docker, spec, base)
            code, _ = self._capture(["start", spec.name])
            state = self._state(spec.name)
            if code != 0 or state.get("Running") is not True:
                raise failed("The staging holder container did not start", {"mode": "hold"})
        except BaseException:
            self._remove(spec.name)
            raise
        return {**base, "runtime_verified": True, "runtime": runtime, "status": "ok"}

    def stop_holder(self, job: AnalysisJob) -> None:
        self._remove(f"px-ana-{job.scan_id}-hold")

    def holder_running(self, job: AnalysisJob) -> bool:
        return self._state(f"px-ana-{job.scan_id}-hold").get("Running") is True

    # ------------------------------------------------------------------ one mode
    def _open_sbom(self, job: AnalysisJob) -> Callable[[], BinaryIO]:
        def opener() -> BinaryIO:
            path = job.sbom_path
            path.unlink(missing_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            return os.fdopen(fd, "wb")

        return opener

    def run(self, job: AnalysisJob, mode: Mode) -> AnalyzerRun:
        if mode == "hold":
            raise refuse("The holder is started with start_holder, not run")
        docker = self._preflight()
        spec = self._spec(job, mode)
        request = build_request(self.settings, job, mode).model_dump_json().encode()
        base = {"mode": mode, "provider": self.name, "image": self.image, "container": spec.name}

        self._check_claim(job)
        if mode == "sbom":
            job.sbom_path.unlink(missing_ok=True)
        sbom_file: list[BinaryIO] = []
        opener = self._open_sbom(job)

        def open_sbom() -> BinaryIO:
            handle = opener()
            sbom_file.append(handle)
            return handle

        decoder = FrameDecoder(
            max_envelope=self.max_output,
            max_sbom=self.max_sbom,
            open_sbom=open_sbom if mode == "sbom" else None,
        )
        ok = False
        try:
            runtime = self._create_verified(docker, spec, base)
            err_head, timed_out, duration = self._attach(
                spec.name,
                spec.scan_id,
                spec.limits.timeout_seconds,
                self.grace,
                request,
                decoder,
                f"analyzer:{mode}",
            )
            for handle in sbom_file:
                handle.close()
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
                # Untrusted output (audit L5): size, digest and an escaped excerpt, never raw.
                logger.warning(
                    "Analyzer %s stderr (first %d bytes, sha256 %s): %s",
                    spec.name,
                    len(err_head),
                    hashlib.sha256(err_head).hexdigest()[:16],
                    printable_excerpt(err_head),
                )
            self._raise_for_exit(spec, mode, record, exit_code)
            try:
                envelope = decoder.finish()
            except FrameError as exc:
                raise output_invalid(str(exc)) from exc
            result = parse_worker_output(envelope, self.max_output, mode)
            if result.isolation_mode != "container" or not is_isolated(
                result.isolation, ANALYZER_CHECKS
            ):
                raise refuse(
                    "The analyzer reported that it was not isolated; its output was discarded",
                    {"failed_checks": failed_checks(result.isolation, ANALYZER_CHECKS)},
                )
            self._check_sbom(result, decoder)
            record["isolation"] = result.isolation
            ok = True
            return AnalyzerRun(result=result, record=record)
        finally:
            for handle in sbom_file:
                handle.close()
            if not ok and mode == "sbom":
                job.sbom_path.unlink(missing_ok=True)
            self._remove(spec.name)

    @staticmethod
    def _raise_for_exit(
        spec: AnalyzerSpec, mode: Mode, record: dict[str, Any], exit_code: Any
    ) -> None:
        if record["timed_out"]:
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
            raise failed("The analyzer exited abnormally", {"mode": mode, "exit_code": exit_code})

    @staticmethod
    def _check_sbom(result: Any, decoder: FrameDecoder) -> None:
        """The SBOM frame must exist exactly when the envelope describes one, and match it."""
        described = result.sbom_run.sbom if result.sbom_run is not None else None
        if described is None:
            if decoder.has_sbom:
                raise output_invalid("an SBOM frame was sent without an SBOM description")
            return
        if not decoder.has_sbom:
            raise output_invalid("the SBOM frame is missing")
        if decoder.sbom_size != described.size or decoder.sbom_sha256 != described.sha256:
            raise output_invalid("the SBOM frame does not match its size and SHA-256")
