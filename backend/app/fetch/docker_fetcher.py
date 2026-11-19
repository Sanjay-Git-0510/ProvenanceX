"""Runs the fetcher worker in a disposable, hardened Docker container (one per scan).

Sequence:
  docker image inspect, docker network inspect (the fetch network must be internal)
  ->  admission: at most FETCHER_MAX_CONCURRENT fetcher containers of this deployment exist
      (counted and created under a PostgreSQL advisory lock; waits up to FETCHER_WAIT_SECONDS)
  ->  docker rm -f (stale)  ->  docker create (assert_fetch_hardened)
  ->  docker inspect (verify_fetch_runtime, including the L3 checks)
  ->  docker start --attach --interactive: request on stdin, framed manifest on stdout, under a
      host deadline (in-container deadline + grace); the worker also stops itself at its deadline
  ->  docker inspect State  ->  docker rm -f (always, in `finally`)

The runner never reads what was downloaded: the bytes stay in the scan's staging volume, and only
the validated manifest (commit, Hub listing, verified hashes) comes back.
"""

import logging
import shutil
import time
from collections.abc import Callable
from typing import Any

from sqlalchemy.engine import Engine

from app.analysis.docker_analyzer import ContainerCli, failed, unavailable
from app.analysis.framing import FrameDecoder, FrameError
from app.analysis.hardening import NO_CLAIM, refuse
from app.analysis.staging import LOCK_FETCH, advisory_lock, scan_of_volume, wait_for_capacity
from app.core.bounded import printable_excerpt
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.fetch.base import (
    FetchJob,
    FetchRun,
    build_fetch_request,
    fetch_output_invalid,
    parse_fetch_output,
)
from app.fetch.hardening import (
    ROLE_FETCHER,
    FetcherLimits,
    FetcherSpec,
    assert_fetch_hardened,
    build_fetch_argv,
    verify_fetch_runtime,
    verify_network,
)
from app.pipeline.ownership import ClaimLost, current_claim
from app.sandbox_worker.exitcodes import EXIT_CPU_LIMIT, EXIT_DEADLINE
from app.sandbox_worker.selfcheck import FETCHER_CHECKS, failed_checks, is_isolated

logger = logging.getLogger(__name__)

MB = 1024 * 1024
_OOM_EXIT_CODES = frozenset({137, -9})
_DOCKER_ERROR_RETURN_CODES = frozenset({125, 126, 127})


class DockerFetcher(ContainerCli):
    name = "docker"

    def __init__(
        self,
        settings: Settings,
        *,
        engine: Engine | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.settings = settings
        self.docker_path = settings.analyzer_docker_path
        self.image = settings.fetcher_image
        self.network = settings.fetcher_network
        self.instance = settings.analyzer_instance_label
        self.max_output = settings.fetcher_max_output_mb * MB
        self.max_stderr = settings.analyzer_max_stderr_kb * 1024
        self.grace = settings.fetcher_host_grace_seconds
        self.engine = engine
        self.clock = clock
        self.sleep = sleep

    # ------------------------------------------------------------------ checks
    def _preflight(self) -> str:
        docker = shutil.which(self.docker_path)
        if docker is None:
            raise unavailable("Docker is not available to the scan runner; nothing was fetched")
        code, _ = self._capture(["version", "--format", "{{.Server.APIVersion}}"])
        if code != 0:
            raise unavailable(
                "The Docker daemon is not reachable from the scan runner; nothing was fetched"
            )
        code, _ = self._capture(["image", "inspect", "--format", "{{.Id}}", self.image])
        if code != 0:
            raise unavailable(
                "The fetcher image has not been built (make fetcher-image); nothing was fetched"
            )
        code, raw = self._capture(["network", "inspect", self.network])
        if code != 0:
            raise unavailable(
                "The internal fetch network does not exist (start the Compose stack, which "
                "creates it with the egress proxy); nothing was fetched"
            )
        import json

        try:
            verify_network(json.loads(raw), self.network)
        except ValueError as exc:
            raise refuse("The fetch network could not be inspected") from exc
        return docker

    def _limits(self, source: str) -> FetcherLimits:
        s = self.settings
        return FetcherLimits(
            timeout_seconds=s.fetch_timeout_seconds(source),
            memory_mb=s.fetcher_memory_mb,
            cpus=s.fetcher_cpus,
            pids=s.fetcher_pids_limit,
            tmp_mb=s.fetcher_tmp_mb,
            cpu_grace_seconds=s.analyzer_cpu_grace_seconds,
        )

    def _spec(self, job: FetchJob) -> FetcherSpec:
        if not job.staging_volume or scan_of_volume(job.staging_volume) != job.scan_id:
            raise refuse("The fetcher may only write to its own scan's staging volume")
        if not job.uid or not job.gid:
            raise refuse("The fetcher never runs as root")
        claim = current_claim()
        return FetcherSpec(
            scan_id=job.scan_id,
            image=self.image,
            network=self.network,
            staging_volume=job.staging_volume,
            uid=job.uid,
            gid=job.gid,
            limits=self._limits(job.source),
            instance=self.instance,
            claim_token=str(claim.token) if claim and claim.scan_id == job.scan_id else NO_CLAIM,
        )

    def count_fetchers(self) -> int:
        code, raw = self._capture(
            [
                "ps",
                "--all",
                "--quiet",
                "--no-trunc",
                "--filter",
                f"label=io.provenancex.role={ROLE_FETCHER}",
                "--filter",
                f"label=io.provenancex.instance={self.instance}",
            ]
        )
        if code != 0:
            raise unavailable("Docker did not list fetcher containers; nothing was fetched")
        return len([line for line in raw.decode("ascii", "replace").splitlines() if line.strip()])

    # ------------------------------------------------------------------ run
    def run(self, job: FetchJob) -> FetchRun:
        docker = self._preflight()
        spec = self._spec(job)
        argv = build_fetch_argv(docker, spec)
        assert_fetch_hardened(argv, self.network)
        request = build_fetch_request(self.settings, job).model_dump_json().encode()
        base = {"mode": "fetch", "provider": self.name, "image": self.image, "container": spec.name}
        claim = current_claim()
        if claim is not None and claim.scan_id == job.scan_id and claim.lost.is_set():
            raise ClaimLost(job.scan_id)
        self._remove(spec.name)  # a leftover from a crashed runner

        def create() -> None:
            code, _ = self._capture(argv[1:])
            if code is None:
                raise unavailable("Docker did not respond; nothing was fetched")
            if code != 0:
                raise failed(
                    "The fetcher container could not be created", {**base, "exit_code": code}
                )

        try:
            wait_for_capacity(
                lambda: self.count_fetchers() < self.settings.fetcher_max_concurrent,
                self.settings.fetcher_wait_seconds,
                AppError(
                    ErrorCode.STAGING_BUDGET_EXCEEDED,
                    "Too many downloads are running; try again later",
                    503,
                    {"fetcher_max_concurrent": self.settings.fetcher_max_concurrent},
                ),
                lock=lambda: advisory_lock(self.engine, LOCK_FETCH),
                admit=create,
                clock=self.clock,
                sleep=self.sleep,
            )
            runtime = verify_fetch_runtime(self._inspect(spec.name), spec)
            decoder = FrameDecoder(max_envelope=self.max_output, max_sbom=0)
            err_head, timed_out, duration = self._attach(
                spec.name,
                spec.scan_id,
                spec.limits.timeout_seconds,
                self.grace,
                request,
                decoder,
                f"fetch:{job.source}",
            )
            state = self._state(spec.name)
            exit_code = state.get("ExitCode")
            timed_out = timed_out or exit_code == EXIT_DEADLINE
            record: dict[str, Any] = {
                **base,
                "runtime_verified": True,
                "runtime": runtime,
                "exit_code": exit_code,
                "oom_killed": bool(state.get("OOMKilled")),
                "timed_out": timed_out,
                "duration_seconds": round(duration, 3),
            }
            if err_head:
                # Untrusted output (audit L5): an escaped excerpt, never raw.
                logger.warning(
                    "Fetcher %s stderr (%d bytes shown escaped): %s",
                    spec.name,
                    len(err_head),
                    printable_excerpt(err_head),
                )
            self._raise_for_exit(spec, record, exit_code)
            try:
                envelope = decoder.finish()
            except FrameError as exc:
                raise fetch_output_invalid(str(exc)) from exc
            result = parse_fetch_output(envelope, self.max_output, job.source)
            if result.isolation_mode != "container" or not is_isolated(
                result.isolation, FETCHER_CHECKS
            ):
                raise refuse(
                    "The fetcher reported that it was not isolated; its output was discarded",
                    {"failed_checks": failed_checks(result.isolation, FETCHER_CHECKS)},
                )
            record["isolation"] = result.isolation
            return FetchRun(result=result, record=record)
        except AppError as exc:
            if exc.code == ErrorCode.ANALYZER_OUTPUT_INVALID:
                raise fetch_output_invalid(str((exc.details or {}).get("reason"))) from exc
            raise
        finally:
            self._remove(spec.name)

    @staticmethod
    def _raise_for_exit(spec: FetcherSpec, record: dict[str, Any], exit_code: Any) -> None:
        if record["timed_out"]:
            raise AppError(
                ErrorCode.FETCH_TIMEOUT,
                f"The download exceeded its {spec.limits.timeout_seconds}s time limit "
                "and was stopped",
                504,
                {"timed_out": True},
            )
        if record["oom_killed"] or exit_code in _OOM_EXIT_CODES:
            raise failed(
                f"The fetcher exceeded its {spec.limits.memory_mb} MB memory limit and was stopped",
                {"mode": "fetch", "oom_killed": True},
            )
        if exit_code == EXIT_CPU_LIMIT:
            raise failed(
                f"The fetcher exceeded its {spec.limits.cpu_seconds}s CPU-time limit",
                {"mode": "fetch", "cpu_limited": True},
            )
        if exit_code in _DOCKER_ERROR_RETURN_CODES:
            raise failed(
                "The fetcher container could not be started",
                {"mode": "fetch", "exit_code": exit_code},
            )
        if exit_code != 0:
            raise failed("The fetcher exited abnormally", {"mode": "fetch", "exit_code": exit_code})
