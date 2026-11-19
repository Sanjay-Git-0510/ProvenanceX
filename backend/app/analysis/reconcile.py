"""Finds and removes orphaned analyzer containers (audit finding M1).

An analyzer container is normally removed by the `finally` in DockerAnalyzer.run. If the runner
is killed (SIGKILL, OOM, host restart) that never runs. The container then stops by itself at
its in-container deadline, and this module removes what is left.

Which containers are considered: only those labelled `io.provenancex.role=analyzer` AND
`io.provenancex.instance=<this deployment's ANALYZER_INSTANCE>`. Containers of another Compose
project, unlabelled containers and anything else on the daemon are never listed, so never
removed.

Which are removed: a container is kept only while its scan is RUNNING, owned by the same claim
token as the container's label, and heartbeating (not stale). Every other labelled container
of this instance is an orphan: its scan finished, failed, was recovered by another runner, or
its claim was replaced. A container whose scan is not in the database at all is removed only
once it has stopped.

Safety under concurrency: the decision is made from the database after listing, containers
are removed by their full id (never by name, which a new run may reuse), and `docker rm -f` on
a container that is already gone is harmless, so several runners can reconcile at once and a
pass can be repeated any number of times.
"""

import logging
import os
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.hardening import (
    LABEL_CLAIM,
    LABEL_INSTANCE,
    LABEL_ROLE,
    LABEL_SCAN,
    ROLE_ANALYZER,
)
from app.core.config import Settings
from app.db.models import Scan, ScanStatus, utcnow

logger = logging.getLogger(__name__)

_COMMAND_TIMEOUT_SECONDS = 30
_MAX_LIST_BYTES = 4 * 1024 * 1024
_PASSTHROUGH_ENV = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "TMPDIR")
_FIELDS = ("ID", "Names", "State", LABEL_ROLE, LABEL_INSTANCE, LABEL_SCAN, LABEL_CLAIM)
_FORMAT = "\t".join(f"{{{{.{f}}}}}" if "." not in f else f'{{{{.Label "{f}"}}}}' for f in _FIELDS)

Decision = Literal["keep", "remove"]
DockerRunner = Callable[[list[str]], tuple[int | None, bytes]]


@dataclass(frozen=True)
class AnalyzerContainer:
    container_id: str
    name: str
    state: str  # created | running | exited | ...
    instance: str
    scan_id: UUID | None
    claim: str


@dataclass(frozen=True)
class ScanOwnership:
    status: ScanStatus
    claim_token: UUID | None
    last_seen: datetime | None


@dataclass
class ReconcileReport:
    listed: int = 0
    kept: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    error: str | None = None


def _aware(moment: datetime | None) -> datetime | None:
    if moment is None:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def decide(
    container: AnalyzerContainer,
    scan: ScanOwnership | None,
    now: datetime,
    stale_seconds: int,
) -> Decision:
    """Keep only the container of a live claim. Pure; unit-tested on every branch."""
    if scan is None:
        # Not in this database. Only clean it up once it has stopped by itself.
        return "keep" if container.state == "running" else "remove"
    if scan.status != ScanStatus.RUNNING:
        return "remove"
    if scan.claim_token is None or str(scan.claim_token) != container.claim:
        return "remove"
    last_seen = _aware(scan.last_seen)
    if last_seen is None or last_seen < now - timedelta(seconds=stale_seconds):
        return "remove"
    return "keep"


def _default_runner(docker_path: str) -> DockerRunner:
    def run(args: list[str]) -> tuple[int | None, bytes]:
        env = {k: os.environ[k] for k in _PASSTHROUGH_ENV if k in os.environ}
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [docker_path, *args],
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=_COMMAND_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("docker %s failed: %s", args[0], exc.__class__.__name__)
            return None, b""
        if done.returncode != 0 and done.stderr:
            logger.warning("docker %s: %s", args[0], done.stderr[:500].decode("utf-8", "replace"))
        return done.returncode, done.stdout[:_MAX_LIST_BYTES]

    return run


class OrphanReconciler:
    def __init__(self, settings: Settings, docker: DockerRunner | None = None) -> None:
        self.instance = settings.analyzer_instance_label
        self.stale_seconds = settings.runner_stale_seconds
        self.docker = docker or _default_runner(settings.analyzer_docker_path)

    def list_containers(self) -> list[AnalyzerContainer] | None:
        """This instance's analyzer containers, or None if Docker could not be asked."""
        code, raw = self.docker(
            [
                "ps",
                "--all",
                "--no-trunc",
                "--filter",
                f"label={LABEL_ROLE}={ROLE_ANALYZER}",
                "--filter",
                f"label={LABEL_INSTANCE}={self.instance}",
                "--format",
                _FORMAT,
            ]
        )
        if code != 0:
            return None
        found: list[AnalyzerContainer] = []
        for line in raw.decode("utf-8", "replace").splitlines():
            parts = line.split("\t")
            if len(parts) != len(_FIELDS):
                continue
            cid, name, state, role, instance, scan, claim = parts
            # Defense in depth: never trust the filter alone.
            if role != ROLE_ANALYZER or instance != self.instance or not cid:
                continue
            try:
                scan_id: UUID | None = UUID(scan)
            except ValueError:
                scan_id = None
            found.append(AnalyzerContainer(cid, name, state, instance, scan_id, claim))
        return found

    @staticmethod
    def _ownership(session: Session, ids: Iterable[UUID]) -> dict[UUID, ScanOwnership]:
        wanted = list(set(ids))
        if not wanted:
            return {}
        rows = session.execute(
            select(
                Scan.id, Scan.status, Scan.claim_token, Scan.heartbeat_at, Scan.claimed_at
            ).where(Scan.id.in_(wanted))
        ).all()
        session.rollback()  # read-only; release the snapshot
        return {
            sid: ScanOwnership(status, token, heartbeat or claimed)
            for sid, status, token, heartbeat, claimed in rows
        }

    def reconcile(self, session: Session) -> ReconcileReport:
        """One pass. Never raises for Docker problems; they are reported and logged."""
        report = ReconcileReport()
        containers = self.list_containers()
        if containers is None:
            report.error = "docker unavailable"
            logger.warning("Orphan reconciliation skipped: Docker is not reachable")
            return report
        report.listed = len(containers)
        scans = self._ownership(session, (c.scan_id for c in containers if c.scan_id))
        now = utcnow()
        for container in containers:
            if container.scan_id is None:
                # Our labels, but a malformed scan id: never created by this code. Leave it.
                report.kept.append(container.container_id)
                continue
            verdict = decide(container, scans.get(container.scan_id), now, self.stale_seconds)
            if verdict == "keep":
                report.kept.append(container.container_id)
                continue
            code, _ = self.docker(["rm", "--force", container.container_id])
            if code == 0:
                report.removed.append(container.container_id)
                logger.warning(
                    "Removed orphaned analyzer container %s (scan %s, state %s)",
                    container.name,
                    container.scan_id,
                    container.state,
                )
            else:
                # Already gone (another runner removed it) or the daemon refused; next pass.
                report.failed.append(container.container_id)
        return report
