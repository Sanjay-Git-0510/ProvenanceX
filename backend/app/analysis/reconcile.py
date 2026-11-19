"""Finds and removes orphaned sandbox containers, staging volumes and workspaces (audit finding
M1, extended in Milestone B to fetcher containers and tmpfs staging volumes).

An analyzer container is normally removed by the `finally` in DockerAnalyzer.run. If the runner
is killed (SIGKILL, OOM, host restart) that never runs. The container then stops by itself at
its in-container deadline, and this module removes what is left.

Which containers are considered: only those labelled `io.provenancex.role=analyzer` or
`io.provenancex.role=fetcher` AND
`io.provenancex.instance=<this deployment's ANALYZER_INSTANCE>`. Containers of another Compose
project, unlabelled containers and anything else on the daemon are never listed, so never
removed.

Which are removed: a container is kept only while its scan is RUNNING, owned by the same claim
token as the container's label, and heartbeating (not stale). Every other labelled container
of this instance is an orphan: its scan finished, failed, was recovered by another runner, or
its claim was replaced. A container whose scan is not in the database at all is removed only
once it has stopped.

Verification containers (mode label `rehash`, Milestone C1) belong to a verification job, not
to a scan run: they carry the job's claim token, and are kept only while that job is running
under the same token and heartbeating; otherwise they are removed like any other orphan.

Staging volumes (`io.provenancex.role=staging`, same instance label) follow the same rule, and are
removed after the containers, because Docker refuses to remove a volume that is still mounted
(that refusal is harmless: the next pass retries). Workspace directories with no scan row at all
are removed once they are older than an hour (the API creates a workspace a moment before its
scan row, so a fresh one is never touched).

Safety under concurrency: the decision is made from the database after listing, containers
are removed by their full id (never by name, which a new run may reuse), and `docker rm -f` on
a container that is already gone is harmless, so several runners can reconcile at once and a
pass can be repeated any number of times.
"""

import logging
import os
import subprocess
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.hardening import (
    LABEL_CLAIM,
    LABEL_INSTANCE,
    LABEL_MODE,
    LABEL_ROLE,
    LABEL_SCAN,
    ROLE_ANALYZER,
)
from app.analysis.staging import DockerStaging
from app.core.bounded import printable_excerpt
from app.core.config import Settings
from app.db.models import Scan, ScanStatus, VerificationRun, VerificationStatus, utcnow
from app.pipeline.workspace import discard_workspace

ROLE_FETCHER = "fetcher"
SANDBOX_ROLES = (ROLE_ANALYZER, ROLE_FETCHER)
ORPHAN_WORKSPACE_AGE_SECONDS = 3600

logger = logging.getLogger(__name__)

_COMMAND_TIMEOUT_SECONDS = 30
_MAX_LIST_BYTES = 4 * 1024 * 1024
_PASSTHROUGH_ENV = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "TMPDIR")
_FIELDS = (
    "ID",
    "Names",
    "State",
    LABEL_ROLE,
    LABEL_INSTANCE,
    LABEL_SCAN,
    LABEL_CLAIM,
    LABEL_MODE,
)
REHASH_MODE = "rehash"
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
    mode: str = ""


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
    volumes_removed: list[str] = field(default_factory=list)
    volumes_kept: list[str] = field(default_factory=list)
    workspaces_removed: list[str] = field(default_factory=list)


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
            logger.warning("docker %s: %s", args[0], printable_excerpt(done.stderr[:500]))
        return done.returncode, done.stdout[:_MAX_LIST_BYTES]

    return run


class OrphanReconciler:
    def __init__(self, settings: Settings, docker: DockerRunner | None = None) -> None:
        self.instance = settings.analyzer_instance_label
        self.stale_seconds = settings.runner_stale_seconds
        self.docker = docker or _default_runner(settings.analyzer_docker_path)
        self.staging = DockerStaging(settings, docker=self.docker)
        self.workspace_root = settings.workspace_root

    def list_containers(self) -> list[AnalyzerContainer] | None:
        """This instance's analyzer and fetcher containers, or None if Docker failed."""
        found: list[AnalyzerContainer] = []
        for wanted_role in SANDBOX_ROLES:
            listed = self._list_role(wanted_role)
            if listed is None:
                return None
            found.extend(listed)
        return found

    def _list_role(self, wanted_role: str) -> list[AnalyzerContainer] | None:
        code, raw = self.docker(
            [
                "ps",
                "--all",
                "--no-trunc",
                "--filter",
                f"label={LABEL_ROLE}={wanted_role}",
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
            cid, name, state, role, instance, scan, claim, mode = parts
            # Defense in depth: never trust the filter alone.
            if role != wanted_role or instance != self.instance or not cid:
                continue
            try:
                scan_id: UUID | None = UUID(scan)
            except ValueError:
                scan_id = None
            found.append(AnalyzerContainer(cid, name, state, instance, scan_id, claim, mode))
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

    @staticmethod
    def _verify_ownership(session: Session, tokens: Iterable[str]) -> dict[str, ScanOwnership]:
        """Ownership of rehash containers, keyed by the verification job's claim token."""
        wanted: list[UUID] = []
        for token in set(tokens):
            try:
                wanted.append(UUID(token))
            except ValueError:
                continue
        if not wanted:
            return {}
        rows = session.execute(
            select(
                VerificationRun.claim_token,
                VerificationRun.status,
                VerificationRun.heartbeat_at,
                VerificationRun.started_at,
            ).where(VerificationRun.claim_token.in_(wanted))
        ).all()
        session.rollback()
        out: dict[str, ScanOwnership] = {}
        for token, status, heartbeat, started in rows:
            running = status == VerificationStatus.RUNNING.value
            out[str(token)] = ScanOwnership(
                ScanStatus.RUNNING if running else ScanStatus.COMPLETED,
                token,
                heartbeat or started,
            )
        return out

    def reconcile(self, session: Session) -> ReconcileReport:
        """One pass. Never raises for Docker problems; they are reported and logged."""
        report = ReconcileReport()
        containers = self.list_containers()
        if containers is None:
            report.error = "docker unavailable"
            logger.warning("Orphan reconciliation skipped: Docker is not reachable")
            return report
        report.listed = len(containers)
        scans = self._ownership(
            session, (c.scan_id for c in containers if c.scan_id and c.mode != REHASH_MODE)
        )
        jobs = self._verify_ownership(
            session, (c.claim for c in containers if c.mode == REHASH_MODE)
        )
        now = utcnow()
        for container in containers:
            if container.scan_id is None:
                # Our labels, but a malformed scan id: never created by this code. Leave it.
                report.kept.append(container.container_id)
                continue
            owner = (
                jobs.get(container.claim)
                if container.mode == REHASH_MODE
                else scans.get(container.scan_id)
            )
            verdict = decide(container, owner, now, self.stale_seconds)
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
        self._reconcile_volumes(session, report)
        self._reconcile_workspaces(session, report)
        return report

    def _reconcile_volumes(self, session: Session, report: ReconcileReport) -> None:
        volumes = self.staging.list_volumes()
        if volumes is None:
            return
        ids = []
        for v in volumes:
            try:
                ids.append(UUID(v["scan"]))
            except ValueError:
                continue
        scans = self._ownership(session, ids)
        now = utcnow()
        for v in volumes:
            try:
                scan_id = UUID(v["scan"])
            except ValueError:
                report.volumes_kept.append(v["name"])
                continue
            # A volume has no running state: decide as for a stopped container.
            probe = AnalyzerContainer(
                v["name"], v["name"], "volume", self.instance, scan_id, v["claim"]
            )
            if decide(probe, scans.get(scan_id), now, self.stale_seconds) == "keep":
                report.volumes_kept.append(v["name"])
            elif self.staging.remove(v["name"]):
                report.volumes_removed.append(v["name"])
                logger.warning("Removed orphaned staging volume %s", v["name"])

    def _reconcile_workspaces(self, session: Session, report: ReconcileReport) -> None:
        base = Path(self.workspace_root)
        if not base.is_dir():
            return
        candidates: dict[UUID, Path] = {}
        cutoff = time.time() - ORPHAN_WORKSPACE_AGE_SECONDS
        for entry in base.iterdir():
            try:
                scan_id = UUID(entry.name)
            except ValueError:
                continue
            if str(scan_id) != entry.name or entry.is_symlink() or not entry.is_dir():
                continue
            if entry.stat().st_mtime < cutoff:
                candidates[scan_id] = entry
        if not candidates:
            return
        known = set(self._ownership(session, candidates))
        for scan_id, path in candidates.items():
            if scan_id in known:
                continue
            discard_workspace(base, scan_id)
            report.workspaces_removed.append(str(scan_id))
            logger.warning("Removed orphaned workspace %s (no scan row)", path.name)
