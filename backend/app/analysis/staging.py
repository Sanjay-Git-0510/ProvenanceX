"""Per-scan staging storage with a kernel-enforced size cap (audit finding L1).

Before Milestone B, extraction and downloads wrote into the shared workspace volume and the only
size limit was a byte count kept by Python code, which the audit showed could be bypassed. Now
every artifact tree is written into its own Docker volume backed by a size-limited tmpfs:

    docker volume create --driver local --opt type=tmpfs --opt device=tmpfs
        --opt o=size=<STAGING_MB>m,uid=<u>,gid=<g>,mode=0700,nosuid,nodev,noexec  px-stg-<scan>

The kernel refuses writes past `size` (ENOSPC), whatever the writer does. The fetcher and the
analyzer's extract mode are the only writers; analyze and persist mount it read-only. The volume
is removed when the scan ends (success, failure, timeout, lost claim), and the reconciler removes
any that a crash left behind (app/analysis/reconcile.py).

Aggregate RAM: tmpfs pages live in memory. Creation is admitted only while the sizes of this
deployment's existing staging volumes plus the new one stay within STAGING_TOTAL_MB; otherwise
the runner waits (up to STAGING_WAIT_SECONDS) and then fails the scan with
staging_budget_exceeded. Admission runs under a PostgreSQL advisory lock, so several runner
replicas cannot over-admit between listing and creating.
"""

import json
import logging
import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.analysis.docker_cli import DockerRunner, make_docker_runner
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode

logger = logging.getLogger(__name__)

LABEL_ROLE = "io.provenancex.role"
LABEL_INSTANCE = "io.provenancex.instance"
LABEL_SCAN = "io.provenancex.scan-id"
LABEL_CLAIM = "io.provenancex.claim"
LABEL_SIZE = "io.provenancex.size-mb"
ROLE_STAGING = "staging"
VOLUME_PREFIX = "px-stg-"
MOUNT_OPTIONS = ("nosuid", "nodev", "noexec")
# Keys for pg advisory locks (arbitrary constants, unique within this application).
LOCK_STAGING = 0x50580001
LOCK_FETCH = 0x50580002
_POLL_SECONDS = 2.0
_NAME_RE = re.compile(r"^px-stg-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")


def volume_name(scan_id: UUID) -> str:
    return f"{VOLUME_PREFIX}{UUID(str(scan_id))}"


def scan_of_volume(name: str) -> UUID | None:
    match = _NAME_RE.match(name)
    return UUID(match.group(1)) if match else None


def mount_option_string(size_mb: int, uid: int, gid: int) -> str:
    return f"size={size_mb}m,uid={uid},gid={gid},mode=0700," + ",".join(MOUNT_OPTIONS)


@dataclass(frozen=True)
class StagingVolume:
    name: str
    scan_id: UUID
    size_mb: int
    uid: int
    gid: int


@contextmanager
def advisory_lock(engine: Engine | None, key: int) -> Iterator[None]:
    """Session-level PostgreSQL advisory lock on its own connection. No-op elsewhere (SQLite)."""
    if engine is None or engine.dialect.name != "postgresql":
        yield
        return
    with engine.connect() as conn:
        conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": key})
        try:
            yield
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": key})
            conn.commit()


def wait_for_capacity(
    has_room: Callable[[], bool],
    wait_seconds: float,
    error: AppError,
    *,
    lock: Callable[[], Any],
    admit: Callable[[], None],
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Under `lock`, call `admit` once `has_room()` is true; give up after `wait_seconds`."""
    deadline = clock() + wait_seconds
    while True:
        with lock():
            if has_room():
                admit()
                return
        if clock() >= deadline:
            raise error
        sleep(_POLL_SECONDS)


def staging_unavailable(message: str, details: Any = None) -> AppError:
    return AppError(ErrorCode.SANDBOX_UNAVAILABLE, message, 503, details)


class DockerStaging:
    """Creates, verifies and removes this deployment's staging volumes."""

    def __init__(
        self,
        settings: Settings,
        *,
        docker: DockerRunner | None = None,
        engine: Engine | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.settings = settings
        self.instance = settings.analyzer_instance_label
        self.size_mb = settings.staging_mb
        self.total_mb = settings.staging_total_mb
        self.wait_seconds = settings.staging_wait_seconds
        self.docker = docker or make_docker_runner(settings.analyzer_docker_path)
        self.engine = engine
        self.clock = clock
        self.sleep = sleep

    # ------------------------------------------------------------------ listing
    def list_volumes(self) -> list[dict[str, str]] | None:
        """This instance's staging volumes: name, scan, claim, size. None if Docker failed."""
        fmt = "\t".join(
            ["{{.Name}}"]
            + [
                f'{{{{.Label "{k}"}}}}'
                for k in (LABEL_ROLE, LABEL_INSTANCE, LABEL_SCAN, LABEL_CLAIM, LABEL_SIZE)
            ]
        )
        code, raw = self.docker(
            [
                "volume",
                "ls",
                "--filter",
                f"label={LABEL_ROLE}={ROLE_STAGING}",
                "--filter",
                f"label={LABEL_INSTANCE}={self.instance}",
                "--format",
                fmt,
            ]
        )
        if code != 0:
            return None
        found = []
        for line in raw.decode("utf-8", "replace").splitlines():
            parts = line.split("\t")
            if len(parts) != 6:
                continue
            name, role, instance, scan, claim, size = parts
            # Defense in depth: never trust the filter alone.
            if role != ROLE_STAGING or instance != self.instance or scan_of_volume(name) is None:
                continue
            found.append({"name": name, "scan": scan, "claim": claim, "size_mb": size})
        return found

    def used_mb(self) -> int:
        volumes = self.list_volumes()
        if volumes is None:
            raise staging_unavailable("Docker did not list staging volumes; nothing was fetched")
        total = 0
        for v in volumes:
            # An unreadable size label counts as a full-size volume (fail closed).
            size = v["size_mb"]
            total += int(size) if size.isdigit() else self.size_mb
        return total

    # ------------------------------------------------------------------ create / verify
    def create(self, scan_id: UUID, claim_token: str, uid: int, gid: int) -> StagingVolume:
        """Admit (aggregate budget), create and verify the scan's staging volume."""
        if uid == 0 or gid == 0:
            raise AppError(ErrorCode.SANDBOX_REFUSED, "Staging is never owned by root", 500)
        name = volume_name(scan_id)
        volume = StagingVolume(name, UUID(str(scan_id)), self.size_mb, uid, gid)
        # A leftover with the same name (crashed earlier attempt) is removed first, because
        # `docker volume create` silently reuses an existing volume with its OLD options.
        self.docker(["volume", "rm", "--force", name])

        def has_room() -> bool:
            return self.used_mb() + self.size_mb <= self.total_mb

        def admit() -> None:
            self._create(volume, claim_token)

        wait_for_capacity(
            has_room,
            self.wait_seconds,
            AppError(
                ErrorCode.STAGING_BUDGET_EXCEEDED,
                "Staging storage for concurrent scans is exhausted; try again later",
                503,
                {"staging_total_mb": self.total_mb, "staging_mb": self.size_mb},
            ),
            lock=lambda: advisory_lock(self.engine, LOCK_STAGING),
            admit=admit,
            clock=self.clock,
            sleep=self.sleep,
        )
        try:
            self.verify(volume, claim_token)
        except AppError:
            self.remove(name)
            raise
        return volume

    def _create(self, volume: StagingVolume, claim_token: str) -> None:
        labels = {
            LABEL_ROLE: ROLE_STAGING,
            LABEL_INSTANCE: self.instance,
            LABEL_SCAN: str(volume.scan_id),
            LABEL_CLAIM: claim_token,
            LABEL_SIZE: str(volume.size_mb),
        }
        argv = [
            "volume",
            "create",
            "--driver",
            "local",
            "--opt",
            "type=tmpfs",
            "--opt",
            "device=tmpfs",
            "--opt",
            f"o={mount_option_string(volume.size_mb, volume.uid, volume.gid)}",
        ]
        for key, value in labels.items():
            argv += ["--label", f"{key}={value}"]
        argv.append(volume.name)
        code, _ = self.docker(argv)
        if code != 0:
            raise staging_unavailable(
                "The staging volume could not be created; nothing was fetched or extracted"
            )

    def verify(self, volume: StagingVolume, claim_token: str) -> dict[str, Any]:
        """`docker volume inspect` must show exactly the tmpfs driver options and labels."""
        code, raw = self.docker(["volume", "inspect", volume.name])
        try:
            info = json.loads(raw) if code == 0 else None
        except ValueError:
            info = None
        if not isinstance(info, list) or len(info) != 1 or not isinstance(info[0], dict):
            raise staging_unavailable("The staging volume could not be inspected")
        return verify_volume_info(info[0], volume, self.instance, claim_token)

    def remove(self, name: str) -> bool:
        """Idempotent. False if Docker refused (still in use, daemon down); reconcile retries."""
        if scan_of_volume(name) is None:
            logger.error("Refusing to remove unexpected volume name %s", name)
            return False
        code, _ = self.docker(["volume", "rm", "--force", name])
        return code == 0


def verify_volume_info(
    info: dict[str, Any], volume: StagingVolume, instance: str, claim_token: str
) -> dict[str, Any]:
    problems: list[str] = []
    options = info.get("Options") or {}
    labels = info.get("Labels") or {}
    if info.get("Name") != volume.name:
        problems.append("name differs")
    if info.get("Driver") != "local":
        problems.append("driver is not local")
    if options.get("type") != "tmpfs" or options.get("device") != "tmpfs":
        problems.append("volume is not tmpfs")
    if options.get("o") != mount_option_string(volume.size_mb, volume.uid, volume.gid):
        problems.append("mount options (size, owner, mode, nosuid/nodev/noexec) differ")
    if set(options) != {"type", "device", "o"}:
        problems.append("unexpected driver options")
    expected_labels = {
        LABEL_ROLE: ROLE_STAGING,
        LABEL_INSTANCE: instance,
        LABEL_SCAN: str(volume.scan_id),
        LABEL_CLAIM: claim_token,
        LABEL_SIZE: str(volume.size_mb),
    }
    if any(labels.get(k) != v for k, v in expected_labels.items()):
        problems.append("labels differ")
    if problems:
        raise AppError(
            ErrorCode.SANDBOX_REFUSED,
            "The staging volume is not configured as required",
            500,
            {"failed": problems},
        )
    return {"name": volume.name, "size_mb": volume.size_mb, "driver": "local", "type": "tmpfs"}
