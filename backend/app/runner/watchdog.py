"""Runner watchdog: detects a hung scan even while the heartbeat keeps renewing its claim.

The heartbeat thread renews the claim as long as the process lives, so a runner whose scan thread
is stuck (a hung download, a wedged Docker CLI call, a deadlock) would keep its scan RUNNING
until RUNNER_MAX_SCAN_SECONDS, and with a single runner nobody would ever recover it, because
recovery runs in the same, stuck loop. The watchdog is a second thread with its own clock:

* every sandbox step registers its deadline (ScanClaim.steps); a step still running
  RUNNER_WATCHDOG_GRACE_SECONDS after its deadline is hung;
* a scan running longer than RUNNER_MAX_SCAN_SECONDS (plus the same grace) is hung.

When it fires it acts only on the scan this runner claimed (one scan per runner process):
  1. marks the claim lost: the heartbeat stops renewing, fenced writes are refused, container
     runs that poll the claim stop;
  2. fails the scan as runner_watchdog_timeout with a conditional UPDATE on its own claim token,
     and replaces the token, so nothing this process still does can write to the scan;
  3. removes the containers and the staging volume labelled with THIS scan id AND claim token
     (other scans' containers never match), and the scan's workspace;
  4. waits RUNNER_WATCHDOG_EXIT_SECONDS for the scan thread to unwind; if it is still stuck the
     process exits (EXIT_WATCHDOG) and Compose restarts it, whose startup recovery is idempotent.
"""

import logging
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path

from sqlalchemy import update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.analysis.docker_cli import DockerRunner, make_docker_runner
from app.analysis.hardening import LABEL_CLAIM, LABEL_INSTANCE, LABEL_SCAN
from app.analysis.staging import volume_name
from app.core.config import Settings
from app.core.errors import ErrorCode
from app.db.models import Scan, ScanStatus, utcnow
from app.pipeline.ownership import ScanClaim, new_token
from app.pipeline.workspace import discard_workspace

logger = logging.getLogger(__name__)

EXIT_WATCHDOG = 75


def fail_as_hung(session_factory: sessionmaker[Session], claim: ScanClaim, reason: str) -> bool:
    """Fail the scan only if this claim still owns it and it is RUNNING. True if it did."""
    try:
        with session_factory() as session:
            done = session.execute(
                update(Scan)
                .where(
                    Scan.id == claim.scan_id,
                    Scan.claim_token == claim.token,
                    Scan.status == ScanStatus.RUNNING,
                )
                .values(
                    status=ScanStatus.FAILED,
                    error_code=str(ErrorCode.RUNNER_WATCHDOG_TIMEOUT),
                    error_message="The scan stopped making progress and was stopped by the "
                    "runner watchdog; no result was recorded",
                    error_details={"reason": reason[:200]},
                    finished_at=utcnow(),
                    claim_token=new_token(),
                )
            )
            session.commit()
            return done.rowcount == 1
    except SQLAlchemyError:
        logger.exception("Watchdog could not record the failure of scan %s", claim.scan_id)
        return False


class Watchdog:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        claim: ScanClaim,
        settings: Settings,
        *,
        docker: DockerRunner | None = None,
        exit_fn: Callable[[int], None] = os._exit,
        clock: Callable[[], float] = time.monotonic,
        poll_seconds: float | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.claim = claim
        self.settings = settings
        self.grace = settings.runner_watchdog_grace_seconds
        self.max_scan = settings.runner_max_scan_seconds
        self.exit_seconds = settings.runner_watchdog_exit_seconds
        self.docker = docker or make_docker_runner(settings.analyzer_docker_path)
        self.exit_fn = exit_fn
        self.clock = clock
        self.poll = (
            poll_seconds
            if poll_seconds is not None
            else min(5.0, settings.runner_heartbeat_seconds)
        )
        self.started = clock()
        self.fired: str | None = None
        self._done = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name=f"watchdog-{claim.scan_id}", daemon=True
        )

    def check(self) -> str | None:
        """The reason the scan counts as hung, or None."""
        step = self.claim.steps.overdue(self.grace)
        if step is not None:
            return f"sandbox step {step} is past its deadline"
        if self.clock() - self.started > self.max_scan + self.grace:
            return "the scan exceeded RUNNER_MAX_SCAN_SECONDS"
        return None

    def _run(self) -> None:
        while not self._done.wait(self.poll):
            if self.claim.lost.is_set():
                return  # someone else owns the outcome now
            reason = self.check()
            if reason is not None:
                self.fire(reason)
                return

    def fire(self, reason: str) -> None:
        self.fired = reason
        scan_id = self.claim.scan_id
        logger.error("Watchdog: scan %s is hung (%s); failing it", scan_id, reason)
        self.claim.mark_lost()
        fail_as_hung(self.session_factory, self.claim, reason)
        self.cleanup()
        if not self._done.wait(self.exit_seconds):
            logger.critical("Watchdog: scan thread for %s did not unwind; exiting", scan_id)
            self.exit_fn(EXIT_WATCHDOG)

    def cleanup(self) -> None:
        """Remove only this scan's containers (matching scan id AND claim token) and volume."""
        instance = self.settings.analyzer_instance_label
        code, raw = self.docker(
            [
                "ps",
                "--all",
                "--quiet",
                "--no-trunc",
                "--filter",
                f"label={LABEL_INSTANCE}={instance}",
                "--filter",
                f"label={LABEL_SCAN}={self.claim.scan_id}",
                "--filter",
                f"label={LABEL_CLAIM}={self.claim.token}",
            ]
        )
        if code == 0:
            for cid in raw.decode("ascii", "replace").split():
                self.docker(["rm", "--force", cid])
        self.docker(["volume", "rm", "--force", volume_name(self.claim.scan_id)])
        discard_workspace(Path(self.settings.workspace_root), self.claim.scan_id)

    def __enter__(self) -> "Watchdog":
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._done.set()
        self._thread.join(timeout=max(5.0, self.poll * 2))
