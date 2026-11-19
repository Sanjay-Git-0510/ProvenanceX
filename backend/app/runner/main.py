"""scan-runner main loop: `python -m app.runner`.

Claims one queued scan at a time and runs it through the sandboxed pipeline. Scale out by
running more replicas; claims are row-locked and each replica needs a unique RUNNER_ID (the
default, the hostname, is unique per Compose container). Every untrusted-content step runs in
a fresh analyzer container. If Docker or the analyzer image is unavailable, each claimed scan
fails with sandbox_unavailable (fail closed); the runner keeps running so the failure is visible.

Recovery (audit findings M1, M2), at startup and every RUNNER_RECONCILE_SECONDS while idle:
  1. scans this runner identity claimed in a previous life (it was killed) are failed;
  2. scans whose heartbeat stopped, or that ran past RUNNER_MAX_SCAN_SECONDS, are failed;
     both replace the claim token, so a surviving old runner can no longer write to them;
  3. analyzer containers of this deployment that no longer belong to a live claim are removed;
  4. the workspaces of the scans failed in 1-2 are removed.
On SIGTERM the runner finishes the current scan, then exits; Compose's stop_grace_period is set
from RUNNER_MAX_SCAN_SECONDS. If it is killed anyway, the next start recovers as above.
"""

import logging
import signal
import threading
import time
from pathlib import Path
from types import FrameType
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.analysis.reconcile import OrphanReconciler, ReconcileReport
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.db.database import get_sessionmaker
from app.db.models import Scan, ScanStatus
from app.pipeline.ownership import default_runner_id
from app.pipeline.providers import build_providers
from app.pipeline.workspace import discard_workspace
from app.runner.executor import run_claimed_scan
from app.runner.queue import claim_next_scan, fail_stale_claims, recover_own_orphans

logger = logging.getLogger(__name__)


def quiet_seconds(settings: Settings) -> float:
    """How long a heartbeat must be silent before this identity's old claims count as dead."""
    return 2 * settings.runner_heartbeat_seconds + 5


def reconcile_once(
    session_factory: sessionmaker[Session],
    settings: Settings,
    runner_id: str,
    reconciler: OrphanReconciler,
) -> tuple[list[UUID], ReconcileReport]:
    """One recovery pass (steps 1-4 above). Idempotent; safe to run on several runners at once."""
    with session_factory() as session:
        recovered = recover_own_orphans(session, runner_id, (), quiet_seconds(settings))
        recovered += fail_stale_claims(
            session, settings.runner_stale_seconds, settings.runner_max_scan_seconds
        )
        report = reconciler.reconcile(session)
    for scan_id in recovered:
        discard_workspace(Path(settings.workspace_root), scan_id)
    return recovered, report


def _wait_for_own_claims_to_quiet(
    session_factory: sessionmaker[Session],
    settings: Settings,
    runner_id: str,
    stop: threading.Event,
) -> None:
    """At startup, if this identity still holds RUNNING claims, wait until their last heartbeat
    is old enough to be sure no sibling process is renewing them, so step 1 can take them."""
    with session_factory() as session:
        held = session.scalar(
            select(func.count())
            .select_from(Scan)
            .where(Scan.status == ScanStatus.RUNNING, Scan.claimed_by == runner_id)
        )
    if held:
        logger.warning(
            "%d scan(s) are still claimed by %s from a previous run; recovering them",
            held,
            runner_id,
        )
        stop.wait(quiet_seconds(settings))


def run_forever(settings: Settings, stop: threading.Event) -> None:
    if settings.analyzer_provider != "docker":
        raise SystemExit("The scan runner requires ANALYZER_PROVIDER=docker")
    session_factory = get_sessionmaker()
    runner_id = default_runner_id(settings.runner_id)
    reconciler = OrphanReconciler(settings)
    logger.info(
        "scan-runner %s started (analyzer image %s, workspace mount %s, instance %s)",
        runner_id,
        settings.analyzer_image,
        settings.analyzer_workspace_mount,
        settings.analyzer_instance_label,
    )
    try:
        _wait_for_own_claims_to_quiet(session_factory, settings, runner_id, stop)
    except SQLAlchemyError:
        logger.exception("Database unavailable at startup")
    next_reconcile = 0.0
    while not stop.is_set():
        try:
            if time.monotonic() >= next_reconcile:
                reconcile_once(session_factory, settings, runner_id, reconciler)
                next_reconcile = time.monotonic() + settings.runner_reconcile_seconds
            with session_factory() as session:
                claim = claim_next_scan(session, runner_id)
        except SQLAlchemyError:
            logger.exception("Database unavailable; retrying")
            stop.wait(max(settings.runner_poll_seconds, 5.0))
            continue
        if claim is None:
            stop.wait(settings.runner_poll_seconds)
            continue
        logger.info("Claimed scan %s (claim %s)", claim.scan_id, claim.token)
        # Providers are rebuilt per scan so configuration and chain state are current.
        run_claimed_scan(claim.scan_id, session_factory, settings, build_providers(settings), claim)
    logger.info("scan-runner stopped")


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    stop = threading.Event()

    def handle(signum: int, _frame: FrameType | None) -> None:
        logger.info("Signal %s received; finishing the current scan, then stopping", signum)
        stop.set()

    signal.signal(signal.SIGTERM, handle)
    signal.signal(signal.SIGINT, handle)
    run_forever(settings, stop)
