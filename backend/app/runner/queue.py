"""Claiming queued scans, and recovering claims whose runner disappeared.

`claim_next_scan` uses SELECT ... FOR UPDATE SKIP LOCKED on PostgreSQL, so several runners can
share one queue and each scan is claimed exactly once. Every claim gets a fresh claim token
(app/pipeline/ownership.py) that fences all later writes by that runner.

Stale recovery (`fail_stale_claims`) fails RUNNING scans whose heartbeat stopped, or that ran
past RUNNER_MAX_SCAN_SECONDS, and in the same locked transaction replaces their claim token.
The previous runner, if it is still alive, can then no longer change the scan: its next commit
is refused by the fence. A row another transaction holds locked (for example, a runner
committing a stage right now) is skipped and looked at again on the next pass.

(SQLite, used by the unit tests, ignores the lock clauses; the concurrency tests in
tests/integration/test_scan_ownership_pg.py run against PostgreSQL.)
"""

import logging
from collections.abc import Collection
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import ErrorCode
from app.db.models import Scan, ScanStatus, utcnow
from app.pipeline.ownership import ScanClaim, new_token

logger = logging.getLogger(__name__)

STALE_MESSAGE = (
    "The scan runner stopped while this scan was running, so its evidence is incomplete. "
    "Start a new scan."
)
OVERRUN_MESSAGE = (
    "The scan ran longer than the maximum scan duration and was stopped, so its evidence is "
    "incomplete. Start a new scan."
)


def _take(session: Session, scan: Scan, runner_id: str) -> ScanClaim:
    now = utcnow()
    token = new_token()
    scan.status = ScanStatus.RUNNING
    scan.claimed_at = now
    scan.heartbeat_at = now
    scan.claim_token = token
    scan.claimed_by = runner_id[:128] or None
    session.commit()
    return ScanClaim(scan_id=scan.id, token=token, runner_id=runner_id)


def claim_next_scan(session: Session, runner_id: str = "") -> ScanClaim | None:
    """Move the oldest QUEUED scan to RUNNING under a fresh claim, or None if the queue is empty."""
    stmt = (
        select(Scan)
        .where(Scan.status == ScanStatus.QUEUED)
        .order_by(Scan.created_at, Scan.id)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    scan = session.scalars(stmt).first()
    if scan is None:
        session.rollback()
        return None
    return _take(session, scan, runner_id)


def claim_scan(session: Session, scan_id: UUID, runner_id: str = "") -> ScanClaim | None:
    """Claim one specific QUEUED scan (used by the test-only inline dispatch)."""
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id, Scan.status == ScanStatus.QUEUED)
        .with_for_update(skip_locked=True)
    )
    scan = session.scalars(stmt).first()
    if scan is None:
        session.rollback()
        return None
    return _take(session, scan, runner_id)


def claim_next(session: Session) -> UUID | None:
    """Compatibility wrapper: claim the next scan and return only its id."""
    claim = claim_next_scan(session)
    return claim.scan_id if claim else None


def claim(session: Session, scan_id: UUID) -> bool:
    """Compatibility wrapper around `claim_scan`."""
    return claim_scan(session, scan_id) is not None


def _aware(moment: datetime) -> datetime:
    """SQLite returns naive datetimes; PostgreSQL returns aware ones."""
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def _fail(scan: Scan, message: str, details: dict[str, object]) -> None:
    scan.status = ScanStatus.FAILED
    scan.error_code = str(ErrorCode.RUNNER_INTERRUPTED)
    scan.error_message = message
    scan.error_details = details
    scan.finished_at = utcnow()
    # Invalidate the old claim in the same transaction: the old runner's fence now fails.
    scan.claim_token = new_token()


def fail_stale_claims(
    session: Session, stale_seconds: int, max_scan_seconds: int | None = None
) -> list[UUID]:
    """Fail RUNNING scans with no heartbeat for `stale_seconds`, or claimed more than
    `max_scan_seconds` ago. They cannot be resumed safely. Returns the failed scan ids.

    Scans claimed before heartbeats existed (heartbeat_at NULL) are judged by claimed_at.
    """
    now = utcnow()
    last_seen = func.coalesce(Scan.heartbeat_at, Scan.claimed_at)
    conditions = [last_seen < now - timedelta(seconds=stale_seconds)]
    if max_scan_seconds is not None:
        conditions.append(Scan.claimed_at < now - timedelta(seconds=max_scan_seconds))
    stmt = (
        select(Scan)
        .where(Scan.status == ScanStatus.RUNNING, or_(*conditions))
        .with_for_update(skip_locked=True)
    )
    failed: list[UUID] = []
    for scan in session.scalars(stmt).all():
        overran = (
            max_scan_seconds is not None
            and scan.claimed_at is not None
            and _aware(scan.claimed_at) < now - timedelta(seconds=max_scan_seconds)
        )
        if overran:
            _fail(scan, OVERRUN_MESSAGE, {"max_scan_seconds": max_scan_seconds})
        else:
            _fail(scan, STALE_MESSAGE, {"stale_after_seconds": stale_seconds})
        failed.append(scan.id)
    session.commit()
    if failed:
        logger.warning("Failed %d abandoned scan(s): %s", len(failed), failed)
    return failed


def recover_own_orphans(
    session: Session,
    runner_id: str,
    active: Collection[UUID],
    quiet_seconds: float,
) -> list[UUID]:
    """Fail RUNNING scans this runner identity claimed in an earlier life (it was killed).

    A runner runs one scan at a time and knows which one, so any other RUNNING scan under its
    identity was orphaned by a previous process, for example after SIGKILL and a container
    restart. Only scans whose heartbeat has been silent for `quiet_seconds` (a few heartbeat
    intervals) are taken, so a live sibling that was misconfigured with the same RUNNER_ID is
    not failed while it is still heartbeating.
    """
    if not runner_id:
        return []
    cutoff = utcnow() - timedelta(seconds=quiet_seconds)
    last_seen = func.coalesce(Scan.heartbeat_at, Scan.claimed_at)
    stmt = (
        select(Scan)
        .where(
            Scan.status == ScanStatus.RUNNING,
            Scan.claimed_by == runner_id,
            last_seen < cutoff,
        )
        .with_for_update(skip_locked=True)
    )
    failed: list[UUID] = []
    for scan in session.scalars(stmt).all():
        if scan.id in active:
            continue
        _fail(scan, STALE_MESSAGE, {"recovered_by": "runner_restart"})
        failed.append(scan.id)
    session.commit()
    if failed:
        logger.warning(
            "Recovered %d scan(s) orphaned by a previous runner: %s", len(failed), failed
        )
    return failed
