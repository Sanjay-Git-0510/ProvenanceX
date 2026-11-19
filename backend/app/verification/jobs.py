"""The verification job queue (table `verification_runs`).

API side (`enqueue`): no file reads and no chain calls. It reuses the scan's active job if there
is one (a partial unique index allows one queued or running job per scan, so concurrent POSTs
collapse onto one row), refuses beyond VERIFY_MAX_PENDING queued jobs with 429, and answers a scan
that can never have an anchor at once with NOT ANCHORED (a database-only decision).

Runner side: `claim_next_verification` uses SELECT ... FOR UPDATE SKIP LOCKED, so each job is
claimed once. A claim gets a fresh token; the heartbeat and the final write are conditional
UPDATEs on that token and status='running', so a runner whose job was recovered as stale can
no longer write its answer. Stale and orphaned jobs are failed with an UNKNOWN answer: a job
that could not finish never reads as VERIFIED.
"""

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.blockchain.verification import NOTE, cannot_be_anchored, not_anchored_response
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.db.models import (
    ACTIVE_VERIFICATION,
    Scan,
    VerificationRun,
    VerificationStatus,
    utcnow,
)
from app.pipeline.ownership import ScanClaim, new_token
from app.schemas.blockchain import VerificationReason, VerificationResponse, VerificationState

logger = logging.getLogger(__name__)

_QUEUE_LOCK_KEY = 0x5058_5645_5249  # "PXVERI": the enqueue advisory lock
INTERRUPTED = ("verify_interrupted", "The verification job stopped before it finished")
TIMED_OUT = ("verify_timeout", "The verification job ran longer than VERIFY_MAX_SECONDS")


@dataclass
class VerifyClaim:
    """A runner's claim on one job. `claim` carries the token, the lost flag and step clock that
    the analyzer uses to label and cancel the rehash container (its scan_id is the job's scan)."""

    job_id: UUID
    claim: ScanClaim
    sandbox: list[dict[str, Any]] = field(default_factory=list)

    @property
    def scan_id(self) -> UUID:
        return self.claim.scan_id

    @property
    def token(self) -> UUID:
        return self.claim.token


def unknown_response(scan_id: UUID, code: str, message: str) -> VerificationResponse:
    """The answer of a job that could not finish: UNKNOWN, with no field comparisons."""
    return VerificationResponse(
        scan_id=scan_id,
        state=VerificationState.UNKNOWN,
        reason=VerificationReason(code=code, message=message),
        source=None,
        is_mock=False,
        fields=[],
        missing_evidence=[],
        tx_hash=None,
        block_number=None,
        block_hash=None,
        anchor_index=None,
        chain_id=None,
        contract_address=None,
        verified_at=utcnow(),
        note=NOTE,
    )


def _finished_values(status: VerificationStatus, result: VerificationResponse) -> dict[str, Any]:
    return {
        "status": status.value,
        "state": result.state.value,
        "reason_code": result.reason.code[:64],
        "reason_message": result.reason.message,
        "result": result.model_dump(mode="json"),
        "finished_at": utcnow(),
    }


# ----------------------------------------------------------------------------- API side
def _active(session: Session, scan_id: UUID) -> VerificationRun | None:
    return session.scalars(
        select(VerificationRun).where(
            VerificationRun.scan_id == scan_id,
            VerificationRun.status.in_(ACTIVE_VERIFICATION),
        )
    ).first()


def enqueue(session: Session, scan_id: UUID, settings: Settings) -> tuple[VerificationRun, bool]:
    """Return (job, finished). Raises scan_not_found (404) or verify_queue_full (429)."""
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise AppError(ErrorCode.SCAN_NOT_FOUND, "Scan not found", 404)
    existing = _active(session, scan_id)
    if existing is not None:
        return existing, False
    if cannot_be_anchored(session, scan):
        result = not_anchored_response(session, scan)
        run = VerificationRun(scan_id=scan_id, requested_at=utcnow())
        for key, value in _finished_values(VerificationStatus.COMPLETED, result).items():
            setattr(run, key, value)
        session.add(run)
        session.commit()
        return run, True
    if session.get_bind().dialect.name == "postgresql":
        # Serialize count-then-insert across API workers so the cap is exact (released at
        # commit or rollback). SQLite, used by unit tests, has a single writer anyway.
        session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _QUEUE_LOCK_KEY})
    pending = session.scalar(
        select(func.count())
        .select_from(VerificationRun)
        .where(VerificationRun.status == VerificationStatus.QUEUED.value)
    )
    if (pending or 0) >= settings.verify_max_pending:
        raise AppError(
            ErrorCode.VERIFY_QUEUE_FULL,
            "Too many verification jobs are waiting; try again later",
            429,
            {"max_pending": settings.verify_max_pending},
        )
    run = VerificationRun(
        scan_id=scan_id, status=VerificationStatus.QUEUED.value, requested_at=utcnow()
    )
    session.add(run)
    try:
        session.commit()
    except IntegrityError:
        # A concurrent POST inserted the active job first (partial unique index): reuse it.
        session.rollback()
        existing = _active(session, scan_id)
        if existing is None:
            raise
        return existing, False
    return run, False


# ----------------------------------------------------------------------------- runner side
def claim_next_verification(
    session: Session, runner_id: str = "", job_id: UUID | None = None
) -> VerifyClaim | None:
    """Move the oldest queued job (or the given one) to running under a fresh claim, or None."""
    stmt = select(VerificationRun).where(VerificationRun.status == VerificationStatus.QUEUED.value)
    if job_id is not None:
        stmt = stmt.where(VerificationRun.id == job_id)
    run = session.scalars(
        stmt.order_by(VerificationRun.requested_at, VerificationRun.id)
        .limit(1)
        .with_for_update(skip_locked=True)
    ).first()
    if run is None:
        session.rollback()
        return None
    now = utcnow()
    token = new_token()
    run.status = VerificationStatus.RUNNING.value
    run.claim_token = token
    run.claimed_by = runner_id[:128] or None
    run.started_at = now
    run.heartbeat_at = now
    session.commit()
    return VerifyClaim(run.id, ScanClaim(scan_id=run.scan_id, token=token, runner_id=runner_id))


def _owned_running(claim: VerifyClaim):  # noqa: ANN202 - SQLAlchemy where clause
    return (
        VerificationRun.id == claim.job_id,
        VerificationRun.claim_token == claim.token,
        VerificationRun.status == VerificationStatus.RUNNING.value,
    )


def renew(session: Session, claim: VerifyClaim) -> bool:
    """Renew the heartbeat. False (and the claim marked lost) if the job was taken away."""
    done = session.execute(
        update(VerificationRun).where(*_owned_running(claim)).values(heartbeat_at=utcnow())
    )
    session.commit()
    if done.rowcount != 1:
        claim.claim.mark_lost()
        return False
    return True


def finish(
    session: Session,
    claim: VerifyClaim,
    result: VerificationResponse,
    status: VerificationStatus = VerificationStatus.COMPLETED,
) -> bool:
    """Store the answer only if this claim still owns the running job. True if it did."""
    if claim.claim.lost.is_set():
        return False
    values = _finished_values(status, result)
    values["sandbox"] = {"runs": claim.sandbox} if claim.sandbox else None
    done = session.execute(update(VerificationRun).where(*_owned_running(claim)).values(**values))
    session.commit()
    if done.rowcount != 1:
        claim.claim.mark_lost()
        logger.warning("Verification job %s was taken away; its answer was dropped", claim.job_id)
        return False
    return True


def fail(session: Session, claim: VerifyClaim, code: str, message: str) -> bool:
    return finish(
        session, claim, unknown_response(claim.scan_id, code, message), VerificationStatus.FAILED
    )


def _fail_rows(session: Session, rows: list[VerificationRun], why: tuple[str, str]) -> None:
    for run in rows:
        result = unknown_response(run.scan_id, *why)
        for key, value in _finished_values(VerificationStatus.FAILED, result).items():
            setattr(run, key, value)
        # The old token stays on the row, so the reconciler can match (and remove) the job's
        # container; the status change alone already fences the old runner's writes.


def fail_stale_verifications(session: Session, stale_seconds: int, max_seconds: int) -> list[UUID]:
    """Fail running jobs whose heartbeat stopped or that ran past VERIFY_MAX_SECONDS."""
    now = utcnow()
    last_seen = func.coalesce(VerificationRun.heartbeat_at, VerificationRun.started_at)
    rows = session.scalars(
        select(VerificationRun)
        .where(
            VerificationRun.status == VerificationStatus.RUNNING.value,
            or_(
                last_seen < now - timedelta(seconds=stale_seconds),
                VerificationRun.started_at < now - timedelta(seconds=max_seconds),
            ),
        )
        .with_for_update(skip_locked=True)
    ).all()
    cutoff = now - timedelta(seconds=max_seconds)
    overran = [r for r in rows if r.started_at is not None and _aware(r.started_at) < cutoff]
    _fail_rows(session, overran, TIMED_OUT)
    _fail_rows(session, [r for r in rows if r not in overran], INTERRUPTED)
    session.commit()
    if rows:
        logger.warning("Failed %d abandoned verification job(s)", len(rows))
    return [r.id for r in rows]


def recover_own_verification_orphans(
    session: Session, runner_id: str, quiet_seconds: float
) -> list[UUID]:
    """Fail running jobs this runner identity claimed in an earlier life (it was killed)."""
    if not runner_id:
        return []
    cutoff = utcnow() - timedelta(seconds=quiet_seconds)
    last_seen = func.coalesce(VerificationRun.heartbeat_at, VerificationRun.started_at)
    rows = list(
        session.scalars(
            select(VerificationRun)
            .where(
                VerificationRun.status == VerificationStatus.RUNNING.value,
                VerificationRun.claimed_by == runner_id,
                last_seen < cutoff,
            )
            .with_for_update(skip_locked=True)
        ).all()
    )
    _fail_rows(session, rows, INTERRUPTED)
    session.commit()
    return [r.id for r in rows]


def _aware(moment: datetime) -> datetime:
    """SQLite returns naive datetimes; PostgreSQL returns aware ones."""
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)
