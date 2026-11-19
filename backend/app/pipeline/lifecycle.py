"""Scan lifecycle shared by the software and model pipelines.

`run_scan` marks the scan RUNNING, opens its workspace, runs the pipeline-specific
`ingest` step (steps 1-3), then the evidence stages, then marks it COMPLETED. It never
raises. An ingestion failure marks the Scan FAILED with a structured error and removes
the workspace. Evidence stages record their own status and never fail the scan.

With a `claim` (the scan-runner always passes one), the session is fenced on the claim token
(app/pipeline/ownership.py) and the RUNNING -> COMPLETED/FAILED transitions are conditional on
it. If the claim is lost (stale recovery replaced it), the run stops without writing anything
more: the recovered state stands, and only this runner's workspace is removed.
"""

import logging
from collections.abc import Callable
from typing import Any, TypeVar
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.db.models import RiskDecision, Scan, ScanStatus, utcnow
from app.pipeline.ownership import (
    ClaimLost,
    ScanClaim,
    bind_claim,
    claim_context,
    transition,
    unbind_claim,
)
from app.pipeline.workspace import Workspace, open_workspace, remove_workspace

logger = logging.getLogger(__name__)
T = TypeVar("T")


def record_failure(
    session: Session,
    scan_id: UUID,
    code: str,
    message: str,
    details: Any = None,
    claim: ScanClaim | None = None,
) -> None:
    """Mark the scan FAILED. With a claim, only while this runner still owns it (ClaimLost)."""
    values = {
        "status": ScanStatus.FAILED,
        "error_code": str(code),
        "error_message": message,
        "error_details": details,
        "finished_at": utcnow(),
    }
    try:
        if claim is not None:
            transition(session, claim, **values)
            return
        scan = session.get(Scan, scan_id)
        if scan is None:
            logger.error("Scan %s vanished while recording failure %s", scan_id, code)
            return
        for key, value in values.items():
            setattr(scan, key, value)
        session.commit()
    except SQLAlchemyError:
        logger.exception("Could not record failure %s for scan %s", code, scan_id)
        session.rollback()


def mark_completed(session: Session, scan_id: UUID, claim: ScanClaim | None = None) -> None:
    if claim is not None:
        transition(session, claim, status=ScanStatus.COMPLETED, finished_at=utcnow())
        return
    scan = session.get(Scan, scan_id)
    if scan is None:
        logger.error("Scan %s vanished before completion", scan_id)
        return
    scan.status = ScanStatus.COMPLETED
    scan.finished_at = utcnow()
    session.commit()


def _require_decision(session: Session, scan_id: UUID) -> None:
    """A scan may only complete once its risk decision is stored."""
    stored = session.scalars(select(RiskDecision.id).where(RiskDecision.scan_id == scan_id)).first()
    if stored is None:
        raise AppError(
            ErrorCode.RISK_NOT_COMPUTED,
            "Risk scoring did not produce a decision, so the scan was not completed",
        )


def _run_after_completed(
    session: Session, scan_id: UUID, step: Callable[[Session, UUID], None]
) -> None:
    """A step after completion can never change the outcome of the scan."""
    try:
        step(session, scan_id)
    except Exception:
        logger.exception("Post-completion step failed for scan %s", scan_id)
        session.rollback()


def run_scan(
    scan_id: UUID,
    session_factory: sessionmaker[Session],
    settings: Settings,
    ingest: Callable[[Session, Scan, Workspace], T],
    evidence: Callable[[Session, UUID, Workspace, T], None],
    after_completed: Callable[[Session, UUID], None] | None = None,
    require_decision: bool = False,
    claim: ScanClaim | None = None,
) -> None:
    """Run one scan end to end. `ingest` commits the artifact identity it collected."""
    with session_factory() as session, claim_context(claim):
        scan = session.get(Scan, scan_id)
        if scan is None:
            logger.error("Scan %s not found; nothing to ingest", scan_id)
            return
        workspace: Workspace | None = None
        try:
            if claim is not None:
                bind_claim(session, claim)
                transition(session, claim, started_at=utcnow())
                session.refresh(scan)
            else:
                scan.status = ScanStatus.RUNNING
                scan.started_at = utcnow()
                session.commit()

            try:
                workspace = open_workspace(settings.workspace_root, scan_id)
                ingested = ingest(session, scan, workspace)
                evidence(session, scan_id, workspace, ingested)
                if require_decision:
                    _require_decision(session, scan_id)
                mark_completed(session, scan_id, claim)
                if after_completed is not None:
                    _run_after_completed(session, scan_id, after_completed)
                return
            except ClaimLost:
                raise
            except AppError as exc:
                logger.warning("Scan %s failed: %s (%s)", scan_id, exc.code, exc.message)
                session.rollback()
                record_failure(session, scan_id, exc.code, exc.message, exc.details, claim)
            except Exception:
                logger.exception("Unexpected error while ingesting scan %s", scan_id)
                session.rollback()
                record_failure(
                    session,
                    scan_id,
                    ErrorCode.INTERNAL_ERROR,
                    "Ingestion failed due to an internal error",
                    claim=claim,
                )
        except ClaimLost:
            # Another runner (stale recovery) owns the outcome now. Write nothing.
            logger.warning("Scan %s: claim lost; abandoning the run without writing", scan_id)
            session.rollback()
        finally:
            unbind_claim(session)

        if workspace is not None:
            remove_workspace(workspace, settings.workspace_root)
