"""Scan lifecycle shared by the software and model pipelines.

`run_scan` marks the scan RUNNING, opens its workspace, runs the pipeline-specific
`ingest` step (steps 1-3), then the evidence stages, then marks it COMPLETED. It never
raises. An ingestion failure marks the Scan FAILED with a structured error and removes
the workspace. Evidence stages record their own status and never fail the scan.
"""

import logging
from collections.abc import Callable
from typing import Any, TypeVar
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.db.models import Scan, ScanStatus, utcnow
from app.pipeline.workspace import Workspace, open_workspace, remove_workspace

logger = logging.getLogger(__name__)
T = TypeVar("T")


def record_failure(
    session: Session, scan_id: UUID, code: str, message: str, details: Any = None
) -> None:
    try:
        scan = session.get(Scan, scan_id)
        if scan is None:
            logger.error("Scan %s vanished while recording failure %s", scan_id, code)
            return
        scan.status = ScanStatus.FAILED
        scan.error_code = str(code)
        scan.error_message = message
        scan.error_details = details
        scan.finished_at = utcnow()
        session.commit()
    except SQLAlchemyError:
        logger.exception("Could not record failure %s for scan %s", code, scan_id)
        session.rollback()


def mark_completed(session: Session, scan_id: UUID) -> None:
    scan = session.get(Scan, scan_id)
    if scan is None:
        logger.error("Scan %s vanished before completion", scan_id)
        return
    scan.status = ScanStatus.COMPLETED
    scan.finished_at = utcnow()
    session.commit()


def run_scan(
    scan_id: UUID,
    session_factory: sessionmaker[Session],
    settings: Settings,
    ingest: Callable[[Session, Scan, Workspace], T],
    evidence: Callable[[Session, UUID, Workspace, T], None],
) -> None:
    """Run one scan end to end. `ingest` commits the artifact identity it collected."""
    with session_factory() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            logger.error("Scan %s not found; nothing to ingest", scan_id)
            return
        scan.status = ScanStatus.RUNNING
        scan.started_at = utcnow()
        session.commit()

        workspace: Workspace | None = None
        try:
            workspace = open_workspace(settings.workspace_root, scan_id)
            ingested = ingest(session, scan, workspace)
            evidence(session, scan_id, workspace, ingested)
            mark_completed(session, scan_id)
            return
        except AppError as exc:
            logger.warning("Scan %s failed: %s (%s)", scan_id, exc.code, exc.message)
            session.rollback()
            record_failure(session, scan_id, exc.code, exc.message, exc.details)
        except Exception:
            logger.exception("Unexpected error while ingesting scan %s", scan_id)
            session.rollback()
            record_failure(
                session,
                scan_id,
                ErrorCode.INTERNAL_ERROR,
                "Ingestion failed due to an internal error",
            )

        if workspace is not None:
            remove_workspace(workspace, settings.workspace_root)
