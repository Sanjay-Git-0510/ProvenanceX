"""Per-stage status recorded on Scan.stages.

A scan can be COMPLETED while individual evidence stages are unavailable or failed.
Recording each stage's status, provider and source keeps partial evidence from being
read as a clean result. Statuses:
  completed    the stage ran and its evidence is complete
  partial      the stage ran but some evidence is missing (see warnings)
  unavailable  a required tool or service could not be used (e.g. Syft missing, OSV down)
  error        the stage failed (see error)
  skipped      the stage did not run because an earlier stage it needs did not succeed
"""

import logging
from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from typing import Any, TypeVar
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.errors import AppError, ErrorCode
from app.db.models import Scan, utcnow

logger = logging.getLogger(__name__)
T = TypeVar("T")


class StageStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    SKIPPED = "skipped"


SUCCESS_STATUSES = frozenset({StageStatus.COMPLETED, StageStatus.PARTIAL})
UNAVAILABLE_CODES = frozenset(
    {ErrorCode.SBOM_TOOL_UNAVAILABLE, ErrorCode.VULN_SOURCE_UNAVAILABLE, ErrorCode.HF_UNAVAILABLE}
)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def record_stage(scan: Scan, name: str, status: StageStatus, **fields: Any) -> dict[str, Any]:
    """Write one stage entry. Assigns a new dict, so SQLAlchemy sees the JSON change."""
    entry = {"status": str(status), **fields}
    entry.setdefault("finished_at", _iso(utcnow()))
    stages = dict(scan.stages or {})
    stages[name] = entry
    scan.stages = stages
    return entry


def status_for_error(exc: AppError) -> StageStatus:
    return StageStatus.UNAVAILABLE if exc.code in UNAVAILABLE_CODES else StageStatus.ERROR


def error_fields(code: str, message: str, details: Any = None) -> dict[str, Any]:
    return {"error": {"code": str(code), "message": message, "details": details}}


def started() -> str:
    return _iso(utcnow()) or ""


def execute_stage(
    session: Session,
    scan_id: UUID,
    name: str,
    body: Callable[[Scan], tuple[T, StageStatus, dict[str, Any]]],
    *,
    provider: str | None = None,
) -> T | None:
    """Run one stage body, persist its output plus status, and never raise.

    `body(scan)` adds its rows to the session and returns (output, status, extra fields).
    On AppError the stage's DB changes are rolled back and a structured error is
    recorded. Unexpected exceptions are logged with a traceback and recorded as
    internal_error, so they are never swallowed silently.
    """
    begun = started()
    base: dict[str, Any] = {"started_at": begun}
    if provider is not None:
        base["provider"] = provider
    scan = session.get(Scan, scan_id)
    if scan is None:
        logger.error("Scan %s vanished before stage %s", scan_id, name)
        return None
    try:
        output, status, fields = body(scan)
        record_stage(scan, name, status, **base, **fields)
        session.commit()
        logger.info("Scan %s stage %s: %s", scan_id, name, status)
        return output
    except AppError as exc:
        logger.warning("Scan %s stage %s failed: %s (%s)", scan_id, name, exc.code, exc.message)
        failure = (status_for_error(exc), error_fields(exc.code, exc.message, exc.details))
    except Exception:
        logger.exception("Scan %s stage %s raised an unexpected error", scan_id, name)
        failure = (
            StageStatus.ERROR,
            error_fields(ErrorCode.INTERNAL_ERROR, f"Stage {name} failed due to an internal error"),
        )
    session.rollback()
    try:
        scan = session.get(Scan, scan_id)
        if scan is not None:
            record_stage(scan, name, failure[0], **base, **failure[1])
            session.commit()
    except SQLAlchemyError:
        logger.exception("Could not record failure of stage %s for scan %s", name, scan_id)
        session.rollback()
    return None


def skip_stage(session: Session, scan_id: UUID, name: str, reason: str) -> None:
    scan = session.get(Scan, scan_id)
    if scan is None:
        return
    record_stage(scan, name, StageStatus.SKIPPED, reason=reason)
    session.commit()
