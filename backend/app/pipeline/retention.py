"""Persistent workspace budget (Milestone B).

The kept trees of finished scans (needed by POST /scans/{id}/verify to re-hash the artifact)
live in the persistent workspace. Each tree is already bounded (copied from a kernel-capped
staging volume, within MAX_ARTIFACT_SIZE_MB and MAX_ARTIFACT_FILES), and the total is bounded
here: before a new tree is persisted, the `src` trees of the oldest finished (COMPLETED or
FAILED) scans are deleted until the new one fits in WORKSPACE_MAX_TOTAL_MB. Their small evidence
files (SBOM, provenance record) are kept; /verify then reports UNKNOWN for the artifact hash,
which is the documented result when off-chain content is missing.

Only directory metadata (lstat) is read here, never file content.
"""

import logging
import shutil
from pathlib import Path
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.db.models import Scan, ScanStatus
from app.pipeline.workspace import MB, directory_size

logger = logging.getLogger(__name__)


def _src_of(base: Path, scan_id: UUID) -> Path:
    return base.resolve() / str(UUID(str(scan_id))) / "src"


def ensure_workspace_room(
    session: Session, settings: Settings, needed_bytes: int, current: UUID
) -> list[UUID]:
    """Prune old trees until `needed_bytes` fits. Returns the pruned scan ids.

    Raises workspace_budget_exceeded if it cannot fit even after pruning everything allowed.
    """
    base = Path(settings.workspace_root)
    budget = settings.workspace_max_total_mb * MB
    if needed_bytes > budget:
        raise AppError(
            ErrorCode.WORKSPACE_BUDGET_EXCEEDED,
            "The artifact is larger than the persistent workspace budget",
            507,
            {"workspace_max_total_mb": settings.workspace_max_total_mb},
        )
    used = directory_size(base) if base.is_dir() else 0
    pruned: list[UUID] = []
    if used + needed_bytes <= budget:
        return pruned
    rows = session.execute(
        select(Scan.id)
        .where(Scan.status.in_((ScanStatus.COMPLETED, ScanStatus.FAILED)), Scan.id != current)
        .order_by(Scan.finished_at.asc().nulls_first())
    ).all()
    session.rollback()  # read-only; release the snapshot before deleting
    for (scan_id,) in rows:
        src = _src_of(base, scan_id)
        if src.is_symlink() or not src.is_dir() or src.parent.parent != base.resolve():
            continue
        size = directory_size(src)
        if size == 0:
            continue
        try:
            shutil.rmtree(src)
        except OSError:
            logger.exception("Could not prune workspace tree %s", src)
            continue
        src.mkdir(mode=0o700)
        used -= size
        pruned.append(scan_id)
        logger.warning("Pruned the kept tree of scan %s (%d bytes) for the budget", scan_id, size)
        if used + needed_bytes <= budget:
            return pruned
    raise AppError(
        ErrorCode.WORKSPACE_BUDGET_EXCEEDED,
        "The persistent workspace is full and could not be pruned enough",
        507,
        {"workspace_max_total_mb": settings.workspace_max_total_mb},
    )
