"""Pipeline step 19: optionally anchor a completed scan. Off by default.

It runs after the scan is marked completed, because only completed scans can be anchored, and it
never changes that status. Transaction hashes are left out of the stage entry: they live in
blockchain_evidence, and the /evidence sanitizer would redact them here.
"""

from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.blockchain.anchoring import anchor_scan
from app.blockchain.base import ChainProvider
from app.core.config import Settings
from app.db.models import Scan
from app.pipeline.stages import StageStatus, execute_stage, skip_stage

STAGE = "anchor"


def run_anchor_stage(
    session: Session, scan_id: UUID, settings: Settings, provider: ChainProvider | None
) -> None:
    if not settings.blockchain_anchor_on_scan:
        skip_stage(session, scan_id, STAGE, "BLOCKCHAIN_ANCHOR_ON_SCAN is off")
        return

    def body(scan: Scan) -> tuple[None, StageStatus, dict[str, Any]]:
        result = anchor_scan(session, scan.id, provider, settings)
        fields = {
            "source": result.source,
            "is_mock": result.is_mock,
            "anchor_status": result.status,
            "missing_evidence": result.missing_evidence,
        }
        return None, StageStatus.COMPLETED, fields

    execute_stage(session, scan_id, STAGE, body, provider=provider.source if provider else None)
