"""Pipeline steps 11-18: features, models, fusion, policy, SHAP, and the stored RiskDecision.

It runs after the sandbox and, like every evidence stage, never fails the scan. It also saves
the comparison snapshot that a later scan of the same source is compared against. Config digests
exist only here, because the workspace files cannot be relied on once the scan has finished.
Graph edges are not copied into the snapshot: they are already stored in graph_edges.
"""

from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.models import Scan
from app.ml.comparison import config_digest
from app.pipeline.stages import StageStatus, execute_stage
from app.pipeline.workspace import Workspace
from app.risk.service import compute_decision, snapshot_document

STAGE = "risk"
SOURCE = "provenancex"


def run_risk_stage(
    session: Session, scan_id: UUID, workspace: Workspace, settings: Settings
) -> dict[str, Any] | None:
    def body(scan: Scan) -> tuple[dict[str, Any], StageStatus, dict[str, Any]]:
        config_sha256 = config_digest(workspace.src_dir)
        decision = compute_decision(session, scan, settings, config_sha256)
        session.add(decision)
        summary = {
            "risk_score": decision.risk_score,
            "decision": str(decision.decision),
            "ml_status": decision.ml_status,
            "model_version": decision.model_version,
        }
        fields = {
            "source": SOURCE,
            **summary,
            "comparison_snapshot": snapshot_document(session, scan, config_sha256),
        }
        return summary, StageStatus.COMPLETED, fields

    return execute_stage(session, scan_id, STAGE, body, provider="provenancex")
