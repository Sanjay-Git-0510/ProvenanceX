"""Pipeline steps 11-18: features, models, fusion, policy, SHAP, and the stored RiskDecision.

It runs after the sandbox and, like every evidence stage, never fails the scan. It also saves
the comparison snapshot that a later scan of the same source is compared against. Config digests
exist only here, because the workspace files cannot be relied on once the scan has finished.
Graph edges are not copied into the snapshot: they are already stored in graph_edges.
"""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.analysis.base import section_to_error
from app.core.config import Settings
from app.db.models import Scan
from app.pipeline.stages import StageStatus, execute_stage
from app.risk.service import compute_decision, snapshot_document
from app.sandbox_worker.protocol import AnalysisOut, SectionError

STAGE = "risk"
SOURCE = "provenancex"


@dataclass(frozen=True)
class CollectedRiskInputs:
    """Content-derived risk inputs, computed in the analyzer sandbox."""

    config_sha256: str | None
    config_error: SectionError | None
    declared_versions: dict[str, str] | None

    @classmethod
    def from_analysis(cls, collected: AnalysisOut) -> "CollectedRiskInputs":
        return cls(
            collected.config_sha256, collected.config_sha256_error, collected.declared_versions
        )


def run_risk_stage(
    session: Session, scan_id: UUID, settings: Settings, inputs: CollectedRiskInputs
) -> dict[str, Any] | None:
    def body(scan: Scan) -> tuple[dict[str, Any], StageStatus, dict[str, Any]]:
        if inputs.config_error is not None:
            raise section_to_error(inputs.config_error)
        config_sha256 = inputs.config_sha256
        decision = compute_decision(
            session, scan, settings, config_sha256, declared_versions=inputs.declared_versions
        )
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
