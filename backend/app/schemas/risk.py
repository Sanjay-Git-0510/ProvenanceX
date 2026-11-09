"""The /risk response.

risk_score is null, never 0, when it cannot be computed, and `status` and `reason` say why.
CVSS, the ML probability, the anomaly score and the ProvenanceX risk are separate values.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from app.db.models import RiskDecision, Scan, ScanStatus
from app.ml.feature_schema import FeatureValue
from app.risk.policy_config import FEATURE_LAYERS, RiskLayer
from app.risk.types import (
    ConfidenceLabel,
    HardRuleResult,
    LayerResult,
    MlSummary,
    RiskAssessment,
)

NO_SCORE_CODE = "no_rule_layer_scored"
NO_SCORE_MESSAGE = (
    "No rule layer could be scored, so there is no risk score. Missing evidence is not reported "
    "as 0. The decision is REVIEW unless a hard rule requires BLOCK."
)
_NO_RESULT_TRAINING_NOTICE = (
    "No model has produced a result for this scan. The only ProvenanceX models so far are trained "
    "on synthetic data."
)
_LABELS = {
    "provenancex_risk": "ProvenanceX risk (0 to 1, fused from the evidence layers)",
    "cvss_max": "Highest CVSS base score among known advisories (0 to 10)",
    "ml_probability": "Random Forest probability of any non-benign class (not the risk score)",
    "anomaly_score": "Isolation Forest anomaly score (higher is more unusual; not the risk score)",
}


class RiskStatus(StrEnum):
    PENDING = "pending"
    COMPUTED = "computed"
    NOT_COMPUTED = "not_computed"


class StatusReason(BaseModel):
    code: str
    message: str


class EvidenceLink(BaseModel):
    rel: str
    href: str


class ScoreValue(BaseModel):
    """One labeled measure. reason says why value is null."""

    label: str
    value: float | None
    reason: str | None = None


class SeparateScores(BaseModel):
    provenancex_risk: ScoreValue
    cvss_max: ScoreValue
    ml_probability: ScoreValue
    anomaly_score: ScoreValue


class LayerOut(LayerResult):
    contribution: float | None = None
    highest_rule_layer: bool = False
    evidence_links: list[EvidenceLink] = []


class HardRuleOut(HardRuleResult):
    finding_ids: list[str] = []
    evidence_links: list[EvidenceLink] = []


class HardRules(BaseModel):
    fired: list[HardRuleOut] = []
    not_evaluated: list[str] = []


class FactorOut(BaseModel):
    feature: str
    layer: RiskLayer
    value: FeatureValue
    evaluated: bool
    null_reason: str | None = None
    shap_contribution: float
    direction: str
    evidence_links: list[EvidenceLink] = []


class NotEvaluatedFeature(BaseModel):
    feature: str
    layer: RiskLayer
    null_reason: str
    in_model: bool | None = None


class ExplanationOut(BaseModel):
    status: str
    message: str | None = None
    method: str | None = None
    explains: str | None = None
    base_value: float | None = None
    model_output: float | None = None
    top_factors: list[FactorOut] = []
    not_evaluated_features: list[NotEvaluatedFeature] = []
    note: str | None = None


class TrainingDataLabel(BaseModel):
    label: str
    models_used: bool
    notice: str


def _api(scan_id: UUID, suffix: str = "") -> str:
    return f"/api/v1/scans/{scan_id}{suffix}"


def layer_links(scan_id: UUID, layer: RiskLayer) -> list[EvidenceLink]:
    """Where the evidence behind a layer can be read."""
    findings = _api(scan_id, "/findings?category=")
    scan = EvidenceLink(rel="scan_stages", href=_api(scan_id))
    graph = EvidenceLink(rel="graph", href=_api(scan_id, "/graph"))
    table = {
        RiskLayer.VULNERABILITY: [
            EvidenceLink(rel="vulnerability_findings", href=f"{findings}vulnerability")
        ],
        RiskLayer.PROVENANCE: [
            EvidenceLink(rel="provenance_findings", href=f"{findings}provenance"),
            scan,
        ],
        RiskLayer.GRAPH: [graph],
        RiskLayer.STATIC: [EvidenceLink(rel="static_findings", href=f"{findings}static")],
        RiskLayer.BEHAVIORAL: [
            EvidenceLink(rel="behavioral_findings", href=f"{findings}behavioral")
        ],
        RiskLayer.AI_SPECIFIC: [scan, graph],
    }
    return table.get(layer, [])


def _all_evidence_links(scan_id: UUID) -> list[EvidenceLink]:
    seen: dict[str, EvidenceLink] = {}
    for layer in RiskLayer:
        for link in layer_links(scan_id, layer):
            seen[link.href] = link
    return list(seen.values())


def _empty_scores(message: str) -> SeparateScores:
    def empty(name: str) -> ScoreValue:
        return ScoreValue(label=_LABELS[name], value=None, reason=message)

    return SeparateScores(
        provenancex_risk=empty("provenancex_risk"),
        cvss_max=empty("cvss_max"),
        ml_probability=empty("ml_probability"),
        anomaly_score=empty("anomaly_score"),
    )


def _layers(scan_id: UUID, assessment: RiskAssessment) -> list[LayerOut]:
    contributions = {c.layer: c for c in assessment.contributions}
    layers = []
    for layer in assessment.layers:
        share = contributions.get(layer.layer)
        layers.append(
            LayerOut(
                **layer.model_dump(),
                contribution=share.contribution if share else None,
                highest_rule_layer=share.highest_rule_layer if share else False,
                evidence_links=layer_links(scan_id, layer.layer),
            )
        )
    return layers


def _hard_rules(scan_id: UUID, assessment: RiskAssessment, evidence: dict[str, Any]) -> HardRules:
    fired = []
    for rule in assessment.hard_rules_fired:
        detail = evidence.get(rule.rule_id, {})
        links = [
            link
            for layer in detail.get("layers", [])
            for link in layer_links(scan_id, RiskLayer(layer))
        ]
        fired.append(
            HardRuleOut(
                **rule.model_dump(),
                finding_ids=detail.get("finding_ids", []),
                evidence_links=links,
            )
        )
    return HardRules(fired=fired, not_evaluated=assessment.hard_rules_not_evaluated)


def _explanation(scan_id: UUID, stored: dict[str, Any]) -> ExplanationOut:
    factors = [
        FactorOut(**factor, evidence_links=layer_links(scan_id, FEATURE_LAYERS[factor["feature"]]))
        for factor in stored.get("top_factors", [])
    ]
    return ExplanationOut(**{**stored, "top_factors": factors})


def _scores(decision: RiskDecision, assessment: RiskAssessment, cvss_reason: str | None):
    no_score = None if decision.risk_score is not None else NO_SCORE_MESSAGE
    ml_reason = assessment.ml.message if assessment.ml.status != "available" else None
    return SeparateScores(
        provenancex_risk=ScoreValue(
            label=_LABELS["provenancex_risk"], value=decision.risk_score, reason=no_score
        ),
        cvss_max=ScoreValue(label=_LABELS["cvss_max"], value=decision.cvss_max, reason=cvss_reason),
        ml_probability=ScoreValue(
            label=_LABELS["ml_probability"], value=decision.ml_probability, reason=ml_reason
        ),
        anomaly_score=ScoreValue(
            label=_LABELS["anomaly_score"], value=decision.anomaly_score, reason=ml_reason
        ),
    )


class RiskResponse(BaseModel):
    scan_id: UUID
    scan_status: ScanStatus
    status: RiskStatus
    reason: StatusReason | None = None
    risk_score: float | None = None
    rule_only_score: float | None = None
    ml_band_adjustment: float | None = None
    decision: str | None = None
    decision_basis: str | None = None
    decision_reasons: list[str] = []
    allow_reason: str | None = None
    confidence: float | None = None
    confidence_label: ConfidenceLabel | None = None
    layers: list[LayerOut] = []
    not_evaluated_layers: list[RiskLayer] = []
    partial_layers: list[RiskLayer] = []
    hard_rules: HardRules = HardRules()
    scores: SeparateScores
    ml: MlSummary | None = None
    explanation: ExplanationOut | None = None
    training_data: TrainingDataLabel
    evidence_links: list[EvidenceLink] = []
    contains_mock_evidence: bool = False
    policy_version: str | None = None
    computed_at: datetime | None = None

    @classmethod
    def without_result(
        cls, scan: Scan, status: RiskStatus, code: str, message: str
    ) -> "RiskResponse":
        """A scan with no risk result yet. Every value stays null."""
        return cls(
            scan_id=scan.id,
            scan_status=scan.status,
            status=status,
            reason=StatusReason(code=code, message=message),
            scores=_empty_scores(message),
            training_data=TrainingDataLabel(
                label="synthetic", models_used=False, notice=_NO_RESULT_TRAINING_NOTICE
            ),
            evidence_links=_all_evidence_links(scan.id),
        )

    @classmethod
    def from_decision(cls, scan: Scan, decision: RiskDecision) -> "RiskResponse":
        stored = decision.explanation
        assessment = RiskAssessment.model_validate(stored["assessment"])
        scored = decision.risk_score is not None
        return cls(
            scan_id=scan.id,
            scan_status=scan.status,
            status=RiskStatus.COMPUTED if scored else RiskStatus.NOT_COMPUTED,
            reason=None if scored else StatusReason(code=NO_SCORE_CODE, message=NO_SCORE_MESSAGE),
            risk_score=decision.risk_score,
            rule_only_score=decision.rule_only_score,
            ml_band_adjustment=assessment.ml_band_adjustment,
            decision=str(decision.decision),
            decision_basis=decision.decision_basis,
            decision_reasons=assessment.reasons,
            allow_reason=assessment.allow_reason,
            confidence=decision.confidence,
            confidence_label=assessment.confidence_label,
            layers=_layers(scan.id, assessment),
            not_evaluated_layers=assessment.not_evaluated_layers,
            partial_layers=assessment.partial_layers,
            hard_rules=_hard_rules(scan.id, assessment, stored.get("hard_rule_evidence", {})),
            scores=_scores(decision, assessment, stored.get("cvss_reason")),
            ml=assessment.ml,
            explanation=_explanation(scan.id, stored["shap"]),
            training_data=TrainingDataLabel(**stored["training_data"]),
            evidence_links=_all_evidence_links(scan.id),
            contains_mock_evidence=bool(stored.get("contains_mock_evidence")),
            policy_version=decision.policy_version,
            computed_at=decision.created_at,
        )
