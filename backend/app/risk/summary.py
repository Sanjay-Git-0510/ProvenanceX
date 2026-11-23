"""One readable explanation of a stored risk result, built when the response is served.

It only rearranges what the assessment and the SHAP result already hold, so it never invents a
value, and a decision stored by an earlier policy still gets a summary (marked as such).
"""

from typing import Any

from app.risk.policy_config import DEFAULT_POLICY, ML_LAYERS, POLICY_VERSION, PolicyConfig
from app.risk.types import EvidenceItem, Frozen, LayerStatus, RiskAssessment

HANDSET_NOTE = (
    "Fusion weights and thresholds are hand-set research parameters. They are not calibrated "
    "on real artifacts and are not security standards."
)
SYNTHETIC_NOTE = (
    "ML outputs come from models trained on synthetic data. They do not measure real-world "
    "detection, and ML alone cannot change the decision."
)
GAP_STATES = frozenset(
    {"weak_provenance", "integrity_unverified", "no_prior_scan", "missing_evidence"}
)
LEGACY_NOTE = "This result was stored by an earlier policy; evidence status was not recorded."
TOP_SIGNALS = 3
TOP_ML_FACTORS = 5


class Factor(Frozen):
    layer: str
    contribution: float
    layer_score: float | None
    top_signals: list[dict[str, Any]]


class Completeness(Frozen):
    confidence: float
    confidence_label: str
    evaluated_layers: list[str]
    partial_layers: list[str]
    not_evaluated_layers: list[str]
    not_applicable_layers: list[str]


class MlFactors(Frozen):
    status: str
    explains: str | None
    message: str | None
    factors: list[dict[str, Any]]


class RiskSummary(Frozen):
    risk_score: float | None
    risk_level: str | None  # LOW / MEDIUM / HIGH band of the score, never colour alone
    decision: str
    decision_basis: str
    decision_reasons: list[str]
    confidence: float
    evidence_completeness: Completeness
    critical_findings: list[dict[str, str]]
    confirmed_evidence: bool | None
    top_factors: list[Factor]
    ml_factors: MlFactors
    missing_evidence: list[EvidenceItem]
    evidence_status: list[EvidenceItem]
    hard_rules_not_evaluated: list[str]
    notes: list[str]
    policy_version: str


def risk_level(score: float | None, policy: PolicyConfig = DEFAULT_POLICY) -> str | None:
    if score is None:
        return None
    if score >= policy.block_threshold:
        return "HIGH"
    return "MEDIUM" if score >= policy.review_threshold else "LOW"


def _factors(assessment: RiskAssessment) -> list[Factor]:
    by_layer = {layer.layer: layer for layer in assessment.layers}
    ranked = sorted(
        (c for c in assessment.contributions if c.contribution > 0),
        key=lambda c: (-c.contribution, str(c.layer)),
    )
    out = []
    for c in ranked:
        layer = by_layer[c.layer]
        signals = sorted(layer.signals, key=lambda s: -s.strength)[:TOP_SIGNALS]
        out.append(
            Factor(
                layer=str(c.layer),
                contribution=round(c.contribution, 4),
                layer_score=layer.score,
                top_signals=[
                    {"name": s.name, "value": s.value, "strength": round(s.strength, 4)}
                    for s in signals
                ],
            )
        )
    return out


def _ml_factors(shap: dict[str, Any] | None) -> MlFactors:
    shap = shap or {}
    if shap.get("status") != "available":
        return MlFactors(
            status="unavailable",
            explains=None,
            message=shap.get("message") or "No SHAP explanation was stored",
            factors=[],
        )
    return MlFactors(
        status="available",
        explains=shap.get("explains"),
        message=shap.get("note"),
        factors=list(shap.get("top_factors") or [])[:TOP_ML_FACTORS],
    )


def _completeness(assessment: RiskAssessment) -> Completeness:
    rule = [layer for layer in assessment.layers if layer.layer not in ML_LAYERS]

    def named(status: LayerStatus) -> list[str]:
        return [str(layer.layer) for layer in rule if layer.status == status]

    return Completeness(
        confidence=assessment.confidence,
        confidence_label=str(assessment.confidence_label),
        evaluated_layers=named(LayerStatus.EVALUATED),
        partial_layers=named(LayerStatus.PARTIAL),
        not_evaluated_layers=named(LayerStatus.NOT_EVALUATED),
        not_applicable_layers=named(LayerStatus.NOT_APPLICABLE),
    )


def build_summary(assessment: RiskAssessment, shap: dict[str, Any] | None) -> RiskSummary:
    status = assessment.evidence_status
    legacy = not status and assessment.policy_version != POLICY_VERSION
    notes = [HANDSET_NOTE, SYNTHETIC_NOTE] + ([LEGACY_NOTE] if legacy else [])
    return RiskSummary(
        risk_score=assessment.risk_score,
        risk_level=risk_level(assessment.risk_score),
        decision=assessment.decision,
        decision_basis=assessment.decision_basis,
        decision_reasons=assessment.reasons,
        confidence=assessment.confidence,
        evidence_completeness=_completeness(assessment),
        critical_findings=[
            {"rule_id": r.rule_id, "decision": r.decision, "description": r.description}
            for r in assessment.hard_rules_fired
        ],
        confirmed_evidence=None if legacy else any(item.confirmed for item in status),
        top_factors=_factors(assessment),
        ml_factors=_ml_factors(shap),
        missing_evidence=[item for item in status if item.state in GAP_STATES],
        evidence_status=status,
        hard_rules_not_evaluated=assessment.hard_rules_not_evaluated,
        notes=notes,
        policy_version=assessment.policy_version,
    )
