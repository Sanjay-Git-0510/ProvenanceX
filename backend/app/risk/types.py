"""Inputs and results of the risk engine.

CVSS, ML probability and the ProvenanceX risk are separate fields and are never merged.
`risk_score` is None when no rule layer could be scored, because 0 would read as clean.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, model_validator

from app.ml.feature_schema import FeatureValue, NullReason
from app.risk.policy_config import Decision, RiskLayer


class LayerStatus(StrEnum):
    EVALUATED = "evaluated"
    PARTIAL = "partial"
    NOT_EVALUATED = "not_evaluated"
    NOT_APPLICABLE = "not_applicable"


class ConfidenceLabel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class FindingRef:
    """The parts of a Finding the risk engine needs."""

    finding_id: str
    category: str
    identifier: str
    severity: str
    source: str


@dataclass(frozen=True)
class MlOutputs:
    """Model outputs. These are not the ProvenanceX risk score."""

    rf_risk_probability: float
    anomaly_score: float
    xgb_risk_probability: float | None = None
    rf_threshold: float | None = None
    anomaly_threshold: float | None = None
    model_version: str | None = None


@dataclass(frozen=True)
class RiskInputs:
    artifact_type: str
    features: Mapping[str, FeatureValue]
    null_reasons: Mapping[str, NullReason | str]
    findings: Sequence[FindingRef] = ()
    provenance_checks: Sequence[Mapping[str, object]] | None = None
    ml: MlOutputs | None = None
    ml_unavailable_reason: str | None = None
    record_id: str | None = field(default=None, compare=False)


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Signal(Frozen):
    name: str
    value: FeatureValue
    strength: float
    finding_id: str | None = None


class LayerResult(Frozen):
    layer: RiskLayer
    status: LayerStatus
    score: float | None
    coverage: float
    weight: float
    signals: list[Signal] = []
    evidence_finding_ids: list[str] = []
    mock_findings_ignored: int = 0
    not_evaluated: dict[str, str] = {}


class Contribution(Frozen):
    layer: RiskLayer
    contribution: float
    highest_rule_layer: bool


class FusionResult(Frozen):
    """contributions + ml_band_adjustment add up to risk_score."""

    risk_score: float | None
    rule_only_score: float | None
    contributions: list[Contribution]
    ml_band_adjustment: float


class HardRuleResult(Frozen):
    rule_id: str
    decision: str
    description: str


class MlSummary(Frozen):
    status: str
    message: str | None = None
    rf_risk_probability: float | None = None
    rf_flagged: bool | None = None
    xgb_risk_probability: float | None = None
    anomaly_score: float | None = None
    anomaly_flagged: bool | None = None
    model_version: str | None = None
    reliability_notes: list[str] = []


class RiskAssessment(Frozen):
    risk_score: float | None
    rule_only_score: float | None
    decision: str
    confidence: float
    confidence_label: ConfidenceLabel
    decision_basis: str
    reasons: list[str]
    allow_reason: str | None = None
    layers: list[LayerResult]
    contributions: list[Contribution]
    ml_band_adjustment: float
    not_evaluated_layers: list[RiskLayer]
    partial_layers: list[RiskLayer]
    hard_rules_fired: list[HardRuleResult]
    hard_rules_not_evaluated: list[str]
    cvss_max: float | None
    ml: MlSummary
    policy_version: str

    @model_validator(mode="after")
    def _allow_is_justified(self) -> "RiskAssessment":
        if self.decision == Decision.ALLOW.name and not self.allow_reason:
            raise ValueError("An ALLOW must carry its reason")
        return self
