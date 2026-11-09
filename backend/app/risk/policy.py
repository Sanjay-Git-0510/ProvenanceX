"""Map fused risk and evidence to ALLOW, REVIEW or BLOCK.

The decision is the strictest of the rule-only score band, the hard rules and the evidence
gates. An ALLOW needs every required layer scored and confidence at or above the configured
minimum, and it always states its reason, confidence and the layers that were not evaluated.
"""

from app.ml.feature_schema import Applies, NullReason
from app.risk.fusion import confidence, confidence_label, fuse, required_layers_missing
from app.risk.layers import build_layers, is_ai, matches, null_reason
from app.risk.policy_config import (
    DEFAULT_POLICY,
    ML_UNAVAILABLE_MESSAGE,
    POLICY_VERSION,
    Decision,
    HardRule,
    PolicyConfig,
    Predicate,
)
from app.risk.types import (
    FusionResult,
    HardRuleResult,
    LayerResult,
    LayerStatus,
    MlSummary,
    RiskAssessment,
    RiskInputs,
)

_NO_COMPARISON_NOTE = (
    "No hash comparison is available. The Random Forest over-flagged benign synthetic records "
    "in this situation, so read its output with care."
)
_SYNTHETIC_NOTE = "Models were trained on synthetic data; outputs are not real-world accuracy."


def _check_status(inputs: RiskInputs, name: str) -> str | None:
    for check in inputs.provenance_checks or ():
        if check.get("name") == name:
            return str(check.get("status"))
    return None


def _predicate(inputs: RiskInputs, predicate: Predicate) -> bool | None:
    """True or False when the predicate could be evaluated, otherwise None."""
    outcomes: list[bool] = []
    if predicate.feature is not None:
        value = inputs.features.get(predicate.feature)
        if value is not None:
            outcomes.append(matches(predicate.op, value, predicate.threshold))
    if predicate.check is not None:
        status = _check_status(inputs, predicate.check)
        if status in {"pass", "fail"}:
            outcomes.append(status == "fail")
    if predicate.finding is not None and any(
        f.identifier == predicate.finding and f.source != "mock" for f in inputs.findings
    ):
        outcomes.append(True)
    if any(outcomes):
        return True
    return False if outcomes else None


def _applies(rule: HardRule, inputs: RiskInputs) -> bool:
    if rule.applies == Applies.ALL:
        return True
    return is_ai(inputs) == (rule.applies == Applies.AI)


def _hard_rules(inputs: RiskInputs, policy: PolicyConfig) -> tuple[list[HardRule], list[str]]:
    fired: list[HardRule] = []
    not_evaluated: list[str] = []
    for rule in policy.hard_rules:
        if not _applies(rule, inputs):
            continue
        outcomes = [_predicate(inputs, predicate) for predicate in rule.predicates]
        if all(outcome is True for outcome in outcomes):
            fired.append(rule)
        elif False not in outcomes:
            not_evaluated.append(rule.rule_id)
    return fired, not_evaluated


def _score_decision(score: float | None, policy: PolicyConfig) -> Decision:
    if score is None:
        return Decision.REVIEW
    if score >= policy.block_threshold:
        return Decision.BLOCK
    return Decision.REVIEW if score >= policy.review_threshold else Decision.ALLOW


def _ml_summary(inputs: RiskInputs) -> MlSummary:
    ml = inputs.ml
    if ml is None:
        return MlSummary(
            status="unavailable",
            message=(
                f"{ML_UNAVAILABLE_MESSAGE}: {inputs.ml_unavailable_reason}"
                if inputs.ml_unavailable_reason
                else ML_UNAVAILABLE_MESSAGE
            ),
        )
    notes = [_SYNTHETIC_NOTE]
    if inputs.features.get("hash_changed") is None and (
        null_reason(inputs, "hash_changed") != NullReason.NOT_APPLICABLE
    ):
        notes.append(_NO_COMPARISON_NOTE)
    return MlSummary(
        status="available",
        rf_risk_probability=ml.rf_risk_probability,
        rf_flagged=None if ml.rf_threshold is None else ml.rf_risk_probability >= ml.rf_threshold,
        xgb_risk_probability=ml.xgb_risk_probability,
        anomaly_score=ml.anomaly_score,
        anomaly_flagged=(
            None if ml.anomaly_threshold is None else ml.anomaly_score >= ml.anomaly_threshold
        ),
        model_version=ml.model_version,
        reliability_notes=notes,
    )


def _layer_names(layers: list) -> str:
    return ", ".join(str(layer) for layer in layers) or "none"


def _allow_reason(fusion: FusionResult, value: float, policy: PolicyConfig, missing: list) -> str:
    return (
        f"Rule-only score {fusion.rule_only_score:.3f} is below the REVIEW threshold "
        f"{policy.review_threshold:.2f}, no hard rule fired, every required layer was scored, "
        f"and confidence {value:.2f} meets the minimum {policy.min_allow_confidence:.2f}. "
        f"Layers not evaluated: {_layer_names(missing)}."
    )


def _decide(
    inputs: RiskInputs,
    layers: list[LayerResult],
    fusion: FusionResult,
    fired: list[HardRule],
    value: float,
    policy: PolicyConfig,
) -> tuple[Decision, str, list[str], str | None]:
    band = _score_decision(fusion.rule_only_score, policy)
    reasons = [f"{rule.rule_id}: {rule.description}" for rule in fired]
    decision = max([band, *(rule.decision for rule in fired)])
    basis = "hard_rule" if fired and decision > band else "score"
    if fusion.rule_only_score is None:
        reasons.append("No rule layer could be scored, so there is no risk score")
        basis = "insufficient_evidence" if basis == "score" else basis
    elif band > Decision.ALLOW:
        reasons.append(f"Rule-only score {fusion.rule_only_score:.3f} is in the {band.name} band")
    if decision > Decision.ALLOW:
        return decision, basis, reasons, None
    missing = required_layers_missing(layers, policy.required_layers(is_ai(inputs)))
    if missing:
        reasons.append(f"Required layers were not evaluated: {_layer_names(missing)}")
    if value < policy.min_allow_confidence:
        reasons.append(
            f"Confidence {value:.2f} is below the ALLOW minimum {policy.min_allow_confidence:.2f}"
        )
    if missing or value < policy.min_allow_confidence:
        return Decision.REVIEW, "insufficient_evidence", reasons, None
    not_evaluated = _not_evaluated(layers)
    reason = _allow_reason(fusion, value, policy, not_evaluated)
    return Decision.ALLOW, "score", [reason], reason


def _not_evaluated(layers: list[LayerResult]) -> list:
    return [r.layer for r in layers if r.status != LayerStatus.NOT_APPLICABLE and r.score is None]


def assess_risk(inputs: RiskInputs, policy: PolicyConfig = DEFAULT_POLICY) -> RiskAssessment:
    """Produce the full, traceable risk result for one scan's evidence."""
    layers = build_layers(inputs, policy)
    fusion = fuse(layers, policy)
    value = confidence(layers)
    fired, rules_not_evaluated = _hard_rules(inputs, policy)
    decision, basis, reasons, allow_reason = _decide(inputs, layers, fusion, fired, value, policy)
    cvss = inputs.features.get("cvss_max")
    return RiskAssessment(
        risk_score=fusion.risk_score,
        rule_only_score=fusion.rule_only_score,
        decision=decision.name,
        confidence=value,
        confidence_label=confidence_label(value, policy),
        decision_basis=basis,
        reasons=reasons,
        allow_reason=allow_reason,
        layers=layers,
        contributions=fusion.contributions,
        ml_band_adjustment=fusion.ml_band_adjustment,
        not_evaluated_layers=_not_evaluated(layers),
        partial_layers=[r.layer for r in layers if r.status == LayerStatus.PARTIAL],
        hard_rules_fired=[
            HardRuleResult(rule_id=r.rule_id, decision=r.decision.name, description=r.description)
            for r in fired
        ],
        hard_rules_not_evaluated=rules_not_evaluated,
        cvss_max=float(cvss) if isinstance(cvss, int | float) else None,
        ml=_ml_summary(inputs),
        policy_version=POLICY_VERSION,
    )
