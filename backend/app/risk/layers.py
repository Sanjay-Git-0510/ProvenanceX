"""Turn features, findings and checks into one result per evidence layer.

A layer's score combines its signals as 1 - product(1 - strength). Evidence that is missing is
not scored as 0: a layer with no usable evidence has score None. Findings from a partial stage
can raise a layer's score, because a problem seen in partial evidence is still a problem, but a
quiet partial stage never reads as clean.
"""

from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from app.ml.feature_schema import FEATURES, FeatureValue, NullReason
from app.ml.features import AI_ARTIFACT_TYPES
from app.risk.policy_config import (
    FEATURE_LAYERS,
    FINDING_LAYERS,
    ML_LAYERS,
    RULE_LAYERS,
    Mode,
    Op,
    PolicyConfig,
    RiskLayer,
    SignalRule,
)
from app.risk.types import FindingRef, LayerResult, LayerStatus, RiskInputs, Signal

_EXCLUDED_FROM_COVERAGE = frozenset({NullReason.NOT_APPLICABLE, NullReason.NO_DATA_SOURCE})
_CHECK_LAYER = RiskLayer.PROVENANCE


def matches(op: Op, value: FeatureValue, threshold: float, values: tuple[str, ...] = ()) -> bool:
    """Whether a non-null feature value meets the condition."""
    if value is None:
        return False
    if op == Op.IS_TRUE:
        return value is True
    if op == Op.IS_FALSE:
        return value is False
    if op == Op.IN:
        return str(value) in values
    if isinstance(value, str):
        return False
    if op == Op.GT:
        return value > threshold
    if op == Op.GE:
        return value >= threshold
    return value < threshold


def null_reason(inputs: RiskInputs, name: str) -> NullReason:
    raw = inputs.null_reasons.get(name, NullReason.NOT_DETERMINABLE)
    return NullReason(raw)


def is_ai(inputs: RiskInputs) -> bool:
    return inputs.artifact_type in AI_ARTIFACT_TYPES


def _strength(rule: SignalRule, value: FeatureValue) -> float:
    if value is None or isinstance(value, str) and rule.mode != Mode.FLAG:
        return 0.0
    if rule.mode == Mode.PER_COUNT:
        return min(rule.cap, rule.weight * float(value))
    if rule.mode == Mode.SCALE:
        return min(1.0, float(value) / rule.divisor)
    return rule.weight if matches(rule.op, value, rule.threshold, rule.values) else 0.0


def _feature_signals(inputs: RiskInputs, policy: PolicyConfig) -> dict[RiskLayer, list[Signal]]:
    found: dict[RiskLayer, list[Signal]] = defaultdict(list)
    for rule in policy.signals:
        value = inputs.features.get(rule.feature)
        strength = _strength(rule, value)
        if strength > 0:
            found[FEATURE_LAYERS[rule.feature]].append(
                Signal(name=rule.feature, value=value, strength=strength)
            )
    if (inputs.features.get("vulnerable_count") or 0) > 0 and (
        inputs.features.get("cvss_max") is None
    ):
        found[RiskLayer.VULNERABILITY].append(
            Signal(
                name="vulnerability_without_cvss",
                value=inputs.features.get("vulnerable_count"),
                strength=policy.unscored_vulnerability_signal,
            )
        )
    return found


def _check_signals(inputs: RiskInputs, policy: PolicyConfig) -> list[Signal]:
    return [
        Signal(name=str(check.get("name")), value=False, strength=policy.check_signals[name])
        for check in inputs.provenance_checks or ()
        if (name := str(check.get("name"))) in policy.check_signals
        and check.get("status") == "fail"
    ]


def _coverage(
    inputs: RiskInputs, names: list[str], policy: PolicyConfig
) -> tuple[float | None, bool, bool, dict[str, str]]:
    """Return (coverage or None if not applicable, any evaluated, any partial, null reasons)."""
    earned = 0.0
    applicable = 0
    any_evaluated = False
    any_partial = False
    not_evaluated: dict[str, str] = {}
    for name in names:
        value = inputs.features.get(name)
        if value is None and _absent_because_clean(inputs, name):
            applicable += 1
            earned += 1.0
            any_evaluated = True
            continue
        if value is not None:
            applicable += 1
            earned += 1.0
            any_evaluated = True
            continue
        reason = null_reason(inputs, name)
        not_evaluated[name] = str(reason)
        if reason in _EXCLUDED_FROM_COVERAGE:
            continue
        applicable += 1
        if reason == NullReason.STAGE_PARTIAL:
            earned += policy.partial_credit
            any_partial = True
    return (earned / applicable if applicable else None), any_evaluated, any_partial, not_evaluated


def _absent_because_clean(inputs: RiskInputs, name: str) -> bool:
    """A maximum CVSS does not exist when the lookup ran and found no vulnerable component."""
    return (
        name == "cvss_max"
        and inputs.features.get("vulnerable_count") == 0
        and null_reason(inputs, name) == NullReason.NOT_DETERMINABLE
    )


def _combine(signals: list[Signal]) -> float:
    remaining = 1.0
    for signal in signals:
        remaining *= 1.0 - signal.strength
    return 1.0 - remaining


def _finding_signals(findings: list[FindingRef], policy: PolicyConfig) -> list[Signal]:
    return [
        Signal(
            name=finding.identifier,
            value=finding.severity,
            strength=policy.severity_signals.get(
                finding.severity.upper(), policy.default_severity_signal
            ),
            finding_id=finding.finding_id,
        )
        for finding in findings
    ]


def _status(score: float | None, coverage: float, any_partial: bool) -> LayerStatus:
    if score is None and not any_partial:
        return LayerStatus.NOT_EVALUATED
    if coverage >= 1.0 and not any_partial:
        return LayerStatus.EVALUATED
    return LayerStatus.PARTIAL


def _rule_layer(
    layer: RiskLayer,
    inputs: RiskInputs,
    policy: PolicyConfig,
    names: list[str],
    signals: list[Signal],
    findings: list[FindingRef],
) -> LayerResult:
    weight = policy.weights[layer]
    real = [f for f in findings if f.source != "mock"]
    coverage, any_evaluated, any_partial, not_evaluated = _coverage(inputs, names, policy)
    common: dict[str, Any] = {
        "layer": layer,
        "weight": weight,
        "evidence_finding_ids": [f.finding_id for f in real],
        "mock_findings_ignored": len(findings) - len(real),
        "not_evaluated": not_evaluated,
    }
    if coverage is None:
        return LayerResult(status=LayerStatus.NOT_APPLICABLE, score=None, coverage=0.0, **common)
    combined = list(signals)
    if any_partial:
        combined += _finding_signals(real, policy)
    score = _combine(combined) if any_evaluated or combined else None
    return LayerResult(
        status=_status(score, coverage, any_partial),
        score=score,
        coverage=coverage,
        signals=combined,
        **common,
    )


def _ml_layers(inputs: RiskInputs, policy: PolicyConfig) -> list[LayerResult]:
    ml = inputs.ml
    scores = {
        RiskLayer.ML_SUPERVISED: ml.rf_risk_probability if ml else None,
        RiskLayer.ML_ANOMALY: ml.anomaly_score if ml else None,
    }
    results = []
    for layer in ML_LAYERS:
        score = scores[layer]
        results.append(
            LayerResult(
                layer=layer,
                status=LayerStatus.EVALUATED if score is not None else LayerStatus.NOT_EVALUATED,
                score=None if score is None else min(1.0, max(0.0, float(score))),
                coverage=1.0 if score is not None else 0.0,
                weight=policy.weights[layer],
            )
        )
    return results


def _group(items: Mapping[str, RiskLayer]) -> dict[RiskLayer, list[str]]:
    grouped: dict[RiskLayer, list[str]] = defaultdict(list)
    for name, layer in items.items():
        grouped[layer].append(name)
    return grouped


def build_layers(inputs: RiskInputs, policy: PolicyConfig) -> list[LayerResult]:
    """One result for every rule layer, then the ML layers, in a fixed order."""
    names = _group({f.name: FEATURE_LAYERS[f.name] for f in FEATURES})
    signals = _feature_signals(inputs, policy)
    signals[_CHECK_LAYER].extend(_check_signals(inputs, policy))
    findings: dict[RiskLayer, list[FindingRef]] = defaultdict(list)
    for finding in inputs.findings:
        if finding.category in FINDING_LAYERS:
            findings[FINDING_LAYERS[finding.category]].append(finding)
    rule_results = [
        _rule_layer(layer, inputs, policy, names[layer], signals[layer], findings[layer])
        for layer in RULE_LAYERS
    ]
    return [*rule_results, *_ml_layers(inputs, policy)]
