"""Cross-layer fusion: a traceable 0..1 risk score and an evidence-based confidence.

risk = max_blend * (highest rule layer) + (1 - max_blend) * (weighted mean of scored layers)

Layers with no score are left out of both terms, so missing evidence is never averaged in as 0.
ML takes part in the weighted mean only, and is then limited to the decision band of the
rule-only score. That makes "ML alone cannot change the decision" structural: it holds for any
weights, and a low ML score cannot pull a borderline REVIEW down to ALLOW either.
"""

from app.risk.policy_config import ML_LAYERS, RULE_LAYERS, PolicyConfig, RiskLayer
from app.risk.types import ConfidenceLabel, Contribution, FusionResult, LayerResult, LayerStatus

_BAND_EDGE = 1e-6


def _blend(scored: list[LayerResult], policy: PolicyConfig) -> tuple[float, list[Contribution]]:
    """Fuse the scored layers and return each one's additive contribution."""
    top = max((r for r in scored if r.layer in RULE_LAYERS), key=lambda r: r.score or 0.0)
    total_weight = sum(r.weight for r in scored)
    contributions = []
    for result in scored:
        share = (1.0 - policy.max_blend) * result.weight / total_weight
        amount = share * (result.score or 0.0)
        if result.layer == top.layer:
            amount += policy.max_blend * (result.score or 0.0)
        contributions.append(
            Contribution(
                layer=result.layer,
                contribution=amount,
                highest_rule_layer=result.layer == top.layer,
            )
        )
    return sum(c.contribution for c in contributions), contributions


def _band(score: float, policy: PolicyConfig) -> tuple[float, float]:
    if score >= policy.block_threshold:
        return policy.block_threshold, 1.0
    if score >= policy.review_threshold:
        return policy.review_threshold, policy.block_threshold - _BAND_EDGE
    return 0.0, policy.review_threshold - _BAND_EDGE


def fuse(layers: list[LayerResult], policy: PolicyConfig) -> FusionResult:
    """Return the fused score, or a None score when no rule layer could be scored."""
    scored = [r for r in layers if r.score is not None]
    rule_scored = [r for r in scored if r.layer not in ML_LAYERS]
    if not rule_scored:
        return FusionResult(
            risk_score=None, rule_only_score=None, contributions=[], ml_band_adjustment=0.0
        )
    rule_only, _ = _blend(rule_scored, policy)
    fused, contributions = _blend(scored, policy)
    low, high = _band(rule_only, policy)
    limited = min(high, max(low, fused))
    return FusionResult(
        risk_score=limited,
        rule_only_score=rule_only,
        contributions=contributions,
        ml_band_adjustment=limited - fused,
    )


def confidence(layers: list[LayerResult]) -> float:
    """Weighted evidence coverage of the applicable rule layers. ML adds no confidence."""
    applicable = [
        r for r in layers if r.layer in RULE_LAYERS and r.status != LayerStatus.NOT_APPLICABLE
    ]
    total = sum(r.weight for r in applicable)
    return sum(r.weight * r.coverage for r in applicable) / total if total else 0.0


def confidence_label(value: float, policy: PolicyConfig) -> ConfidenceLabel:
    if value >= policy.high_confidence:
        return ConfidenceLabel.HIGH
    if value >= policy.medium_confidence:
        return ConfidenceLabel.MEDIUM
    return ConfidenceLabel.LOW


def required_layers_missing(
    layers: list[LayerResult], required: tuple[RiskLayer, ...]
) -> list[RiskLayer]:
    scored = {r.layer for r in layers if r.score is not None}
    return [layer for layer in required if layer not in scored]
