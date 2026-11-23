"""Every fusion weight, policy threshold and hard rule, in one place.

THESE ARE HAND-SET RESEARCH PARAMETERS. They were chosen by judgment. They have not been tuned
or validated, on the synthetic dataset or on real artifacts, and they are not security
standards. `ml/reports/fusion_sensitivity.md` shows how decisions on the synthetic validation
split move when each weight changes; that is analysis only and fitted nothing. Do not adjust
any value here after looking at test-split results.

Deliberate trade-off: ML alone cannot change the decision. The decision band comes from the
rule-only score, and ML moves the score only inside that band (see fusion.py). A threat that
only the model sees therefore does not trigger REVIEW. The reason is measured: on the synthetic
test split the Random Forest flagged 19 of 26 benign records that had no hash comparison, which
is the situation of every first scan.

Policy v2 (2026-11-23, still hand-set and uncalibrated):
- Separate weights for software and AI artifacts (model, lora, dataset), because their threat
  models differ: an AI artifact's vulnerability layer covers only runtime dependencies, while its
  AI-specific layer (custom code, serialization, config) carries most of its risk.
- A BLOCK that comes from the score band alone needs confidence >= min_block_confidence and every
  required layer scored; otherwise it becomes REVIEW. A BLOCK from a hard rule (confirmed
  tampering, dangerous pickle globals, sensitive access plus an external destination) stays.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import IntEnum, StrEnum
from types import MappingProxyType

from app.ml.feature_schema import FEATURES, Applies, Layer

POLICY_VERSION = "provenancex-policy-v2-handset"
ML_UNAVAILABLE_MESSAGE = "ML model unavailable"


class RiskLayer(StrEnum):
    VULNERABILITY = "vulnerability"
    PROVENANCE = "provenance_integrity"
    GRAPH = "graph"
    STATIC = "static"
    BEHAVIORAL = "behavioral"
    AI_SPECIFIC = "ai_specific"
    ML_SUPERVISED = "ml_supervised"
    ML_ANOMALY = "ml_anomaly"


RULE_LAYERS = (
    RiskLayer.VULNERABILITY,
    RiskLayer.PROVENANCE,
    RiskLayer.GRAPH,
    RiskLayer.STATIC,
    RiskLayer.BEHAVIORAL,
    RiskLayer.AI_SPECIFIC,
)
ML_LAYERS = (RiskLayer.ML_SUPERVISED, RiskLayer.ML_ANOMALY)


class Decision(IntEnum):
    """Ordered by severity, so the strictest of several outcomes is max()."""

    ALLOW = 0
    REVIEW = 1
    BLOCK = 2


class Op(StrEnum):
    IS_TRUE = "is_true"
    IS_FALSE = "is_false"
    GT = "gt"
    GE = "ge"
    LT = "lt"
    IN = "in"


class Mode(StrEnum):
    FLAG = "flag"  # `weight` when the condition holds
    PER_COUNT = "per_count"  # `weight` per unit, up to `cap`
    SCALE = "scale"  # value / divisor, up to 1


@dataclass(frozen=True)
class SignalRule:
    """One way a feature raises its layer's score. Null features never fire."""

    feature: str
    weight: float = 1.0
    mode: Mode = Mode.FLAG
    op: Op = Op.IS_TRUE
    threshold: float = 0.0
    values: tuple[str, ...] = ()
    cap: float = 1.0
    divisor: float = 1.0


@dataclass(frozen=True)
class Predicate:
    """Holds when the feature test, the failed check or the non-mock finding is present."""

    feature: str | None = None
    op: Op = Op.IS_TRUE
    threshold: float = 0.0
    check: str | None = None
    finding: str | None = None


@dataclass(frozen=True)
class HardRule:
    """Forces at least `decision`, whatever the score or the model says."""

    rule_id: str
    decision: Decision
    description: str
    predicates: tuple[Predicate, ...]  # all must hold
    applies: Applies = Applies.ALL


# Layer of each feature where it differs from the name of its ML layer.
_LAYER_FOR_ML_LAYER: Mapping[Layer, RiskLayer] = {
    Layer.DEPENDENCY: RiskLayer.GRAPH,
    Layer.VULNERABILITY: RiskLayer.VULNERABILITY,
    Layer.AI_MODEL: RiskLayer.AI_SPECIFIC,
    Layer.PROVENANCE: RiskLayer.PROVENANCE,
    Layer.METADATA: RiskLayer.AI_SPECIFIC,
    Layer.STATIC: RiskLayer.STATIC,
    Layer.BEHAVIOR: RiskLayer.BEHAVIORAL,
    Layer.GRAPH: RiskLayer.GRAPH,
}
FEATURE_LAYERS: Mapping[str, RiskLayer] = MappingProxyType(
    {feature.name: _LAYER_FOR_ML_LAYER[feature.layer] for feature in FEATURES}
    | {"version_consistency": RiskLayer.PROVENANCE}  # applies to software too
)

FINDING_LAYERS: Mapping[str, RiskLayer] = MappingProxyType(
    {
        "vulnerability": RiskLayer.VULNERABILITY,
        "provenance": RiskLayer.PROVENANCE,
        "static": RiskLayer.STATIC,
        "behavioral": RiskLayer.BEHAVIORAL,
    }
)

_SIGNALS: tuple[SignalRule, ...] = (
    # Vulnerability. CVSS is an input here and stays a separate value in the result.
    SignalRule("cvss_max", mode=Mode.SCALE, divisor=10.0),
    SignalRule("vulnerable_count", 0.02, Mode.PER_COUNT, cap=0.10),
    # Provenance / integrity
    SignalRule("hash_changed_same_commit", 0.90),
    SignalRule("provenance_removed", 0.60),
    SignalRule("hash_changed", 0.15),
    SignalRule("provenance_present", 0.15, op=Op.IS_FALSE),
    SignalRule("source_known", 0.30, op=Op.IS_FALSE),
    SignalRule("revision_pinned", 0.05, op=Op.IS_FALSE),
    SignalRule("version_consistency", 0.30, op=Op.IS_FALSE),
    SignalRule("lineage_completeness", 0.20, op=Op.LT, threshold=0.5),
    # Graph
    SignalRule("new_edge_count", 0.05, Mode.PER_COUNT, cap=0.40),
    SignalRule("centrality_shift", 0.15, op=Op.GT, threshold=0.2),
    SignalRule("suspicious_lineage", 0.30, Mode.PER_COUNT, cap=0.60),
    SignalRule("unexpected_parent_or_base_model", 0.50),
    # Static
    SignalRule("dangerous_import_count", 0.10, Mode.PER_COUNT, cap=0.40),
    SignalRule("suspicious_api_count", 0.10, Mode.PER_COUNT, cap=0.40),
    SignalRule("script_presence", 0.05),
    SignalRule("archive_anomaly", 0.60, op=Op.GT),
    SignalRule("install_hook_count", 0.50, op=Op.GT),
    SignalRule("pickle_dangerous_global_count", 0.90, op=Op.GT),
    # Behavioral
    SignalRule("network_count", 0.05, Mode.PER_COUNT, cap=0.30),
    SignalRule("process_count", 0.02, Mode.PER_COUNT, cap=0.15),
    SignalRule("file_write_count", 0.01, Mode.PER_COUNT, cap=0.10),
    SignalRule("external_destination_count", 0.30, Mode.PER_COUNT, cap=0.60),
    SignalRule("resource_spike", 0.20),
    SignalRule("sensitive_file_access_count", 0.40, Mode.PER_COUNT, cap=0.70),
    SignalRule("shell_spawn_count", 0.40, Mode.PER_COUNT, cap=0.60),
    # AI-specific
    SignalRule("custom_code_present", 0.40),
    SignalRule("serialization_type", 0.30, op=Op.IN, values=("pickle", "pytorch_zip")),
    SignalRule("config_changed", 0.30),
    SignalRule("model_card_completeness", 0.10, op=Op.LT, threshold=0.5),
    SignalRule("license_present", 0.05, op=Op.IS_FALSE),
)

_EXTERNAL = Predicate("external_destination_count", Op.GT, finding="PX-BEHAV-EXTERNAL-CONNECT")
_SENSITIVE = Predicate("sensitive_file_access_count", Op.GT, finding="PX-BEHAV-SENSITIVE-FILE")

_HARD_RULES: tuple[HardRule, ...] = (
    HardRule(
        "hash_consistency_failed",
        Decision.BLOCK,
        "The same commit produced different content than an earlier scan",
        (Predicate("hash_changed_same_commit", check="hash_consistency"),),
    ),
    HardRule(
        "download_integrity_failed",
        Decision.BLOCK,
        "A downloaded file did not match the hash listed by the source",
        (Predicate(check="download_integrity"),),
        Applies.AI,
    ),
    HardRule(
        "dangerous_pickle_globals",
        Decision.BLOCK,
        "A pickle references globals that can execute code",
        (Predicate("pickle_dangerous_global_count", Op.GT),),
        Applies.AI,
    ),
    HardRule(
        "sensitive_access_with_external_destination",
        Decision.BLOCK,
        "The sandbox saw sensitive file access and an external destination",
        (_SENSITIVE, _EXTERNAL),
    ),
    HardRule(
        "install_hook_present",
        Decision.REVIEW,
        "The artifact declares install-time hooks",
        (Predicate("install_hook_count", Op.GT),),
    ),
    HardRule(
        "archive_anomaly",
        Decision.REVIEW,
        "An archive inside the artifact is anomalous",
        (Predicate("archive_anomaly", Op.GT),),
    ),
    HardRule(
        "custom_model_code",
        Decision.REVIEW,
        "The model ships custom code",
        (Predicate("custom_code_present"),),
        Applies.AI,
    ),
    HardRule(
        "shell_spawn",
        Decision.REVIEW,
        "The sandbox saw a shell or network tool start",
        (Predicate("shell_spawn_count", Op.GT, finding="PX-BEHAV-SHELL-SPAWN"),),
    ),
    HardRule(
        "external_destination",
        Decision.REVIEW,
        "The sandbox saw an attempt to reach a public destination",
        (_EXTERNAL,),
    ),
    HardRule(
        "provenance_removed",
        Decision.REVIEW,
        "Provenance present in an earlier scan is gone",
        (Predicate("provenance_removed"),),
    ),
    HardRule(
        "unexpected_base_model",
        Decision.REVIEW,
        "The lineage has an unexpected parent or base model",
        (Predicate("unexpected_parent_or_base_model"),),
        Applies.AI,
    ),
    HardRule(
        "critical_known_vulnerability",
        Decision.REVIEW,
        "A known vulnerability has CVSS 9.0 or higher (vulnerable does not mean malicious)",
        (Predicate("cvss_max", Op.GE, threshold=9.0),),
    ),
)


def _default_weights() -> dict[RiskLayer, float]:
    """Software (and container) weights. Hand-set, not calibrated."""
    return {
        RiskLayer.VULNERABILITY: 0.25,
        RiskLayer.PROVENANCE: 0.25,
        RiskLayer.GRAPH: 0.10,
        RiskLayer.STATIC: 0.20,
        RiskLayer.BEHAVIORAL: 0.15,
        RiskLayer.AI_SPECIFIC: 0.10,
        RiskLayer.ML_SUPERVISED: 0.15,
        RiskLayer.ML_ANOMALY: 0.02,  # near chance on the synthetic data, so deliberately small
    }


def _default_ai_weights() -> dict[RiskLayer, float]:
    """Model, LoRA and dataset weights. Hand-set, not calibrated."""
    return {
        RiskLayer.VULNERABILITY: 0.10,  # runtime dependencies only
        RiskLayer.PROVENANCE: 0.25,
        RiskLayer.GRAPH: 0.10,  # lineage
        RiskLayer.STATIC: 0.20,  # includes pickle opcode analysis
        RiskLayer.BEHAVIORAL: 0.15,
        RiskLayer.AI_SPECIFIC: 0.20,
        RiskLayer.ML_SUPERVISED: 0.15,
        RiskLayer.ML_ANOMALY: 0.02,
    }


@dataclass(frozen=True)
class PolicyConfig:
    """Fusion and policy parameters. See the module docstring: hand-set, not validated."""

    weights: Mapping[RiskLayer, float] = field(default_factory=_default_weights)
    weights_ai: Mapping[RiskLayer, float] = field(default_factory=_default_ai_weights)
    max_blend: float = 0.5  # share of the score taken from the highest rule layer
    review_threshold: float = 0.35
    block_threshold: float = 0.70
    min_allow_confidence: float = 0.60
    min_block_confidence: float = 0.60  # below it, a score-only BLOCK becomes REVIEW
    medium_confidence: float = 0.40
    high_confidence: float = 0.75
    partial_credit: float = 0.5  # coverage credit for a feature whose stage was partial
    unscored_vulnerability_signal: float = 0.5  # advisory exists but has no CVSS
    severity_signals: Mapping[str, float] = field(
        default_factory=lambda: {"CRITICAL": 0.90, "HIGH": 0.70, "MEDIUM": 0.40, "LOW": 0.15}
    )
    default_severity_signal: float = 0.15
    check_signals: Mapping[str, float] = field(default_factory=lambda: {"download_integrity": 0.95})
    required_software: tuple[RiskLayer, ...] = (
        RiskLayer.VULNERABILITY,
        RiskLayer.PROVENANCE,
        RiskLayer.STATIC,
    )
    required_ai: tuple[RiskLayer, ...] = (
        RiskLayer.PROVENANCE,
        RiskLayer.STATIC,
        RiskLayer.AI_SPECIFIC,
    )
    signals: tuple[SignalRule, ...] = _SIGNALS
    hard_rules: tuple[HardRule, ...] = _HARD_RULES

    def __post_init__(self) -> None:
        for weights in (self.weights, self.weights_ai):
            if set(weights) != set(RiskLayer):
                raise ValueError("Every risk layer needs exactly one weight")
            if any(weights[layer] <= 0 for layer in RULE_LAYERS):
                raise ValueError("Rule layer weights must be positive")
            if any(weights[layer] < 0 for layer in ML_LAYERS):
                raise ValueError("ML layer weights cannot be negative")
        if not 0 <= self.max_blend <= 1:
            raise ValueError("max_blend must be within 0..1")
        if not 0 < self.review_threshold < self.block_threshold <= 1:
            raise ValueError("Thresholds must satisfy 0 < review < block <= 1")
        if not 0 <= self.medium_confidence < self.high_confidence <= 1:
            raise ValueError("Confidence bands must be ordered within 0..1")
        if not all(
            0 <= v <= 1
            for v in (self.min_allow_confidence, self.min_block_confidence, self.partial_credit)
        ):
            raise ValueError("Confidence parameters must be within 0..1")

    def required_layers(self, is_ai: bool) -> tuple[RiskLayer, ...]:
        return self.required_ai if is_ai else self.required_software

    def weights_for(self, is_ai: bool) -> Mapping[RiskLayer, float]:
        return self.weights_ai if is_ai else self.weights

    def with_scaled_weight(self, layer: RiskLayer, factor: float) -> "PolicyConfig":
        """Scale one layer's weight in both the software and the AI profile."""
        return replace(
            self,
            weights={**self.weights, layer: self.weights[layer] * factor},
            weights_ai={**self.weights_ai, layer: self.weights_ai[layer] * factor},
        )


DEFAULT_POLICY = PolicyConfig()
