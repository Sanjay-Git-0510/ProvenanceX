"""The ML feature contract: every feature, its evidence layer, labels and the record shape.

A null feature means "not evaluated". It is never a clean 0 or False, and `null_reasons`
records why each one is null. Features with `has_data_source=False` have no collector in the
pipeline yet, so they are null in every record and are reported as not evaluated.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

DATASET_FORMAT = "provenancex-feature-dataset-v1"
SYNTHETIC_GROUND_TRUTH = "synthetic_by_construction"
ESTABLISHED_GROUND_TRUTH = "established"

FeatureValue = bool | int | float | str | None


class Layer(StrEnum):
    DEPENDENCY = "dependency"
    VULNERABILITY = "vulnerability"
    AI_MODEL = "ai_model"
    PROVENANCE = "provenance"
    METADATA = "metadata"
    STATIC = "static"
    BEHAVIOR = "behavior"
    GRAPH = "graph"


class Kind(StrEnum):
    COUNT = "count"
    FLOAT = "float"
    BOOL = "bool"
    CATEGORY = "category"


class Applies(StrEnum):
    ALL = "all"
    SOFTWARE = "software"
    AI = "ai"


class Label(StrEnum):
    """Vulnerable is not malicious. malicious_known_bad requires established ground truth."""

    BENIGN = "benign"
    VULNERABLE = "vulnerable"
    PROVENANCE_WEAK = "provenance_weak"
    SUSPICIOUS = "suspicious"
    MALICIOUS_KNOWN_BAD = "malicious_known_bad"


class NullReason(StrEnum):
    NO_DATA_SOURCE = "no_data_source"
    NOT_APPLICABLE = "not_applicable"
    STAGE_NOT_RUN = "stage_not_run"
    STAGE_PARTIAL = "stage_partial"
    STAGE_ERROR = "stage_error"
    STAGE_UNAVAILABLE = "stage_unavailable"
    STAGE_SKIPPED = "stage_skipped"
    MOCK_EVIDENCE = "mock_evidence"
    NO_PRIOR_SCAN = "no_prior_scan"
    NOT_DETERMINABLE = "not_determinable"


@dataclass(frozen=True)
class FeatureDef:
    name: str
    layer: Layer
    kind: Kind
    stages: tuple[str, ...] = ()  # every stage here must be completed and non-mock
    applies: Applies = Applies.ALL
    has_data_source: bool = True
    needs_prior: bool = False


_GRAPH = ("graph",)
_VULN = ("graph", "vulnerabilities")
_AIBOM = ("aibom",)
_PROV = ("provenance",)
_STATIC = ("static",)
_SANDBOX = ("sandbox",)


def _unavailable(name: str, layer: Layer, kind: Kind) -> FeatureDef:
    return FeatureDef(name, layer, kind, has_data_source=False)


FEATURES: tuple[FeatureDef, ...] = (
    # Software dependency
    FeatureDef("dependency_count", Layer.DEPENDENCY, Kind.COUNT, _GRAPH),
    FeatureDef("transitive_depth", Layer.DEPENDENCY, Kind.COUNT, _GRAPH, Applies.SOFTWARE),
    FeatureDef("centrality", Layer.DEPENDENCY, Kind.FLOAT, _GRAPH, Applies.SOFTWARE),
    _unavailable("package_age", Layer.DEPENDENCY, Kind.FLOAT),
    _unavailable("release_change", Layer.DEPENDENCY, Kind.FLOAT),
    # Known vulnerabilities (a separate layer so it can be ablated on its own)
    FeatureDef("vulnerable_count", Layer.VULNERABILITY, Kind.COUNT, _VULN),
    FeatureDef("cvss_max", Layer.VULNERABILITY, Kind.FLOAT, _VULN),
    # AI / model
    FeatureDef("file_type_count", Layer.AI_MODEL, Kind.COUNT, _AIBOM, Applies.AI),
    FeatureDef("custom_code_present", Layer.AI_MODEL, Kind.BOOL, _AIBOM, Applies.AI),
    FeatureDef("serialization_type", Layer.AI_MODEL, Kind.CATEGORY, _AIBOM, Applies.AI),
    FeatureDef("config_changed", Layer.AI_MODEL, Kind.BOOL, _AIBOM, Applies.AI, needs_prior=True),
    FeatureDef("adapter_present", Layer.AI_MODEL, Kind.BOOL, _GRAPH, Applies.AI),
    FeatureDef("adapter_count", Layer.AI_MODEL, Kind.COUNT, _GRAPH, Applies.AI),
    # Provenance / integrity
    _unavailable("signed", Layer.PROVENANCE, Kind.BOOL),
    FeatureDef("provenance_present", Layer.PROVENANCE, Kind.BOOL, _PROV),
    FeatureDef("source_known", Layer.PROVENANCE, Kind.BOOL, _PROV),
    FeatureDef("revision_pinned", Layer.PROVENANCE, Kind.BOOL, _PROV),
    _unavailable("commit_age", Layer.PROVENANCE, Kind.FLOAT),
    FeatureDef("hash_changed", Layer.PROVENANCE, Kind.BOOL, _PROV, needs_prior=True),
    FeatureDef("hash_changed_same_commit", Layer.PROVENANCE, Kind.BOOL, _PROV, needs_prior=True),
    FeatureDef("provenance_removed", Layer.PROVENANCE, Kind.BOOL, _PROV, needs_prior=True),
    FeatureDef("lineage_completeness", Layer.PROVENANCE, Kind.FLOAT, _PROV, Applies.AI),
    # Metadata
    FeatureDef("model_card_completeness", Layer.METADATA, Kind.FLOAT, _AIBOM, Applies.AI),
    _unavailable("publisher_consistency", Layer.METADATA, Kind.BOOL),
    FeatureDef("license_present", Layer.METADATA, Kind.BOOL, _AIBOM, Applies.AI),
    FeatureDef("version_consistency", Layer.METADATA, Kind.BOOL),
    # Static analysis
    FeatureDef("dangerous_import_count", Layer.STATIC, Kind.COUNT, _STATIC),
    FeatureDef("suspicious_api_count", Layer.STATIC, Kind.COUNT, _STATIC),
    FeatureDef("script_presence", Layer.STATIC, Kind.BOOL, _STATIC),
    FeatureDef("archive_anomaly", Layer.STATIC, Kind.COUNT, _STATIC),
    FeatureDef("install_hook_count", Layer.STATIC, Kind.COUNT, _STATIC),
    FeatureDef("pickle_dangerous_global_count", Layer.STATIC, Kind.COUNT, _STATIC, Applies.AI),
    # Sandbox behavior
    FeatureDef("network_count", Layer.BEHAVIOR, Kind.COUNT, _SANDBOX),
    FeatureDef("process_count", Layer.BEHAVIOR, Kind.COUNT, _SANDBOX),
    FeatureDef("file_write_count", Layer.BEHAVIOR, Kind.COUNT, _SANDBOX),
    FeatureDef("syscall_count", Layer.BEHAVIOR, Kind.COUNT, _SANDBOX),
    FeatureDef("external_destination_count", Layer.BEHAVIOR, Kind.COUNT, _SANDBOX),
    FeatureDef("resource_spike", Layer.BEHAVIOR, Kind.BOOL, _SANDBOX),
    FeatureDef("sensitive_file_access_count", Layer.BEHAVIOR, Kind.COUNT, _SANDBOX),
    FeatureDef("shell_spawn_count", Layer.BEHAVIOR, Kind.COUNT, _SANDBOX),
    # Graph
    FeatureDef("new_edge_count", Layer.GRAPH, Kind.COUNT, _GRAPH, needs_prior=True),
    FeatureDef(
        "centrality_shift", Layer.GRAPH, Kind.FLOAT, _GRAPH, Applies.SOFTWARE, needs_prior=True
    ),
    FeatureDef("suspicious_lineage", Layer.GRAPH, Kind.COUNT, _GRAPH, Applies.AI),
    FeatureDef("unexpected_parent_or_base_model", Layer.GRAPH, Kind.BOOL, _GRAPH, Applies.AI),
)

FEATURES_BY_NAME = {f.name: f for f in FEATURES}
FEATURE_NAMES = tuple(FEATURES_BY_NAME)
NOT_EVALUATED_FEATURES = tuple(f.name for f in FEATURES if not f.has_data_source)


def features_in_layer(layer: Layer) -> tuple[str, ...]:
    return tuple(f.name for f in FEATURES if f.layer == layer)


def _kind_matches(kind: Kind, value: FeatureValue) -> bool:
    if kind == Kind.BOOL:
        return isinstance(value, bool)
    if kind == Kind.COUNT:
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0
    if kind == Kind.FLOAT:
        return isinstance(value, int | float) and not isinstance(value, bool)
    return isinstance(value, str)


class FeatureRecord(BaseModel):
    """One labeled row. Validation rejects a row that breaks the data policy."""

    model_config = ConfigDict(extra="forbid")

    record_id: str
    family_id: str
    artifact_type: Literal["software", "model", "lora"]
    variant: str
    applied_recipes: list[str]
    label: Label
    label_source: str
    ground_truth_status: Literal["synthetic_by_construction", "established"]
    synthetic: bool
    label_evidence_observable: bool
    split: Literal["train", "validation", "test"]
    features: dict[str, FeatureValue]
    null_reasons: dict[str, NullReason]

    @model_validator(mode="after")
    def _check_policy(self) -> "FeatureRecord":
        if set(self.features) != set(FEATURE_NAMES):
            missing = set(FEATURE_NAMES) ^ set(self.features)
            raise ValueError(f"Feature set does not match the schema: {sorted(missing)}")
        for name, value in self.features.items():
            feature = FEATURES_BY_NAME[name]
            if value is None:
                if name not in self.null_reasons:
                    raise ValueError(f"Null feature {name} has no recorded reason")
            elif name in self.null_reasons:
                raise ValueError(f"Non-null feature {name} has a null reason")
            elif not _kind_matches(feature.kind, value):
                raise ValueError(f"Feature {name} has the wrong type for {feature.kind}")
            if not feature.has_data_source and value is not None:
                raise ValueError(f"Feature {name} has no data source and must stay null")
        if self.label == Label.MALICIOUS_KNOWN_BAD and (
            self.ground_truth_status != ESTABLISHED_GROUND_TRUTH or self.synthetic
        ):
            raise ValueError("malicious_known_bad requires established, non-synthetic ground truth")
        if self.synthetic and self.ground_truth_status != SYNTHETIC_GROUND_TRUTH:
            raise ValueError("Synthetic records must use synthetic_by_construction ground truth")
        return self
