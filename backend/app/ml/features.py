"""Turn the evidence recorded for a scan into one ML feature vector (pipeline step 11).

A feature keeps its value only when every stage it depends on is `completed` and is not mock
data. A partial, failed, unavailable, skipped or mock stage makes the feature null with a
recorded reason, so missing evidence can never read as a clean result.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from app.ml.feature_schema import FEATURES, Applies, FeatureDef, FeatureValue, NullReason

AI_ARTIFACT_TYPES = frozenset({"model", "lora", "dataset"})
NO_WEIGHTS = "none"

_STATUS_REASONS = {
    "partial": NullReason.STAGE_PARTIAL,
    "error": NullReason.STAGE_ERROR,
    "unavailable": NullReason.STAGE_UNAVAILABLE,
    "skipped": NullReason.STAGE_SKIPPED,
}


@dataclass(frozen=True)
class FeatureExtraction:
    features: dict[str, FeatureValue]
    null_reasons: dict[str, NullReason]


def stage_null_reason(stage: Mapping[str, Any] | None) -> NullReason | None:
    """Why this stage's evidence cannot be used, or None when it can."""
    if stage is None:
        return NullReason.STAGE_NOT_RUN
    if stage.get("source") == "mock" or stage.get("is_mock") is True:
        return NullReason.MOCK_EVIDENCE
    status = stage.get("status")
    if status == "completed":
        return None
    return _STATUS_REASONS.get(status, NullReason.STAGE_ERROR)


def _applies(feature: FeatureDef, artifact_type: str) -> bool:
    if feature.applies == Applies.ALL:
        return True
    is_ai = artifact_type in AI_ARTIFACT_TYPES
    return is_ai if feature.applies == Applies.AI else not is_ai


def _section(stage: Mapping[str, Any] | None, *path: str) -> Mapping[str, Any]:
    current: Any = stage or {}
    for key in path:
        current = current.get(key) if isinstance(current, Mapping) else None
    return current if isinstance(current, Mapping) else {}


def _serialization_type(aibom: Mapping[str, Any] | None) -> str | None:
    """The riskiest declared weight format: a code-executing one if any, else the most common."""
    if aibom is None or "model" not in aibom:
        return None
    summary = _section(aibom, "model", "summary")
    executing = summary.get("code_executing_formats") or []
    if executing:
        return str(sorted(executing)[0])
    counts = _section(aibom, "model", "serialization_types")
    if not counts:
        return NO_WEIGHTS
    return str(min(counts, key=lambda name: (-int(counts[name]), name)))


def _same_commit_change(provenance: Mapping[str, Any]) -> bool | None:
    if provenance.get("hash_changed") is None:
        return None
    return any(
        check.get("name") == "hash_consistency" and check.get("status") == "fail"
        for check in provenance.get("checks") or []
    )


def _count_flags(value: Any) -> int | None:
    return len(value) if isinstance(value, list) else None


def _raw_values(
    stages: Mapping[str, Any],
    provenance: Mapping[str, Any],
    comparison: Mapping[str, Any],
    version_consistency: bool | None,
) -> dict[str, Any]:
    graph = _section(stages.get("graph"), "features")
    static = _section(stages.get("static"), "features")
    sandbox = _section(stages.get("sandbox"), "features")
    aibom = stages.get("aibom")
    summary = _section(aibom, "model", "summary")
    license_present = bool(summary.get("license")) if "license" in summary else None
    return {
        "dependency_count": graph.get("dependency_count", graph.get("runtime_dependency_count")),
        "transitive_depth": graph.get("transitive_depth"),
        "centrality": graph.get("max_betweenness_centrality"),
        "vulnerable_count": graph.get("vulnerable_count"),
        "cvss_max": graph.get("cvss_max"),
        "file_type_count": summary.get("file_type_count"),
        "custom_code_present": summary.get("custom_code_present"),
        "serialization_type": _serialization_type(aibom),
        "config_changed": comparison.get("config_changed"),
        "adapter_present": graph.get("adapter_present"),
        "adapter_count": graph.get("adapter_count"),
        "provenance_present": provenance.get("provenance_present"),
        "source_known": provenance.get("source_known"),
        "revision_pinned": provenance.get("revision_pinned"),
        "hash_changed": provenance.get("hash_changed"),
        "hash_changed_same_commit": _same_commit_change(provenance),
        "provenance_removed": comparison.get("provenance_removed"),
        "lineage_completeness": provenance.get("lineage_completeness"),
        "model_card_completeness": summary.get("model_card_completeness"),
        "license_present": license_present,
        "version_consistency": version_consistency,
        "dangerous_import_count": static.get("dangerous_import_count"),
        "suspicious_api_count": static.get("suspicious_api_count"),
        "script_presence": static.get("script_presence"),
        "archive_anomaly": static.get("archive_anomaly"),
        "install_hook_count": static.get("install_hook_count"),
        "pickle_dangerous_global_count": static.get("pickle_dangerous_global_count"),
        "network_count": sandbox.get("network_count"),
        "process_count": sandbox.get("process_count"),
        "file_write_count": sandbox.get("file_write_count"),
        "syscall_count": sandbox.get("syscall_count"),
        "external_destination_count": sandbox.get("external_destination_count"),
        "resource_spike": sandbox.get("resource_spike"),
        "sensitive_file_access_count": sandbox.get("sensitive_file_access_count"),
        "shell_spawn_count": sandbox.get("shell_spawn_count"),
        "new_edge_count": comparison.get("new_edge_count"),
        "centrality_shift": comparison.get("centrality_shift"),
        "suspicious_lineage": _count_flags(graph.get("suspicious_lineage")),
        "unexpected_parent_or_base_model": graph.get("unexpected_parent_or_base_model"),
    }


def _null_reason(
    feature: FeatureDef,
    artifact_type: str,
    stages: Mapping[str, Any],
    comparison: Mapping[str, Any] | None,
) -> NullReason | None:
    """The structural reason a feature is null, before its value is even looked at."""
    if not feature.has_data_source:
        return NullReason.NO_DATA_SOURCE
    if not _applies(feature, artifact_type):
        return NullReason.NOT_APPLICABLE
    for name in feature.stages:
        if (reason := stage_null_reason(stages.get(name))) is not None:
            return reason
    if feature.needs_prior and comparison is None:
        return NullReason.NO_PRIOR_SCAN
    return None


def extract_features(
    artifact_type: str,
    stages: Mapping[str, Any],
    provenance: Mapping[str, Any] | None = None,
    comparison: Mapping[str, Any] | None = None,
    version_consistency: bool | None = None,
) -> FeatureExtraction:
    """Build the full feature vector. `comparison` is None when there is no prior scan."""
    raw = _raw_values(stages, provenance or {}, comparison or {}, version_consistency)
    features: dict[str, FeatureValue] = {}
    reasons: dict[str, NullReason] = {}
    for feature in FEATURES:
        reason = _null_reason(feature, artifact_type, stages, comparison)
        value = None if reason is not None else raw.get(feature.name)
        if value is None and reason is None:
            reason = NullReason.NOT_DETERMINABLE
        features[feature.name] = value
        if reason is not None:
            reasons[feature.name] = reason
    return FeatureExtraction(features, reasons)
