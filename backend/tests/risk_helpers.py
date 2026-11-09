"""Builders for risk-engine unit tests."""

from app.ml.feature_schema import FEATURES, Applies, NullReason
from app.risk.policy_config import FEATURE_LAYERS
from app.risk.types import FindingRef, MlOutputs, RiskInputs

_SOFTWARE_CLEAN = {
    "dependency_count": 3,
    "transitive_depth": 2,
    "centrality": 0.1,
    "vulnerable_count": 0,
    "provenance_present": True,
    "source_known": True,
    "revision_pinned": True,
    "hash_changed": False,
    "hash_changed_same_commit": False,
    "provenance_removed": False,
    "version_consistency": True,
    "dangerous_import_count": 0,
    "suspicious_api_count": 0,
    "script_presence": False,
    "archive_anomaly": 0,
    "install_hook_count": 0,
    "network_count": 0,
    "process_count": 0,
    "file_write_count": 0,
    "syscall_count": 0,
    "external_destination_count": 0,
    "resource_spike": False,
    "sensitive_file_access_count": 0,
    "shell_spawn_count": 0,
    "new_edge_count": 0,
    "centrality_shift": 0.0,
}
_AI_CLEAN = {
    "file_type_count": 3,
    "custom_code_present": False,
    "serialization_type": "safetensors",
    "config_changed": False,
    "adapter_present": False,
    "adapter_count": 0,
    "lineage_completeness": 1.0,
    "model_card_completeness": 1.0,
    "license_present": True,
    "pickle_dangerous_global_count": 0,
    "suspicious_lineage": 0,
    "unexpected_parent_or_base_model": False,
}
_SOFTWARE_ONLY = {"transitive_depth", "centrality", "centrality_shift"}


def _default_reason(feature, is_ai: bool) -> NullReason:
    if not feature.has_data_source:
        return NullReason.NO_DATA_SOURCE
    if feature.applies == Applies.AI and not is_ai:
        return NullReason.NOT_APPLICABLE
    if feature.applies == Applies.SOFTWARE and is_ai:
        return NullReason.NOT_APPLICABLE
    return NullReason.NOT_DETERMINABLE


def make_inputs(
    artifact_type="software",
    *,
    drop_layers=(),
    drop_reason=NullReason.STAGE_SKIPPED,
    findings=(),
    checks=None,
    ml=None,
    **overrides,
):
    """Clean, fully evaluated evidence, with named layers removed and features overridden."""
    is_ai = artifact_type != "software"
    values = dict(_SOFTWARE_CLEAN)
    if is_ai:
        values.update(_AI_CLEAN)
        for name in _SOFTWARE_ONLY:
            values.pop(name)
    reasons = {}
    features = {}
    for feature in FEATURES:
        value = values.get(feature.name)
        applicable = _default_reason(feature, is_ai) == NullReason.NOT_DETERMINABLE
        if FEATURE_LAYERS[feature.name] in drop_layers and applicable:
            value = None
            reasons[feature.name] = drop_reason
        if feature.name in overrides:
            value = overrides[feature.name]
        if value is None:
            reasons.setdefault(feature.name, _default_reason(feature, is_ai))
        else:
            reasons.pop(feature.name, None)
        features[feature.name] = value
    return RiskInputs(
        artifact_type=artifact_type,
        features=features,
        null_reasons=reasons,
        findings=tuple(findings),
        provenance_checks=checks,
        ml=ml,
    )


def finding(identifier="PX-BEHAV-SHELL-SPAWN", category="behavioral", severity="HIGH", source="px"):
    return FindingRef(
        finding_id=f"id-{identifier}",
        category=category,
        identifier=identifier,
        severity=severity,
        source=source,
    )


def ml_outputs(rf=0.9, anomaly=0.7):
    return MlOutputs(
        rf_risk_probability=rf,
        anomaly_score=anomaly,
        xgb_risk_probability=0.8,
        rf_threshold=0.4488,
        anomaly_threshold=0.5987,
        model_version="test",
    )
