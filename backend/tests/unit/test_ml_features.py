"""Feature extraction: an unevaluated stage gives null with a reason, never 0 or False."""

import pytest
from pydantic import ValidationError

from app.ml.feature_schema import (
    FEATURE_NAMES,
    NOT_EVALUATED_FEATURES,
    FeatureRecord,
    Label,
    Layer,
    NullReason,
    features_in_layer,
)
from app.ml.features import extract_features, stage_null_reason

STATIC = {
    "dangerous_import_count": 0,
    "suspicious_api_count": 0,
    "script_presence": False,
    "archive_anomaly": 0,
    "install_hook_count": 0,
    "pickle_dangerous_global_count": None,
}
GRAPH = {
    "dependency_count": 5,
    "transitive_depth": 2,
    "max_betweenness_centrality": 0.1,
    "vulnerable_count": 0,
    "cvss_max": None,
}
SANDBOX = {
    "network_count": 0,
    "process_count": 1,
    "file_write_count": 0,
    "syscall_count": 9,
    "external_destination_count": 0,
    "resource_spike": False,
    "sensitive_file_access_count": 0,
    "shell_spawn_count": 0,
}
PROVENANCE = {
    "source_known": True,
    "revision_pinned": False,
    "provenance_present": False,
    "hash_changed": False,
    "checks": [],
}


def software_stages():
    return {
        "graph": {"status": "completed", "source": "syft", "features": GRAPH},
        "vulnerabilities": {"status": "completed", "source": "osv"},
        "provenance": {"status": "completed", "source": "provenancex"},
        "static": {"status": "completed", "source": "provenancex", "features": STATIC},
        "sandbox": {"status": "completed", "source": "sandbox", "features": SANDBOX},
    }


def extract(stages=None, comparison=None):
    return extract_features("software", stages or software_stages(), PROVENANCE, comparison)


def test_completed_zero_stays_zero_and_false_stays_false():
    result = extract()
    assert result.features["dangerous_import_count"] == 0
    assert result.features["script_presence"] is False
    assert result.features["vulnerable_count"] == 0
    assert "dangerous_import_count" not in result.null_reasons


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        ("partial", NullReason.STAGE_PARTIAL),
        ("error", NullReason.STAGE_ERROR),
        ("unavailable", NullReason.STAGE_UNAVAILABLE),
        ("skipped", NullReason.STAGE_SKIPPED),
        ("something_new", NullReason.STAGE_ERROR),
    ],
)
@pytest.mark.parametrize(
    ("stage", "layer"),
    [("static", Layer.STATIC), ("sandbox", Layer.BEHAVIOR)],
)
def test_unfinished_stage_nulls_its_layer_even_with_values(status, reason, stage, layer):
    stages = software_stages()
    stages[stage] = {**stages[stage], "status": status}
    result = extract(stages)
    for name in features_in_layer(layer):
        if name != "pickle_dangerous_global_count":
            assert result.features[name] is None
            assert result.null_reasons[name] == reason


@pytest.mark.parametrize("status", ["partial", "error", "unavailable", "skipped"])
def test_failed_vulnerability_lookup_is_not_zero_vulnerabilities(status):
    stages = software_stages()
    stages["vulnerabilities"] = {"status": status, "source": "osv"}
    result = extract(stages)
    assert result.features["vulnerable_count"] is None
    assert result.features["dependency_count"] == 5


def test_stage_that_never_ran_is_null():
    stages = software_stages()
    del stages["sandbox"]
    result = extract(stages)
    assert result.features["syscall_count"] is None
    assert result.null_reasons["syscall_count"] == NullReason.STAGE_NOT_RUN


@pytest.mark.parametrize("mock", [{"source": "mock"}, {"is_mock": True}])
def test_mock_evidence_is_never_used(mock):
    stages = software_stages()
    stages["sandbox"] = {**stages["sandbox"], **mock}
    result = extract(stages)
    assert result.features["network_count"] is None
    assert result.null_reasons["network_count"] == NullReason.MOCK_EVIDENCE


def test_stage_null_reason_completed_is_none():
    assert stage_null_reason({"status": "completed", "source": "x"}) is None


def test_features_without_a_data_source_are_always_null():
    assert set(NOT_EVALUATED_FEATURES) == {
        "package_age",
        "release_change",
        "commit_age",
        "publisher_consistency",
        "signed",
    }
    result = extract(comparison={"new_edge_count": 1})
    for name in NOT_EVALUATED_FEATURES:
        assert result.features[name] is None
        assert result.null_reasons[name] == NullReason.NO_DATA_SOURCE


def test_ai_features_are_not_applicable_to_software():
    result = extract()
    assert result.null_reasons["custom_code_present"] == NullReason.NOT_APPLICABLE


def test_no_prior_scan_is_null_not_unchanged():
    result = extract(comparison=None)
    assert result.features["new_edge_count"] is None
    assert result.null_reasons["new_edge_count"] == NullReason.NO_PRIOR_SCAN


def test_comparison_values_flow_through():
    comparison = {"new_edge_count": 0, "centrality_shift": 0.2, "provenance_removed": True}
    result = extract(comparison=comparison)
    assert result.features["new_edge_count"] == 0
    assert result.features["centrality_shift"] == 0.2
    assert result.features["provenance_removed"] is True


def test_same_commit_change_comes_from_the_real_check():
    failed = {
        **PROVENANCE,
        "hash_changed": True,
        "checks": [{"name": "hash_consistency", "status": "fail"}],
    }
    result = extract_features("software", software_stages(), failed, {"new_edge_count": 0})
    assert result.features["hash_changed_same_commit"] is True


def _aibom(formats, counts, **summary):
    model = {
        "serialization_types": counts,
        "summary": {"code_executing_formats": formats, **summary},
    }
    return {"status": "completed", "source": "provenancex", "model": model}


@pytest.mark.parametrize(
    ("formats", "counts", "expected"),
    [
        (["pickle"], {"safetensors": 3, "pickle": 1}, "pickle"),
        ([], {"safetensors": 2, "onnx": 1}, "safetensors"),
        ([], {}, "none"),
    ],
)
def test_serialization_type_prefers_code_executing_formats(formats, counts, expected):
    result = extract_features("model", {"aibom": _aibom(formats, counts)})
    assert result.features["serialization_type"] == expected


def test_software_only_feature_not_applicable_to_model():
    result = extract_features("lora", {"aibom": _aibom([], {})})
    assert result.null_reasons["transitive_depth"] == NullReason.NOT_APPLICABLE


def _record(**overrides):
    extraction = extract()
    values = {
        "record_id": "f:v",
        "family_id": "f",
        "artifact_type": "software",
        "variant": "v",
        "applied_recipes": [],
        "label": Label.BENIGN,
        "label_source": "controlled_fixture:clean",
        "ground_truth_status": "synthetic_by_construction",
        "synthetic": True,
        "label_evidence_observable": True,
        "split": "train",
        "features": extraction.features,
        "null_reasons": extraction.null_reasons,
    }
    return FeatureRecord(**{**values, **overrides})


def test_valid_record_passes_and_covers_schema():
    assert set(_record().features) == set(FEATURE_NAMES)


def test_record_rejects_synthetic_malicious_label():
    with pytest.raises(ValidationError, match="established"):
        _record(label=Label.MALICIOUS_KNOWN_BAD)


def test_record_rejects_missing_label_source():
    with pytest.raises(ValidationError):
        values = _record().model_dump()
        del values["label_source"]
        FeatureRecord(**values)


def test_record_rejects_null_without_reason():
    record = _record()
    reasons = {k: v for k, v in record.null_reasons.items() if k != "signed"}
    with pytest.raises(ValidationError, match="no recorded reason"):
        _record(null_reasons=reasons)


def test_record_rejects_value_for_feature_with_no_data_source():
    record = _record()
    features = {**record.features, "signed": True}
    reasons = {k: v for k, v in record.null_reasons.items() if k != "signed"}
    with pytest.raises(ValidationError, match="no data source"):
        _record(features=features, null_reasons=reasons)


def test_record_rejects_wrong_feature_type():
    with pytest.raises(ValidationError, match="wrong type"):
        _record(features={**_record().features, "dependency_count": "many"})


def test_record_rejects_incomplete_feature_set():
    features = dict(_record().features)
    del features["cvss_max"]
    with pytest.raises(ValidationError, match="does not match"):
        _record(features=features)


def test_record_rejects_synthetic_claiming_established_truth():
    with pytest.raises(ValidationError, match="synthetic_by_construction"):
        _record(ground_truth_status="established")
