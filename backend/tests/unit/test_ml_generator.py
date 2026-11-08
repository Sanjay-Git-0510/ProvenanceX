"""The generated dataset: real scanner output, policy on every record, no leaks."""

import hashlib
import json
from collections import defaultdict

import pytest

from app.ml.dataset import generator
from app.ml.dataset.generator import draw_availability, generate_records, write_dataset
from app.ml.dataset.splits import find_family_leaks
from app.ml.feature_schema import FEATURE_NAMES, NOT_EVALUATED_FEATURES, Label, NullReason

FAMILIES = 60
SEED = 7


@pytest.fixture(scope="module")
def records():
    return generate_records(FAMILIES, SEED)


def by_variant(records, name):
    return [r for r in records if r.variant == name]


def values(records, feature):
    return [r.features[feature] for r in records if r.features[feature] is not None]


def observed(records):
    return [r for r in records if r.label_evidence_observable]


def test_every_record_is_labeled_synthetic_with_provenance_of_label(records):
    assert len(records) > FAMILIES * 8
    for record in records:
        assert record.synthetic is True
        assert record.ground_truth_status == "synthetic_by_construction"
        assert record.label_source.startswith(("controlled_fixture:", "controlled_tampering:"))
        assert set(record.features) == set(FEATURE_NAMES)


def test_no_known_bad_labels_exist(records):
    assert not [r for r in records if r.label == Label.MALICIOUS_KNOWN_BAD]


def test_labels_follow_recipes_not_features(records):
    assert all(r.label == Label.BENIGN for r in by_variant(records, "clean_rescan"))
    assert all(r.label == Label.VULNERABLE for r in by_variant(records, "vulnerable"))
    assert all(r.label == Label.SUSPICIOUS for r in by_variant(records, "suspicious_behavior"))


def test_no_family_crosses_splits(records):
    assert find_family_leaks((r.family_id, r.split) for r in records) == {}
    assert {r.split for r in records} == {"train", "validation", "test"}


def test_features_without_data_source_stay_null_everywhere(records):
    for record in records:
        for name in NOT_EVALUATED_FEATURES:
            assert record.features[name] is None
            assert record.null_reasons[name] == NullReason.NO_DATA_SOURCE


def test_failed_stages_are_null_never_zero(records):
    partial = [
        r
        for r in records
        if r.null_reasons.get("dangerous_import_count") == NullReason.STAGE_PARTIAL
    ]
    assert partial
    assert all(r.features["dangerous_import_count"] is None for r in partial)
    missing = [r for r in records if "vulnerable_count" in r.null_reasons]
    assert missing
    assert all(r.features["vulnerable_count"] is None for r in missing)


def test_absent_sandbox_is_null_not_quiet(records):
    absent = [r for r in records if r.null_reasons.get("syscall_count") == NullReason.STAGE_NOT_RUN]
    assert absent
    assert all(r.features["network_count"] is None for r in absent)


def test_clean_rescan_shows_no_change_when_observed(records):
    rows = [
        r for r in by_variant(records, "clean_rescan") if r.features["hash_changed"] is not None
    ]
    assert rows
    assert all(r.features["hash_changed"] is False for r in rows)
    assert all(r.features["new_edge_count"] in (0, None) for r in rows)


def test_each_tampering_case_reaches_its_feature(records):
    def rows(name):
        return observed(by_variant(records, name))

    assert all(r.features["hash_changed_same_commit"] is True for r in rows("changed_hash"))
    assert all(r.features["provenance_removed"] is True for r in rows("removed_provenance"))
    assert all(r.features["config_changed"] is True for r in rows("altered_config"))
    assert all(r.features["new_edge_count"] >= 1 for r in rows("replaced_dependency"))
    assert all(r.features["version_consistency"] is False for r in rows("version_mismatch"))


def test_real_static_scanner_flags_the_inert_seed(records):
    rows = observed(by_variant(records, "suspicious_code"))
    assert rows
    assert all(r.features["suspicious_api_count"] >= 2 for r in rows)
    assert all(r.features["dangerous_import_count"] >= 1 for r in rows)


def test_real_telemetry_parser_counts_external_connections(records):
    rows = observed(by_variant(records, "suspicious_behavior"))
    assert rows
    assert all(r.features["external_destination_count"] >= 1 for r in rows)


def test_vulnerability_counts_are_real_sums(records):
    rows = observed(by_variant(records, "vulnerable"))
    assert all(r.features["vulnerable_count"] >= 1 for r in rows)
    clean = [
        r for r in by_variant(records, "clean_rescan") if "vulnerable_count" not in r.null_reasons
    ]
    assert all(r.features["vulnerable_count"] == 0 for r in clean)


def test_benign_overlaps_tampered_on_single_traits(records):
    """No single trait may separate benign from tampered by construction."""
    benign = [r for r in records if r.label == Label.BENIGN]
    assert any(r.features["provenance_present"] is False for r in benign)
    assert any(r.features["hash_changed"] is True for r in benign)
    assert any(r.features["new_edge_count"] not in (0, None) for r in benign)
    assert any(r.features["config_changed"] is True for r in benign)
    assert any((r.features["dangerous_import_count"] or 0) > 0 for r in benign)
    assert any((r.features["external_destination_count"] or 0) > 0 for r in benign)


def test_unobservable_labels_are_kept_and_marked(records):
    hidden = [
        r for r in by_variant(records, "suspicious_behavior") if not r.label_evidence_observable
    ]
    assert hidden
    assert all(r.label == Label.SUSPICIOUS for r in hidden)
    assert all(r.features["syscall_count"] is None for r in hidden)


@pytest.mark.parametrize(
    "feature",
    [
        "dangerous_import_count",
        "syscall_count",
        "vulnerable_count",
        "provenance_present",
        "hash_changed",
    ],
)
def test_missingness_does_not_depend_on_label(feature):
    records = generate_records(120, SEED)
    grouped = defaultdict(list)
    for record in records:
        grouped[record.label].append(record.features[feature] is None)
    rates = [sum(flags) / len(flags) for flags in grouped.values()]
    assert max(rates) - min(rates) < 0.12, rates


def test_availability_draw_takes_only_identifiers():
    assert draw_availability(1, 2, 3) == draw_availability(1, 2, 3)
    code = draw_availability.__code__
    assert code.co_varnames[: code.co_argcount] == ("seed", "family_index", "variant_index")


def test_same_seed_gives_byte_identical_output(tmp_path):
    first = write_dataset(generate_records(12, SEED), SEED, tmp_path / "a")
    second = write_dataset(generate_records(12, SEED), SEED, tmp_path / "b")
    assert (tmp_path / "a/dataset.jsonl").read_bytes() == (
        tmp_path / "b/dataset.jsonl"
    ).read_bytes()
    assert first == second


def test_different_seed_changes_output(tmp_path):
    write_dataset(generate_records(30, SEED), SEED, tmp_path / "a")
    write_dataset(generate_records(30, SEED + 1), SEED + 1, tmp_path / "b")
    assert (tmp_path / "a/dataset.jsonl").read_bytes() != (
        tmp_path / "b/dataset.jsonl"
    ).read_bytes()


def test_metadata_states_synthetic_and_not_evaluated(tmp_path, records):
    metadata = write_dataset(records, SEED, tmp_path)
    saved = json.loads((tmp_path / "dataset_metadata.json").read_text())
    assert saved == metadata
    assert saved["synthetic"] is True
    assert "SYNTHETIC" in saved["notice"]
    assert saved["ground_truth_status"] == "synthetic_by_construction"
    assert saved["not_evaluated_features"] == list(NOT_EVALUATED_FEATURES)
    assert saved["split_unit"] == "artifact_family"
    assert "malicious_known_bad" not in saved["label_counts"]
    digest = hashlib.sha256((tmp_path / "dataset.jsonl").read_bytes()).hexdigest()
    assert saved["dataset_sha256"] == digest


def test_stage_failure_rates_are_recorded(records):
    metadata = generator.dataset_metadata(records, SEED, "x")
    assert metadata["stage_failure_rates"] == generator.STAGE_FAILURE_RATES
