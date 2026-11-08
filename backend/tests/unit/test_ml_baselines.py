"""Baselines: rules are fixed, and null evidence can never fire one."""

from app.ml.baselines import RULES, rules_only, vulnerability_only
from app.ml.feature_schema import Label, NullReason
from tests.ml_helpers import record


def per_class(result, name):
    return result["evaluated_records_only"]["multiclass"]["per_class"][name]


def test_vulnerability_only_counts_records_it_cannot_evaluate():
    rows = [
        record(label="vulnerable", vulnerable_count=2),
        record(label="benign", vulnerable_count=0),
        record(label="vulnerable"),
    ]
    result = vulnerability_only(rows)
    assert result["could_not_evaluate"] == 1
    assert result["records"] == 3


def test_null_vulnerability_is_excluded_or_counted_as_not_flagged():
    rows = [record(label="vulnerable", vulnerable_count=2), record(label="vulnerable")]
    result = vulnerability_only(rows)
    assert result["evaluated_records_only"]["binary"]["recall"] == 1.0
    assert result["all_records_unevaluated_not_flagged"]["binary"]["recall"] == 0.5


def test_vulnerability_only_flags_only_positive_counts():
    rows = [
        record(label="vulnerable", vulnerable_count=1),
        record(label="benign", vulnerable_count=0),
    ]
    assert per_class(vulnerability_only(rows), "vulnerable")["precision"] == 1.0


def test_null_feature_cannot_fire_a_rule():
    result = rules_only([record(label="suspicious", dangerous_import_count=0)])
    assert result["evaluated_records_only"]["binary"]["tp"] == 0


def test_record_with_no_rule_input_cannot_be_evaluated():
    result = rules_only([record(label="benign")])
    assert result["could_not_evaluate"] == 1
    assert result["evaluated_records_only"]["binary"] is None
    assert result["all_records_unevaluated_not_flagged"]["binary"]["fp"] == 0


def test_some_rules_unevaluated_counts_as_partial():
    assert rules_only([record(label="benign", shell_spawn_count=0)])["partially_evaluated"] == 1


def test_not_applicable_rules_do_not_count_as_partial():
    full = {rule.feature: _zero(rule.feature) for rule in RULES}
    not_applicable = "pickle_dangerous_global_count"
    full[not_applicable] = None
    row = record(
        label="benign", reasons={not_applicable: NullReason.NOT_APPLICABLE}, **_clean(full)
    )
    assert rules_only([row])["partially_evaluated"] == 0


def _zero(feature):
    return False if feature in _booleans() else 0


def _clean(values):
    values["version_consistency"] = True
    return values


def _booleans():
    return {
        "hash_changed_same_commit",
        "provenance_removed",
        "version_consistency",
        "unexpected_parent_or_base_model",
    }


def test_most_severe_fired_rule_wins():
    row = record(
        label="suspicious", vulnerable_count=1, suspicious_api_count=1, provenance_removed=True
    )
    assert per_class(rules_only([row]), "suspicious")["tp"] == 1


def test_integrity_rules_predict_provenance_weak():
    row = record(label="provenance_weak", version_consistency=False)
    assert per_class(rules_only([row]), "provenance_weak")["tp"] == 1


def test_consistent_version_does_not_fire():
    row = record(label="benign", version_consistency=True)
    assert rules_only([row])["evaluated_records_only"]["binary"]["fp"] == 0


def test_legitimate_release_changes_are_not_rules():
    used = {rule.feature for rule in RULES}
    assert not used & {"hash_changed", "config_changed", "new_edge_count", "centrality_shift"}


def test_rules_use_only_trained_risk_labels():
    assert {rule.label for rule in RULES} == {
        Label.VULNERABLE,
        Label.PROVENANCE_WEAK,
        Label.SUSPICIOUS,
    }
