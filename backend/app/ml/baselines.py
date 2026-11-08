"""Vulnerability-only and rules-only baselines. Neither one learns or tunes anything.

A rule whose feature is null cannot fire. Results are given two ways: only over records the
baseline could evaluate, and over all records with an unevaluated record counted as not flagged.

Rules fire on explicit findings with no fitted cut-offs. Changes that a legitimate release also
makes (hash_changed on a new commit, config_changed, new_edge_count) are deliberately not rules.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

from app.ml.dataset.tampering import LABEL_PRECEDENCE
from app.ml.evaluation import binary_metrics, binary_truth, per_class_metrics
from app.ml.feature_schema import FeatureRecord, Label, NullReason
from app.ml.training import BENIGN_INDEX, LABEL_INDEX, LABEL_ORDER, encode_labels


def _positive(value: Any) -> bool:
    return value > 0


def _is_true(value: Any) -> bool:
    return value is True


def _is_false(value: Any) -> bool:
    return value is False


@dataclass(frozen=True)
class Rule:
    feature: str
    fires: Callable[[Any], bool]
    label: Label


RULES = (
    Rule("vulnerable_count", _positive, Label.VULNERABLE),
    Rule("hash_changed_same_commit", _is_true, Label.PROVENANCE_WEAK),
    Rule("provenance_removed", _is_true, Label.PROVENANCE_WEAK),
    Rule("version_consistency", _is_false, Label.PROVENANCE_WEAK),
    Rule("dangerous_import_count", _positive, Label.SUSPICIOUS),
    Rule("suspicious_api_count", _positive, Label.SUSPICIOUS),
    Rule("install_hook_count", _positive, Label.SUSPICIOUS),
    Rule("archive_anomaly", _positive, Label.SUSPICIOUS),
    Rule("pickle_dangerous_global_count", _positive, Label.SUSPICIOUS),
    Rule("unexpected_parent_or_base_model", _is_true, Label.SUSPICIOUS),
    Rule("external_destination_count", _positive, Label.SUSPICIOUS),
    Rule("sensitive_file_access_count", _positive, Label.SUSPICIOUS),
    Rule("shell_spawn_count", _positive, Label.SUSPICIOUS),
)


def _one_hot(predictions: np.ndarray) -> np.ndarray:
    scores = np.zeros((predictions.size, len(LABEL_ORDER)))
    scores[np.arange(predictions.size), predictions] = 1.0
    return scores


def _metrics(
    records: Sequence[FeatureRecord], predictions: np.ndarray, binary_scores: np.ndarray
) -> dict[str, Any]:
    if not len(records):
        return {"multiclass": None, "binary": None}
    y_true = encode_labels(list(records))
    return {
        "multiclass": per_class_metrics(y_true, predictions, _one_hot(predictions)),
        "binary": binary_metrics(binary_truth(records), predictions != BENIGN_INDEX, binary_scores),
    }


def _result(
    records: Sequence[FeatureRecord],
    predictions: np.ndarray,
    binary_scores: np.ndarray,
    evaluated: np.ndarray,
    partial: int,
) -> dict[str, Any]:
    chosen = [record for record, keep in zip(records, evaluated, strict=True) if keep]
    return {
        "records": len(records),
        "could_not_evaluate": int(np.sum(~evaluated)),
        "partially_evaluated": partial,
        "evaluated_records_only": _metrics(
            chosen, predictions[evaluated], binary_scores[evaluated]
        ),
        "all_records_unevaluated_not_flagged": _metrics(records, predictions, binary_scores),
    }


def vulnerability_only(records: Sequence[FeatureRecord]) -> dict[str, Any]:
    """Flags a record as vulnerable when vulnerable_count > 0; the score is that count."""
    counts = [record.features["vulnerable_count"] for record in records]
    evaluated = np.asarray([count is not None for count in counts], dtype=bool)
    scores = np.asarray([float(count or 0) for count in counts])
    predictions = np.where(scores > 0, LABEL_INDEX[Label.VULNERABLE], BENIGN_INDEX)
    return _result(records, predictions, scores, evaluated, 0)


def _applicable_rules(record: FeatureRecord) -> list[Rule]:
    return [
        rule for rule in RULES if record.null_reasons.get(rule.feature) != NullReason.NOT_APPLICABLE
    ]


def _judge(record: FeatureRecord) -> tuple[int, int, bool, bool]:
    """(predicted class, rules fired, any rule evaluated, some rule not evaluated)."""
    labels: set[Label] = set()
    fired = 0
    rules = _applicable_rules(record)
    evaluated = [rule for rule in rules if record.features[rule.feature] is not None]
    for rule in evaluated:
        if rule.fires(record.features[rule.feature]):
            fired += 1
            labels.add(rule.label)
    predicted = next((label for label in LABEL_PRECEDENCE if label in labels), Label.BENIGN)
    return LABEL_INDEX[predicted], fired, bool(evaluated), len(evaluated) < len(rules)


def rules_only(records: Sequence[FeatureRecord]) -> dict[str, Any]:
    """Predicts the most severe class among fired rules. The binary score is the rules fired."""
    judged = [_judge(record) for record in records]
    predictions = np.asarray([row[0] for row in judged], dtype=int)
    scores = np.asarray([float(row[1]) for row in judged])
    evaluated = np.asarray([row[2] for row in judged], dtype=bool)
    partial = sum(1 for row in judged if row[2] and row[3])
    return _result(records, predictions, scores, evaluated, partial)


def evaluate_baselines(records: Sequence[FeatureRecord]) -> dict[str, Any]:
    return {"vulnerability_only": vulnerability_only(records), "rules_only": rules_only(records)}
