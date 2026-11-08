"""Preprocessing: null is explicit, never 0, and everything is fitted on train only."""

import math

import numpy as np
import pytest

from app.ml.feature_schema import FEATURE_NAMES, NOT_EVALUATED_FEATURES, FeatureRecord, NullReason
from app.ml.preprocessing import (
    NULL_SUFFIX,
    PreprocessingParams,
    fit_preprocessor,
    transform,
)


def record(split="train", **values):
    features = dict.fromkeys(FEATURE_NAMES)
    features.update(values)
    reasons = {
        name: NullReason.NO_DATA_SOURCE
        if name in NOT_EVALUATED_FEATURES
        else NullReason.STAGE_ERROR
        for name, value in features.items()
        if value is None
    }
    return FeatureRecord(
        record_id="r",
        family_id="f",
        artifact_type="software",
        variant="v",
        applied_recipes=[],
        label="benign",
        label_source="controlled_fixture:clean",
        ground_truth_status="synthetic_by_construction",
        synthetic=True,
        label_evidence_observable=True,
        split=split,
        features=features,
        null_reasons=reasons,
    )


def train_rows():
    return [
        record(
            dependency_count=2, centrality=0.5, script_presence=True, serialization_type="pickle"
        ),
        record(dependency_count=4, script_presence=False, serialization_type="safetensors"),
        record(dependency_count=10, script_presence=False),
    ]


def cell(params, matrix, column, row=0):
    return matrix[row, params.columns.index(column)]


def test_null_uses_train_median_and_sets_indicator_not_zero():
    params = fit_preprocessor(train_rows())
    matrix = transform(params, [record(split="validation")])
    assert cell(params, matrix, "dependency_count") == 4.0
    assert cell(params, matrix, f"dependency_count{NULL_SUFFIX}") == 1.0


def test_measured_zero_is_distinct_from_null():
    params = fit_preprocessor(train_rows())
    matrix = transform(params, [record(dependency_count=0), record()])
    assert cell(params, matrix, "dependency_count", 0) == 0.0
    assert cell(params, matrix, f"dependency_count{NULL_SUFFIX}", 0) == 0.0
    assert cell(params, matrix, f"dependency_count{NULL_SUFFIX}", 1) == 1.0


def test_medians_ignore_other_splits():
    params = fit_preprocessor(train_rows())
    extreme = [record(split="validation", dependency_count=100000)]
    transform(params, extreme)
    assert next(f.median for f in params.features if f.name == "dependency_count") == 4.0


@pytest.mark.parametrize("split", ["validation", "test"])
def test_fit_refuses_non_train_records(split):
    with pytest.raises(ValueError, match="train split"):
        fit_preprocessor([*train_rows(), record(split=split, dependency_count=1)])


def test_fit_refuses_empty():
    with pytest.raises(ValueError, match="empty"):
        fit_preprocessor([])


def test_all_null_features_are_dropped_and_recorded():
    params = fit_preprocessor(train_rows())
    assert set(NOT_EVALUATED_FEATURES) <= set(params.dropped_all_null)
    assert not any(c.startswith("signed") for c in params.columns)


def test_booleans_become_numbers():
    params = fit_preprocessor(train_rows())
    matrix = transform(params, [record(script_presence=True)])
    assert cell(params, matrix, "script_presence") == 1.0


def test_categories_are_one_hot_and_unseen_is_all_zero():
    params = fit_preprocessor(train_rows())
    matrix = transform(
        params,
        [
            record(serialization_type="pickle"),
            record(serialization_type="onnx"),
            record(),
        ],
    )
    assert cell(params, matrix, "serialization_type=pickle", 0) == 1.0
    assert cell(params, matrix, "serialization_type=pickle", 1) == 0.0
    assert cell(params, matrix, "serialization_type=safetensors", 1) == 0.0
    assert cell(params, matrix, f"serialization_type{NULL_SUFFIX}", 1) == 0.0
    assert cell(params, matrix, f"serialization_type{NULL_SUFFIX}", 2) == 1.0


def test_matrix_never_contains_nan():
    params = fit_preprocessor(train_rows())
    assert not np.isnan(transform(params, [record(), *train_rows()])).any()


def test_non_finite_value_is_rejected():
    params = fit_preprocessor(train_rows())
    with pytest.raises(ValueError, match="non-finite"):
        transform(params, [record(split="validation", centrality=math.inf)])


def test_feature_subset_removes_columns_for_ablation():
    params = fit_preprocessor(train_rows(), ["dependency_count"])
    assert params.columns == ["dependency_count", f"dependency_count{NULL_SUFFIX}"]


def test_params_round_trip_through_json():
    params = fit_preprocessor(train_rows())
    again = PreprocessingParams.model_validate_json(params.model_dump_json())
    assert np.array_equal(transform(params, train_rows()), transform(again, train_rows()))
    assert again.fitted_on == "train"
