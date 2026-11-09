"""Turn feature records into a numeric matrix, handling null features explicitly.

Null means "not evaluated", so it must never look like a measured 0. Every feature gets:
  <name>            its value, or the training-set median when the value is null
  <name>__is_null   1 when the feature was not evaluated, otherwise 0
A categorical feature becomes one column per training-set category, all 0 when null or unseen.
A feature that is null across the whole training set is dropped and recorded. All learned
values come from the training split only; fit_preprocessor refuses any other split.
"""

import math
import statistics
from collections.abc import Iterable, Mapping, Sequence
from typing import Literal

import numpy as np
from pydantic import BaseModel, ConfigDict

from app.ml.feature_schema import (
    FEATURE_NAMES,
    FEATURES_BY_NAME,
    FeatureRecord,
    FeatureValue,
    Kind,
)

PREPROCESSING_FORMAT = "provenancex-preprocessing-v1"
NULL_SUFFIX = "__is_null"
NULL_POLICY = (
    "Each feature has a <name>__is_null indicator (1 = not evaluated). Null values are filled "
    "with the training-set median so the model never reads them as a measured 0. Categorical "
    "features are one-hot encoded and are all 0 when null. Features null in every training "
    "record are dropped. Fitted on the training split only."
)


class FittedFeature(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    kind: Kind
    median: float | None = None
    categories: list[str] | None = None


class PreprocessingParams(BaseModel):
    """Everything needed to reproduce the transform. Saved as plain JSON."""

    model_config = ConfigDict(extra="forbid")

    format: Literal["provenancex-preprocessing-v1"] = PREPROCESSING_FORMAT
    fitted_on: Literal["train"] = "train"
    train_record_count: int
    null_policy: str = NULL_POLICY
    features: list[FittedFeature]
    dropped_all_null: list[str]
    columns: list[str]


def _as_number(name: str, value: bool | int | float) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"Feature {name} has a non-finite value")
    return number


def feature_columns(feature: FittedFeature) -> list[str]:
    if feature.kind == Kind.CATEGORY:
        values = [f"{feature.name}={category}" for category in feature.categories or []]
    else:
        values = [feature.name]
    return [*values, f"{feature.name}{NULL_SUFFIX}"]


def _fit_feature(name: str, values: list) -> FittedFeature:
    kind = FEATURES_BY_NAME[name].kind
    if kind == Kind.CATEGORY:
        return FittedFeature(name=name, kind=kind, categories=sorted({str(v) for v in values}))
    numbers = [_as_number(name, value) for value in values]
    return FittedFeature(name=name, kind=kind, median=float(statistics.median(numbers)))


def fit_preprocessor(
    train_records: Sequence[FeatureRecord], feature_names: Iterable[str] = FEATURE_NAMES
) -> PreprocessingParams:
    """Learn medians and categories. `feature_names` lets an ablation remove a layer."""
    if not train_records:
        raise ValueError("Cannot fit preprocessing on an empty training set")
    wrong = sorted({record.split for record in train_records} - {"train"})
    if wrong:
        raise ValueError(f"Preprocessing may only be fitted on the train split, got {wrong}")
    fitted: list[FittedFeature] = []
    dropped: list[str] = []
    for name in feature_names:
        values = [r.features[name] for r in train_records if r.features[name] is not None]
        if values:
            fitted.append(_fit_feature(name, values))
        else:
            dropped.append(name)
    if not fitted:
        raise ValueError("Every feature is null in the training set")
    columns = [column for feature in fitted for column in feature_columns(feature)]
    return PreprocessingParams(
        train_record_count=len(train_records),
        features=fitted,
        dropped_all_null=dropped,
        columns=columns,
    )


def _encode(feature: FittedFeature, value: bool | int | float | str | None) -> list[float]:
    is_null = 1.0 if value is None else 0.0
    if feature.kind == Kind.CATEGORY:
        return [float(value == c) for c in feature.categories or []] + [is_null]
    if value is None:
        return [float(feature.median), is_null]
    return [_as_number(feature.name, value), is_null]


def transform_features(
    params: PreprocessingParams, feature_rows: Sequence[Mapping[str, FeatureValue]]
) -> np.ndarray:
    """Build the matrix from plain feature mappings, as a live scan provides them."""
    rows = [
        [cell for f in params.features for cell in _encode(f, row[f.name])] for row in feature_rows
    ]
    return np.asarray(rows, dtype=float).reshape(len(feature_rows), len(params.columns))


def transform(params: PreprocessingParams, records: Sequence[FeatureRecord]) -> np.ndarray:
    """Build the matrix. The result never contains NaN, and its columns are params.columns."""
    return transform_features(params, [record.features for record in records])
