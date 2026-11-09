"""SHAP factors for the primary model (Random Forest).

SHAP explains the model's probability of any non-benign class, not the ProvenanceX risk score.
A feature's factor is the sum over its encoded columns (value, null indicator, one-hot), so the
factors plus the base value still add up to the model output.

A factor for a feature that was not evaluated describes how the model reacts to the absence of
that evidence. It says nothing about the artifact, so those factors are marked.
"""

import logging
from collections.abc import Mapping
from typing import Any

from app.ml.feature_schema import FeatureValue
from app.risk.model_runtime import LoadedModels
from app.risk.policy_config import FEATURE_LAYERS

logger = logging.getLogger(__name__)

TOP_FACTOR_COUNT = 10
METHOD = "shap.TreeExplainer"
EXPLAINS = "Random Forest probability of any non-benign class (not the ProvenanceX risk score)"
NOT_EVALUATED_NOTE = (
    "A factor marked evaluated=false shows how the model reacts to missing evidence. "
    "It is not evidence about the artifact."
)


def _risk_shap_values(models: LoadedModels, row: Any) -> tuple[Any, float]:
    """SHAP values per column for risk = 1 - P(benign), and the matching base value."""
    import shap

    from app.ml.training import BENIGN_INDEX

    explainer = shap.TreeExplainer(models.bundle.random_forest)
    values = explainer.shap_values(row, check_additivity=True)
    return -values[0, :, BENIGN_INDEX], 1.0 - float(explainer.expected_value[BENIGN_INDEX])


def _feature_totals(models: LoadedModels, column_values: Any) -> dict[str, float]:
    from app.ml.preprocessing import feature_columns

    params = models.bundle.preprocessing
    index = {column: position for position, column in enumerate(params.columns)}
    return {
        feature.name: float(sum(column_values[index[c]] for c in feature_columns(feature)))
        for feature in params.features
    }


def _factor(
    name: str,
    contribution: float,
    features: Mapping[str, FeatureValue],
    null_reasons: Mapping[str, Any],
) -> dict[str, Any]:
    value = features.get(name)
    return {
        "feature": name,
        "layer": str(FEATURE_LAYERS[name]),
        "value": value,
        "evaluated": value is not None,
        "null_reason": None if value is not None else str(null_reasons.get(name)),
        "shap_contribution": contribution,
        "direction": "raises_model_probability" if contribution > 0 else "lowers_model_probability",
    }


def not_evaluated_features(
    models: LoadedModels | None,
    features: Mapping[str, FeatureValue],
    null_reasons: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Every feature with no value, why, and whether the model has a column for it."""
    known = {f.name for f in models.bundle.preprocessing.features} if models else None
    return [
        {
            "feature": name,
            "layer": str(FEATURE_LAYERS[name]),
            "null_reason": str(null_reasons.get(name)),
            "in_model": None if known is None else name in known,
        }
        for name, value in features.items()
        if value is None
    ]


def unavailable(message: str, not_evaluated: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "status": "unavailable",
        "message": message,
        "method": None,
        "explains": None,
        "base_value": None,
        "model_output": None,
        "top_factors": [],
        "not_evaluated_features": not_evaluated,
        "note": None,
    }


def explain_random_forest(
    models: LoadedModels,
    row: Any,
    features: Mapping[str, FeatureValue],
    null_reasons: Mapping[str, Any],
    model_output: float,
    top_n: int = TOP_FACTOR_COUNT,
) -> dict[str, Any]:
    """Top SHAP factors, or an explicit unavailable result. Never invents a factor."""
    not_evaluated = not_evaluated_features(models, features, null_reasons)
    try:
        column_values, base_value = _risk_shap_values(models, row)
        totals = _feature_totals(models, column_values)
    except ImportError:
        return unavailable("SHAP explanation unavailable: shap is not installed", not_evaluated)
    except Exception as exc:  # shap raises many types, including its additivity check
        logger.exception("SHAP explanation failed")
        return unavailable(f"SHAP explanation failed: {type(exc).__name__}", not_evaluated)
    ranked = sorted(
        ((name, amount) for name, amount in totals.items() if amount != 0.0),
        key=lambda item: (-abs(item[1]), item[0]),
    )
    return {
        "status": "available",
        "message": None,
        "method": METHOD,
        "explains": EXPLAINS,
        "base_value": base_value,
        "model_output": model_output,
        "top_factors": [_factor(n, a, features, null_reasons) for n, a in ranked[:top_n]],
        "not_evaluated_features": not_evaluated,
        "note": NOT_EVALUATED_NOTE,
    }
