"""Load the trained models and score one scan's features.

Models are loaded through `load_bundle` only, which verifies every digest before parsing. The
ML packages are imported inside functions because the API image may not include them; a scan
then falls back to the rule-based result and says "ML model unavailable".
"""

import logging
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.ml.feature_schema import FeatureValue
from app.risk.types import MlOutputs

logger = logging.getLogger(__name__)

# The types the models were trained on. A dataset scan is outside what they have seen.
TRAINED_ARTIFACT_TYPES = frozenset({"software", "model", "lora"})


class ModelUnavailable(Exception):
    """No usable model. The message is safe to show in the API."""


@dataclass(frozen=True)
class LoadedModels:
    bundle: Any  # app.ml.training.ModelBundle, imported lazily
    model_version: str


_lock = threading.Lock()
_cache: dict[Path, tuple[Any, LoadedModels]] = {}


def load_models(model_dir: Path) -> LoadedModels:
    """Return the verified models, reloading whenever the manifest's file digests change."""
    try:
        from app.ml.artifacts import (
            RANDOM_FOREST_NAME,
            ModelArtifactError,
            load_bundle,
            read_manifest,
        )
    except ImportError as exc:
        raise ModelUnavailable("the ML packages are not installed") from exc

    key = model_dir.resolve()
    with _lock:
        try:
            files = read_manifest(model_dir)["files"]
            cached = _cache.get(key)
            if cached is not None and cached[0] == files:
                return cached[1]
            bundle = load_bundle(model_dir)
        except ModelArtifactError as exc:
            raise ModelUnavailable(str(exc)) from exc
        digest = str(files[RANDOM_FOREST_NAME].get("sha256"))
        models = LoadedModels(bundle=bundle, model_version=f"rf-sha256:{digest[:16]}")
        _cache[key] = (files, models)
        return models


def clear_cache() -> None:
    with _lock:
        _cache.clear()


def encode_features(models: LoadedModels, features: Mapping[str, FeatureValue]) -> Any:
    """One preprocessed row, using the parameters saved with the models."""
    from app.ml.preprocessing import transform_features

    return transform_features(models.bundle.preprocessing, [features])


def score_row(models: LoadedModels, row: Any) -> MlOutputs:
    """Model outputs for one row. These are not the ProvenanceX risk score."""
    from app.ml.training import anomaly_scores, risk_scores

    bundle = models.bundle
    return MlOutputs(
        rf_risk_probability=float(risk_scores(bundle.random_forest.predict_proba(row))[0]),
        xgb_risk_probability=float(risk_scores(bundle.xgboost.predict_proba(row))[0]),
        anomaly_score=float(anomaly_scores(bundle.isolation_forest, row)[0]),
        rf_threshold=bundle.thresholds.random_forest.value,
        anomaly_threshold=bundle.thresholds.isolation_forest.value,
        model_version=models.model_version,
    )
