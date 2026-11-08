"""Train Random Forest (primary), XGBoost (comparison) and Isolation Forest (anomaly).

Learned values come from the training split. Decision thresholds are chosen on the validation
split. The test split is never read here: load_training_records discards it before parsing and
train_models refuses it. Scores here are research outputs on synthetic data, not risk decisions.
"""

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

import numpy as np
from pydantic import BaseModel, ConfigDict
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from app.ml.feature_schema import DATASET_FORMAT, FeatureRecord, Label
from app.ml.preprocessing import PreprocessingParams, fit_preprocessor, transform

# malicious_known_bad is excluded: the synthetic dataset cannot establish that ground truth.
LABEL_ORDER = (Label.BENIGN, Label.VULNERABLE, Label.PROVENANCE_WEAK, Label.SUSPICIOUS)
BENIGN_INDEX = LABEL_ORDER.index(Label.BENIGN)
LABEL_INDEX = {label: index for index, label in enumerate(LABEL_ORDER)}
MODELS_FORMAT = "provenancex-models-v1"


@dataclass(frozen=True)
class TrainingConfig:
    """Research parameters, recorded with the saved models."""

    seed: int = 42
    rf_estimators: int = 300
    rf_min_samples_leaf: int = 2
    xgb_estimators: int = 300
    xgb_max_depth: int = 6
    xgb_learning_rate: float = 0.1
    iforest_estimators: int = 300
    anomaly_target_fpr: float = 0.05
    n_jobs: int = -1


class ThresholdChoice(BaseModel):
    """A threshold and how it was chosen. Scores at or above it count as flagged."""

    model_config = ConfigDict(extra="forbid")

    value: float
    selected_on: Literal["validation"] = "validation"
    criterion: str
    validation_f1: float | None = None
    validation_fpr: float


class Thresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    random_forest: ThresholdChoice
    xgboost: ThresholdChoice
    isolation_forest: ThresholdChoice


@dataclass
class ModelBundle:
    preprocessing: PreprocessingParams
    random_forest: RandomForestClassifier
    xgboost: XGBClassifier
    isolation_forest: IsolationForest
    thresholds: Thresholds
    metadata: dict[str, Any]


def load_training_records(data_dir: Path) -> tuple[list[FeatureRecord], list[FeatureRecord], dict]:
    """Return (train, validation, dataset metadata). Test rows are discarded unparsed.

    The file digest covers the whole file so a modified dataset is refused, but test rows are
    never decoded into records or returned.
    """
    metadata = json.loads((data_dir / "dataset_metadata.json").read_text(encoding="utf-8"))
    if metadata.get("format") != DATASET_FORMAT:
        raise ValueError("Unknown dataset format")
    body = (data_dir / "dataset.jsonl").read_bytes()
    if hashlib.sha256(body).hexdigest() != metadata.get("dataset_sha256"):
        raise ValueError("dataset.jsonl does not match the digest in its metadata")
    splits: dict[str, list[FeatureRecord]] = {"train": [], "validation": []}
    for line in body.splitlines():
        row = json.loads(line)
        if row.get("split") in splits:
            splits[row["split"]].append(FeatureRecord.model_validate(row))
    return splits["train"], splits["validation"], metadata


def encode_labels(records: list[FeatureRecord]) -> np.ndarray:
    unknown = sorted({str(r.label) for r in records if r.label not in LABEL_INDEX})
    if unknown:
        raise ValueError(f"Labels outside the trained set: {unknown}")
    return np.asarray([LABEL_INDEX[r.label] for r in records], dtype=int)


def risk_scores(probabilities: np.ndarray) -> np.ndarray:
    """Probability of any non-benign class. A model output, not the ProvenanceX risk score."""
    return 1.0 - probabilities[:, BENIGN_INDEX]


def anomaly_scores(model: IsolationForest, matrix: np.ndarray) -> np.ndarray:
    """Higher means more anomalous (sklearn's score_samples has the opposite sign)."""
    return -model.score_samples(matrix)


def _candidate_thresholds(scores: np.ndarray) -> np.ndarray:
    unique = np.unique(scores)
    middles = (unique[:-1] + unique[1:]) / 2
    return np.concatenate(([unique[0]], middles, [np.nextafter(unique[-1], np.inf)]))


def _rates(flagged: np.ndarray, is_risk: np.ndarray) -> tuple[float, float]:
    true_pos = int(np.sum(flagged & is_risk))
    false_pos = int(np.sum(flagged & ~is_risk))
    false_neg = int(np.sum(~flagged & is_risk))
    denominator = 2 * true_pos + false_pos + false_neg
    f1 = 2 * true_pos / denominator if denominator else 0.0
    return f1, false_pos / max(int(np.sum(~is_risk)), 1)


def choose_risk_threshold(scores: np.ndarray, is_risk: np.ndarray) -> ThresholdChoice:
    """Best validation F1 for benign vs. any risk. Ties go to the lower false-positive rate."""
    if not is_risk.any() or is_risk.all():
        raise ValueError("Validation needs both benign and non-benign records")
    best: tuple[float, float, float] | None = None
    for threshold in _candidate_thresholds(scores):
        f1, fpr = _rates(scores >= threshold, is_risk)
        if best is None or (f1, -fpr) > (best[0], -best[1]):
            best = (f1, fpr, float(threshold))
    return ThresholdChoice(
        value=best[2],
        criterion="max_f1_benign_vs_any_risk",
        validation_f1=round(best[0], 6),
        validation_fpr=round(best[1], 6),
    )


def choose_anomaly_threshold(benign_scores: np.ndarray, target_fpr: float) -> ThresholdChoice:
    """The lowest threshold that flags at most `target_fpr` of benign validation records."""
    if benign_scores.size == 0:
        raise ValueError("Validation needs benign records to choose an anomaly threshold")
    for threshold in _candidate_thresholds(benign_scores):
        fpr = float(np.mean(benign_scores >= threshold))
        if fpr <= target_fpr:
            return ThresholdChoice(
                value=float(threshold),
                criterion=f"benign_validation_fpr_at_most_{target_fpr}",
                validation_fpr=round(fpr, 6),
            )
    raise ValueError("No anomaly threshold satisfies the target")  # the top candidate flags 0


def _require_split(records: list[FeatureRecord], expected: str) -> None:
    if not records:
        raise ValueError(f"The {expected} split is empty")
    wrong = sorted({r.split for r in records} - {expected})
    if wrong:
        raise ValueError(f"Expected only {expected} records, got {wrong}")


def _fit_forest(matrix: np.ndarray, labels: np.ndarray, cfg: TrainingConfig):
    model = RandomForestClassifier(
        n_estimators=cfg.rf_estimators,
        min_samples_leaf=cfg.rf_min_samples_leaf,
        class_weight="balanced",
        random_state=cfg.seed,
        n_jobs=cfg.n_jobs,
    )
    return model.fit(matrix, labels)


def _fit_xgboost(matrix: np.ndarray, labels: np.ndarray, cfg: TrainingConfig):
    model = XGBClassifier(
        n_estimators=cfg.xgb_estimators,
        max_depth=cfg.xgb_max_depth,
        learning_rate=cfg.xgb_learning_rate,
        objective="multi:softprob",
        tree_method="hist",
        random_state=cfg.seed,
        n_jobs=cfg.n_jobs,
    )
    return model.fit(matrix, labels, sample_weight=compute_sample_weight("balanced", labels))


def fit_supervised_and_preprocess(
    train: list[FeatureRecord], cfg: TrainingConfig, feature_names=None
) -> tuple[PreprocessingParams, np.ndarray, np.ndarray]:
    """Fit preprocessing on the training split and return its matrix and encoded labels."""
    _require_split(train, "train")
    params = fit_preprocessor(train, *([feature_names] if feature_names else []))
    labels = encode_labels(train)
    if set(labels.tolist()) != set(range(len(LABEL_ORDER))):
        raise ValueError("The training split must contain every trained label")
    return params, transform(params, train), labels


def train_models(
    train: list[FeatureRecord],
    validation: list[FeatureRecord],
    dataset_metadata: dict[str, Any],
    cfg: TrainingConfig | None = None,
) -> ModelBundle:
    """Fit all three models on train and pick their thresholds on validation."""
    cfg = cfg or TrainingConfig()
    _require_split(validation, "validation")
    params, x_train, y_train = fit_supervised_and_preprocess(train, cfg)
    forest = _fit_forest(x_train, y_train, cfg)
    booster = _fit_xgboost(x_train, y_train, cfg)
    # Fitted on benign training records only, so "anomalous" means unlike known-good artifacts.
    benign_train = x_train[y_train == BENIGN_INDEX]
    isolation = IsolationForest(
        n_estimators=cfg.iforest_estimators, random_state=cfg.seed, n_jobs=cfg.n_jobs
    ).fit(benign_train)

    x_val = transform(params, validation)
    is_risk = encode_labels(validation) != BENIGN_INDEX
    thresholds = Thresholds(
        random_forest=choose_risk_threshold(risk_scores(forest.predict_proba(x_val)), is_risk),
        xgboost=choose_risk_threshold(risk_scores(booster.predict_proba(x_val)), is_risk),
        isolation_forest=choose_anomaly_threshold(
            anomaly_scores(isolation, x_val)[~is_risk], cfg.anomaly_target_fpr
        ),
    )
    metadata = {
        "format": MODELS_FORMAT,
        "synthetic": bool(dataset_metadata.get("synthetic")),
        "notice": dataset_metadata.get("notice"),
        "ground_truth_status": dataset_metadata.get("ground_truth_status"),
        "dataset_sha256": dataset_metadata.get("dataset_sha256"),
        "label_order": [str(label) for label in LABEL_ORDER],
        "primary_model": "random_forest",
        "training_config": asdict(cfg),
        "train_record_count": len(train),
        "validation_record_count": len(validation),
        "benign_train_record_count": int(benign_train.shape[0]),
        "column_count": len(params.columns),
        "not_evaluated_features": params.dropped_all_null,
        "split_use": {
            "train": "models, medians and categories",
            "validation": "thresholds only",
            "test": "not read during training",
        },
    }
    return ModelBundle(params, forest, booster, isolation, thresholds, metadata)
