"""Train and evaluate real-world models for one artifact type (benign vs known_vulnerable).

Leakage rules:
- splits are by family (dataset.assign_splits); preprocessing and models fit on train only
- thresholds are chosen on validation only; the test split is scored once per run
- repeated-split and ablation runs re-choose thresholds on their own validation split

Outputs are research measurements on a small real dataset. They are not the ProvenanceX risk
score and do not change the runtime models.
"""

import hashlib
import json
import platform
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

import numpy as np
import skops.io as sio
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import average_precision_score, brier_score_loss
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from app.ml.artifacts import library_versions
from app.ml.baselines import RULES
from app.ml.evaluation import binary_metrics
from app.ml.feature_schema import FEATURE_NAMES, Layer, NullReason, features_in_layer
from app.ml.preprocessing import PreprocessingParams, fit_preprocessor, transform_features
from app.ml.realworld.dataset import InsufficientData, RealRow, assign_splits, with_splits
from app.ml.training import (
    ThresholdChoice,
    anomaly_scores,
    choose_anomaly_threshold,
    choose_risk_threshold,
)

MODELS_FORMAT = "provenancex-realworld-models-v1"


@dataclass(frozen=True)
class Config:
    seed: int = 42
    rf_estimators: int = 300
    rf_min_samples_leaf: int = 2
    xgb_estimators: int = 200
    xgb_max_depth: int = 4
    xgb_learning_rate: float = 0.1
    iforest_estimators: int = 300
    anomaly_target_fpr: float = 0.10
    repeated_seeds: int = 20
    bootstrap_resamples: int = 1000


@dataclass
class Trained:
    preprocessing: PreprocessingParams
    random_forest: RandomForestClassifier
    xgboost: XGBClassifier
    isolation_forest: IsolationForest
    thresholds: dict[str, ThresholdChoice]


def _matrix(prep: PreprocessingParams, rows: list[RealRow]) -> np.ndarray:
    return transform_features(prep, [r.features for r in rows])


def _targets(rows: list[RealRow]) -> np.ndarray:
    return np.asarray([r.target for r in rows], dtype=int)


def train(
    train_rows: list[RealRow],
    val_rows: list[RealRow],
    cfg: Config,
    feature_names: tuple[str, ...] = FEATURE_NAMES,
) -> Trained:
    prep = fit_preprocessor(train_rows, feature_names)  # type: ignore[arg-type]
    x, y = _matrix(prep, train_rows), _targets(train_rows)
    rf = RandomForestClassifier(
        n_estimators=cfg.rf_estimators,
        min_samples_leaf=cfg.rf_min_samples_leaf,
        class_weight="balanced",
        random_state=cfg.seed,
        n_jobs=1,
    ).fit(x, y)
    xgb = XGBClassifier(
        n_estimators=cfg.xgb_estimators,
        max_depth=cfg.xgb_max_depth,
        learning_rate=cfg.xgb_learning_rate,
        objective="binary:logistic",
        tree_method="hist",
        random_state=cfg.seed,
        n_jobs=1,
    ).fit(x, y, sample_weight=compute_sample_weight("balanced", y))
    iforest = IsolationForest(
        n_estimators=cfg.iforest_estimators, random_state=cfg.seed, n_jobs=1
    ).fit(x[y == 0])
    xv, yv = _matrix(prep, val_rows), _targets(val_rows).astype(bool)
    thresholds = {
        "random_forest": choose_risk_threshold(rf.predict_proba(xv)[:, 1], yv),
        "xgboost": choose_risk_threshold(xgb.predict_proba(xv)[:, 1], yv),
        "isolation_forest": choose_anomaly_threshold(
            anomaly_scores(iforest, xv)[~yv], cfg.anomaly_target_fpr
        ),
    }
    return Trained(prep, rf, xgb, iforest, thresholds)


def scores(models: Trained, rows: list[RealRow]) -> dict[str, np.ndarray]:
    x = _matrix(models.preprocessing, rows)
    return {
        "random_forest": models.random_forest.predict_proba(x)[:, 1],
        "xgboost": models.xgboost.predict_proba(x)[:, 1],
        "isolation_forest": anomaly_scores(models.isolation_forest, x),
    }


# --- baselines ------------------------------------------------------------------------------


def rules_only_scores(rows: list[RealRow]) -> tuple[np.ndarray, np.ndarray]:
    """(rules fired, any rule evaluated). Same rules as the synthetic baseline; nothing fitted."""
    fired, evaluated = [], []
    for row in rows:
        n, any_eval = 0, False
        for rule in RULES:
            if row.null_reasons.get(rule.feature) == NullReason.NOT_APPLICABLE:
                continue
            value = row.features.get(rule.feature)
            if value is None:
                continue
            any_eval = True
            n += int(rule.fires(value))
        fired.append(float(n))
        evaluated.append(any_eval)
    return np.asarray(fired), np.asarray(evaluated, dtype=bool)


def vulnerability_only_scores(rows: list[RealRow]) -> np.ndarray:
    return np.asarray([float(r.features.get("vulnerable_count") or 0) for r in rows])


# --- metrics ----------------------------------------------------------------------------------


def _pr_auc(y: np.ndarray, s: np.ndarray) -> float | None:
    return float(average_precision_score(y, s)) if 0 < y.sum() < y.size else None


def _calibration(y: np.ndarray, p: np.ndarray, bins: int = 5) -> dict[str, Any]:
    edges = np.linspace(0, 1, bins + 1)
    table = []
    for lo, hi in zip(edges[:-1], edges[1:], strict=True):
        mask = (p >= lo) & ((p < hi) if hi < 1 else (p <= hi))
        if mask.any():
            table.append(
                {
                    "bin": f"{lo:.1f}-{hi:.1f}",
                    "n": int(mask.sum()),
                    "mean_predicted": round(float(p[mask].mean()), 4),
                    "observed_positive_rate": round(float(y[mask].mean()), 4),
                }
            )
    return {"brier": round(float(brier_score_loss(y, p)), 4), "bins": table}


def _threshold_table(y: np.ndarray, s: np.ndarray, points: list[float]) -> list[dict[str, Any]]:
    out = []
    for t in points:
        m = binary_metrics(y.astype(bool), s >= t)
        out.append({"threshold": t, **{k: m[k] for k in ("precision", "recall", "fpr", "fnr")}})
    return out


def evaluate_scores(
    rows: list[RealRow], s: np.ndarray, threshold: float, probability: bool
) -> dict[str, Any]:
    y = _targets(rows)
    flagged = s >= threshold
    m = binary_metrics(y.astype(bool), flagged, s)
    no_prior = np.asarray(
        [r.null_reasons.get("hash_changed") == NullReason.NO_PRIOR_SCAN for r in rows], dtype=bool
    )
    benign_np = no_prior & (y == 0)
    result: dict[str, Any] = {
        **m,
        "pr_auc": _pr_auc(y, s),
        "threshold": threshold,
        "confusion_matrix": {"tp": m["tp"], "fp": m["fp"], "tn": m["tn"], "fn": m["fn"]},
        "no_prior_scan": {
            "benign_rows": int(benign_np.sum()),
            "false_positives": int((flagged & benign_np).sum()),
            "fpr": float((flagged & benign_np).sum() / benign_np.sum())
            if benign_np.any()
            else None,
        },
    }
    if probability:
        result["calibration"] = _calibration(y, s)
        result["threshold_analysis"] = _threshold_table(y, s, [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8])
    return result


def _bootstrap(y: np.ndarray, s: np.ndarray, t: float, n: int, seed: int) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    f1s, aucs = [], []
    for _ in range(n):
        idx = rng.integers(0, y.size, y.size)
        yy, ss = y[idx], s[idx]
        m = binary_metrics(yy.astype(bool), ss >= t, ss)
        if m["f1"] is not None:
            f1s.append(m["f1"])
        if m["roc_auc"] is not None:
            aucs.append(m["roc_auc"])

    def ci(values: list[float]) -> list[float] | None:
        return [round(float(np.percentile(values, q)), 4) for q in (2.5, 97.5)] if values else None

    return {"resamples": n, "f1_95ci": ci(f1s), "roc_auc_95ci": ci(aucs)}


def evaluate_split(
    models: Trained, rows: list[RealRow], cfg: Config, bootstrap: bool = False
) -> dict[str, Any]:
    s = scores(models, rows)
    out = {
        name: evaluate_scores(
            rows, s[name], models.thresholds[name].value, name != "isolation_forest"
        )
        for name in s
    }
    fired, evaluated = rules_only_scores(rows)
    out["rules_only"] = evaluate_scores(rows, fired, 1.0, False)
    out["rules_only"]["rows_no_rule_evaluable"] = int((~evaluated).sum())
    out["vulnerability_only"] = evaluate_scores(rows, vulnerability_only_scores(rows), 1.0, False)
    if bootstrap:
        y = _targets(rows)
        rf_t = models.thresholds["random_forest"].value
        out["random_forest"]["bootstrap"] = _bootstrap(
            y, s["random_forest"], rf_t, cfg.bootstrap_resamples, cfg.seed
        )
        out["rules_only"]["bootstrap"] = _bootstrap(
            y, fired, 1.0, cfg.bootstrap_resamples, cfg.seed
        )
    return out


def top_features(models: Trained, k: int = 10) -> list[dict[str, Any]]:
    """Random Forest impurity importances (a training-set statistic, not a causal claim)."""
    imp = models.random_forest.feature_importances_
    order = np.argsort(-imp)[:k]
    return [
        {"column": models.preprocessing.columns[i], "importance": round(float(imp[i]), 4)}
        for i in order
    ]


def repeated_splits(rows: list[RealRow], cfg: Config) -> dict[str, Any]:
    """Re-split by family with other seeds; each run tunes on its own validation split."""
    rows = [replace(r) for r in rows]  # splits are set on copies; the caller's rows keep theirs
    per_model: dict[str, dict[str, list[float]]] = {}
    skipped = 0
    for seed in range(cfg.seed + 1, cfg.seed + 1 + cfg.repeated_seeds):
        try:
            parts = with_splits(rows, assign_splits(rows, seed))
            models = train(
                parts["train"], parts["validation"], Config(**{**asdict(cfg), "seed": seed})
            )
        except (InsufficientData, ValueError):
            skipped += 1
            continue
        result = evaluate_split(models, parts["test"], cfg)
        for name in ("random_forest", "xgboost", "rules_only", "vulnerability_only"):
            for key in ("f1", "roc_auc", "pr_auc", "fpr", "fnr"):
                value = result[name][key]
                if value is not None:
                    per_model.setdefault(name, {}).setdefault(key, []).append(value)
    summary = {
        name: {
            key: {
                "n": len(v),
                "mean": round(float(np.mean(v)), 4),
                "std": round(float(np.std(v)), 4),
                "min": round(float(np.min(v)), 4),
                "max": round(float(np.max(v)), 4),
            }
            for key, v in metrics.items()
        }
        for name, metrics in per_model.items()
    }
    return {"seeds": cfg.repeated_seeds, "skipped": skipped, "summary": summary}


def ablation(parts: dict[str, list[RealRow]], cfg: Config) -> list[dict[str, Any]]:
    """Remove one evidence layer at a time; thresholds re-chosen on validation each time."""
    out = []
    for layer in Layer:
        removed = set(features_in_layer(layer))
        keep = tuple(n for n in FEATURE_NAMES if n not in removed)
        try:
            models = train(parts["train"], parts["validation"], cfg, keep)
        except ValueError as exc:
            out.append({"removed_layer": str(layer), "error": str(exc)})
            continue
        rf = evaluate_split(models, parts["test"], cfg)["random_forest"]
        out.append(
            {"removed_layer": str(layer), **{k: rf[k] for k in ("f1", "roc_auc", "pr_auc", "fpr")}}
        )
    return out


# --- artifacts --------------------------------------------------------------------------------


def _json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def save_models(models: Trained, out_dir: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    """Write models, preprocessing and thresholds, then a manifest of SHA-256 digests last."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "manifest.json").unlink(missing_ok=True)
    contents = {
        "preprocessing.json": _json(models.preprocessing.model_dump(mode="json")),
        "random_forest.skops": sio.dumps(models.random_forest),
        "isolation_forest.skops": sio.dumps(models.isolation_forest),
        "xgboost.json": bytes(models.xgboost.get_booster().save_raw(raw_format="json")),
        "thresholds.json": _json(
            {k: v.model_dump(mode="json") for k, v in models.thresholds.items()}
        ),
        "training_metadata.json": _json({"format": MODELS_FORMAT, **metadata}),
    }
    for name, raw in contents.items():
        (out_dir / name).write_bytes(raw)
    manifest = {
        "format": MODELS_FORMAT,
        "synthetic": False,
        "python_version": platform.python_version(),
        "library_versions": library_versions(),
        "files": {
            n: {"sha256": hashlib.sha256(r).hexdigest(), "bytes": len(r)}
            for n, r in sorted(contents.items())
        },
    }
    (out_dir / "manifest.json").write_bytes(_json(manifest))
    return manifest
