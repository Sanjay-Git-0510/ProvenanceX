"""Gated, digest-verified loading of the real-world software model for the scan runtime.

The model is used only when every check passes; otherwise the caller falls back to the
synthetic-labelled models or the rule-based result, and states why. Checks, in order:

1. manifest format, exact file set, regular files, size caps, SHA-256 of every file, and the
   library versions used in training (same rules as app.ml.artifacts);
2. the metadata says real (not synthetic) software data labelled benign vs known_vulnerable;
3. the quality gates below, recomputed here from the digest-covered evaluation summary. A
   stored "passed" flag is never trusted.

The model predicts known_vulnerable vs benign. Vulnerable is not malicious, and this model makes
no malware-detection claim. Model, LoRA and dataset artifacts never use it.
"""

import json
import stat
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

MODELS_FORMAT = "provenancex-realworld-models-v1"
EVALUATION_NAME = "evaluation_summary.json"
EXPECTED_FILES = frozenset(
    {
        "preprocessing.json",
        "random_forest.skops",
        "isolation_forest.skops",
        "xgboost.json",
        "thresholds.json",
        "training_metadata.json",
        EVALUATION_NAME,
    }
)
EXPECTED_LABELS = ["benign", "known_vulnerable"]
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024

# Owner-approved gates (2026-11-23). Research parameters, not standards.
MIN_LABELLED_ROWS = 150
MIN_TEST_ROWS_PER_CLASS = 30
MIN_ROC_AUC_CI_LOWER = 0.5  # strictly greater than


class RealWorldUnavailable(Exception):
    """The real-world model must not be used. The message is safe to show in the API."""


@dataclass(frozen=True)
class GateResult:
    passed: bool
    reasons: tuple[str, ...]


def _read_regular(path: Path, cap: int) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RealWorldUnavailable(f"missing real-world model file: {path.name}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise RealWorldUnavailable(f"real-world model file is not a regular file: {path.name}")
    if info.st_size > cap:
        raise RealWorldUnavailable(f"real-world model file is too large: {path.name}")
    return path.read_bytes()


def _json(raw: bytes, name: str) -> Any:
    try:
        return json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise RealWorldUnavailable(f"{name} is not valid JSON") from exc


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def evaluate_gates(summary: Any) -> GateResult:
    """Apply the quality gates to an evaluation summary. Missing values fail their gate."""
    if not isinstance(summary, dict):
        return GateResult(False, ("the evaluation summary is not an object",))
    reasons: list[str] = []
    rows = summary.get("labelled_rows")
    if not isinstance(rows, int) or isinstance(rows, bool) or rows < MIN_LABELLED_ROWS:
        reasons.append(f"labelled rows {rows!r} < {MIN_LABELLED_ROWS}")
    test = summary.get("test_class_counts")
    test = test if isinstance(test, dict) else {}
    for label in EXPECTED_LABELS:
        n = test.get(label)
        if not isinstance(n, int) or isinstance(n, bool) or n < MIN_TEST_ROWS_PER_CLASS:
            reasons.append(f"test rows for {label} {n!r} < {MIN_TEST_ROWS_PER_CLASS}")
    f1, rules_f1 = _number(summary.get("test_f1")), _number(summary.get("rules_only_test_f1"))
    if f1 is None or rules_f1 is None or f1 < rules_f1:
        reasons.append(f"test F1 {f1!r} is below the rules-only baseline {rules_f1!r}")
    ci = summary.get("test_roc_auc_95ci")
    lower = _number(ci[0]) if isinstance(ci, list) and len(ci) == 2 else None
    if lower is None or not lower > MIN_ROC_AUC_CI_LOWER:
        reasons.append(f"ROC-AUC 95% CI lower bound {lower!r} is not > {MIN_ROC_AUC_CI_LOWER}")
    return GateResult(not reasons, tuple(reasons))


def read_verified(model_dir: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Return the manifest and each file's bytes after verifying every SHA-256 digest."""
    import hashlib

    from app.ml.artifacts import library_versions

    manifest = _json(_read_regular(model_dir / "manifest.json", MAX_JSON_BYTES), "manifest.json")
    if not isinstance(manifest, dict) or manifest.get("format") != MODELS_FORMAT:
        raise RealWorldUnavailable("the real-world model manifest has an unknown format")
    if manifest.get("synthetic") is not False:
        raise RealWorldUnavailable("the real-world model manifest does not state real data")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != EXPECTED_FILES:
        raise RealWorldUnavailable("the real-world model manifest does not list the expected files")
    verified: dict[str, bytes] = {}
    for name in sorted(EXPECTED_FILES):
        cap = (
            MAX_JSON_BYTES if name.endswith(".json") and name != "xgboost.json" else MAX_FILE_BYTES
        )
        raw = _read_regular(model_dir / name, cap)
        entry = files[name]
        if not isinstance(entry, dict) or hashlib.sha256(raw).hexdigest() != entry.get("sha256"):
            raise RealWorldUnavailable(f"SHA-256 mismatch for real-world model file {name}")
        verified[name] = raw
    if manifest.get("library_versions") != library_versions():
        raise RealWorldUnavailable("library versions differ from the real-world training run")
    return manifest, verified


def load_realworld_software(model_dir: Path) -> Any:
    """Verify and gate the bundle, then load it. Raises RealWorldUnavailable on any failure.

    Returns an object with the same attributes the runtime scorer and SHAP explainer use
    (preprocessing, random_forest, xgboost, isolation_forest, thresholds, metadata).
    """
    manifest, raw = read_verified(model_dir)
    metadata = _json(raw["training_metadata.json"], "training_metadata.json")
    if not isinstance(metadata, dict):
        raise RealWorldUnavailable("training_metadata.json is not an object")
    if (
        metadata.get("format") != MODELS_FORMAT
        or metadata.get("synthetic") is not False
        or metadata.get("artifact_type") != "software"
        or metadata.get("labels") != EXPECTED_LABELS
    ):
        raise RealWorldUnavailable(
            "the real-world metadata is not a benign/known_vulnerable software model"
        )
    gates = evaluate_gates(_json(raw[EVALUATION_NAME], EVALUATION_NAME))
    if not gates.passed:
        raise RealWorldUnavailable("quality gates not met: " + "; ".join(gates.reasons))

    # Only now are the model files parsed, from the verified bytes.
    from pydantic import ValidationError
    from sklearn.ensemble import IsolationForest, RandomForestClassifier

    from app.ml.artifacts import ModelArtifactError, _load_skops, _load_xgboost
    from app.ml.preprocessing import PreprocessingParams
    from app.ml.training import ThresholdChoice

    try:
        preprocessing = PreprocessingParams.model_validate_json(raw["preprocessing.json"])
        thresholds = {
            k: ThresholdChoice.model_validate(v)
            for k, v in _json(raw["thresholds.json"], "thresholds.json").items()
        }
        forest = _load_skops(
            raw["random_forest.skops"], "random_forest.skops", RandomForestClassifier
        )
        isolation = _load_skops(
            raw["isolation_forest.skops"], "isolation_forest.skops", IsolationForest
        )
        booster = _load_xgboost(raw["xgboost.json"])
    except (ModelArtifactError, ValidationError, AttributeError) as exc:
        raise RealWorldUnavailable(f"a real-world model file was refused: {exc}") from exc
    if {"random_forest", "isolation_forest"} - set(thresholds):
        raise RealWorldUnavailable("the real-world thresholds are incomplete")
    width = len(preprocessing.columns)
    if forest.n_features_in_ != width or isolation.n_features_in_ != width:
        raise RealWorldUnavailable("the real-world model width does not match its preprocessing")
    if list(getattr(forest, "classes_", [])) != [0, 1]:
        raise RealWorldUnavailable("the real-world forest is not a benign/known_vulnerable model")
    forest.n_jobs = 1
    return SimpleNamespace(
        preprocessing=preprocessing,
        random_forest=forest,
        xgboost=booster,
        isolation_forest=isolation,
        thresholds=SimpleNamespace(
            random_forest=thresholds["random_forest"],
            isolation_forest=thresholds["isolation_forest"],
        ),
        metadata={**metadata, "manifest_files": manifest["files"]},
    )
