"""Save and load trained models without pickle or joblib.

Formats: skops for the scikit-learn models, XGBoost native JSON, plain JSON for the rest.
Loading reads each file once, checks its SHA-256 against the manifest, and only then parses
those same bytes, so a file cannot change between the check and the load. skops is given an
explicit list of types, and a file needing anything else is refused before it is built.

The manifest detects corruption and partial replacement. It is not signed, so someone able to
rewrite the whole directory could rewrite the manifest too; the directory must stay trusted.
"""

import hashlib
import json
import platform
import stat
from pathlib import Path
from typing import Any

import numpy
import sklearn
import skops
import skops.io as sio
import xgboost
from pydantic import ValidationError
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from xgboost import XGBClassifier

from app.ml.preprocessing import PreprocessingParams
from app.ml.training import LABEL_ORDER, MODELS_FORMAT, ModelBundle, Thresholds

MANIFEST_NAME = "manifest.json"
MANIFEST_FORMAT = "provenancex-model-manifest-v1"
PREPROCESSING_NAME = "preprocessing.json"
RANDOM_FOREST_NAME = "random_forest.skops"
ISOLATION_FOREST_NAME = "isolation_forest.skops"
XGBOOST_NAME = "xgboost.json"
THRESHOLDS_NAME = "thresholds.json"
METADATA_NAME = "training_metadata.json"
ARTIFACT_NAMES = frozenset(
    {
        PREPROCESSING_NAME,
        RANDOM_FOREST_NAME,
        ISOLATION_FOREST_NAME,
        XGBOOST_NAME,
        THRESHOLDS_NAME,
        METADATA_NAME,
    }
)
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
# skops already trusts its built-in scikit-learn and numpy types. This is the only addition.
TRUSTED_SKOPS_TYPES = ("sklearn.tree._tree.Tree",)


class ModelArtifactError(ValueError):
    """A model artifact is missing, altered or not of the expected form."""


def library_versions() -> dict[str, str]:
    return {
        "scikit-learn": sklearn.__version__,
        "xgboost": xgboost.__version__,
        "skops": skops.__version__,
        "numpy": numpy.__version__,
    }


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json_bytes(document: Any) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def save_bundle(bundle: ModelBundle, out_dir: Path) -> dict[str, Any]:
    """Write every artifact, then the manifest, so a partial save can never verify."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / MANIFEST_NAME).unlink(missing_ok=True)
    contents = {
        PREPROCESSING_NAME: _json_bytes(bundle.preprocessing.model_dump(mode="json")),
        RANDOM_FOREST_NAME: sio.dumps(bundle.random_forest),
        ISOLATION_FOREST_NAME: sio.dumps(bundle.isolation_forest),
        XGBOOST_NAME: bytes(bundle.xgboost.get_booster().save_raw(raw_format="json")),
        THRESHOLDS_NAME: _json_bytes(bundle.thresholds.model_dump(mode="json")),
        METADATA_NAME: _json_bytes(bundle.metadata),
    }
    for name, raw in contents.items():
        (out_dir / name).write_bytes(raw)
    manifest = {
        "format": MANIFEST_FORMAT,
        "synthetic": bundle.metadata.get("synthetic"),
        "python_version": platform.python_version(),
        "library_versions": library_versions(),
        "files": {
            name: {"sha256": _digest(raw), "bytes": len(raw)}
            for name, raw in sorted(contents.items())
        },
    }
    (out_dir / MANIFEST_NAME).write_bytes(_json_bytes(manifest))
    return manifest


def _read_regular(path: Path) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ModelArtifactError(f"Missing model artifact: {path.name}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ModelArtifactError(f"Model artifact is not a regular file: {path.name}")
    if info.st_size > MAX_ARTIFACT_BYTES:
        raise ModelArtifactError(f"Model artifact is too large: {path.name}")
    return path.read_bytes()


def read_manifest(model_dir: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(_read_regular(model_dir / MANIFEST_NAME))
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, ModelArtifactError):
            raise
        raise ModelArtifactError("The model manifest is not valid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != MANIFEST_FORMAT:
        raise ModelArtifactError("The model manifest has an unknown format")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != ARTIFACT_NAMES:
        raise ModelArtifactError("The model manifest does not list the expected files")
    return manifest


def read_verified(model_dir: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Return the manifest and every artifact's bytes, after verifying each digest."""
    manifest = read_manifest(model_dir)
    verified: dict[str, bytes] = {}
    for name in sorted(ARTIFACT_NAMES):
        raw = _read_regular(model_dir / name)
        entry = manifest["files"][name]
        if not isinstance(entry, dict) or _digest(raw) != entry.get("sha256"):
            raise ModelArtifactError(f"SHA-256 mismatch for {name}")
        verified[name] = raw
    expected = manifest.get("library_versions")
    if expected != library_versions():
        raise ModelArtifactError(
            f"Library versions differ from training: {expected} vs {library_versions()}"
        )
    return manifest, verified


def _load_skops(raw: bytes, name: str, expected_type: type) -> Any:
    """Rebuild one model. Refuses any type beyond the explicit list before building anything."""
    try:
        needed = sio.get_untrusted_types(data=raw)
        unexpected = sorted(set(needed) - set(TRUSTED_SKOPS_TYPES))
        if unexpected:
            raise ModelArtifactError(f"{name} requires untrusted types: {unexpected}")
        model = sio.loads(raw, trusted=list(TRUSTED_SKOPS_TYPES))
    except ModelArtifactError:
        raise
    except Exception as exc:  # skops raises many types on malformed files; all are refusals
        raise ModelArtifactError(f"{name} could not be parsed: {type(exc).__name__}") from exc
    if type(model) is not expected_type:
        raise ModelArtifactError(f"{name} is not a {expected_type.__name__}")
    return model


def _load_xgboost(raw: bytes) -> XGBClassifier:
    model = XGBClassifier()
    try:
        model.load_model(bytearray(raw))
    except Exception as exc:  # XGBoostError and decode errors both mean the file is refused
        raise ModelArtifactError(f"{XGBOOST_NAME} could not be parsed") from exc
    return model


def load_bundle(model_dir: Path) -> ModelBundle:
    """Verify the manifest and every digest, then load the models from the verified bytes."""
    _, raw = read_verified(model_dir)
    try:
        preprocessing = PreprocessingParams.model_validate_json(raw[PREPROCESSING_NAME])
        thresholds = Thresholds.model_validate_json(raw[THRESHOLDS_NAME])
        metadata = json.loads(raw[METADATA_NAME])
    except (ValidationError, ValueError) as exc:
        raise ModelArtifactError("A model JSON artifact is malformed") from exc
    if metadata.get("format") != MODELS_FORMAT or metadata.get("label_order") != [
        str(label) for label in LABEL_ORDER
    ]:
        raise ModelArtifactError("Training metadata does not match this code's label order")
    forest = _load_skops(raw[RANDOM_FOREST_NAME], RANDOM_FOREST_NAME, RandomForestClassifier)
    isolation = _load_skops(raw[ISOLATION_FOREST_NAME], ISOLATION_FOREST_NAME, IsolationForest)
    booster = _load_xgboost(raw[XGBOOST_NAME])
    width = len(preprocessing.columns)
    if forest.n_features_in_ != width or isolation.n_features_in_ != width:
        raise ModelArtifactError("Model width does not match the preprocessing columns")
    return ModelBundle(preprocessing, forest, booster, isolation, thresholds, metadata)
