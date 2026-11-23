"""Phase 4: synthetic and real-world ML data never mix.

Static checks: real-world code names no synthetic dataset file or loader, and synthetic code and
reports name no real-world file. Runtime check: the synthetic model loader refuses a real-world
model directory, so real-world artifacts cannot be served as the runtime (synthetic) models.
"""

import ast

import pytest

from app.ml.artifacts import ModelArtifactError, load_bundle
from app.ml.realworld.dataset import assign_splits, with_splits
from app.ml.realworld.train_eval import Config, save_models, train
from tests.conftest import FIXTURES
from tests.unit.test_realworld_training import make_rows

REPO = FIXTURES.parents[2]
BACKEND = REPO / "backend"

REALWORLD_CODE = [
    *sorted((BACKEND / "app" / "ml" / "realworld").glob("*.py")),
    *sorted((BACKEND / "app" / "dataset_collection").rglob("*.py")),
    *sorted((REPO / "ml" / "scripts").glob("*_realworld.py")),
]
SYNTHETIC_CODE = [
    REPO / "ml" / "scripts" / name
    for name in (
        "generate_dataset.py",
        "train_models.py",
        "evaluate_models.py",
        "fusion_sensitivity.py",
    )
] + [
    BACKEND / "app" / "ml" / name
    for name in ("training.py", "evaluation.py", "ablation.py", "reporting.py", "artifacts.py")
]
SYNTHETIC_REPORTS = [
    REPO / "ml" / "reports" / name
    for name in (
        "evaluation_report.json",
        "evaluation_report.md",
        "fusion_sensitivity.json",
        "fusion_sensitivity.md",
    )
]
# Synthetic dataset files and the functions/modules that read or build them.
SYNTHETIC_NAMES = ("dataset.jsonl", "dataset_metadata.json")
SYNTHETIC_SYMBOLS = {"load_training_records", "read_verified_dataset", "load_bundle"}
# The synthetic generator modules. app.ml.dataset.splits is a shared, data-free split helper.
SYNTHETIC_MODULES = (
    "app.ml.dataset.generator",
    "app.ml.dataset.templates",
    "app.ml.dataset.tampering",
)


def _strings(tree: ast.AST) -> list[str]:
    return [
        n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]


def _imports(tree: ast.AST) -> list[tuple[str, str]]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            out += [(node.module or "", alias.name) for alias in node.names]
        elif isinstance(node, ast.Import):
            out += [(alias.name, "") for alias in node.names]
    return out


def test_file_lists_are_not_empty():
    assert len(REALWORLD_CODE) >= 8
    assert all(p.exists() for p in SYNTHETIC_CODE + SYNTHETIC_REPORTS)


@pytest.mark.parametrize("path", REALWORLD_CODE, ids=lambda p: p.name)
def test_realworld_code_never_reads_synthetic_data(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for text in _strings(tree):
        for name in SYNTHETIC_NAMES:
            # docstrings may say "never reads the synthetic dataset"; paths may not name the file
            assert name not in text, f"{path.name} names synthetic file {name}"
    for module, name in _imports(tree):
        assert not module.startswith(SYNTHETIC_MODULES), f"{path.name} imports {module}"
        assert name not in SYNTHETIC_SYMBOLS, f"{path.name} imports {name}"


@pytest.mark.parametrize("path", SYNTHETIC_CODE, ids=lambda p: p.name)
def test_synthetic_code_never_reads_realworld_data(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for module, _ in _imports(tree):
        assert "realworld" not in module and "dataset_collection" not in module, path.name
    # String constants other than the module docstring must not point at real-world paths.
    body = tree.body[1:] if ast.get_docstring(tree) else tree.body
    for node in body:
        for text in _strings(node):
            assert "realworld" not in text.lower(), f"{path.name}: {text[:60]!r}"


@pytest.mark.parametrize("path", SYNTHETIC_REPORTS, ids=lambda p: p.name)
def test_synthetic_reports_do_not_reference_realworld_data(path):
    # Disclaimers such as "not real-world accuracy" are fine; real-world files and data are not.
    text = path.read_text(encoding="utf-8").lower()
    assert "realworld" not in text
    assert "known_vulnerable" not in text  # the real-world label set


def test_synthetic_loader_refuses_realworld_models(tmp_path):
    rows = make_rows(20, 40)
    parts = with_splits(rows, assign_splits(rows, 42))
    cfg = Config(rf_estimators=5, xgb_estimators=5, iforest_estimators=5)
    save_models(train(parts["train"], parts["validation"], cfg), tmp_path, {"synthetic": False}, {})
    with pytest.raises(ModelArtifactError, match="unknown format"):
        load_bundle(tmp_path)
