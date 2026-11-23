"""Phase 4: ml/scripts/train_realworld.py end to end on constructed rows in a temp directory.

The script's data, model and report directories are pointed at tmp_path, and its Config is made
small so the run is fast. No database, network or real dataset is used. The rows are test inputs.
"""

import importlib.util
import json
import re
import sys
from functools import partial

import numpy as np
import pytest

from app.ml.realworld.dataset import FEATURE_ROWS_FORMAT
from app.ml.realworld.manifest import DATASET_VERSION, GroundTruth, RealLabel, write_manifest
from app.ml.realworld.train_eval import Config
from tests.conftest import FIXTURES
from tests.realworld_helpers import record
from tests.unit.test_realworld_training import features, reasons

REPO_ROOT = FIXTURES.parents[2]
SCRIPT = REPO_ROOT / "ml" / "scripts" / "train_realworld.py"
SMALL = partial(
    Config,
    rf_estimators=10,
    xgb_estimators=10,
    iforest_estimators=10,
    repeated_seeds=2,
    bootstrap_resamples=20,
)


def load_script():
    spec = importlib.util.spec_from_file_location("train_realworld_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_data(data_dir, n_benign, n_vuln, n_failed=0):
    rng = np.random.default_rng(3)
    recs, rows = [], []
    for i in range(n_benign + n_vuln + n_failed):
        vuln = n_benign <= i < n_benign + n_vuln
        rec = record(
            artifact_identifier=f"github.com/o/r{i}",
            family_id=f"github:o/r{i}",
            label=RealLabel.KNOWN_VULNERABLE if vuln else RealLabel.BENIGN,
            ground_truth_status=GroundTruth.ESTABLISHED if vuln else GroundTruth.CRITERIA_BASED,
        )
        recs.append(rec)
        f = features(int(rng.integers(1, 4)) if vuln else 0, int(rng.integers(5, 50)))
        completed = i < n_benign + n_vuln
        rows.append(
            {
                "format": FEATURE_ROWS_FORMAT,
                "dataset_version": DATASET_VERSION,
                "record_id": rec.record_id,
                "family_id": rec.family_id,
                "artifact_type": "software",
                "label": str(rec.label),
                "usable_for_training": completed,
                "scan_status": "completed" if completed else "failed",
                "features": f if completed else {},
                "null_reasons": reasons(f) if completed else {},
                "sha256": f"{i:064x}",
                "scan_id": f"s{i}",
            }
        )
    write_manifest(recs, data_dir, {})
    (data_dir / f"features-{DATASET_VERSION}.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows)
    )


@pytest.fixture
def run(tmp_path, monkeypatch):
    def go(n_benign, n_vuln, n_failed=0):
        data, models, reports = tmp_path / "data", tmp_path / "models", tmp_path / "reports"
        write_data(data, n_benign, n_vuln, n_failed)
        script = load_script()
        monkeypatch.setattr(script, "DATA", data)
        monkeypatch.setattr(script, "MODELS", models)
        monkeypatch.setattr(script, "REPORTS", reports)
        monkeypatch.setattr(script, "Config", SMALL)
        monkeypatch.setattr(sys, "argv", ["train_realworld.py"])
        assert script.main() == 0
        results = json.loads((reports / "realworld_evaluation_report.json").read_text())
        md = (reports / "realworld_evaluation_report.md").read_text()
        card = (reports / "realworld_model_card.md").read_text()
        return results, md, card, models

    return go


def table_row(md, model):
    """The test-split metric row for one model, as printed in the Markdown report."""
    section = md.split("### Test split", 1)[1]
    line = next(x for x in section.splitlines() if x.startswith(f"| {model} |"))
    return [c.strip() for c in line.strip("|").split("|")][1:]


def fmt(value):
    return "n/a" if value is None else f"{value:.3f}"


def test_sufficient_data_trains_saves_and_report_matches_json(run):
    results, md, card, models = run(20, 22, n_failed=3)
    assert results["feature_rows_read"] == 45 and results["usable_rows"] == 42
    assert results["scan_outcomes"] == {"completed": 42, "failed": 3}
    assert list(results["models"]) == ["software"]
    test = results["models"]["software"]["test"]
    for name in ("random_forest", "xgboost", "rules_only", "vulnerability_only"):
        cells = table_row(md, name)
        want = [fmt(test[name][k]) for k in ("precision", "recall", "f1", "roc_auc", "pr_auc")]
        assert cells[:5] == want, name
        cm = test[name]["confusion_matrix"]
        assert cells[7:11] == [str(cm[k]) for k in ("tp", "fp", "tn", "fn")]
    meta = json.loads((models / "software" / "training_metadata.json").read_text())
    manifest = json.loads((models / "software" / "manifest.json").read_text())
    assert meta["synthetic"] is False and manifest["synthetic"] is False
    assert "SYNTHETIC" not in md.split("Synthetic data is not used here", 1)[0].upper()
    assert any(g.startswith("model: no model") for g in results["evidence_gaps"])
    assert "software" in card


def test_insufficient_data_writes_no_model_and_says_so(run):
    results, md, card, models = run(10, 10)
    assert results["models"] == {}
    assert not models.exists()  # nothing is written when no type has enough rows
    gap = next(g for g in results["evidence_gaps"] if g.startswith("software:"))
    assert "fewer than 15 usable rows" in gap and "REVIEW fallback kept" in gap
    assert re.search(r"\| software \| 20 \|.*\| no \| fewer than 15", md)
    assert "no model was trained" in card
