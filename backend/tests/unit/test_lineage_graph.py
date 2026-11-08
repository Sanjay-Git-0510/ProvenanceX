import shutil

import pytest

from app.core.config import Settings
from app.graph.dependency_graph import ROOT_KEY
from app.graph.lineage_graph import build_lineage_graph
from app.scanners.model.aibom import ModelContext, analyze_model
from tests.conftest import FIXTURES
from tests.model_helpers import safetensors_bytes, write


@pytest.fixture
def settings():
    return Settings(_env_file=None)


def analyze(src, settings, **kw):
    ctx = ModelContext(name="x", artifact_type="lora", source="upload", source_url=None, **kw)
    return analyze_model(src, ctx, settings)


def edges(g):
    return {(u, v, d["relation"]) for u, v, d in g.edges(data=True)}


def test_lora_lineage(tmp_path, settings):
    shutil.copytree(FIXTURES / "model/lora_adapter", tmp_path / "src")
    write(tmp_path / "src/adapter_model.safetensors", safetensors_bytes())
    lg = build_lineage_graph("x", "lora", analyze(tmp_path / "src", settings))
    e = edges(lg.graph)
    assert (ROOT_KEY, "model:example-org/base-model-7b", "fine_tuned_from") in e
    assert (ROOT_KEY, "dataset:example-org/synthetic-instructions", "trained_on") in e
    assert (ROOT_KEY, "file:adapter_model.safetensors", "bundled_with") in e
    assert (ROOT_KEY, "file:adapter_config.json", "bundled_with") in e
    assert (ROOT_KEY, "package:pypi/requests", "requires") in e
    assert lg.graph.nodes["package:pypi/requests"]["pinned"] is True
    f = lg.features
    assert f["graph_kind"] == "lineage" and f["is_adapter"] and f["lineage_depth"] == 1
    assert f["base_model_count"] == 1 and f["dataset_count"] == 1
    assert f["lineage_completeness"] == 1.0 and f["suspicious_lineage"] == []
    assert f["unexpected_parent_or_base_model"] is False
    assert f["vulnerable_count"] is None


def test_adapter_base_mismatch_flagged(tmp_path, settings):
    write(
        tmp_path / "adapter_config.json",
        '{"peft_type": "LORA", "base_model_name_or_path": "org/a"}',
    )
    write(tmp_path / "README.md", "---\nbase_model: org/b\n---\n")
    lg = build_lineage_graph("x", "lora", analyze(tmp_path, settings))
    flags = [f["flag"] for f in lg.features["suspicious_lineage"]]
    assert "adapter_base_mismatch" in flags and lg.features["unexpected_parent_or_base_model"]


def test_config_parent_mismatch_and_self_reference(tmp_path, settings):
    write(tmp_path / "config.json", '{"_name_or_path": "other/parent"}')
    write(tmp_path / "README.md", "---\nbase_model: [org/base, me/model]\n---\n")
    lg = build_lineage_graph(
        "x", "model", analyze(tmp_path, settings, repo_id="me/model"), "me/model"
    )
    flags = {f["flag"] for f in lg.features["suspicious_lineage"]}
    assert {"config_parent_mismatch", "self_reference"} <= flags


def test_nested_adapter_links_its_own_base(tmp_path, settings):
    write(tmp_path / "config.json", '{"model_type": "x"}')
    write(tmp_path / "loras/a/adapter_config.json", '{"base_model_name_or_path": "org/base"}')
    lg = build_lineage_graph("x", "model", analyze(tmp_path, settings))
    e = edges(lg.graph)
    assert (ROOT_KEY, "adapter:loras/a", "bundled_with") in e
    assert ("adapter:loras/a", "model:org/base", "fine_tuned_from") in e
    assert (ROOT_KEY, "model:org/base", "fine_tuned_from") not in e
    assert lg.features["lineage_depth"] == 0  # no lineage edge from the root itself


def test_empty_lineage_is_incomplete(tmp_path, settings):
    write(tmp_path / "weights.safetensors", safetensors_bytes())
    f = build_lineage_graph("x", "model", analyze(tmp_path, settings)).features
    assert f["base_model_count"] == 0 and f["lineage_depth"] == 0
    assert f["lineage_checks"]["weights_hash_known"] is True
    assert f["lineage_completeness"] == round(1 / 6, 4)
