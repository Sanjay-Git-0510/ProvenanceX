import os
import shutil

import pytest

from app.core.config import Settings
from app.scanners.model.aibom import AIBOM_FORMAT, ModelContext, analyze_model
from app.scanners.model.inventory import RemoteOnlyFile
from tests.conftest import FIXTURES
from tests.model_helpers import reduce_pickle, safetensors_bytes, torch_zip_bytes, write

MODEL = FIXTURES / "model"


@pytest.fixture
def settings():
    return Settings(_env_file=None)


def ctx(**kw):
    base = {"name": "x", "artifact_type": "lora", "source": "upload", "source_url": None}
    return ModelContext(**{**base, **kw})


def test_lora_adapter_aibom(tmp_path, settings):
    shutil.copytree(MODEL / "lora_adapter", tmp_path / "src")
    write(tmp_path / "src/adapter_model.safetensors", safetensors_bytes())
    a = analyze_model(tmp_path / "src", ctx(), settings)
    doc = a.aibom
    assert doc["format"] == AIBOM_FORMAT
    assert {"peft", "safetensors"} <= set(a.frameworks)
    assert a.serialization_counts == {"safetensors": 1}
    [base] = a.base_models
    assert base.ref_id == "example-org/base-model-7b" and base.relation == "fine_tuned_from"
    assert base.origin == "adapter_config" and base.revision.startswith("0123")
    assert [d.ref_id for d in a.datasets] == ["example-org/synthetic-instructions"]
    assert a.adapters[0]["r"] == 8
    assert {(r.name, r.version) for r in a.runtime_deps} == {
        ("requests", "2.32.3"),
        ("torch", None),
        ("peft", None),
    }
    weights = [f for f in a.inventory if f.category == "weights"]
    assert weights[0].analysis["safetensors"]["valid"] is True
    assert doc["summary"]["custom_code_present"] is False
    assert doc["summary"]["model_card_completeness"] == 1.0


def test_pickle_weights_scanned(tmp_path, settings):
    write(tmp_path / "pytorch_model.bin", torch_zip_bytes(reduce_pickle(os.system, ("id",))))
    write(tmp_path / "config.json", '{"model_type": "gpt2", "transformers_version": "4.0"}')
    a = analyze_model(tmp_path, ctx(artifact_type="model"), settings)
    f = next(f for f in a.inventory if f.path == "pytorch_model.bin")
    assert f.serialization == "pytorch_zip" and f.category == "weights"
    assert any(g.endswith(".system") for g in f.analysis["pickle"]["dangerous_globals"])
    assert a.aibom["summary"]["code_executing_formats"] == ["pytorch_zip"]
    assert "transformers" in a.frameworks


def test_format_mismatch(tmp_path, settings):
    write(tmp_path / "model.safetensors", reduce_pickle(os.system, ("id",)))
    a = analyze_model(tmp_path, ctx(), settings)
    [f] = a.inventory
    assert f.serialization == "pickle" and "extension suggests safetensors" in f.format_mismatch
    assert f.analysis["pickle"]["dangerous_globals"]


def test_remote_code_detected(tmp_path, settings):
    shutil.copytree(MODEL / "remote_code_model", tmp_path / "src")
    a = analyze_model(tmp_path / "src", ctx(artifact_type="model", repo_id="me/custom"), settings)
    assert a.custom_code.remote_code_required
    assert sorted(a.custom_code.scripts) == ["configuration_custom.py", "modeling_custom.py"]
    [base] = a.base_models
    assert base.origin == "config" and base.confidence == "weak" and base.relation == "derived_from"


def test_remote_only_files_inventoried(tmp_path, settings):
    write(tmp_path / "config.json", "{}")
    remote = [RemoteOnlyFile("model-00001.safetensors", 10**10, "a" * 64, "exceeds cap")]
    a = analyze_model(tmp_path, ctx(remote_only=remote), settings)
    f = next(f for f in a.inventory if not f.downloaded)
    assert f.sha256 is None and f.remote_sha256 == "a" * 64
    assert f.serialization == "safetensors" and f.serialization_verified is False
    assert any("not downloaded" in lim for lim in a.limitations)


def test_local_path_parent_and_card_relation(tmp_path, settings):
    write(tmp_path / "config.json", '{"_name_or_path": "/home/user/checkpoints/run3"}')
    write(
        tmp_path / "README.md",
        "---\nbase_model: [org/a, ./local]\nbase_model_relation: quantized\n---\n",
    )
    a = analyze_model(tmp_path, ctx(artifact_type="model"), settings)
    assert [(b.ref_id, b.relation) for b in a.base_models] == [("org/a", "derived_from")]
    assert a.local_path_references == ["./local", "/home/user/checkpoints/run3"]


def test_api_card_used_when_readme_missing(tmp_path, settings):
    write(tmp_path / "config.json", "{}")
    a = analyze_model(
        tmp_path, ctx(api_card_data={"license": "mit", "base_model": "o/b"}), settings
    )
    assert a.card.source == "hf_api" and [b.ref_id for b in a.base_models] == ["o/b"]
