import json

from app.scanners.model.config_parse import is_config_path, parse_config_file
from app.scanners.model.custom_code import parse_requirements
from tests.conftest import FIXTURES
from tests.model_helpers import write

MODEL = FIXTURES / "model"


def test_adapter_config_fields():
    cfg = parse_config_file(MODEL / "lora_adapter" / "adapter_config.json", "adapter_config.json")
    assert cfg.valid and cfg.kind == "adapter"
    assert cfg.fields["peft_type"] == "LORA"
    assert cfg.fields["base_model_name_or_path"] == "example-org/base-model-7b"
    assert cfg.fields["r"] == 8 and cfg.fields["target_modules"] == ["q_proj", "v_proj"]


def test_auto_map_extracted():
    cfg = parse_config_file(MODEL / "remote_code_model" / "config.json", "config.json")
    assert cfg.kind == "model"
    assert cfg.auto_map == {
        "AutoConfig": "configuration_custom.CustomConfig",
        "AutoModel": "modeling_custom.CustomModel",
    }
    assert cfg.fields["_name_or_path"] == "example-org/custom-base"


def test_auto_map_list_values(tmp_path):
    path = write(
        tmp_path / "tokenizer_config.json",
        json.dumps({"auto_map": {"AutoTokenizer": [None, "tok.Fast"]}}),
    )
    assert parse_config_file(path, "tokenizer_config.json").auto_map == {
        "AutoTokenizer": "tok.Fast"
    }


def test_invalid_and_oversized(tmp_path):
    bad = parse_config_file(write(tmp_path / "config.json", "{nope"), "config.json")
    assert not bad.valid and "invalid JSON" in bad.error
    arr = parse_config_file(write(tmp_path / "c2.json", "[1]"), "config.json")
    assert not arr.valid
    big = parse_config_file(write(tmp_path / "c3.json", " " * (1024 * 1024 + 1)), "config.json")
    assert not big.valid and "exceeds" in big.error


def test_deeply_nested_json_does_not_crash(tmp_path):
    cfg = parse_config_file(write(tmp_path / "config.json", "[" * 100000), "config.json")
    assert not cfg.valid


def test_is_config_path():
    assert is_config_path("config.json") and is_config_path("unet/config.json")
    assert not is_config_path("a/b/c/d/config.json") and not is_config_path("other.json")


def test_requirements_parsing():
    reqs = parse_requirements(
        b"requests==2.32.3\nTorch_Vision[cuda] == 0.18.0 ; python_version>'3'\n"
        b"peft>=0.10\n# c\n-r other.txt\ngit+https://x/y\nnumpy==1.26.4 # pin\n",
        "requirements.txt",
    )
    by = {r.name: r.version for r in reqs}
    assert by == {"requests": "2.32.3", "torch-vision": "0.18.0", "peft": None, "numpy": "1.26.4"}
