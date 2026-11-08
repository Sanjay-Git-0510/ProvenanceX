from app.scanners.model.model_card import card_from_api, parse_model_card
from tests.conftest import FIXTURES

MAX = 256 * 1024


def test_full_card_completeness():
    card = parse_model_card((FIXTURES / "model/lora_adapter/README.md").read_bytes(), max_bytes=MAX)
    assert card.present and card.source == "readme" and card.issues == []
    assert card.metadata["license"] == "mit"
    assert card.metadata["base_model"] == ["example-org/base-model-7b"]
    assert card.metadata["language"] == ["en"]
    assert set(card.sections_present) == {"intended_use", "limitations", "training", "evaluation"}
    assert card.completeness == 1.0


def test_card_without_front_matter():
    card = parse_model_card((FIXTURES / "model/card_minimal/README.md").read_bytes(), max_bytes=MAX)
    assert card.present and card.metadata == {} and card.completeness == 0.0


def test_missing_card():
    card = parse_model_card(None, max_bytes=MAX)
    assert not card.present and card.completeness == 0.0


def test_yaml_alias_bomb_rejected():
    bomb = b"---\na: &a [x, x]\nb: &b [*a, *a]\nc: [*b, *b]\nlicense: mit\n---\nbody\n"
    card = parse_model_card(bomb, max_bytes=MAX)
    assert card.metadata == {} and "anchors" in card.issues[0]


def test_python_tags_not_constructed():
    evil = b"---\nlicense: !!python/object/apply:os.system ['echo pwned']\n---\n"
    card = parse_model_card(evil, max_bytes=MAX)
    assert card.metadata == {} and card.issues == ["front matter is not valid YAML"]


def test_non_mapping_and_oversize_front_matter():
    assert parse_model_card(b"---\n- a\n- b\n---\n", max_bytes=MAX).issues == [
        "front matter is not a mapping"
    ]
    big = b"---\nx: " + b"a" * (70 * 1024) + b"\n---\n"
    assert "exceeds" in parse_model_card(big, max_bytes=MAX).issues[0]


def test_readme_truncated_at_limit():
    card = parse_model_card(b"# t\n" + b"x" * 100, max_bytes=10)
    assert "only the first part" in card.issues[0]


def test_non_string_values_dropped():
    card = parse_model_card(b"---\nlicense: 3\nbase_model: [1, ok/model]\n---\n", max_bytes=MAX)
    assert "license" not in card.metadata and card.metadata["base_model"] == ["ok/model"]


def test_api_fallback():
    card = card_from_api({"license": "apache-2.0", "datasets": ["a/b"]})
    assert card.source == "hf_api" and card.fields_present == ["license", "datasets"]
    assert not card_from_api(None).present
