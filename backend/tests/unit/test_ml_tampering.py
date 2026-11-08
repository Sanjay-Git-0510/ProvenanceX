"""Tampering recipes: each changes what it claims, and labels come only from recipes."""

import json

import numpy as np
import pytest

from app.ml.dataset.tampering import (
    RECIPES,
    TAMPERING_CASES,
    VARIANTS,
    resolve_label,
    variant_applies,
)
from app.ml.dataset.templates import Family, baseline_state, older_release_state
from app.ml.feature_schema import Label


def family(**overrides):
    values = {
        "index": 3,
        "family_id": "family-0003",
        "name": "synth-x-0003",
        "artifact_type": "software",
        "ecosystem": "pypi",
        "source": "github",
        "has_attestation": True,
        "uses_tag": True,
        "has_tooling": False,
        "custom_code": False,
        "pickle_weights": False,
        "full_card": True,
        "component_count": 6,
        "major": 2,
        "minor": 3,
    }
    return Family(**{**values, **overrides})


def model_family(**overrides):
    return family(artifact_type="model", source="huggingface", **overrides)


def applied(name, fam=None):
    fam = fam or family()
    state = baseline_state(fam, 1)
    RECIPES[name].apply(state, fam, np.random.default_rng(0))
    return baseline_state(fam, 1), state


def test_required_tampering_cases_exist():
    assert set(TAMPERING_CASES) == {
        "changed_hash",
        "removed_provenance",
        "altered_config",
        "replaced_dependency",
        "version_mismatch",
    }
    assert set(TAMPERING_CASES) <= set(RECIPES)


def test_changed_hash_keeps_commit():
    before, after = applied("changed_hash")
    assert before.files["README.md"] != after.files["README.md"]
    assert before.commit == after.commit


def test_removed_provenance_deletes_attestation():
    before, after = applied("removed_provenance")
    assert "release.intoto.jsonl" in before.files
    assert "release.intoto.jsonl" not in after.files
    assert "release.sig" not in after.files


def test_altered_config_changes_config():
    before, after = applied("altered_config", model_family())
    assert json.loads(before.files["config.json"]) != json.loads(after.files["config.json"])


def test_replaced_dependency_swaps_name_and_edges():
    before, after = applied("replaced_dependency")
    names = {n for n, _ in after.components}
    assert names != {n for n, _ in before.components}
    assert any("synth1ib" in n for n in names)
    assert all(a == "root" or a in names for a, _ in after.edges)
    assert all(b in names for _, b in after.edges)


def test_version_mismatch_changes_requested_tag():
    before, after = applied("version_mismatch")
    assert before.revision == "v2.3.0"
    assert after.revision == "v9.3.0"


def test_inject_advisories_uses_synthetic_ids_only():
    _, after = applied("inject_advisories")
    assert after.advisories
    assert all(a["id"].startswith("SYNTH-") for a in after.advisories)
    known = {n for n, _ in after.components}
    assert all(a["component"] in known for a in after.advisories)


def test_recipes_do_not_mutate_the_baseline_clone():
    fam = family()
    base = baseline_state(fam, 1)
    copy = base.clone()
    RECIPES["suspicious_code"].apply(copy, fam, np.random.default_rng(0))
    assert "helper_ext.py" not in base.files


@pytest.mark.parametrize(
    ("recipes", "label"),
    [
        ((), Label.BENIGN),
        (("docs_update",), Label.BENIGN),
        (("inject_advisories",), Label.VULNERABLE),
        (("changed_hash",), Label.PROVENANCE_WEAK),
        (("inject_advisories", "changed_hash"), Label.PROVENANCE_WEAK),
        (("inject_advisories", "suspicious_code"), Label.SUSPICIOUS),
    ],
)
def test_label_precedence(recipes, label):
    assert resolve_label(recipes) == label


def test_vulnerable_is_not_malicious_and_no_recipe_claims_known_bad():
    assert RECIPES["inject_advisories"].label == Label.VULNERABLE
    assert all(r.label != Label.MALICIOUS_KNOWN_BAD for r in RECIPES.values())


def test_every_variant_uses_known_recipes():
    for variant in VARIANTS:
        assert set(variant.recipes) <= set(RECIPES)


@pytest.mark.parametrize(
    ("variant", "fam", "expected"),
    [
        ("altered_config", family(), False),
        ("altered_config", model_family(), True),
        ("replaced_dependency", model_family(), False),
        ("removed_provenance", family(has_attestation=False), False),
        ("version_mismatch", family(uses_tag=False), False),
        ("changed_hash", family(source="upload"), False),
        ("clean_new_release", family(source="upload"), False),
        ("clean_rescan", family(source="upload"), True),
    ],
)
def test_variant_applicability(variant, fam, expected):
    chosen = next(v for v in VARIANTS if v.name == variant)
    assert variant_applies(chosen, fam) is expected


def test_older_release_is_a_legitimate_earlier_version():
    fam = family()
    new, old = baseline_state(fam, 1), older_release_state(fam, 1)
    assert old.commit != new.commit
    assert old.revision == "v2.2.0"
    assert b'version = "2.2.0"' in old.files["pyproject.toml"]
    assert len(old.components) == len(new.components) - 1
