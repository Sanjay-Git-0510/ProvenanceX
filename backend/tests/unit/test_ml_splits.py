"""Family splits: variants of one family never cross train, validation and test."""

import pytest

from app.ml.dataset.splits import assign_family_splits, find_family_leaks


def families(count=40):
    return {f"f{i}": ("software" if i % 2 else "model") for i in range(count)}


def test_every_family_gets_one_split_with_expected_sizes():
    result = assign_family_splits(families(), 1)
    assert set(result) == set(families())
    sizes = [list(result.values()).count(s) for s in ("train", "validation", "test")]
    assert sizes == [28, 6, 6]


def test_split_is_stratified_by_artifact_type():
    result = assign_family_splits(families(), 1)
    for kind in ("software", "model"):
        kinds = [split for f, split in result.items() if families()[f] == kind]
        assert {"train", "validation", "test"} == set(kinds)


def test_same_seed_is_stable_and_seeds_differ():
    assert assign_family_splits(families(), 5) == assign_family_splits(families(), 5)
    assert assign_family_splits(families(), 5) != assign_family_splits(families(), 6)


def test_too_few_families_is_an_error():
    with pytest.raises(ValueError, match="at least"):
        assign_family_splits({"a": "model", "b": "model"}, 1)


def test_leak_detection():
    assert find_family_leaks([("a", "train"), ("a", "train"), ("b", "test")]) == {}
    assert find_family_leaks([("a", "train"), ("a", "test")]) == {"a": {"train", "test"}}
