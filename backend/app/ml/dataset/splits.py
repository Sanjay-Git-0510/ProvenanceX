"""Train/validation/test assignment by artifact family, so variants never cross splits."""

from collections.abc import Iterable, Mapping

import numpy as np

SPLIT_FRACTIONS = {"train": 0.70, "validation": 0.15, "test": 0.15}
MIN_FAMILIES_PER_TYPE = 3


def assign_family_splits(families: Mapping[str, str], seed: int) -> dict[str, str]:
    """Map family_id to a split. `families` is family_id -> artifact_type (stratified on it)."""
    assignment: dict[str, str] = {}
    rng = np.random.default_rng(seed)
    for artifact_type in sorted(set(families.values())):
        members = sorted(f for f, kind in families.items() if kind == artifact_type)
        if len(members) < MIN_FAMILIES_PER_TYPE:
            raise ValueError(
                f"{artifact_type}: need at least {MIN_FAMILIES_PER_TYPE} families to split"
            )
        order = [members[int(i)] for i in rng.permutation(len(members))]
        n_validation = max(1, round(len(order) * SPLIT_FRACTIONS["validation"]))
        n_test = max(1, round(len(order) * SPLIT_FRACTIONS["test"]))
        for i, family in enumerate(order):
            if i < n_validation:
                assignment[family] = "validation"
            elif i < n_validation + n_test:
                assignment[family] = "test"
            else:
                assignment[family] = "train"
    return assignment


def find_family_leaks(pairs: Iterable[tuple[str, str]]) -> dict[str, set[str]]:
    """Families seen in more than one split. Takes (family_id, split) pairs."""
    seen: dict[str, set[str]] = {}
    for family, split in pairs:
        seen.setdefault(family, set()).add(split)
    return {family: splits for family, splits in seen.items() if len(splits) > 1}
