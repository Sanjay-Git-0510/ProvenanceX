"""Real-world training rows: join scan feature rows to the manifest, validate, split by family.

Only rows that are usable for training (completed scan, stored feature vector, no mock
evidence) with a trainable label are kept. Trainable labels: benign (0) and known_vulnerable (1).
`unknown`, `suspicious` and `confirmed_malicious` are never training rows. Synthetic data cannot
enter: the feature-row format and dataset version are checked, and the synthetic dataset has a
different format.
"""

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from app.ml.feature_schema import FEATURE_NAMES, FEATURES_BY_NAME, Kind
from app.ml.realworld.manifest import DATASET_VERSION, RealLabel, read_manifest

FEATURE_ROWS_FORMAT = "provenancex-realworld-features-v1"
TRAINABLE = {RealLabel.BENIGN: 0, RealLabel.KNOWN_VULNERABLE: 1}
SPLIT_FRACTIONS = {"train": 0.6, "validation": 0.2, "test": 0.2}
MIN_ROWS_PER_CLASS = 15  # per artifact type, before splitting
MIN_PER_CLASS_PER_SPLIT = 3


class InsufficientData(ValueError):
    """Not enough real labelled rows to train or evaluate honestly."""


@dataclass
class RealRow:
    record_id: str
    family_id: str
    artifact_type: str
    label: RealLabel
    features: dict[str, Any]
    null_reasons: dict[str, str]
    sha256: str | None
    scan_id: str
    split: str = "unassigned"

    @property
    def target(self) -> int:
        return TRAINABLE[self.label]


@dataclass
class LoadResult:
    rows: list[RealRow]
    excluded: Counter = field(default_factory=Counter)
    label_counts_all: Counter = field(default_factory=Counter)


def _value_ok(name: str, value: Any) -> bool:
    if value is None:
        return True
    feature = FEATURES_BY_NAME[name]
    if not feature.has_data_source:
        return False
    if feature.kind == Kind.BOOL:
        return isinstance(value, bool)
    if feature.kind == Kind.COUNT:
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0
    if feature.kind == Kind.FLOAT:
        return isinstance(value, int | float) and not isinstance(value, bool)
    return isinstance(value, str)


def _features_ok(features: Any) -> bool:
    return (
        isinstance(features, dict)
        and set(features) == set(FEATURE_NAMES)
        and all(_value_ok(name, value) for name, value in features.items())
    )


def load_rows(manifest_path: Path, features_path: Path) -> LoadResult:
    """Join and validate. Every dropped row is counted by reason; nothing is filled in."""
    manifest = {r.record_id: r for r in read_manifest(manifest_path)}
    result = LoadResult(rows=[])
    seen_sha: dict[str, str] = {}
    for line in features_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        record = manifest.get(row.get("record_id"))
        if (
            row.get("format") != FEATURE_ROWS_FORMAT
            or row.get("dataset_version") != DATASET_VERSION
        ):
            result.excluded["wrong_format_or_version"] += 1
            continue
        if record is None:
            result.excluded["not_in_manifest"] += 1
            continue
        result.label_counts_all[str(record.label)] += 1
        if row.get("label") != str(record.label) or row.get("family_id") != record.family_id:
            result.excluded["label_or_family_mismatch"] += 1
        elif not row.get("usable_for_training"):
            result.excluded[f"not_usable:{row.get('scan_status')}"] += 1
        elif record.label not in TRAINABLE:
            result.excluded[f"label_not_trainable:{record.label}"] += 1
        elif not _features_ok(row.get("features")):
            result.excluded["invalid_feature_vector"] += 1
        elif row.get("sha256") and row["sha256"] in seen_sha:
            result.excluded["duplicate_content_sha256"] += 1
        else:
            if row.get("sha256"):
                seen_sha[row["sha256"]] = record.record_id
            result.rows.append(
                RealRow(
                    record_id=record.record_id,
                    family_id=record.family_id,
                    artifact_type=record.artifact_type,
                    label=record.label,
                    features=row["features"],
                    null_reasons=row.get("null_reasons") or {},
                    sha256=row.get("sha256"),
                    scan_id=str(row.get("scan_id")),
                )
            )
    result.rows.sort(key=lambda r: r.record_id)
    return result


def sufficiency(rows: list[RealRow]) -> dict[str, dict[str, Any]]:
    """Per artifact type: class counts, family counts and whether a model may be trained."""
    out: dict[str, dict[str, Any]] = {}
    for artifact_type in ("software", "model", "lora", "dataset"):
        mine = [r for r in rows if r.artifact_type == artifact_type]
        counts = {str(label): sum(r.label == label for r in mine) for label in TRAINABLE}
        families = {
            str(label): len({r.family_id for r in mine if r.label == label}) for label in TRAINABLE
        }
        short = [label for label, n in counts.items() if n < MIN_ROWS_PER_CLASS]
        out[artifact_type] = {
            "rows": len(mine),
            "class_counts": counts,
            "family_counts": families,
            "sufficient": not short,
            "reason": None
            if not short
            else f"fewer than {MIN_ROWS_PER_CLASS} usable rows for: {', '.join(short)}",
        }
    return out


def assign_splits(rows: list[RealRow], seed: int) -> dict[str, str]:
    """record_id -> split. Whole families move together, stratified by family label.

    A family is positive when any of its rows is known_vulnerable. Raises InsufficientData when
    any split would lack MIN_PER_CLASS_PER_SPLIT rows of either class.
    """
    families: dict[str, list[RealRow]] = {}
    for row in rows:
        families.setdefault(row.family_id, []).append(row)
    rng = np.random.default_rng(seed)
    family_split: dict[str, str] = {}
    for positive in (False, True):
        members = sorted(f for f, rs in families.items() if any(r.target for r in rs) == positive)
        order = [members[int(i)] for i in rng.permutation(len(members))]
        n_val = max(1, round(len(order) * SPLIT_FRACTIONS["validation"]))
        n_test = max(1, round(len(order) * SPLIT_FRACTIONS["test"]))
        for i, family in enumerate(order):
            family_split[family] = (
                "validation" if i < n_val else "test" if i < n_val + n_test else "train"
            )
    split_of = {r.record_id: family_split[r.family_id] for r in rows}
    for split in SPLIT_FRACTIONS:
        for target in (0, 1):
            n = sum(1 for r in rows if split_of[r.record_id] == split and r.target == target)
            if n < MIN_PER_CLASS_PER_SPLIT:
                raise InsufficientData(f"{split} has {n} rows of class {target}")
    return split_of


def with_splits(rows: list[RealRow], split_of: dict[str, str]) -> dict[str, list[RealRow]]:
    out: dict[str, list[RealRow]] = {s: [] for s in SPLIT_FRACTIONS}
    for row in rows:
        row.split = split_of[row.record_id]
        out[row.split].append(row)
    return out
