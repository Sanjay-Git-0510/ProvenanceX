"""Family assignment, deduplication and leakage checks for the real-world manifest."""

from app.ml.realworld.dedup import (
    deduplicate,
    family_identity_conflicts,
    hf_family,
    package_family,
    software_family,
    split_leaks,
)
from app.ml.realworld.manifest import GroundTruth, RealLabel
from tests.realworld_helpers import record


def test_family_ids():
    assert software_family("Pallets", "Flask") == "github:pallets/flask"
    assert package_family("npm", "Evil") == "pkg:npm/evil"
    assert hf_family("dataset", "a/B") == "hf-dataset:a/b"
    assert hf_family("model", "x/lora", ["Base/M"]) == "hf:base/m"
    assert hf_family("model", "base/m") == "hf:base/m"  # base model and its adapter share a family


def test_exact_duplicates_are_removed():
    kept, report = deduplicate([record(), record()])
    assert len(kept) == 1
    assert report.duplicates_removed == 1 and report.label_conflicts == []


def test_conflict_keeps_most_severe_label():
    benign = record()
    vulnerable = record(
        label=RealLabel.KNOWN_VULNERABLE,
        ground_truth_status=GroundTruth.ESTABLISHED,
        data_source="ghsa",
    )
    for order in ([benign, vulnerable], [vulnerable, benign]):
        kept, report = deduplicate(order)
        assert [r.label for r in kept] == [RealLabel.KNOWN_VULNERABLE]
        assert report.label_conflicts[0]["kept"].startswith("known_vulnerable")


def test_conflict_never_turns_unknown_into_benign():
    unknown = record(
        label=RealLabel.UNKNOWN, ground_truth_status=GroundTruth.NONE, scan_eligible=False
    )
    kept, _ = deduplicate([unknown, record()])
    assert kept[0].label == RealLabel.BENIGN  # benign is more severe than unknown...
    kept, _ = deduplicate([record(), unknown])
    assert kept[0].label == RealLabel.BENIGN  # ...and order does not matter


def test_different_revisions_stay_separate_but_share_family():
    a = record()
    b = record(revision="b" * 40, record_id="rw-other")
    kept, _ = deduplicate([a, b])
    assert len(kept) == 2 and {r.family_id for r in kept} == {"github:pallets/flask"}


def test_identity_conflicts_detected():
    a = record()
    b = record(revision="b" * 40, record_id="rw-other", family_id="github:someone/else")
    assert family_identity_conflicts([a]) == {}
    assert "github.com/pallets/flask" in family_identity_conflicts([a, b])


def test_split_leaks():
    a = record()
    b = record(revision="b" * 40, record_id="rw-other")
    assert split_leaks([a, b], {a.record_id: "train", b.record_id: "train"}) == {}
    leaks = split_leaks([a, b], {a.record_id: "train", b.record_id: "test"})
    assert leaks == {"github:pallets/flask": {"train", "test"}}
