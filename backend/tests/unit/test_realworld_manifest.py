"""Manifest schema policy, round trip and metadata for the real-world dataset."""

import json

import pytest
from pydantic import ValidationError

from app.ml.realworld.manifest import (
    DATASET_VERSION,
    MANIFEST_FORMAT,
    GroundTruth,
    RealLabel,
    canonical_sha256,
    read_manifest,
    record_id_for,
    write_manifest,
)
from tests.realworld_helpers import record

REQUIRED = (
    "data_source",
    "source_url",
    "collection_date",
    "artifact_identifier",
    "artifact_type",
    "label",
    "label_justification",
    "license",
    "sha256",
    "dataset_version",
    "preprocessing",
)


def test_record_has_every_required_field():
    dumped = record().model_dump(mode="json")
    assert all(name in dumped for name in REQUIRED)


@pytest.mark.parametrize(
    ("label", "truth"),
    [
        (RealLabel.BENIGN, GroundTruth.ESTABLISHED),
        (RealLabel.UNKNOWN, GroundTruth.CRITERIA_BASED),
        (RealLabel.CONFIRMED_MALICIOUS, GroundTruth.THIRD_PARTY_FLAG),
        (RealLabel.KNOWN_VULNERABLE, GroundTruth.NONE),
        (RealLabel.SUSPICIOUS, GroundTruth.ESTABLISHED),
    ],
)
def test_label_must_match_ground_truth(label, truth):
    with pytest.raises(ValidationError):
        record(label=label, ground_truth_status=truth, scan_eligible=False)


@pytest.mark.parametrize(
    ("label", "truth"),
    [
        (RealLabel.CONFIRMED_MALICIOUS, GroundTruth.ESTABLISHED),
        (RealLabel.SUSPICIOUS, GroundTruth.THIRD_PARTY_FLAG),
        (RealLabel.UNKNOWN, GroundTruth.NONE),
    ],
)
def test_unscannable_labels_cannot_be_scan_eligible(label, truth):
    with pytest.raises(ValidationError, match="never be scanned"):
        record(label=label, ground_truth_status=truth, scan_eligible=True)
    assert record(label=label, ground_truth_status=truth, scan_eligible=False)


def test_scan_eligible_needs_url_and_revision():
    with pytest.raises(ValidationError, match="pinned revision"):
        record(revision=None)
    with pytest.raises(ValidationError, match="pinned revision"):
        record(scan_url=None)


def test_registry_packages_are_metadata_only():
    with pytest.raises(ValidationError):
        record(artifact_type="package")


def test_sha256_only_from_scan():
    with pytest.raises(ValidationError):
        record(sha256="a" * 64)  # status is pending_scan
    with pytest.raises(ValidationError):
        record(sha256_status="from_scan")  # no sha256
    assert record(sha256="a" * 64, sha256_status="from_scan").sha256 == "a" * 64
    with pytest.raises(ValidationError):
        record(sha256="not-a-hash", sha256_status="from_scan")


def test_unknown_fields_are_rejected():
    with pytest.raises(ValidationError):
        record(extra_field=1)


def test_record_id_is_stable_and_case_insensitive():
    a = record_id_for("software", "github.com/Pallets/Flask", "abc")
    assert a == record_id_for("software", "github.com/pallets/flask", "abc")
    assert a != record_id_for("software", "github.com/pallets/flask", "abd")
    assert canonical_sha256({"b": 1, "a": 2}) == canonical_sha256({"a": 2, "b": 1})


def test_write_read_round_trip_is_deterministic(tmp_path):
    rows = [
        record(),
        record(
            artifact_identifier="npm:evil-pkg",
            artifact_type="package",
            label=RealLabel.CONFIRMED_MALICIOUS,
            ground_truth_status=GroundTruth.ESTABLISHED,
            revision=None,
            scan_url=None,
            scan_eligible=False,
            sha256_status="not_collected",
            family_id="pkg:npm/evil-pkg",
            license="NOASSERTION",
        ),
    ]
    meta1 = write_manifest(rows, tmp_path / "a", {"p": 1})
    meta2 = write_manifest(list(reversed(rows)), tmp_path / "b", {"p": 1})
    assert meta1["manifest_sha256"] == meta2["manifest_sha256"]
    path = tmp_path / "a" / f"manifest-{DATASET_VERSION}.jsonl"
    assert read_manifest(path) == sorted(rows, key=lambda r: r.record_id)
    assert meta1["format"] == MANIFEST_FORMAT
    assert meta1["label_counts"] == {"benign": 1, "confirmed_malicious": 1}
    assert meta1["scan_eligible_count"] == 1
    assert meta1["family_count"] == 2
    assert "unknown' is not benign" in meta1["notice"]
    on_disk = json.loads((tmp_path / "a" / f"manifest-{DATASET_VERSION}.metadata.json").read_text())
    assert on_disk["manifest_sha256"] == meta1["manifest_sha256"]


def test_read_manifest_names_the_bad_line(tmp_path):
    path = tmp_path / "m.jsonl"
    good = json.dumps(record().model_dump(mode="json"))
    bad = json.loads(good)
    bad["label"] = "benign"
    bad["ground_truth_status"] = "none"
    path.write_text(good + "\n\n" + json.dumps(bad) + "\n")
    with pytest.raises(ValueError, match="line 3"):
        read_manifest(path)


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/advisories/GHSA-4v6f-7vjh-6x4m",
        "https://GITHUB.com/Advisories/GHSA-4v6f-7vjh-6x4m",
        "https://www.github.com/advisories/GHSA-xxxx",
    ],
)
def test_an_advisory_page_is_never_scan_eligible(url):
    with pytest.raises(ValueError, match="advisory page"):
        record(
            label=RealLabel.KNOWN_VULNERABLE,
            ground_truth_status=GroundTruth.ESTABLISHED,
            scan_eligible=True,
            scan_url=url,
            revision="a" * 40,
        )


def test_an_advisory_source_url_with_a_repo_scan_url_is_allowed():
    rec = record(
        label=RealLabel.KNOWN_VULNERABLE,
        ground_truth_status=GroundTruth.ESTABLISHED,
        source_url="https://github.com/advisories/GHSA-4v6f-7vjh-6x4m",
        scan_eligible=True,
        scan_url="https://github.com/o/r",
        revision="a" * 40,
    )
    assert rec.scan_eligible
