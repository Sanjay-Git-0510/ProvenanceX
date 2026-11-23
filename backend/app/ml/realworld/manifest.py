"""The versioned real-world dataset manifest: one validated row per collected artifact.

Label rules (owner decision 2026-11-22):
- `benign` needs all of: no known advisory for that version, a verified publisher or a signed
  release, and a minimum age. It is a criteria-based label, not ground truth.
- A missing advisory never makes an artifact benign. Anything that fails the criteria is
  `unknown`, and unknown rows are excluded from training.
- `confirmed_malicious` rows are metadata only. No payload is downloaded or scanned.
- `suspicious` rows (a third-party scanner flag) are never scanned either.
"""

import hashlib
import json
from collections import Counter
from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

MANIFEST_FORMAT = "provenancex-realworld-manifest-v1"
DATASET_VERSION = "realworld-v1"
NOASSERTION = "NOASSERTION"  # SPDX value for "license not known"

_SHA256 = r"^[0-9a-f]{64}$"


class RealLabel(StrEnum):
    BENIGN = "benign"
    KNOWN_VULNERABLE = "known_vulnerable"
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class GroundTruth(StrEnum):
    ESTABLISHED = "established"  # a reviewed advisory database entry
    CRITERIA_BASED = "criteria_based"  # the benign criteria above, checked from metadata
    THIRD_PARTY_FLAG = "third_party_flag"  # a scanner flag, not a confirmed finding
    NONE = "none"  # unknown


# The ground truth each label may carry.
_ALLOWED_TRUTH = {
    RealLabel.BENIGN: {GroundTruth.CRITERIA_BASED},
    RealLabel.KNOWN_VULNERABLE: {GroundTruth.ESTABLISHED},
    RealLabel.CONFIRMED_MALICIOUS: {GroundTruth.ESTABLISHED},
    RealLabel.SUSPICIOUS: {GroundTruth.THIRD_PARTY_FLAG},
    RealLabel.UNKNOWN: {GroundTruth.NONE},
}

# Labels whose artifacts may go through the scan step. Malicious and suspicious never do.
SCANNABLE_LABELS = frozenset({RealLabel.BENIGN, RealLabel.KNOWN_VULNERABLE})

# Most severe first; used when one artifact gets more than one label.
LABEL_SEVERITY = (
    RealLabel.CONFIRMED_MALICIOUS,
    RealLabel.SUSPICIOUS,
    RealLabel.KNOWN_VULNERABLE,
    RealLabel.BENIGN,
    RealLabel.UNKNOWN,
)

ArtifactType = Literal["software", "model", "lora", "dataset", "package"]


class ManifestRecord(BaseModel):
    """One collected artifact. The 11 required fields come first."""

    model_config = ConfigDict(extra="forbid")

    data_source: str
    source_url: str
    collection_date: date
    artifact_identifier: str
    artifact_type: ArtifactType
    label: RealLabel
    label_justification: str = Field(min_length=1)
    license: str = Field(min_length=1)
    sha256: str | None = Field(default=None, pattern=_SHA256)
    dataset_version: str
    preprocessing: list[str]

    record_id: str
    family_id: str
    ground_truth_status: GroundTruth
    revision: str | None = None
    scan_url: str | None = None  # what the scan step submits; None means metadata only
    scan_eligible: bool = False
    sha256_status: Literal["pending_scan", "from_scan", "not_collected"] = "not_collected"
    source_record_sha256: str = Field(pattern=_SHA256)
    evidence: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_policy(self) -> "ManifestRecord":
        if self.ground_truth_status not in _ALLOWED_TRUTH[self.label]:
            raise ValueError(f"{self.label} cannot have ground truth {self.ground_truth_status}")
        if self.scan_eligible:
            if self.label not in SCANNABLE_LABELS:
                raise ValueError(f"{self.label} artifacts must never be scanned")
            if not self.scan_url or not self.revision:
                raise ValueError("A scan-eligible record needs scan_url and a pinned revision")
        if self.artifact_type == "package" and self.scan_eligible:
            raise ValueError("Registry packages are metadata only")
        if self.sha256 is None and self.sha256_status == "from_scan":
            raise ValueError("sha256_status=from_scan needs a sha256")
        if self.sha256 is not None and self.sha256_status != "from_scan":
            raise ValueError("A sha256 can only come from a scan")
        return self


def canonical_sha256(value: Any) -> str:
    """SHA-256 of a value's canonical JSON, used to pin the source metadata a label used."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode()).hexdigest()


def record_id_for(artifact_type: str, identifier: str, revision: str | None) -> str:
    return "rw-" + canonical_sha256([artifact_type, identifier.lower(), revision or ""])[:20]


def _line(record: ManifestRecord) -> str:
    return json.dumps(record.model_dump(mode="json"), sort_keys=True, ensure_ascii=True)


def write_manifest(
    records: list[ManifestRecord], out_dir: Path, parameters: dict[str, Any]
) -> dict[str, Any]:
    """Write manifest-<version>.jsonl and its metadata. Records are sorted by record_id."""
    out_dir.mkdir(parents=True, exist_ok=True)
    ordered = sorted(records, key=lambda r: r.record_id)
    body = "".join(_line(r) + "\n" for r in ordered)
    manifest_path = out_dir / f"manifest-{DATASET_VERSION}.jsonl"
    manifest_path.write_text(body, encoding="utf-8")
    metadata = build_metadata(ordered, hashlib.sha256(body.encode()).hexdigest(), parameters)
    (out_dir / f"manifest-{DATASET_VERSION}.metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return metadata


def read_manifest(path: Path) -> list[ManifestRecord]:
    """Parse and validate every row. Raises ValueError naming the first bad line."""
    records: list[ManifestRecord] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            records.append(ManifestRecord.model_validate_json(line))
        except ValueError as exc:
            raise ValueError(f"{path.name} line {number}: {exc}") from exc
    return records


SOURCE_LICENSES = {
    "ghsa": "CC-BY-4.0 (GitHub Advisory Database)",
    "osv": "CC-BY-4.0 for OSV-native data; each upstream source keeps its own terms",
    "nvd": "Public NVD data (U.S. government work); NVD terms of use apply",
    "github": "GitHub REST API metadata; each repository keeps its own license",
    "huggingface": "Hugging Face Hub API metadata; each repository keeps its own license",
}


def build_metadata(
    records: list[ManifestRecord], manifest_sha256: str, parameters: dict[str, Any]
) -> dict[str, Any]:
    def count(key: str) -> dict[str, int]:
        return dict(sorted(Counter(str(getattr(r, key)) for r in records).items()))

    by_type_label = Counter(f"{r.artifact_type}/{r.label}" for r in records)
    return {
        "format": MANIFEST_FORMAT,
        "dataset_version": DATASET_VERSION,
        "manifest_sha256": manifest_sha256,
        "record_count": len(records),
        "family_count": len({r.family_id for r in records}),
        "label_counts": count("label"),
        "artifact_type_counts": count("artifact_type"),
        "type_label_counts": dict(sorted(by_type_label.items())),
        "data_source_counts": count("data_source"),
        "license_counts": count("license"),
        "scan_eligible_count": sum(r.scan_eligible for r in records),
        "source_licenses": SOURCE_LICENSES,
        "parameters": parameters,
        "notice": (
            "REAL-WORLD METADATA. Labels come from public advisory databases and published "
            "metadata. 'unknown' is not benign and is excluded from training. Benign is "
            "criteria-based, not ground truth. confirmed_malicious rows are metadata only: no "
            "payload was downloaded, scanned or run."
        ),
    }
