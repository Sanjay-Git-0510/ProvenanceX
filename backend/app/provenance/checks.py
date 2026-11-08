"""Provenance and integrity checks (pipeline step 8), shared by software and model scans.

Each check has a status:
  pass     the evidence supports the property
  fail     the property is missing or contradicted (becomes a provenance Finding)
  unknown  the property could not be determined (never treated as pass or fail)
  info     context only (e.g. a hash change that is explained by a new commit)

Signatures and attestations are only DETECTED (by file name). They are not verified, so
`signed` stays None ("unverified") and the limitation is reported. Severities are
ProvenanceX rule severities, not CVSS.
"""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any
from uuid import UUID

from app.security.revision import is_commit_sha

RECORD_FORMAT = "provenancex-provenance-v1"
MAX_LISTED = 20

SIGNATURE_SUFFIXES = (".sig", ".asc", ".sigstore", ".sigstore.json", ".cosign.bundle")
ATTESTATION_SUFFIXES = (".intoto.jsonl", ".intoto.json", ".slsa.json", ".provenance.json", ".att")
ATTESTATION_NAMES = frozenset({"provenance.json", "attestation.json", "attestations.json"})


@dataclass(frozen=True)
class PriorScan:
    scan_id: UUID
    resolved_commit: str | None
    artifact_sha256: str | None
    manifest_sha256: str | None


@dataclass
class ProvenanceInputs:
    source: str  # github | huggingface | upload
    source_url: str | None
    revision_requested: str | None
    resolved_commit: str | None
    artifact_sha256: str | None
    file_paths: list[str]
    artifact_type: str
    manifest_sha256: str | None = None  # HF: digest over the full remote listing
    hf_files: list[dict[str, Any]] | None = None  # HfFile.to_dict() entries
    hf_source: str | None = None  # "huggingface" | "mock"
    lineage_completeness: float | None = None
    prior: PriorScan | None = None


@dataclass
class Check:
    name: str
    status: str
    evidence: str
    severity: str | None = None  # for fail: HIGH | MEDIUM | LOW
    identifier: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "evidence": self.evidence,
            "severity": self.severity,
            "identifier": self.identifier,
            "data": self.data,
        }


@dataclass
class ProvenanceResult:
    source_known: bool
    revision_pinned: bool
    resolved_commit: str | None
    signed: bool | None
    signature_files: list[str]
    attestation_files: list[str]
    hash_changed: bool | None
    previous_scan_id: UUID | None
    lineage_completeness: float | None
    checks: list[Check]
    limitations: list[str]

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if c.status == "fail"]


def _detect(paths: list[str]) -> tuple[list[str], list[str]]:
    sigs, atts = [], []
    for rel in paths:
        name = PurePosixPath(rel).name.lower()
        if name.endswith(ATTESTATION_SUFFIXES) or name in ATTESTATION_NAMES:
            atts.append(rel)
        elif name.endswith(SIGNATURE_SUFFIXES):
            sigs.append(rel)
    return sorted(sigs)[:MAX_LISTED], sorted(atts)[:MAX_LISTED]


def _hash_check(inp: ProvenanceInputs) -> tuple[Check, bool | None]:
    prior = inp.prior
    if inp.source == "upload" or not inp.source_url:
        return (
            Check(
                "hash_consistency",
                "unknown",
                "Uploads have no stable source identity to compare against earlier scans",
            ),
            None,
        )
    if prior is None:
        return (
            Check("hash_consistency", "unknown", "No earlier completed scan of this source"),
            None,
        )
    content_changed = prior.artifact_sha256 != inp.artifact_sha256 or (
        prior.manifest_sha256 is not None
        and inp.manifest_sha256 is not None
        and prior.manifest_sha256 != inp.manifest_sha256
    )
    data = {
        "previous_scan_id": str(prior.scan_id),
        "previous_commit": prior.resolved_commit,
        "previous_sha256": prior.artifact_sha256,
    }
    same_commit = bool(inp.resolved_commit) and prior.resolved_commit == inp.resolved_commit
    if not content_changed:
        matched = Check(
            "hash_consistency", "pass", "Content hash matches the previous scan", data=data
        )
        return matched, False
    if same_commit:
        return (
            Check(
                "hash_consistency",
                "fail",
                "Content hash differs from an earlier scan of the SAME commit",
                "HIGH",
                "PX-PROV-HASH-CHANGED-SAME-COMMIT",
                data,
            ),
            True,
        )
    return (
        Check(
            "hash_consistency",
            "info",
            "Content hash changed since the previous scan, which was of a different commit",
            data=data,
        ),
        True,
    )


def _hf_checks(inp: ProvenanceInputs) -> list[Check]:
    files = inp.hf_files or []
    if inp.hf_source == "mock":
        return [
            Check(
                "download_integrity",
                "unknown",
                "Mock Hugging Face provider: files were not fetched from or verified against "
                "the Hub",
            )
        ]
    checks: list[Check] = []
    mismatched = [f["path"] for f in files if f.get("status") == "integrity_mismatch"]
    downloaded = [f for f in files if f.get("downloaded")]
    if mismatched:
        checks.append(
            Check(
                "download_integrity",
                "fail",
                f"{len(mismatched)} downloaded file(s) did not match the Hub's listed hash; "
                "they were discarded",
                "HIGH",
                "PX-PROV-DOWNLOAD-INTEGRITY",
                {"files": mismatched[:MAX_LISTED]},
            )
        )
    elif downloaded and all(f.get("hash_verified") for f in downloaded):
        checks.append(
            Check(
                "download_integrity",
                "pass",
                f"All {len(downloaded)} downloaded file(s) match the Hub's listed SHA-256 "
                "(LFS) or git blob id",
            )
        )
    else:
        checks.append(Check("download_integrity", "unknown", "No verified downloads"))

    rejected = [f["path"] for f in files if f.get("status") == "rejected"]
    if rejected:
        checks.append(
            Check(
                "repository_listing",
                "fail",
                f"{len(rejected)} listed file(s) were refused (unsafe path, bad metadata or "
                "a disallowed redirect)",
                "MEDIUM",
                "PX-PROV-UNSAFE-LISTING",
                {"files": rejected[:MAX_LISTED]},
            )
        )
    skipped = [f for f in files if f.get("status") in ("skipped", "failed")]
    if skipped:
        checks.append(
            Check(
                "content_coverage",
                "unknown",
                f"{len(skipped)} listed file(s) were not downloaded, so they were not verified "
                "locally (size cap, budget or download failure)",
                data={"files": [f["path"] for f in skipped][:MAX_LISTED]},
            )
        )
    return checks


def run_provenance_checks(inp: ProvenanceInputs) -> ProvenanceResult:
    checks: list[Check] = []
    limitations = [
        "Signature and attestation files are detected by name only; they are not verified."
    ]
    source_known = inp.source in ("github", "huggingface")
    checks.append(
        Check("source_known", "pass", f"Fetched from {inp.source}: {inp.source_url}")
        if source_known
        else Check(
            "source_known",
            "fail",
            "Uploaded artifact: its origin cannot be confirmed",
            "LOW",
            "PX-PROV-SOURCE-UNKNOWN",
        )
    )

    pinned = bool(inp.revision_requested) and is_commit_sha(inp.revision_requested or "")
    if inp.source == "upload":
        checks.append(Check("revision_pinned", "unknown", "Uploads have no revision"))
    elif pinned:
        checks.append(Check("revision_pinned", "pass", "A full commit sha was requested"))
    else:
        checks.append(
            Check(
                "revision_pinned",
                "fail",
                "The scan was not pinned to a full commit sha "
                f"(requested: {inp.revision_requested or 'default branch'})",
                "LOW",
                "PX-PROV-REVISION-UNPINNED",
            )
        )
    if inp.resolved_commit:
        checks.append(
            Check("resolved_commit", "pass", f"Content resolved to commit {inp.resolved_commit}")
        )
    else:
        checks.append(Check("resolved_commit", "unknown", "No commit is known for this content"))

    hash_check, hash_changed = _hash_check(inp)
    checks.append(hash_check)

    sigs, atts = _detect(inp.file_paths)
    checks.append(
        Check(
            "signature_files",
            "pass",
            "Signature file(s) present (not verified)",
            data={"files": sigs},
        )
        if sigs
        else Check(
            "signature_files",
            "fail",
            "No signature files found",
            "LOW",
            "PX-PROV-NO-SIGNATURE",
        )
    )
    checks.append(
        Check(
            "provenance_attestation",
            "pass",
            "Provenance attestation file(s) present (not verified)",
            data={"files": atts},
        )
        if atts
        else Check(
            "provenance_attestation",
            "fail",
            "No SLSA/in-toto provenance attestation found",
            "LOW",
            "PX-PROV-NO-ATTESTATION",
        )
    )

    if inp.source == "huggingface":
        checks.extend(_hf_checks(inp))
    if inp.lineage_completeness is not None:
        checks.append(
            Check(
                "lineage_completeness",
                "info",
                f"Declared lineage completeness {inp.lineage_completeness:.2f} "
                "(research heuristic, see the lineage graph features)",
                data={"value": inp.lineage_completeness},
            )
        )

    return ProvenanceResult(
        source_known=source_known,
        revision_pinned=pinned,
        resolved_commit=inp.resolved_commit,
        signed=None,
        signature_files=sigs,
        attestation_files=atts,
        hash_changed=hash_changed,
        previous_scan_id=inp.prior.scan_id if inp.prior and hash_changed is not None else None,
        lineage_completeness=inp.lineage_completeness,
        checks=checks,
        limitations=limitations,
    )


def provenance_document(
    scan_id: UUID, inp: ProvenanceInputs, result: ProvenanceResult
) -> dict[str, Any]:
    """The canonical off-chain provenance record. Its SHA-256 is the provenance hash."""
    return {
        "format": RECORD_FORMAT,
        "scan_id": str(scan_id),
        "artifact_type": inp.artifact_type,
        "artifact_sha256": inp.artifact_sha256,
        "manifest_sha256": inp.manifest_sha256,
        "source": inp.source,
        "source_url": inp.source_url,
        "revision_requested": inp.revision_requested,
        "resolved_commit": result.resolved_commit,
        "source_known": result.source_known,
        "revision_pinned": result.revision_pinned,
        "signed": result.signed,
        "signature_files": result.signature_files,
        "attestation_files": result.attestation_files,
        "hash_changed": result.hash_changed,
        "previous_scan_id": str(result.previous_scan_id) if result.previous_scan_id else None,
        "lineage_completeness": result.lineage_completeness,
        "checks": [c.to_dict() for c in result.checks],
    }


def canonical_sha256(document: dict[str, Any]) -> tuple[bytes, str]:
    raw = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return raw, hashlib.sha256(raw).hexdigest()
