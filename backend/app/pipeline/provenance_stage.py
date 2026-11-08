"""Pipeline step 8: provenance/integrity checks, ProvenanceRecord row, provenance Findings.

Runs for software and model scans, after the other evidence stages (it uses whatever
they produced and does not require them to have succeeded). The canonical record is
written off-chain to <workspace>/provenance.json (mode 0600). Its SHA-256 is
ProvenanceRecord.record_sha256, which Phase 7 anchors as `provenance_hash`.

Only failed checks become Findings (category="provenance"). `unknown` checks are kept
in the record, so missing evidence is visible without being reported as a failure.
"""

import os
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.hashing import list_tree_files
from app.db.models import (
    Artifact,
    Finding,
    FindingCategory,
    ProvenanceRecord,
    Scan,
    ScanStatus,
)
from app.pipeline.stages import StageStatus, execute_stage
from app.pipeline.workspace import Workspace
from app.provenance.checks import (
    Check,
    PriorScan,
    ProvenanceInputs,
    canonical_sha256,
    provenance_document,
    run_provenance_checks,
)

STAGE = "provenance"
PROVENANCE_FILENAME = "provenance.json"


@dataclass
class ProvenanceExtras:
    """Pipeline-specific evidence for the checks."""

    hf_files: list[dict[str, Any]] | None = None
    hf_source: str | None = None
    manifest_sha256: str | None = None
    lineage_features: dict[str, Any] | None = None
    file_paths: list[str] = field(default_factory=list)


def _prior_scan(session: Session, scan: Scan) -> PriorScan | None:
    artifact = scan.artifact
    if not artifact.source_url:
        return None
    row = session.execute(
        select(Scan, Artifact)
        .join(Artifact, Scan.artifact_id == Artifact.id)
        .where(
            Artifact.source_url == artifact.source_url,
            Artifact.artifact_type == artifact.artifact_type,
            Artifact.sha256.is_not(None),
            Scan.status == ScanStatus.COMPLETED,
            Scan.id != scan.id,
            Scan.created_at <= scan.created_at,
        )
        .order_by(Scan.created_at.desc())
        .limit(1)
    ).first()
    if row is None:
        return None
    prior_scan, prior_artifact = row
    meta = prior_scan.ingest_metadata or {}
    hf = meta.get("hf") if isinstance(meta.get("hf"), dict) else {}
    return PriorScan(
        scan_id=prior_scan.id,
        resolved_commit=meta.get("commit_sha"),
        artifact_sha256=prior_artifact.sha256,
        manifest_sha256=hf.get("manifest_sha256"),
    )


def _lineage_check(features: dict[str, Any] | None) -> Check | None:
    if not features:
        return None
    flags = [f for f in features.get("suspicious_lineage") or [] if isinstance(f, dict)]
    if features.get("unexpected_parent_or_base_model"):
        return Check(
            "lineage_consistency",
            "fail",
            "Declared lineage is inconsistent: "
            + "; ".join(f.get("detail", "") for f in flags)[:400],
            "MEDIUM",
            "PX-PROV-LINEAGE-INCONSISTENT",
            {"flags": flags},
        )
    if flags:
        return Check(
            "lineage_consistency",
            "unknown",
            "Lineage could not be fully traced: "
            + "; ".join(f.get("detail", "") for f in flags)[:400],
            data={"flags": flags},
        )
    return Check("lineage_consistency", "pass", "Declared lineage sources agree")


def _finding(scan_id: UUID, source: str, check: Check) -> Finding:
    return Finding(
        scan_id=scan_id,
        component_id=None,
        category=FindingCategory.PROVENANCE,
        identifier=check.identifier or f"PX-PROV-{check.name.upper()}",
        aliases=[],
        title=check.evidence[:512],
        severity=check.severity or "LOW",
        severity_source="provenancex_rule",
        cvss_score=None,
        cvss_vector=None,
        cvss_version=None,
        source=source,
        details={"kind": "provenance_check", "check": check.name, "data": check.data},
    )


def _write_private(path: os.PathLike[str], data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def run_provenance_stage(
    session: Session,
    scan_id: UUID,
    workspace: Workspace,
    extras: ProvenanceExtras,
    max_files: int,
) -> dict[str, Any] | None:
    source = "mock" if extras.hf_source == "mock" else "provenancex"

    def body(scan: Scan) -> tuple[dict[str, Any], StageStatus, dict[str, Any]]:
        artifact = scan.artifact
        meta = scan.ingest_metadata or {}
        paths = extras.file_paths or [
            rel.decode("utf-8", errors="replace")
            for rel, _ in list_tree_files(workspace.src_dir, max_files=max_files)
        ]
        lineage = extras.lineage_features or {}
        inputs = ProvenanceInputs(
            source=str(artifact.source),
            source_url=artifact.source_url,
            revision_requested=scan.revision_requested,
            resolved_commit=meta.get("commit_sha"),
            artifact_sha256=artifact.sha256,
            file_paths=paths,
            artifact_type=str(artifact.artifact_type),
            manifest_sha256=extras.manifest_sha256,
            hf_files=extras.hf_files,
            hf_source=extras.hf_source,
            lineage_completeness=lineage.get("lineage_completeness"),
            prior=_prior_scan(session, scan),
        )
        result = run_provenance_checks(inputs)
        if (lineage_check := _lineage_check(extras.lineage_features)) is not None:
            result.checks.append(lineage_check)

        document = provenance_document(scan.id, inputs, result)
        raw, record_sha = canonical_sha256(document)
        _write_private(workspace.root / PROVENANCE_FILENAME, raw)

        session.add(
            ProvenanceRecord(
                scan_id=scan.id,
                source_known=result.source_known,
                revision_pinned=result.revision_pinned,
                resolved_commit=result.resolved_commit,
                signed=result.signed,
                signature_files_present=bool(result.signature_files),
                provenance_present=bool(result.attestation_files),
                hash_changed=result.hash_changed,
                previous_scan_id=result.previous_scan_id,
                lineage_completeness=result.lineage_completeness,
                checks=[c.to_dict() for c in result.checks],
                record_sha256=record_sha,
                source=source,
            )
        )
        failed = result.failed
        session.add_all(_finding(scan.id, source, c) for c in failed)

        statuses: dict[str, int] = {}
        for c in result.checks:
            statuses[c.status] = statuses.get(c.status, 0) + 1
        summary = {
            "record_sha256": record_sha,
            "hash_changed": result.hash_changed,
            "checks": statuses,
        }
        fields = {
            "source": source,
            "provenance_file": PROVENANCE_FILENAME,
            "record_sha256": record_sha,
            "counts": {**statuses, "findings": len(failed)},
            "limitations": result.limitations,
        }
        return summary, StageStatus.COMPLETED, fields

    return execute_stage(session, scan_id, STAGE, body, provider="provenancex")
