"""Scan API schemas, including the normalized artifact record from CLAUDE.md."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from app.db.models import ArtifactSource, ArtifactType, Scan, ScanStatus
from app.schemas.provenance import ProvenanceOut


class ScanCreatedResponse(BaseModel):
    scan_id: UUID
    artifact_id: UUID
    status: ScanStatus


class ArtifactRecord(BaseModel):
    """The normalized artifact record. sha256 is the provenancex-tree-v1 content digest."""

    artifact_id: UUID
    name: str
    artifact_type: ArtifactType
    version: str | None
    source: ArtifactSource
    source_url: str | None
    sha256: str | None
    collected_at: datetime | None
    scan_id: UUID


class ManifestOut(BaseModel):
    path: str
    ecosystem: str
    kind: str


class ProjectPackageOut(BaseModel):
    ecosystem: str
    name: str
    version: str | None
    manifest: str


class IngestSummary(BaseModel):
    file_count: int
    total_bytes: int
    tree_digest_version: str
    archive_sha256: str | None = None
    commit_sha: str | None = None
    revision_requested: str | None = None
    manifests: list[ManifestOut] = []
    manifests_truncated: bool = False
    # Software: the project's own package from its top-level manifest (graph root).
    project_packages: list[ProjectPackageOut] = []
    # Model scans from Hugging Face: repo, manifest digest, download counts, Hub metadata.
    hf: dict[str, Any] | None = None


class ScanErrorOut(BaseModel):
    code: str
    message: str
    details: Any = None


_RUN_FIELDS = (
    "mode",
    "provider",
    "status",
    "runtime_verified",
    "exit_code",
    "oom_killed",
    "timed_out",
    "duration_seconds",
    "error_code",
    "isolation",
    "finished_at",
    # Milestone B: fetch runs (source, what was fetched) and the tmpfs staging volume.
    "source",
    "fetched",
    "staging",
)
_RUNTIME_FIELDS = (
    "image_id",
    "network",
    "read_only_rootfs",
    "cap_drop",
    "no_new_privileges",
    "memory_mb",
    "cpus",
    "pids_limit",
    "tmp_mb",
    "timeout_seconds",
    "deadline_seconds",
    "cpu_seconds",
    "network_internal",
    "staging_volume",
)


def sandbox_summary(record: dict[str, Any] | None) -> dict[str, Any] | None:
    """An allowlisted view of Scan.sandbox: isolation facts, never host paths or user ids."""
    if not record:
        return None
    runs = []
    for run in record.get("runs") or []:
        if not isinstance(run, dict):
            continue
        out = {k: run.get(k) for k in _RUN_FIELDS if k in run}
        runtime = run.get("runtime")
        if isinstance(runtime, dict):
            out["runtime"] = {k: runtime.get(k) for k in _RUNTIME_FIELDS if k in runtime}
        if "image" in run:
            out["image"] = run["image"]
        runs.append(out)
    return {"provider": record.get("provider"), "runs": runs}


class ScanResponse(BaseModel):
    scan_id: UUID
    status: ScanStatus
    scanner_version: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    artifact: ArtifactRecord
    ingest: IngestSummary | None
    # Per-stage evidence status (sbom | aibom, graph, vulnerabilities, provenance).
    # See app/pipeline/stages.py.
    stages: dict[str, Any] | None = None
    bom_sha256: str | None = None
    component_count: int = 0
    finding_count: int = 0
    provenance: ProvenanceOut | None = None
    # Isolated analyzer runs that read this artifact (see app/pipeline/sandboxed.py).
    sandbox: dict[str, Any] | None = None
    error: ScanErrorOut | None

    @classmethod
    def from_scan(
        cls, scan: Scan, component_count: int = 0, finding_count: int = 0
    ) -> "ScanResponse":
        artifact = scan.artifact
        error = (
            ScanErrorOut(
                code=scan.error_code, message=scan.error_message or "", details=scan.error_details
            )
            if scan.error_code
            else None
        )
        return cls(
            scan_id=scan.id,
            status=scan.status,
            scanner_version=scan.scanner_version,
            created_at=scan.created_at,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            artifact=ArtifactRecord(
                artifact_id=artifact.id,
                name=artifact.name,
                artifact_type=artifact.artifact_type,
                version=artifact.version,
                source=artifact.source,
                source_url=artifact.source_url,
                sha256=artifact.sha256,
                collected_at=artifact.collected_at,
                scan_id=scan.id,
            ),
            ingest=IngestSummary.model_validate(scan.ingest_metadata)
            if scan.ingest_metadata
            else None,
            stages=scan.stages,
            bom_sha256=scan.bom_sha256,
            component_count=component_count,
            finding_count=finding_count,
            provenance=ProvenanceOut.from_row(scan.provenance) if scan.provenance else None,
            sandbox=sandbox_summary(scan.sandbox),
            error=error,
        )
