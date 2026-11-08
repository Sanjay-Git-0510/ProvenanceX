"""Software scan pipeline.

Implements CLAUDE.md pipeline steps for software artifacts:
  1. receive input / scan_id   (the API creates the Scan row and workspace)
  2. safe working directory    (ZIP extraction or hardened git fetch into workspace/src)
  3. SHA-256                   (provenancex-tree-v1 content digest; raw ZIP hash for uploads)
  4. SBOM                      (Syft -> CycloneDX -> Component rows)        [sbom_stage]
  6. dependency graph          (NetworkX -> GraphNode/GraphEdge rows)       [graph_stage]
  7. OSV/NVD lookup            (vulnerability Findings)                     [vuln_stage]
  8. provenance/integrity      (ProvenanceRecord + provenance Findings)       [provenance_stage]
  9. static analysis           (static features + static Findings)            [static_stage]
 10. sandbox (optional)        (behavior features + behavioral Findings)      [sandbox_stage]
Later phases add their steps after these.

`run_software_ingestion` never raises (see app/pipeline/lifecycle.py). An ingestion
failure (steps 1-3) marks the Scan FAILED with a structured error and removes the
workspace. Failures in later evidence stages do not fail the scan. They are recorded per
stage in Scan.stages (unavailable/error/skipped), so partial evidence is never shown as
complete.
"""

import logging
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.core.hashing import (
    TREE_DIGEST_VERSION,
    TreeDigest,
    list_tree_files,
    sha256_file,
    tree_digest,
)
from app.db.models import ArtifactSource, Scan, utcnow
from app.pipeline.graph_stage import run_graph_stage
from app.pipeline.lifecycle import run_scan
from app.pipeline.provenance_stage import ProvenanceExtras, run_provenance_stage
from app.pipeline.providers import ScanProviders, build_providers
from app.pipeline.sandbox_stage import run_sandbox_stage
from app.pipeline.sbom_stage import run_sbom_stage
from app.pipeline.stages import skip_stage
from app.pipeline.static_stage import StaticExtras, run_static_stage
from app.pipeline.vuln_stage import run_vuln_stage
from app.pipeline.workspace import MB, Workspace
from app.scanners.git_fetch import CloneLimits, clone_repository
from app.scanners.manifests import (
    ManifestScan,
    ProjectPackage,
    detect_manifests,
    detect_project_packages,
)
from app.security.archive import ArchiveLimits, safe_extract_zip
from app.security.url_validation import validate_github_repo_url

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IngestEvidence:
    tree: TreeDigest
    archive_sha256: str | None
    commit_sha: str | None
    revision_requested: str | None
    manifests: ManifestScan
    project_packages: list[ProjectPackage]
    file_paths: list[str]

    def to_metadata(self) -> dict[str, Any]:
        return {
            "file_count": self.tree.file_count,
            "total_bytes": self.tree.total_bytes,
            "tree_digest_version": TREE_DIGEST_VERSION,
            "archive_sha256": self.archive_sha256,
            "commit_sha": self.commit_sha,
            "revision_requested": self.revision_requested,
            "manifests": [
                {"path": m.path, "ecosystem": m.ecosystem, "kind": m.kind}
                for m in self.manifests.manifests
            ],
            "manifests_truncated": self.manifests.truncated,
            "project_packages": [
                {
                    "ecosystem": p.ecosystem,
                    "name": p.name,
                    "version": p.version,
                    "manifest": p.manifest,
                }
                for p in self.project_packages
            ],
        }


def _ingest(scan: Scan, workspace: Workspace, settings: Settings) -> IngestEvidence:
    max_bytes = settings.max_artifact_size_mb * MB
    artifact = scan.artifact
    archive_sha256: str | None = None
    commit_sha: str | None = None

    if artifact.source == ArtifactSource.UPLOAD:
        if not workspace.upload_path.is_file():
            raise AppError(ErrorCode.WORKSPACE_ERROR, "Uploaded archive is missing", 500)
        archive_sha256 = sha256_file(workspace.upload_path)
        safe_extract_zip(
            workspace.upload_path,
            workspace.src_dir,
            ArchiveLimits(
                max_total_bytes=max_bytes,
                max_files=settings.max_artifact_files,
                max_compression_ratio=settings.max_compression_ratio,
            ),
        )
    elif artifact.source == ArtifactSource.GITHUB:
        # Re-validate (including DNS) just before network access.
        repo = validate_github_repo_url(artifact.source_url)
        result = clone_repository(
            repo.clone_url,
            workspace.src_dir,
            scan.revision_requested,
            CloneLimits(timeout_seconds=settings.git_clone_timeout_seconds, max_bytes=max_bytes),
        )
        commit_sha = result.commit_sha
    else:
        raise AppError(ErrorCode.INVALID_INPUT, "Unsupported source for a software scan", 400)

    tree = tree_digest(workspace.src_dir, max_files=settings.max_artifact_files)
    if tree.file_count == 0:
        raise AppError(ErrorCode.EMPTY_ARTIFACT, "Artifact contains no files", 400)
    if tree.total_bytes > max_bytes:
        raise AppError(
            ErrorCode.ARTIFACT_TOO_LARGE,
            "Artifact exceeds the size limit",
            413,
            {"max_bytes": max_bytes},
        )

    return IngestEvidence(
        tree=tree,
        archive_sha256=archive_sha256,
        commit_sha=commit_sha,
        revision_requested=scan.revision_requested,
        manifests=detect_manifests(workspace.src_dir),
        project_packages=detect_project_packages(workspace.src_dir),
        file_paths=[
            rel.decode("utf-8", errors="replace")
            for rel, _ in list_tree_files(workspace.src_dir, max_files=settings.max_artifact_files)
        ],
    )


def _run_evidence_stages(
    session: Session,
    scan_id: UUID,
    workspace: Workspace,
    settings: Settings,
    providers: ScanProviders,
    ingested: "SoftwareIngest",
) -> None:
    """Steps 4, 6, 7, 8, 9, 10. Each stage records its own status and never raises."""
    sbom = run_sbom_stage(
        session,
        scan_id,
        workspace,
        settings,
        providers.sbom,
        ingested.evidence.project_packages,
    )
    if sbom is None:
        skip_stage(session, scan_id, "graph", "sbom stage did not succeed")
        skip_stage(session, scan_id, "vulnerabilities", "sbom stage did not succeed")
    else:
        run_graph_stage(session, scan_id, sbom, ingested.root_label)
        run_vuln_stage(session, scan_id, sbom, providers)
    run_provenance_stage(
        session,
        scan_id,
        workspace,
        ProvenanceExtras(file_paths=ingested.file_paths),
        settings.max_artifact_files,
    )
    run_static_stage(session, scan_id, workspace, settings, StaticExtras())
    run_sandbox_stage(session, scan_id, workspace, settings, providers.sandbox, "software")


@dataclass(frozen=True)
class SoftwareIngest:
    evidence: IngestEvidence
    root_label: str
    file_paths: list[str]


def run_software_ingestion(
    scan_id: UUID,
    session_factory: sessionmaker[Session],
    settings: Settings,
    providers: ScanProviders | None = None,
) -> None:
    """Background entry point: ingest and analyze the artifact of `scan_id`. Never raises."""
    resolved = providers or build_providers(settings)

    def ingest(session: Session, scan: Scan, workspace: Workspace) -> SoftwareIngest:
        evidence = _ingest(scan, workspace, settings)
        artifact = scan.artifact
        artifact.sha256 = evidence.tree.sha256
        artifact.collected_at = utcnow()
        if artifact.version is None and evidence.commit_sha:
            artifact.version = evidence.commit_sha
        scan.ingest_metadata = evidence.to_metadata()
        session.commit()
        logger.info(
            "Scan %s ingested: %s files, sha256=%s",
            scan.id,
            evidence.tree.file_count,
            evidence.tree.sha256,
        )
        return SoftwareIngest(evidence, artifact.name, evidence.file_paths)

    def evidence_stages(
        session: Session, sid: UUID, workspace: Workspace, ingested: SoftwareIngest
    ) -> None:
        _run_evidence_stages(session, sid, workspace, settings, resolved, ingested)

    run_scan(scan_id, session_factory, settings, ingest, evidence_stages)
