"""Software scan pipeline.

Implements CLAUDE.md pipeline steps for software artifacts:
  1. receive input / scan_id   (the API creates the Scan row and workspace)
  2. safe working directory    (a kernel-capped tmpfs staging volume per scan; ZIP extraction
                                in the analyzer sandbox, or a hardened git fetch in the isolated
                                fetcher container behind the egress proxy)
  3. SHA-256                   (provenancex-tree-v1 content digest, computed in the analyzer;
                                raw ZIP hash for uploads)
  4. SBOM                      (Syft -> CycloneDX -> Component rows)        [sbom_stage]
  6. dependency graph          (NetworkX -> GraphNode/GraphEdge rows)       [graph_stage]
  7. OSV/NVD lookup            (vulnerability Findings)                     [vuln_stage]
  8. provenance/integrity      (ProvenanceRecord + provenance Findings)       [provenance_stage]
  9. static analysis           (static features + static Findings)            [static_stage]
 10. sandbox (optional)        (behavior features + behavioral Findings)      [sandbox_stage]
 11-18. risk                  (features, models, fusion, policy, SHAP, RiskDecision) [risk_stage]
Later phases add their steps after these.

Sandbox-only processing: the download runs in the fetcher container and every step that reads
artifact content (extraction, tree digest, manifest detection, Syft, static analysis, config
digest, declared versions) runs in the analyzer container (app/pipeline/sandboxed.py). The
runner never clones, downloads or parses the artifact; the stages here only store validated
output. Without a working fetcher or analyzer the scan fails; there is no host fallback.

`run_software_ingestion` never raises (see app/pipeline/lifecycle.py). An ingestion
failure (steps 1-3) marks the Scan FAILED with a structured error and removes the
workspace. Failures in later evidence stages do not fail the scan. They are recorded per
stage in Scan.stages (unavailable/error/skipped), so partial evidence is never shown as
complete.
"""

import hashlib
import logging
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from app.analysis.base import SBOM_INCOMING, AnalysisJob, ContentAnalyzer, section_to_error
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.core.hashing import TREE_DIGEST_VERSION, TreeDigest, sha256_file
from app.db.models import ArtifactSource, Scan, utcnow
from app.fetch.base import FetchJob
from app.pipeline.anchor_stage import run_anchor_stage
from app.pipeline.graph_stage import run_graph_stage
from app.pipeline.lifecycle import run_scan
from app.pipeline.ownership import ScanClaim
from app.pipeline.provenance_stage import ProvenanceExtras, run_provenance_stage
from app.pipeline.providers import (
    ScanProviders,
    build_providers,
    require_analyzer,
    require_fetcher,
)
from app.pipeline.risk_stage import CollectedRiskInputs, run_risk_stage
from app.pipeline.sandbox_stage import run_sandbox_stage
from app.pipeline.sandboxed import (
    analyze_tree,
    extract_upload,
    fetch_artifact,
    persist_tree,
    staging_area,
)
from app.pipeline.sbom_stage import run_sbom_stage
from app.pipeline.stages import skip_stage
from app.pipeline.static_stage import StaticExtras, run_static_stage
from app.pipeline.vuln_stage import run_vuln_stage
from app.pipeline.workspace import MB, Workspace
from app.sandbox_worker.protocol import AnalysisOut
from app.scanners.manifests import Manifest, ManifestScan, ProjectPackage
from app.scanners.sbom.base import SbomResult
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
    collected: AnalysisOut

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


class CollectedSbom:
    """The SBOM the analyzer produced, served to run_sbom_stage through the provider interface.

    Syft ran inside the analyzer container. Its raw document arrived as a separate frame and
    was spooled to `sbom_path`; run_sbom_stage parses it in a memory-limited child process.
    """

    def __init__(self, name: str, collected: AnalysisOut, sbom_path: Path) -> None:
        self.name = name
        self.collected = collected
        self.sbom_path = sbom_path

    def generate(self, src_dir: object, work_dir: object) -> SbomResult:  # noqa: ARG002
        if self.collected.sbom_error is not None:
            raise section_to_error(self.collected.sbom_error)
        sbom = self.collected.sbom
        if sbom is None:
            raise AppError(ErrorCode.ANALYZER_OUTPUT_INVALID, "The analyzer returned no SBOM", 502)
        try:
            raw = self.sbom_path.read_bytes()
        except OSError as exc:
            raise AppError(
                ErrorCode.ANALYZER_OUTPUT_INVALID, "The SBOM frame was not received", 502
            ) from exc
        finally:
            self.sbom_path.unlink(missing_ok=True)
        if len(raw) != sbom.size or hashlib.sha256(raw).hexdigest() != sbom.sha256:
            raise AppError(
                ErrorCode.ANALYZER_OUTPUT_INVALID, "The SBOM does not match its description", 502
            )
        return SbomResult(
            raw=raw,
            source=sbom.source,
            tool_name=sbom.tool_name,
            tool_version=sbom.tool_version,
            format=sbom.format,
        )


def check_tree(collected: AnalysisOut, settings: Settings) -> TreeDigest:
    """Ingestion limits, applied to the analyzer's validated counts."""
    max_bytes = settings.max_artifact_size_mb * MB
    tree = TreeDigest(collected.tree.sha256, collected.tree.file_count, collected.tree.total_bytes)
    if len(collected.file_paths) > settings.max_artifact_files:
        raise AppError(
            ErrorCode.TOO_MANY_FILES,
            "Artifact contains too many files",
            413,
            {"max_files": settings.max_artifact_files},
        )
    if tree.total_bytes > max_bytes:
        raise AppError(
            ErrorCode.ARTIFACT_TOO_LARGE,
            "Artifact exceeds the size limit",
            413,
            {"max_bytes": max_bytes},
        )
    return tree


def _ingest(
    session: Session,
    scan: Scan,
    workspace: Workspace,
    settings: Settings,
    analyzer: ContentAnalyzer,
    providers: ScanProviders,
) -> IngestEvidence:
    artifact = scan.artifact
    archive_sha256: str | None = None
    commit_sha: str | None = None
    has_upload = artifact.source == ArtifactSource.UPLOAD
    job = AnalysisJob(
        scan_id=scan.id,
        workspace=workspace,
        kind="software",
        has_upload=has_upload,
        revision_requested=scan.revision_requested,
    )

    if not has_upload and artifact.source != ArtifactSource.GITHUB:
        raise AppError(ErrorCode.INVALID_INPUT, "Unsupported source for a software scan", 400)
    if has_upload:
        if not workspace.upload_path.is_file():
            raise AppError(ErrorCode.WORKSPACE_ERROR, "Uploaded archive is missing", 500)
        # Hashing the raw bytes reads nothing as structure; extraction happens in the sandbox.
        archive_sha256 = sha256_file(workspace.upload_path)
    else:
        # Re-validate (including DNS) before queuing the download. The egress proxy resolves
        # and checks every address again at connection time.
        validate_github_repo_url(artifact.source_url)

    with staging_area(session, scan, settings, analyzer, job) as staging:
        job = replace(job, staging_volume=staging.volume)
        if has_upload:
            extract_upload(session, scan, analyzer, job)
        else:
            fetched = fetch_artifact(
                session,
                scan,
                require_fetcher(providers),
                FetchJob(
                    scan_id=scan.id,
                    workspace=workspace,
                    source="github",
                    url=artifact.source_url,
                    revision=scan.revision_requested,
                    staging_volume=staging.volume,
                    uid=staging.uid,
                    gid=staging.gid,
                ),
            )
            commit_sha = fetched.result.commit_sha

        collected = analyze_tree(session, scan, analyzer, job)
        if collected.tree.file_count == 0:
            raise AppError(ErrorCode.EMPTY_ARTIFACT, "Artifact contains no files", 400)
        tree = check_tree(collected, settings)
        persist_tree(session, scan, analyzer, job, settings, collected.tree)

    return IngestEvidence(
        tree=tree,
        archive_sha256=archive_sha256,
        commit_sha=commit_sha,
        revision_requested=scan.revision_requested,
        manifests=ManifestScan(
            [Manifest(m.path, m.ecosystem, m.kind) for m in collected.manifests],
            collected.manifests_truncated,
        ),
        project_packages=[
            ProjectPackage(p.ecosystem, p.name, p.version, p.manifest)
            for p in collected.project_packages
        ],
        file_paths=list(collected.file_paths),
        collected=collected,
    )


def _run_evidence_stages(
    session: Session,
    scan_id: UUID,
    workspace: Workspace,
    settings: Settings,
    providers: ScanProviders,
    ingested: "SoftwareIngest",
) -> None:
    """Steps 4, 6-18. Each stage records its own status and never raises."""
    collected = ingested.evidence.collected
    sbom = run_sbom_stage(
        session,
        scan_id,
        workspace,
        settings,
        CollectedSbom(
            collected.sbom_provider or settings.sbom_provider, collected, ingested.sbom_path
        ),
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
    run_static_stage(session, scan_id, collected, StaticExtras())
    run_sandbox_stage(session, scan_id, workspace, settings, providers.sandbox, "software")
    run_risk_stage(session, scan_id, settings, CollectedRiskInputs.from_analysis(collected))


@dataclass(frozen=True)
class SoftwareIngest:
    evidence: IngestEvidence
    root_label: str
    file_paths: list[str]
    sbom_path: Path


def run_software_ingestion(
    scan_id: UUID,
    session_factory: sessionmaker[Session],
    settings: Settings,
    providers: ScanProviders | None = None,
    claim: ScanClaim | None = None,
) -> None:
    """Background entry point: ingest and analyze the artifact of `scan_id`. Never raises."""
    resolved = providers or build_providers(settings)

    def ingest(session: Session, scan: Scan, workspace: Workspace) -> SoftwareIngest:
        evidence = _ingest(session, scan, workspace, settings, require_analyzer(resolved), resolved)
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
        return SoftwareIngest(
            evidence, artifact.name, evidence.file_paths, workspace.root / SBOM_INCOMING
        )

    def evidence_stages(
        session: Session, sid: UUID, workspace: Workspace, ingested: SoftwareIngest
    ) -> None:
        _run_evidence_stages(session, sid, workspace, settings, resolved, ingested)

    def anchor(session: Session, sid: UUID) -> None:
        run_anchor_stage(session, sid, settings, resolved.chain)

    run_scan(
        scan_id,
        session_factory,
        settings,
        ingest,
        evidence_stages,
        anchor,
        require_decision=True,
        claim=claim,
    )
