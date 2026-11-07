"""Software scan pipeline, Phase 1 portion.

Implements CLAUDE.md pipeline steps 1-3 for software artifacts, plus manifest detection:
  1. receive input / scan_id   (the API creates the Scan row and workspace)
  2. safe working directory    (ZIP extraction or hardened git fetch into workspace/src)
  3. SHA-256                   (provenancex-tree-v1 content digest; raw ZIP hash for uploads)
Later phases add their steps after `_ingest`.

`run_software_ingestion` never raises. Every failure is recorded on the Scan as a
structured error (code, message, details), and the workspace is removed.
"""

import logging
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.core.hashing import TREE_DIGEST_VERSION, TreeDigest, sha256_file, tree_digest
from app.db.models import ArtifactSource, Scan, ScanStatus, utcnow
from app.pipeline.workspace import MB, Workspace, open_workspace, remove_workspace
from app.scanners.git_fetch import CloneLimits, clone_repository
from app.scanners.manifests import ManifestScan, detect_manifests
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
    )


def _record_failure(
    session: Session, scan_id: UUID, code: str, message: str, details: Any = None
) -> None:
    try:
        scan = session.get(Scan, scan_id)
        if scan is None:
            logger.error("Scan %s vanished while recording failure %s", scan_id, code)
            return
        scan.status = ScanStatus.FAILED
        scan.error_code = str(code)
        scan.error_message = message
        scan.error_details = details
        scan.finished_at = utcnow()
        session.commit()
    except SQLAlchemyError:
        logger.exception("Could not record failure %s for scan %s", code, scan_id)
        session.rollback()


def run_software_ingestion(
    scan_id: UUID, session_factory: sessionmaker[Session], settings: Settings
) -> None:
    """Background entry point: ingest the artifact of `scan_id` and record the outcome."""
    with session_factory() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            logger.error("Scan %s not found; nothing to ingest", scan_id)
            return
        scan.status = ScanStatus.RUNNING
        scan.started_at = utcnow()
        session.commit()

        workspace: Workspace | None = None
        try:
            workspace = open_workspace(settings.workspace_root, scan_id)
            evidence = _ingest(scan, workspace, settings)

            artifact = scan.artifact
            artifact.sha256 = evidence.tree.sha256
            artifact.collected_at = utcnow()
            if artifact.version is None and evidence.commit_sha:
                artifact.version = evidence.commit_sha
            scan.ingest_metadata = evidence.to_metadata()
            scan.status = ScanStatus.COMPLETED
            scan.finished_at = utcnow()
            session.commit()
            logger.info(
                "Scan %s ingested: %s files, sha256=%s",
                scan_id,
                evidence.tree.file_count,
                evidence.tree.sha256,
            )
            return
        except AppError as exc:
            logger.warning("Scan %s failed: %s (%s)", scan_id, exc.code, exc.message)
            session.rollback()
            _record_failure(session, scan_id, exc.code, exc.message, exc.details)
        except Exception:
            logger.exception("Unexpected error while ingesting scan %s", scan_id)
            session.rollback()
            _record_failure(
                session,
                scan_id,
                ErrorCode.INTERNAL_ERROR,
                "Ingestion failed due to an internal error",
            )

        if workspace is not None:
            remove_workspace(workspace, settings.workspace_root)
