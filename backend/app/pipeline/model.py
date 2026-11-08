"""AI/ML scan pipeline (models, LoRA adapters, datasets).

Implements CLAUDE.md pipeline steps for AI artifacts:
  1. receive input / scan_id   (the API creates the Scan row and workspace)
  2. safe working directory    (ZIP extraction, or a capped Hugging Face download)
  3. SHA-256                   (provenancex-tree-v1 over local content; for HF also a
                                manifest digest over the full remote listing)
  5. AI-BOM / lineage record   (inventory, formats, configs, card, adapters)  [aibom_stage]
  6. lineage graph             (NetworkX -> GraphNode/GraphEdge rows)          [lineage_stage]
  7. OSV lookup                (exactly pinned runtime requirements only)      [vuln_stage]
  8. provenance/integrity      (ProvenanceRecord + provenance Findings)        [provenance_stage]
  9. static analysis           (static features + static Findings)             [static_stage]

Nothing from the artifact is executed, imported or deserialized. The lifecycle (failure
handling, workspace cleanup) is shared with the software pipeline (lifecycle.py).
"""

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.core.hashing import TREE_DIGEST_VERSION, sha256_file, tree_digest
from app.db.models import ArtifactSource, Scan, utcnow
from app.pipeline.aibom_stage import AiBomStageOutput, run_aibom_stage
from app.pipeline.lifecycle import run_scan
from app.pipeline.lineage_stage import run_lineage_stage
from app.pipeline.provenance_stage import ProvenanceExtras, run_provenance_stage
from app.pipeline.providers import ScanProviders, build_providers
from app.pipeline.stages import skip_stage
from app.pipeline.static_stage import StaticExtras, run_static_stage
from app.pipeline.vuln_stage import run_vuln_stage
from app.pipeline.workspace import MB, Workspace
from app.scanners.hf.base import HfFetchLimits, HfFetchResult
from app.scanners.model.aibom import ModelContext
from app.scanners.model.inventory import RemoteOnlyFile
from app.security.archive import ArchiveLimits, safe_extract_zip
from app.security.url_validation import validate_hf_repo_url

logger = logging.getLogger(__name__)

HF_MANIFEST_VERSION = "provenancex-hf-manifest-v1"
HF_LISTING_FILENAME = "hf_listing.json"


@dataclass
class ModelIngest:
    ctx: ModelContext
    hf: HfFetchResult | None
    file_paths: list[str]
    manifest_sha256: str | None = None


def hf_manifest_digest(result: HfFetchResult) -> str:
    """Digest over the complete remote listing (path, content id, size), downloaded or not.

    It detects changes to files that were too large to download, which the local tree
    digest cannot see. Content id = LFS SHA-256, else the git blob id.
    """
    digest = hashlib.sha256(f"{HF_MANIFEST_VERSION}\n".encode())
    for f in sorted(result.files, key=lambda x: x.path.encode()):
        content_id = f.lfs_sha256 or f.git_oid or ""
        digest.update(f.path.encode() + b"\0" + content_id.encode() + b"\0" + str(f.size).encode())
        digest.update(b"\n")
    return digest.hexdigest()


def _write_private(path: os.PathLike[str], data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _fetch_hf(
    scan: Scan, workspace: Workspace, settings: Settings, providers: ScanProviders
) -> HfFetchResult:
    if providers.hf is None:
        raise AppError(ErrorCode.HF_UNAVAILABLE, "No Hugging Face provider is configured", 503)
    # Re-validate (including DNS) just before network access.
    repo = validate_hf_repo_url(scan.artifact.source_url)
    limits = HfFetchLimits(
        max_total_bytes=settings.max_artifact_size_mb * MB,
        max_file_bytes=settings.hf_max_file_mb * MB,
        max_files=min(settings.hf_max_files, settings.max_artifact_files),
        timeout_seconds=settings.hf_download_timeout_seconds,
    )
    result = providers.hf.fetch(repo, scan.revision_requested, workspace.src_dir, limits)
    listing = {
        "source": result.source,
        "repo_id": repo.repo_id,
        "repo_type": repo.repo_type,
        "commit_sha": result.commit_sha,
        "files": [f.to_dict() for f in result.files],
    }
    _write_private(
        workspace.root / HF_LISTING_FILENAME, json.dumps(listing, indent=2).encode("utf-8")
    )
    return result


def _ingest(
    session: Session,
    scan: Scan,
    workspace: Workspace,
    settings: Settings,
    providers: ScanProviders,
) -> ModelIngest:
    artifact = scan.artifact
    max_bytes = settings.max_artifact_size_mb * MB
    archive_sha256: str | None = None
    hf: HfFetchResult | None = None

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
    elif artifact.source == ArtifactSource.HUGGINGFACE:
        hf = _fetch_hf(scan, workspace, settings, providers)
    else:
        raise AppError(ErrorCode.INVALID_INPUT, "Unsupported source for a model scan", 400)

    tree = tree_digest(workspace.src_dir, max_files=settings.max_artifact_files)
    if tree.file_count == 0 and not (hf and hf.files):
        raise AppError(ErrorCode.EMPTY_ARTIFACT, "Artifact contains no files", 400)
    if tree.total_bytes > max_bytes:
        raise AppError(
            ErrorCode.ARTIFACT_TOO_LARGE,
            "Artifact exceeds the size limit",
            413,
            {"max_bytes": max_bytes},
        )

    remote_only: list[RemoteOnlyFile] = []
    remote_hashes: dict[str, str | None] = {}
    hf_meta: dict[str, Any] | None = None
    if hf is not None:
        for f in hf.files:
            if f.downloaded:
                remote_hashes[f.path] = f.lfs_sha256
            else:
                remote_only.append(
                    RemoteOnlyFile(f.path, f.size, f.lfs_sha256, f.reason or f.status)
                )
        hf_meta = {
            "source": hf.source,
            "repo_id": hf.repo.repo_id,
            "repo_type": hf.repo.repo_type,
            "manifest_sha256": hf_manifest_digest(hf),
            "manifest_version": HF_MANIFEST_VERSION,
            "counts": hf.counts(),
            "warnings": hf.warnings,
            "meta": hf.meta,
        }

    commit_sha = hf.commit_sha if hf else None
    artifact.sha256 = tree.sha256
    artifact.collected_at = utcnow()
    if artifact.version is None and commit_sha:
        artifact.version = commit_sha
    scan.ingest_metadata = {
        "file_count": tree.file_count,
        "total_bytes": tree.total_bytes,
        "tree_digest_version": TREE_DIGEST_VERSION,
        "archive_sha256": archive_sha256,
        "commit_sha": commit_sha,
        "revision_requested": scan.revision_requested,
        "manifests": [],
        "manifests_truncated": False,
        "hf": hf_meta,
    }
    session.commit()
    logger.info(
        "Model scan %s ingested: %s local files, sha256=%s", scan.id, tree.file_count, tree.sha256
    )

    ctx = ModelContext(
        name=artifact.name,
        artifact_type=str(artifact.artifact_type),
        source=str(artifact.source),
        source_url=artifact.source_url,
        repo_id=hf.repo.repo_id if hf else None,
        commit_sha=commit_sha,
        remote_only=remote_only,
        remote_hashes=remote_hashes,
        api_card_data=hf.card_data if hf else None,
        api_meta=hf.meta if hf else {},
    )
    paths = [f.path for f in hf.files] if hf else []
    manifest = hf_meta["manifest_sha256"] if hf_meta else None
    return ModelIngest(ctx=ctx, hf=hf, file_paths=paths, manifest_sha256=manifest)


def _run_evidence_stages(
    session: Session,
    scan_id: UUID,
    workspace: Workspace,
    settings: Settings,
    providers: ScanProviders,
    ingested: ModelIngest,
) -> None:
    """Steps 5, 6, 7, 8, 9. Each stage records its own status and never raises."""
    input_source = ingested.hf.source if ingested.hf else "upload"
    aibom = run_aibom_stage(session, scan_id, workspace, settings, ingested.ctx, input_source)
    lineage: dict[str, Any] | None = None
    if aibom is None:
        skip_stage(session, scan_id, "graph", "aibom stage did not succeed")
        skip_stage(session, scan_id, "vulnerabilities", "aibom stage did not succeed")
    else:
        lineage = run_lineage_stage(
            session,
            scan_id,
            aibom,
            ingested.ctx.name,
            ingested.ctx.artifact_type,
            ingested.ctx.repo_id,
        )
        pinned = [c for c in aibom.vuln_input.parsed.components if c.version]
        if pinned:
            run_vuln_stage(session, scan_id, aibom.vuln_input, providers)
        else:
            skip_stage(
                session,
                scan_id,
                "vulnerabilities",
                "no exactly pinned runtime dependencies (name==version) to look up",
            )
    hf = ingested.hf
    run_provenance_stage(
        session,
        scan_id,
        workspace,
        ProvenanceExtras(
            hf_files=[f.to_dict() for f in hf.files] if hf else None,
            hf_source=hf.source if hf else None,
            manifest_sha256=ingested.manifest_sha256,
            lineage_features=lineage,
            file_paths=ingested.file_paths,
        ),
        settings.max_artifact_files,
    )
    run_static_stage(
        session,
        scan_id,
        workspace,
        settings,
        _static_extras(input_source, aibom, hf),
    )


def _static_extras(
    input_source: str, aibom: AiBomStageOutput | None, hf: HfFetchResult | None
) -> StaticExtras:
    """Pickle and auto_map evidence comes from the AI-BOM, so no finding is duplicated."""
    pickle_dangerous: int | None = None
    auto_map_targets = 0
    if aibom is not None:
        analysis = aibom.analysis
        pickle_dangerous = sum(
            len(f.analysis["pickle"]["dangerous_globals"])
            for f in analysis.inventory
            if f.analysis.get("pickle") is not None
        )
        auto_map_targets = sum(len(m) for m in analysis.custom_code.auto_map.values())
    return StaticExtras(
        input_source=input_source,
        auto_map_targets=auto_map_targets,
        pickle_dangerous_globals=pickle_dangerous,
        undownloaded_files=sum(1 for f in hf.files if not f.downloaded) if hf else 0,
    )


def run_model_ingestion(
    scan_id: UUID,
    session_factory: sessionmaker[Session],
    settings: Settings,
    providers: ScanProviders | None = None,
) -> None:
    """Background entry point: ingest and analyze the AI artifact of `scan_id`. Never raises."""
    resolved = providers or build_providers(settings)

    def ingest(session: Session, scan: Scan, workspace: Workspace) -> ModelIngest:
        return _ingest(session, scan, workspace, settings, resolved)

    def evidence(session: Session, sid: UUID, workspace: Workspace, ingested: ModelIngest) -> None:
        _run_evidence_stages(session, sid, workspace, settings, resolved, ingested)

    run_scan(scan_id, session_factory, settings, ingest, evidence)
