"""Scan endpoints (Phase 1: software ingestion)."""

import logging
import re
from pathlib import PurePosixPath
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, UploadFile
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.core.errors import AppError, ErrorCode
from app.db.database import get_sessionmaker
from app.db.models import Artifact, ArtifactSource, ArtifactType, Scan, ScanStatus
from app.pipeline.software import run_software_ingestion
from app.pipeline.workspace import MB, create_workspace, remove_workspace, write_stream_limited
from app.schemas.scans import ScanCreatedResponse, ScanResponse
from app.security.revision import validate_revision
from app.security.url_validation import validate_github_repo_url

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scans", tags=["scans"])

_NAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def get_session_factory() -> sessionmaker[Session]:
    """Dependency so tests can swap in a different database."""
    return get_sessionmaker()


SettingsDep = Annotated[Settings, Depends(get_settings)]
SessionFactoryDep = Annotated[sessionmaker[Session], Depends(get_session_factory)]


def _clean_name(name: str | None) -> str | None:
    if name is None or not name.strip():
        return None
    cleaned = name.strip()
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in cleaned):
        raise AppError(ErrorCode.INVALID_INPUT, "name contains control characters", 400)
    return cleaned


def _name_from_filename(filename: str) -> str:
    """Display name derived from an upload filename. It is never used as a path."""
    stem = PurePosixPath(filename.replace("\\", "/")).name
    if stem.lower().endswith(".zip"):
        stem = stem[: -len(".zip")]
    return _NAME_SAFE_RE.sub("_", stem).strip("._")[:100] or "upload"


@router.post("/software", status_code=202, response_model=ScanCreatedResponse)
def create_software_scan(
    background_tasks: BackgroundTasks,
    settings: SettingsDep,
    session_factory: SessionFactoryDep,
    source_url: Annotated[str | None, Form(max_length=2048)] = None,
    revision: Annotated[str | None, Form(max_length=255)] = None,
    name: Annotated[str | None, Form(max_length=255)] = None,
    file: Annotated[UploadFile | None, File()] = None,
) -> ScanCreatedResponse:
    """Start a software scan from a GitHub URL or an uploaded ZIP (multipart form)."""
    url = (source_url or "").strip() or None
    has_file = file is not None and bool(file.filename)
    if bool(url) == has_file:
        raise AppError(ErrorCode.INVALID_INPUT, "Provide exactly one of source_url or file", 400)

    rev = validate_revision(revision)
    display_name = _clean_name(name)

    if url:
        repo = validate_github_repo_url(url)
        source, canonical_url = ArtifactSource.GITHUB, repo.canonical_url
        display_name = display_name or f"{repo.owner}/{repo.repo}"
    else:
        assert file is not None  # noqa: S101 - narrowed by the has_file check above
        filename = file.filename or ""
        if not filename.lower().endswith(".zip"):
            raise AppError(ErrorCode.UNSUPPORTED_MEDIA_TYPE, "Only .zip uploads are supported", 415)
        source, canonical_url = ArtifactSource.UPLOAD, None
        display_name = display_name or _name_from_filename(filename)

    scan_id, artifact_id = uuid4(), uuid4()
    workspace = create_workspace(settings.workspace_root, scan_id)
    try:
        if file is not None and has_file:
            write_stream_limited(file.file, workspace.upload_path, settings.max_upload_mb * MB)
        with session_factory() as session:
            artifact = Artifact(
                id=artifact_id,
                artifact_type=ArtifactType.SOFTWARE,
                name=display_name,
                version=rev,
                source=source,
                source_url=canonical_url,
            )
            scan = Scan(
                id=scan_id,
                artifact=artifact,
                status=ScanStatus.QUEUED,
                scanner_version=settings.scanner_version,
                revision_requested=rev,
            )
            session.add_all([artifact, scan])
            session.commit()
    except Exception:
        remove_workspace(workspace, settings.workspace_root)
        raise

    background_tasks.add_task(run_software_ingestion, scan_id, session_factory, settings)
    logger.info("Scan %s queued (source=%s)", scan_id, source)
    return ScanCreatedResponse(scan_id=scan_id, artifact_id=artifact_id, status=ScanStatus.QUEUED)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: UUID, session_factory: SessionFactoryDep) -> ScanResponse:
    with session_factory() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise AppError(ErrorCode.SCAN_NOT_FOUND, "Scan not found", 404)
        return ScanResponse.from_scan(scan)
