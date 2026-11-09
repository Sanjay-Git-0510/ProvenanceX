"""Scan endpoints: software (Phase 1) and AI/model (Phase 3) ingestion, findings, graph."""

import logging
import re
from collections.abc import Callable
from pathlib import PurePosixPath
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, Query, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload, sessionmaker

from app.core.config import Settings, get_settings
from app.core.errors import AppError, ErrorCode
from app.db.database import get_sessionmaker
from app.db.models import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Component,
    Finding,
    FindingCategory,
    GraphEdge,
    GraphNode,
    Scan,
    ScanStatus,
)
from app.graph.dependency_graph import ROOT_KEY
from app.pipeline.model import run_model_ingestion
from app.pipeline.providers import ScanProviders, build_providers
from app.pipeline.software import run_software_ingestion
from app.pipeline.workspace import MB, create_workspace, remove_workspace, write_stream_limited
from app.risk.service import risk_for_scan
from app.schemas.findings import FindingOut, FindingsResponse, Severity
from app.schemas.graph import GraphEdgeOut, GraphNodeOut, GraphResponse
from app.schemas.risk import RiskResponse
from app.schemas.scans import ScanCreatedResponse, ScanResponse
from app.security.revision import validate_revision
from app.security.url_validation import validate_github_repo_url, validate_hf_repo_url

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scans", tags=["scans"])

_NAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def get_session_factory() -> sessionmaker[Session]:
    """Dependency so tests can swap in a different database."""
    return get_sessionmaker()


SettingsDep = Annotated[Settings, Depends(get_settings)]
SessionFactoryDep = Annotated[sessionmaker[Session], Depends(get_session_factory)]


def get_scan_providers(settings: SettingsDep) -> ScanProviders:
    """Dependency so tests can inject providers (SBOM/vulnerability adapters)."""
    return build_providers(settings)


ProvidersDep = Annotated[ScanProviders, Depends(get_scan_providers)]


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


def _check_upload_name(filename: str) -> None:
    if not filename.lower().endswith(".zip"):
        raise AppError(ErrorCode.UNSUPPORTED_MEDIA_TYPE, "Only .zip uploads are supported", 415)


def _exactly_one(url: str | None, file: UploadFile | None) -> tuple[str | None, bool]:
    cleaned = (url or "").strip() or None
    has_file = file is not None and bool(file.filename)
    if bool(cleaned) == has_file:
        raise AppError(ErrorCode.INVALID_INPUT, "Provide exactly one of source_url or file", 400)
    return cleaned, has_file


def _queue_scan(
    *,
    background_tasks: BackgroundTasks,
    settings: Settings,
    session_factory: sessionmaker[Session],
    providers: ScanProviders,
    runner: Callable[..., None],
    artifact_type: ArtifactType,
    name: str,
    source: ArtifactSource,
    source_url: str | None,
    revision: str | None,
    file: UploadFile | None,
) -> ScanCreatedResponse:
    """Create the workspace, store the upload, persist Artifact+Scan, queue the pipeline."""
    scan_id, artifact_id = uuid4(), uuid4()
    workspace = create_workspace(settings.workspace_root, scan_id)
    try:
        if file is not None:
            write_stream_limited(file.file, workspace.upload_path, settings.max_upload_mb * MB)
        with session_factory() as session:
            artifact = Artifact(
                id=artifact_id,
                artifact_type=artifact_type,
                name=name,
                version=revision,
                source=source,
                source_url=source_url,
            )
            scan = Scan(
                id=scan_id,
                artifact=artifact,
                status=ScanStatus.QUEUED,
                scanner_version=settings.scanner_version,
                revision_requested=revision,
            )
            session.add_all([artifact, scan])
            session.commit()
    except Exception:
        remove_workspace(workspace, settings.workspace_root)
        raise

    background_tasks.add_task(runner, scan_id, session_factory, settings, providers)
    logger.info("Scan %s queued (type=%s, source=%s)", scan_id, artifact_type, source)
    return ScanCreatedResponse(scan_id=scan_id, artifact_id=artifact_id, status=ScanStatus.QUEUED)


@router.post("/software", status_code=202, response_model=ScanCreatedResponse)
def create_software_scan(
    background_tasks: BackgroundTasks,
    settings: SettingsDep,
    session_factory: SessionFactoryDep,
    providers: ProvidersDep,
    source_url: Annotated[str | None, Form(max_length=2048)] = None,
    revision: Annotated[str | None, Form(max_length=255)] = None,
    name: Annotated[str | None, Form(max_length=255)] = None,
    file: Annotated[UploadFile | None, File()] = None,
) -> ScanCreatedResponse:
    """Start a software scan from a GitHub URL or an uploaded ZIP (multipart form)."""
    url, has_file = _exactly_one(source_url, file)
    rev = validate_revision(revision)
    display_name = _clean_name(name)

    if url:
        repo = validate_github_repo_url(url)
        source, canonical_url = ArtifactSource.GITHUB, repo.canonical_url
        display_name = display_name or f"{repo.owner}/{repo.repo}"
    else:
        assert file is not None  # noqa: S101 - narrowed by _exactly_one
        _check_upload_name(file.filename or "")
        source, canonical_url = ArtifactSource.UPLOAD, None
        display_name = display_name or _name_from_filename(file.filename or "")

    return _queue_scan(
        background_tasks=background_tasks,
        settings=settings,
        session_factory=session_factory,
        providers=providers,
        runner=run_software_ingestion,
        artifact_type=ArtifactType.SOFTWARE,
        name=display_name,
        source=source,
        source_url=canonical_url,
        revision=rev,
        file=file if has_file else None,
    )


ModelArtifactType = Literal["model", "lora", "dataset"]


@router.post("/model", status_code=202, response_model=ScanCreatedResponse)
def create_model_scan(
    background_tasks: BackgroundTasks,
    settings: SettingsDep,
    session_factory: SessionFactoryDep,
    providers: ProvidersDep,
    source_url: Annotated[str | None, Form(max_length=2048)] = None,
    revision: Annotated[str | None, Form(max_length=255)] = None,
    name: Annotated[str | None, Form(max_length=255)] = None,
    artifact_type: Annotated[ModelArtifactType | None, Form()] = None,
    file: Annotated[UploadFile | None, File()] = None,
) -> ScanCreatedResponse:
    """Start an AI/ML scan from a Hugging Face repo URL or an uploaded model-directory ZIP.

    artifact_type: model (default), lora or dataset. A `huggingface.co/datasets/...` URL is
    always a dataset. Files are only parsed; nothing from the artifact is executed.
    """
    url, has_file = _exactly_one(source_url, file)
    rev = validate_revision(revision)
    display_name = _clean_name(name)
    kind = ArtifactType(artifact_type) if artifact_type else None

    if url:
        repo = validate_hf_repo_url(url)
        if repo.repo_type == "dataset":
            if kind not in (None, ArtifactType.DATASET):
                raise AppError(
                    ErrorCode.INVALID_INPUT,
                    "A Hugging Face dataset URL requires artifact_type=dataset",
                    400,
                )
            kind = ArtifactType.DATASET
        elif kind == ArtifactType.DATASET:
            raise AppError(
                ErrorCode.INVALID_INPUT,
                "artifact_type=dataset requires a https://huggingface.co/datasets/... URL",
                400,
            )
        source, canonical_url = ArtifactSource.HUGGINGFACE, repo.canonical_url
        display_name = display_name or repo.repo_id
    else:
        assert file is not None  # noqa: S101 - narrowed by _exactly_one
        _check_upload_name(file.filename or "")
        source, canonical_url = ArtifactSource.UPLOAD, None
        display_name = display_name or _name_from_filename(file.filename or "")

    return _queue_scan(
        background_tasks=background_tasks,
        settings=settings,
        session_factory=session_factory,
        providers=providers,
        runner=run_model_ingestion,
        artifact_type=kind or ArtifactType.MODEL,
        name=display_name,
        source=source,
        source_url=canonical_url,
        revision=rev,
        file=file if has_file else None,
    )


def _get_scan_or_404(session: Session, scan_id: UUID) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise AppError(ErrorCode.SCAN_NOT_FOUND, "Scan not found", 404)
    return scan


def _count(session: Session, model: type[Component] | type[Finding], scan_id: UUID) -> int:
    return (
        session.scalar(select(func.count()).select_from(model).where(model.scan_id == scan_id)) or 0
    )


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: UUID, session_factory: SessionFactoryDep) -> ScanResponse:
    with session_factory() as session:
        scan = _get_scan_or_404(session, scan_id)
        return ScanResponse.from_scan(
            scan,
            component_count=_count(session, Component, scan_id),
            finding_count=_count(session, Finding, scan_id),
        )


_FINDING_STAGES = {
    "vulnerability": "vulnerabilities",
    "static": "static",
    "behavioral": "sandbox",
    "provenance": "provenance",
}


@router.get("/{scan_id}/findings", response_model=FindingsResponse)
def get_scan_findings(
    scan_id: UUID,
    session_factory: SessionFactoryDep,
    category: FindingCategory | None = None,
    severity: Severity | None = None,
    source: Annotated[str | None, Query(max_length=16, pattern=r"^[a-z]+$")] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> FindingsResponse:
    """Findings for a scan, highest CVSS first. Filters: category, severity, source."""
    with session_factory() as session:
        scan = _get_scan_or_404(session, scan_id)
        conditions = [Finding.scan_id == scan_id]
        if category is not None:
            conditions.append(Finding.category == category)
        if severity is not None:
            conditions.append(Finding.severity == severity)
        if source is not None:
            conditions.append(Finding.source == source)
        total = session.scalar(select(func.count()).select_from(Finding).where(*conditions)) or 0
        rows = session.scalars(
            select(Finding)
            .where(*conditions)
            .options(selectinload(Finding.component))
            .order_by(Finding.cvss_score.desc().nulls_last(), Finding.identifier, Finding.id)
            .limit(limit)
            .offset(offset)
        ).all()
        contains_mock = bool(
            session.scalar(
                select(func.count())
                .select_from(Finding)
                .where(Finding.scan_id == scan_id, Finding.source == "mock")
            )
        )
        return FindingsResponse(
            scan_id=scan_id,
            total=total,
            limit=limit,
            offset=offset,
            items=[FindingOut.from_row(f) for f in rows],
            contains_mock=contains_mock,
            stage=(scan.stages or {}).get("vulnerabilities"),
            stages={
                cat: (scan.stages or {}).get(name)
                for cat, name in _FINDING_STAGES.items()
                if (scan.stages or {}).get(name) is not None
            },
        )


@router.get("/{scan_id}/graph", response_model=GraphResponse)
def get_scan_graph(scan_id: UUID, session_factory: SessionFactoryDep) -> GraphResponse:
    """Dependency graph (software) or model-lineage graph (AI), plus features and limitations."""
    with session_factory() as session:
        scan = _get_scan_or_404(session, scan_id)
        nodes = session.scalars(
            select(GraphNode).where(GraphNode.scan_id == scan_id).order_by(GraphNode.node_key)
        ).all()
        edges = session.scalars(
            select(GraphEdge)
            .where(GraphEdge.scan_id == scan_id)
            .order_by(GraphEdge.source_key, GraphEdge.target_key)
        ).all()
        stage = (scan.stages or {}).get("graph")
        source = (stage or {}).get("source")
        return GraphResponse(
            scan_id=scan_id,
            root_key=ROOT_KEY,
            graph_kind=(stage or {}).get("graph_kind"),
            source=source,
            is_mock=source == "mock",
            nodes=[
                GraphNodeOut(
                    key=n.node_key,
                    node_type=n.node_type,
                    label=n.label,
                    component_id=n.component_id,
                    attributes=n.attributes or {},
                )
                for n in nodes
            ],
            edges=[
                GraphEdgeOut(
                    source=e.source_key,
                    target=e.target_key,
                    relation=e.relation,
                    origin=e.origin,
                    attributes=e.attributes,
                )
                for e in edges
            ],
            features=(stage or {}).get("features"),
            limitations=list((stage or {}).get("limitations") or []),
            stage=stage,
        )


@router.get("/{scan_id}/risk", response_model=RiskResponse)
def get_scan_risk(
    scan_id: UUID, session_factory: SessionFactoryDep, settings: SettingsDep
) -> RiskResponse:
    """The explainable risk result. risk_score is null, never 0, when it cannot be computed."""
    with session_factory() as session:
        return risk_for_scan(session, _get_scan_or_404(session, scan_id), settings)
