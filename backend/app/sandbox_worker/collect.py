"""Collect artifact evidence. Runs only inside the analyzer container (or the pytest-only
in-process executor), never in the API or the scan-runner.

Two modes, each a separate container run:
  extract  the raw upload (read-only) -> the per-scan src directory (the only writable mount).
  analyze  the src directory (read-only) -> one JSON result on stdout. Nothing is written.

Each evidence section (SBOM, AI-BOM, static, config digest, declared versions) is captured on
its own. A failing section becomes a structured section error, so one failing tool is recorded
as that stage's failure on the host, exactly as before, and never fails the whole scan. Only a
failure to read the tree itself (unsafe content, too many files) fails the analysis.
"""

import logging
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.core.hashing import list_tree_files, tree_digest
from app.ml.comparison import config_digest, declared_versions
from app.pipeline.workspace import MB
from app.sandbox_worker.protocol import WorkerRequest
from app.scanners.manifests import detect_manifests, detect_project_packages
from app.scanners.model.aibom import ModelAnalysis, ModelContext, analyze_model
from app.scanners.model.inventory import RemoteOnlyFile
from app.scanners.sbom.base import SbomProvider
from app.scanners.sbom.mock import MockSbomProvider
from app.scanners.sbom.syft import SyftProvider
from app.scanners.static.analyzer import StaticLimits, StaticResult, analyze_artifact
from app.security.archive import ArchiveLimits, safe_extract_zip
from app.security.sandbox_guard import require_worker_context

logger = logging.getLogger(__name__)
T = TypeVar("T")
KB = 1024


def settings_for(request: WorkerRequest) -> Settings:
    """Analysis settings come only from the request, never from the container environment."""
    limits = request.limits.model_dump()
    return Settings(_env_file=None, sbom_provider=request.sbom_provider, **limits)


def section_error(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, AppError):
        return {"code": str(exc.code), "message": exc.message[:2000], "details": exc.details}
    # The traceback goes to stderr (captured, capped and logged by the runner), not the result.
    traceback.print_exception(exc)
    return {
        "code": str(ErrorCode.INTERNAL_ERROR),
        "message": f"Analyzer section failed ({exc.__class__.__name__})",
        "details": None,
    }


def _section(fn: Callable[[], T]) -> tuple[T | None, dict[str, Any] | None]:
    try:
        return fn(), None
    except Exception as exc:  # noqa: BLE001 - every failure becomes a structured section error
        return None, section_error(exc)


# --------------------------------------------------------------------------- extract
def run_extract(request: WorkerRequest, upload_path: Path, out_dir: Path) -> dict[str, Any]:
    """Extract the uploaded ZIP into out_dir with the archive safety checks of security/archive."""
    require_worker_context()
    s = settings_for(request)
    safe_extract_zip(
        upload_path,
        out_dir,
        ArchiveLimits(
            max_total_bytes=s.max_artifact_size_mb * MB,
            max_files=s.max_artifact_files,
            max_compression_ratio=s.max_compression_ratio,
        ),
    )
    return {}


# --------------------------------------------------------------------------- analyze
def _sbom_provider(s: Settings) -> SbomProvider:
    if s.sbom_provider == "mock":
        return MockSbomProvider()
    return SyftProvider(s.syft_path, s.syft_timeout_seconds, s.max_sbom_mb * MB)


def _sbom(s: Settings, src: Path, scratch: Path, provider: SbomProvider) -> dict[str, Any]:
    result = provider.generate(src, scratch)
    if len(result.raw) > s.max_sbom_mb * MB:
        raise AppError(ErrorCode.SBOM_TOO_LARGE, "SBOM exceeds the size limit", 502)
    try:
        raw = result.raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AppError(ErrorCode.SBOM_PARSE_ERROR, "SBOM is not valid UTF-8", 502) from exc
    return {
        "raw": raw,
        "source": result.source,
        "tool_name": result.tool_name,
        "tool_version": result.tool_version,
        "format": result.format,
    }


def _model_context(request: WorkerRequest) -> ModelContext:
    ctx = request.model_context
    if ctx is None:
        raise AppError(ErrorCode.INVALID_INPUT, "A model analysis needs a model context", 400)
    return ModelContext(
        name=ctx.name,
        artifact_type=ctx.artifact_type,
        source=ctx.source,
        source_url=ctx.source_url,
        repo_id=ctx.repo_id,
        commit_sha=ctx.commit_sha,
        remote_only=[
            RemoteOnlyFile(r.path, r.size, r.remote_sha256, r.skip_reason) for r in ctx.remote_only
        ],
        remote_hashes=dict(ctx.remote_hashes),
        api_card_data=ctx.api_card_data,
        api_meta=dict(ctx.api_meta),
    )


def static_limits(s: Settings) -> StaticLimits:
    return StaticLimits(
        max_files=s.static_max_files,
        max_file_bytes=s.static_max_file_kb * KB,
        max_total_bytes=s.static_max_total_mb * MB,
        max_findings=s.static_max_findings,
        max_compression_ratio=s.max_compression_ratio,
        ratio_warn_fraction=s.static_archive_ratio_warn_fraction,
    )


def static_to_dict(result: StaticResult) -> dict[str, Any]:
    return {
        "features": result.features,
        "findings": [
            {
                "rule": {
                    "id": g.rule.id,
                    "kind": g.rule.kind,
                    "severity": g.rule.severity,
                    "title": g.rule.title,
                },
                "file": g.file,
                "occurrences": g.occurrences,
                "lines": g.lines,
                "cells": g.cells,
                "symbols": g.symbols,
            }
            for g in result.findings
        ],
        "findings_truncated": result.findings_truncated,
        "not_analyzed": result.not_analyzed,
        "not_analyzed_count": result.not_analyzed_count,
        "limitations": result.limitations,
    }


def _model_static_inputs(
    analysis: ModelAnalysis | None, ctx: ModelContext | None
) -> dict[str, Any]:
    """Pickle and auto_map evidence comes from the AI-BOM, so no finding is duplicated."""
    if ctx is None:
        return {}
    extras: dict[str, Any] = {"undownloaded_files": len(ctx.remote_only)}
    if analysis is not None:
        extras["pickle_dangerous_globals"] = sum(
            len(f.analysis["pickle"]["dangerous_globals"])
            for f in analysis.inventory
            if f.analysis.get("pickle") is not None
        )
        extras["auto_map_targets"] = sum(len(m) for m in analysis.custom_code.auto_map.values())
    return extras


def run_analyze(
    request: WorkerRequest,
    src: Path,
    upload_path: Path | None,
    scratch: Path,
    *,
    sbom_provider: SbomProvider | None = None,
) -> dict[str, Any]:
    """Analyze the artifact tree at `src`. Raises AppError only if the tree is unreadable.

    `sbom_provider` is a test hook used only by the in-process test executor; the container
    always builds its provider from the request.
    """
    require_worker_context()
    s = settings_for(request)
    tree = tree_digest(src, max_files=s.max_artifact_files)
    file_paths = [
        rel.decode("utf-8", errors="replace")
        for rel, _ in list_tree_files(src, max_files=s.max_artifact_files)
    ]
    out: dict[str, Any] = {
        "tree": {
            "sha256": tree.sha256,
            "file_count": tree.file_count,
            "total_bytes": tree.total_bytes,
        },
        "file_paths": file_paths,
    }

    analysis: ModelAnalysis | None = None
    ctx: ModelContext | None = None
    if request.kind == "software":
        manifests = detect_manifests(src)
        out["manifests"] = [
            {"path": m.path, "ecosystem": m.ecosystem, "kind": m.kind} for m in manifests.manifests
        ]
        out["manifests_truncated"] = manifests.truncated
        out["project_packages"] = [
            {"ecosystem": p.ecosystem, "name": p.name, "version": p.version, "manifest": p.manifest}
            for p in detect_project_packages(src)
        ]
        provider = sbom_provider or _sbom_provider(s)
        out["sbom_provider"] = str(provider.name)[:32]
        out["sbom"], out["sbom_error"] = _section(lambda: _sbom(s, src, scratch, provider))
    else:
        ctx = _model_context(request)
        analysis, out["aibom_error"] = _section(lambda: analyze_model(src, ctx, s))
        out["aibom"] = analysis.aibom if analysis is not None else None

    upload = upload_path if request.has_upload else None
    extras = _model_static_inputs(analysis, ctx)
    static, out["static_error"] = _section(
        lambda: analyze_artifact(
            src, static_limits(s), upload_path=upload, max_tree_files=s.max_artifact_files, **extras
        )
    )
    out["static"] = static_to_dict(static) if static is not None else None
    out["config_sha256"], out["config_sha256_error"] = _section(lambda: config_digest(src))
    out["declared_versions"], out["declared_versions_error"] = _section(
        lambda: declared_versions(src, request.revision_requested)
    )
    return out
