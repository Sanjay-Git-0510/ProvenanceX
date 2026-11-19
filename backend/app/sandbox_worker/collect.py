"""Collect artifact evidence. Runs only inside the analyzer container (or the pytest-only
in-process executor), never in the API or the scan-runner.

Three modes, each a separate container run:
  extract  the raw upload (read-only) -> the per-scan staging tmpfs volume (the only writable
           mount; its size is capped by the kernel, audit finding L1).
  analyze  the staging tree (read-only) -> one framed result on stdout; the SBOM is written to
           the container's own /tmp and sent as a separate frame (audit finding M3).
  persist  the staging tree (read-only) -> a bounded copy in the persistent workspace, so that
           /verify can re-hash it later. Returns the digest of what was written.

Each evidence section (SBOM, AI-BOM, static, config digest, declared versions) is captured on
its own. A failing section becomes a structured section error, so one failing tool is recorded
as that stage's failure on the host, exactly as before, and never fails the whole scan. Only a
failure to read the tree itself (unsafe content, too many files) fails the analysis.
"""

import errno
import hashlib
import logging
import os
import stat
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from app.core.bounded import clamp_details
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.core.evidence_files import AIBOM_FILENAME, PROVENANCE_FILENAME, SBOM_FILENAME
from app.core.hashing import list_tree_files, sha256_file, tree_digest
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
from app.security.archive import ArchiveLimits, safe_extract_zip, storage_limit_error
from app.security.sandbox_guard import require_worker_context

logger = logging.getLogger(__name__)
T = TypeVar("T")
KB = 1024


def settings_for(request: WorkerRequest) -> Settings:
    """Analysis settings come only from the request, never from the container environment."""
    limits = request.limits.model_dump()
    return Settings(_env_file=None, sbom_provider=request.sbom_provider, **limits)


def section_error(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
        exc = storage_limit_error()
    if isinstance(exc, AppError):
        return {
            "code": str(exc.code),
            "message": exc.message[:2000],
            "details": clamp_details(exc.details),
        }
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


def _sbom(
    s: Settings, src: Path, scratch: Path, provider: SbomProvider, sbom_out: Path
) -> dict[str, Any]:
    """Generate the SBOM and write its raw bytes to `sbom_out` (sent as its own frame)."""
    result = provider.generate(src, scratch)
    if len(result.raw) > s.max_sbom_mb * MB:
        raise AppError(ErrorCode.SBOM_TOO_LARGE, "SBOM exceeds the size limit", 502)
    try:
        result.raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AppError(ErrorCode.SBOM_PARSE_ERROR, "SBOM is not valid UTF-8", 502) from exc
    fd = os.open(sbom_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(result.raw)
    return {
        "size": len(result.raw),
        "sha256": hashlib.sha256(result.raw).hexdigest(),
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
    scratch: Path,  # noqa: ARG001 - kept for the call signature; analyze writes no scratch
) -> dict[str, Any]:
    """Analyze the artifact tree at `src`. Raises AppError only if the tree is unreadable.

    Syft does not run here: it runs alone in the `sbom` container (run_sbom, audit finding M4).
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
        # The SBOM is generated by the separate `sbom` container (run_sbom), never here.
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


# --------------------------------------------------------------------------- sbom
def run_sbom(
    request: WorkerRequest,
    src: Path,
    scratch: Path,
    *,
    sbom_out: Path,
    sbom_provider: SbomProvider | None = None,
) -> dict[str, Any]:
    """Generate the SBOM of `src` alone (audit finding M4), plus this container's own digest of
    the tree, which the runner requires to equal the analyze container's digest.

    The raw SBOM is written to `sbom_out` (a path that must not exist yet) and sent as its own
    frame. A Syft failure is a section error, never a failed run. `sbom_provider` is a test hook
    for the in-process executor; the container always builds its provider from the request.
    """
    require_worker_context()
    s = settings_for(request)
    if request.kind != "software":
        raise AppError(ErrorCode.INVALID_INPUT, "Only software artifacts get an SBOM", 400)
    tree = tree_digest(src, max_files=s.max_artifact_files)
    provider = sbom_provider or _sbom_provider(s)
    sbom, sbom_error = _section(lambda: _sbom(s, src, scratch, provider, sbom_out))
    return {
        "tree": {
            "sha256": tree.sha256,
            "file_count": tree.file_count,
            "total_bytes": tree.total_bytes,
        },
        "sbom_provider": str(provider.name)[:32],
        "sbom": sbom,
        "sbom_error": sbom_error,
    }


# --------------------------------------------------------------------------- persist
_COPY_CHUNK = 1024 * 1024


def rehash_tree(request: WorkerRequest, src: Path) -> dict[str, Any]:
    """The digest of `src` (the in-process test executor's persist, where staging == src)."""
    require_worker_context()
    s = settings_for(request)
    tree = tree_digest(src, max_files=s.max_artifact_files)
    return {"sha256": tree.sha256, "file_count": tree.file_count, "total_bytes": tree.total_bytes}


def _digest_or_status(compute: Callable[[], Any]) -> dict[str, Any]:
    """Map a hashing attempt onto the DigestOut statuses."""
    try:
        return {"status": "ok", **compute()}
    except FileNotFoundError:
        return {"status": "missing"}
    except AppError as exc:
        if exc.code == ErrorCode.UNSAFE_CONTENT:
            return {"status": "invalid"}
        return {"status": "unavailable"}
    except OSError as exc:
        logger.warning("rehash could not read evidence: %s", exc.__class__.__name__)
        return {"status": "unavailable"}


def _file_digest(path: Path, max_bytes: int) -> dict[str, Any]:
    def compute() -> dict[str, Any]:
        info = os.lstat(path)  # FileNotFoundError -> missing
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise AppError(ErrorCode.UNSAFE_CONTENT, "Evidence file is not a regular file", 400)
        if info.st_size > max_bytes:
            raise AppError(ErrorCode.ARTIFACT_TOO_LARGE, "Evidence file is too large", 413)
        return {"sha256": sha256_file(path, info), "file_count": 1, "total_bytes": info.st_size}

    return _digest_or_status(compute)


def _tree(src: Path, max_files: int, max_bytes: int) -> dict[str, Any]:
    def compute() -> dict[str, Any]:
        info = os.lstat(src)  # FileNotFoundError -> missing
        if stat.S_ISLNK(info.st_mode):
            raise AppError(ErrorCode.UNSAFE_CONTENT, "The artifact tree is a symlink", 400)
        if not stat.S_ISDIR(info.st_mode):
            raise FileNotFoundError(str(src))
        tree = tree_digest(src, max_files=max_files, max_bytes=max_bytes)
        return {
            "sha256": tree.sha256,
            "file_count": tree.file_count,
            "total_bytes": tree.total_bytes,
        }

    return _digest_or_status(compute)


def run_rehash(request: WorkerRequest, evidence_root: Path) -> dict[str, Any]:
    """Recompute the three anchored digests from the scan's kept evidence (audit finding M5).

    `evidence_root` is the scan's workspace directory, mounted read-only. Only bytes are hashed:
    nothing is parsed, decoded or executed. File names are fixed here, never taken from input.
    """
    require_worker_context()
    s = settings_for(request)
    max_bytes = s.max_artifact_size_mb * MB
    bom_name = SBOM_FILENAME if request.kind == "software" else AIBOM_FILENAME
    # The SBOM/AI-BOM are bounded by MAX_SBOM_MB when written; allow the larger of the two caps.
    file_cap = max(max_bytes, s.max_sbom_mb * MB)
    return {
        "artifact": _tree(evidence_root / "src", s.max_artifact_files, max_bytes),
        "bom": _file_digest(evidence_root / bom_name, file_cap),
        "provenance": _file_digest(evidence_root / PROVENANCE_FILENAME, file_cap),
    }


def _persist_error(message: str, details: Any = None) -> AppError:
    return AppError(ErrorCode.UNSAFE_CONTENT, message, 400, details)


def run_persist(request: WorkerRequest, src: Path, out_dir: Path) -> dict[str, Any]:
    """Copy the analyzed staging tree into the persistent workspace, within the request limits.

    The source is already bounded by its tmpfs volume; these checks bound the copy again, so the
    persistent workspace can never receive more than MAX_ARTIFACT_SIZE_MB and MAX_ARTIFACT_FILES
    per scan. Only directories and regular files are copied; a symlink, device, FIFO or socket
    anywhere fails the copy (the analyzed tree never contains one: extraction and fetching refuse
    them). The top-level `.git` directory is not copied (it is excluded from the tree digest).
    Returns the tree digest of what was written, which the runner compares with the analysis.
    """
    require_worker_context()
    s = settings_for(request)
    max_bytes = s.max_artifact_size_mb * MB
    max_files = s.max_artifact_files
    if any(out_dir.iterdir()):
        raise AppError(ErrorCode.WORKSPACE_ERROR, "The persist destination is not empty", 500)
    files = total = 0
    src_root = src.resolve()
    for dirpath, dirnames, filenames in os.walk(src_root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(src_root)
        if rel_dir == Path("."):
            dirnames[:] = [d for d in dirnames if d != ".git"]
        dirnames.sort()
        for name in dirnames:
            info = os.lstat(os.path.join(dirpath, name))
            if not stat.S_ISDIR(info.st_mode):
                raise _persist_error("The tree contains a symlink or special file", {"path": name})
            (out_dir / rel_dir / name).mkdir(mode=0o700)
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode):
                raise _persist_error("The tree contains a symlink or special file", {"path": name})
            files += 1
            total += info.st_size
            if files > max_files:
                raise AppError(
                    ErrorCode.TOO_MANY_FILES,
                    "Artifact contains too many files",
                    413,
                    {"max_files": max_files},
                )
            if total > max_bytes:
                raise AppError(
                    ErrorCode.ARTIFACT_TOO_LARGE,
                    "Artifact exceeds the size limit",
                    413,
                    {"max_bytes": max_bytes},
                )
            _copy_file(path, out_dir / rel_dir / name, info.st_size)
    tree = tree_digest(out_dir, max_files=max_files)
    return {"sha256": tree.sha256, "file_count": tree.file_count, "total_bytes": tree.total_bytes}


def _copy_file(src: str, dst: Path, expected: int) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(src, flags), "rb") as fin:
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fout:
            copied = 0
            while chunk := fin.read(_COPY_CHUNK):
                copied += len(chunk)
                if copied > expected:
                    raise _persist_error("A file grew while it was copied")
                fout.write(chunk)
