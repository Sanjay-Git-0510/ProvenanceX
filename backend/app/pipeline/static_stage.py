"""Pipeline step 9: static analysis features and category="static" findings.

Runs for software and model scans, after provenance. Artifact code is only parsed. The
findings are suspicious signals with ProvenanceX rule severities and no CVSS, so they
stay visibly separate from known vulnerabilities.
"""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.models import Finding, FindingCategory, Scan
from app.pipeline.stages import StageStatus, execute_stage
from app.pipeline.workspace import MB, Workspace
from app.scanners.static.analyzer import GroupedFinding, StaticLimits, analyze_artifact

STAGE = "static"
KB = 1024


@dataclass(frozen=True)
class StaticExtras:
    """Pipeline-specific inputs."""

    input_source: str = "provenancex"  # "mock" when files came from a mock provider
    auto_map_targets: int = 0
    pickle_dangerous_globals: int | None = None  # None: not a model scan, or AI-BOM failed
    undownloaded_files: int = 0


def _finding(scan_id: UUID, source: str, g: GroupedFinding) -> Finding:
    shown = ", ".join(g.symbols[:3])
    return Finding(
        scan_id=scan_id,
        component_id=None,
        category=FindingCategory.STATIC,
        identifier=g.rule.id,
        aliases=[],
        title=f"{g.rule.title} in {g.file}: {shown}"[:512],
        severity=g.rule.severity,
        severity_source="provenancex_rule",
        cvss_score=None,
        cvss_vector=None,
        cvss_version=None,
        source=source,
        details={
            "kind": g.rule.kind,
            "file": g.file,
            "occurrences": g.occurrences,
            "lines": g.lines,
            "cells": g.cells,
            "symbols": g.symbols,
        },
    )


def run_static_stage(
    session: Session,
    scan_id: UUID,
    workspace: Workspace,
    settings: Settings,
    extras: StaticExtras,
) -> dict[str, Any] | None:
    source = "mock" if extras.input_source == "mock" else "provenancex"
    limits = StaticLimits(
        max_files=settings.static_max_files,
        max_file_bytes=settings.static_max_file_kb * KB,
        max_total_bytes=settings.static_max_total_mb * MB,
        max_findings=settings.static_max_findings,
        max_compression_ratio=settings.max_compression_ratio,
        ratio_warn_fraction=settings.static_archive_ratio_warn_fraction,
    )

    def body(scan: Scan) -> tuple[dict[str, Any], StageStatus, dict[str, Any]]:
        result = analyze_artifact(
            workspace.src_dir,
            limits,
            upload_path=workspace.upload_path,
            max_tree_files=settings.max_artifact_files,
            auto_map_targets=extras.auto_map_targets,
            pickle_dangerous_globals=extras.pickle_dangerous_globals,
            undownloaded_files=extras.undownloaded_files,
        )
        session.add_all(_finding(scan.id, source, g) for g in result.findings)
        incomplete = result.not_analyzed_count > 0 or result.findings_truncated
        status = StageStatus.PARTIAL if incomplete else StageStatus.COMPLETED
        fields = {
            "source": source,
            "features": result.features,
            "counts": {
                "findings": len(result.findings),
                "not_analyzed": result.not_analyzed_count,
            },
            "findings_truncated": result.findings_truncated,
            "not_analyzed": result.not_analyzed,
            "limitations": result.limitations,
        }
        return result.features, status, fields

    return execute_stage(session, scan_id, STAGE, body, provider="provenancex")
