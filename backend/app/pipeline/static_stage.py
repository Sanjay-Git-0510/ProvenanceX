"""Pipeline step 9: static analysis features and category="static" findings.

Runs for software and model scans, after provenance. The analysis itself ran inside the
analyzer sandbox (app/sandbox_worker/collect.py); this stage only validates and stores its
output. Artifact code is only parsed, never run. The findings are suspicious signals with
ProvenanceX rule severities and no CVSS, so they stay visibly separate from known
vulnerabilities.
"""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.analysis.base import section_to_error
from app.analysis.codec import static_from_dict
from app.core.errors import AppError, ErrorCode
from app.db.models import Finding, FindingCategory, Scan
from app.pipeline.stages import StageStatus, execute_stage
from app.sandbox_worker.protocol import AnalysisOut
from app.scanners.static.analyzer import GroupedFinding

STAGE = "static"


@dataclass(frozen=True)
class StaticExtras:
    """Pipeline-specific inputs. The pickle/auto_map inputs are computed in the analyzer."""

    input_source: str = "provenancex"  # "mock" when files came from a mock provider


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
    collected: AnalysisOut,
    extras: StaticExtras,
) -> dict[str, Any] | None:
    source = "mock" if extras.input_source == "mock" else "provenancex"

    def body(scan: Scan) -> tuple[dict[str, Any], StageStatus, dict[str, Any]]:
        if collected.static_error is not None:
            raise section_to_error(collected.static_error)
        if collected.static is None:
            raise AppError(
                ErrorCode.ANALYZER_OUTPUT_INVALID, "The analyzer returned no static result", 502
            )
        result = static_from_dict(collected.static)
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
