"""Pipeline step 4 (software): SBOM generation, CycloneDX parsing, Component rows.

The raw SBOM is kept off-chain at <workspace>/sbom.cdx.json. Its SHA-256 is stored as
Scan.bom_sha256, which Phase 7 anchors as `bom_hash`.

The SBOM is untrusted (Syft ran on attacker-controlled content), so it is parsed in a
memory-limited child process (app/scanners/sbom/parse_child.py, audit finding M3), never by
`json.loads` in the runner itself.
"""

import hashlib
import logging
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from app.analysis.consistency import check_sbom_locations
from app.core import evidence_files
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.db.models import Component, Scan
from app.pipeline.stages import StageStatus, execute_stage
from app.pipeline.workspace import MB, Workspace
from app.scanners.manifests import ProjectPackage, normalize_package_name
from app.scanners.sbom.base import SbomProvider
from app.scanners.sbom.cyclonedx import ParsedComponent, ParsedSbom
from app.scanners.sbom.parse_child import parse_sbom_isolated

logger = logging.getLogger(__name__)

STAGE = "sbom"
SBOM_FILENAME = evidence_files.SBOM_FILENAME
_PARSING_FILENAME = ".sbom-parsing.cdx.json"


@dataclass
class SbomStageOutput:
    parsed: ParsedSbom
    component_ids: dict[str, UUID]  # bom-ref -> Component.id
    source: str  # "syft" | "mock" | "aibom"
    # bom-refs of the scanned project's own package(s); merged into the graph root and
    # left out of the vulnerability lookup.
    root_package_refs: frozenset[str] = field(default_factory=frozenset)


def match_project_packages(
    components: Sequence[ParsedComponent], projects: Sequence[ProjectPackage]
) -> frozenset[str]:
    """bom-refs of components that are the project itself (same ecosystem, name, version)."""
    refs: set[str] = set()
    for project in projects:
        wanted = normalize_package_name(project.ecosystem, project.name)
        for comp in components:
            if comp.ecosystem != project.ecosystem:
                continue
            if normalize_package_name(comp.ecosystem, comp.name) != wanted:
                continue
            if project.version is not None and comp.version != project.version:
                continue
            refs.add(comp.bom_ref)
    return frozenset(refs)


def _write_private(path: os.PathLike[str], data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def run_sbom_stage(
    session: Session,
    scan_id: UUID,
    workspace: Workspace,
    settings: Settings,
    provider: SbomProvider,
    project_packages: Sequence[ProjectPackage] = (),
    tree_files: Sequence[str] | None = None,
) -> SbomStageOutput | None:
    """`tree_files`: the analyzed tree's file list. Real Syft component locations must lie in
    it (audit finding M4); otherwise the stage fails with analyzer_output_invalid. Recorded
    mock SBOMs (source="mock") describe a fixture, not this tree, so they are not checked."""

    def body(scan: Scan) -> tuple[SbomStageOutput, StageStatus, dict[str, Any]]:
        result = provider.generate(workspace.src_dir, workspace.root)
        max_bytes = settings.max_sbom_mb * MB
        if len(result.raw) > max_bytes:
            raise AppError(
                ErrorCode.SBOM_TOO_LARGE,
                "SBOM exceeds the size limit",
                413,
                {"size_bytes": len(result.raw), "max_bytes": max_bytes},
            )
        parsing = workspace.root / _PARSING_FILENAME
        _write_private(parsing, result.raw)
        try:
            parsed = parse_sbom_isolated(
                parsing,
                max_bytes=max_bytes,
                max_components=settings.max_sbom_components,
                memory_mb=settings.sbom_parse_memory_mb,
                timeout_seconds=settings.sbom_parse_timeout_seconds,
            )
            if tree_files is not None and result.source != "mock":
                check_sbom_locations(
                    (loc for comp in parsed.components for loc in comp.locations), tree_files
                )
        except BaseException:
            parsing.unlink(missing_ok=True)
            raise
        os.replace(parsing, workspace.root / SBOM_FILENAME)
        bom_sha256 = hashlib.sha256(result.raw).hexdigest()
        scan.bom_sha256 = bom_sha256

        root_refs = match_project_packages(parsed.components, project_packages)
        component_ids: dict[str, UUID] = {}
        for comp in parsed.components:
            component_ids[comp.bom_ref] = cid = uuid4()
            session.add(
                Component(
                    id=cid,
                    scan_id=scan.id,
                    bom_ref=comp.bom_ref,
                    name=comp.name,
                    version=comp.version,
                    component_type=comp.component_type,
                    ecosystem=comp.ecosystem,
                    purl=comp.purl,
                    licenses=list(comp.licenses) or None,
                    source=result.source,
                    properties={
                        "found_by": comp.found_by,
                        "locations": list(comp.locations),
                        "cpe": comp.cpe,
                        "project_root": comp.bom_ref in root_refs,
                    },
                )
            )
        fields = {
            "source": result.source,
            "root_packages": sorted(root_refs),
            "tool": result.tool_name,
            "tool_version": result.tool_version,
            "format": result.format,
            "spec_version": parsed.spec_version,
            "sbom_file": SBOM_FILENAME,
            "bom_sha256": bom_sha256,
            "counts": {
                "components": len(parsed.components),
                "edges": len(parsed.edges),
                **parsed.stats,
            },
        }
        output = SbomStageOutput(parsed, component_ids, result.source, root_refs)
        return output, StageStatus.COMPLETED, fields

    return execute_stage(session, scan_id, STAGE, body, provider=provider.name)
