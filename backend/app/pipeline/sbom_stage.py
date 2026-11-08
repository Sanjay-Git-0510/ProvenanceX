"""Pipeline step 4 (software): SBOM generation, CycloneDX parsing, Component rows.

The raw SBOM is kept off-chain at <workspace>/sbom.cdx.json. Its SHA-256 is stored as
Scan.bom_sha256, which Phase 7 anchors as `bom_hash`.
"""

import hashlib
import logging
import os
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.models import Component, Scan
from app.pipeline.stages import StageStatus, execute_stage
from app.pipeline.workspace import MB, Workspace
from app.scanners.sbom.base import SbomProvider
from app.scanners.sbom.cyclonedx import ParsedSbom, parse_cyclonedx

logger = logging.getLogger(__name__)

STAGE = "sbom"
SBOM_FILENAME = "sbom.cdx.json"


@dataclass
class SbomStageOutput:
    parsed: ParsedSbom
    component_ids: dict[str, UUID]  # bom-ref -> Component.id
    source: str  # "syft" | "mock"


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
) -> SbomStageOutput | None:
    def body(scan: Scan) -> tuple[SbomStageOutput, StageStatus, dict[str, Any]]:
        result = provider.generate(workspace.src_dir, workspace.root)
        parsed = parse_cyclonedx(
            result.raw,
            max_bytes=settings.max_sbom_mb * MB,
            max_components=settings.max_sbom_components,
        )
        _write_private(workspace.root / SBOM_FILENAME, result.raw)
        bom_sha256 = hashlib.sha256(result.raw).hexdigest()
        scan.bom_sha256 = bom_sha256

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
                    },
                )
            )
        fields = {
            "source": result.source,
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
        return SbomStageOutput(parsed, component_ids, result.source), StageStatus.COMPLETED, fields

    return execute_stage(session, scan_id, STAGE, body, provider=provider.name)
