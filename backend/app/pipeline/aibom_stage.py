"""Pipeline step 5 (AI/ML): AI-BOM, Component rows and static model-file findings.

The AI-BOM is written off-chain to <workspace>/aibom.json (mode 0600). Its SHA-256 is
stored as Scan.bom_sha256, the same `bom_hash` slot a software SBOM uses (Phase 7).

Components (source="aibom", or "mock" when the input came from the mock HF provider):
  runtime deps   component_type=library, ecosystem=pypi, bom_ref=package:pypi/<name>
  base models    component_type=machine-learning-model, bom_ref=model:<hub id>
  datasets       component_type=data, bom_ref=dataset:<hub id>
The bom_refs equal the lineage-graph node keys, so findings and graph nodes line up.

Static findings (category="static") describe properties of the model files themselves:
code-executing serialization formats, dangerous pickle imports, malformed safetensors,
format/extension mismatches and custom code. They are suspicious signals, NOT known
vulnerabilities, and carry no CVSS.
"""

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.models import Component, Finding, FindingCategory, Scan
from app.graph.lineage_graph import package_key
from app.pipeline.sbom_stage import SbomStageOutput
from app.pipeline.stages import StageStatus, execute_stage
from app.pipeline.workspace import Workspace
from app.scanners.model.aibom import ModelAnalysis, ModelContext, analyze_model
from app.scanners.model.inventory import InventoryFile
from app.scanners.sbom.cyclonedx import ParsedComponent, ParsedSbom

STAGE = "aibom"
AIBOM_FILENAME = "aibom.json"
RULE_SOURCE = "provenancex_rule"


@dataclass
class AiBomStageOutput:
    analysis: ModelAnalysis
    source: str  # "aibom" | "mock"
    vuln_input: SbomStageOutput  # runtime deps in the shape the vulnerability stage takes


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _finding(
    scan_id: UUID,
    source: str,
    identifier: str,
    severity: str,
    title: str,
    details: dict[str, Any],
    component_id: UUID | None = None,
) -> Finding:
    return Finding(
        scan_id=scan_id,
        component_id=component_id,
        category=FindingCategory.STATIC,
        identifier=identifier,
        aliases=[],
        title=title[:512],
        severity=severity,
        severity_source=RULE_SOURCE,
        cvss_score=None,
        cvss_vector=None,
        cvss_version=None,
        source=source,
        details=details,
    )


def _file_findings(scan_id: UUID, source: str, f: InventoryFile) -> list[Finding]:
    out: list[Finding] = []
    base = {"file": f.path, "serialization": f.serialization, "sha256": f.sha256}
    pick = f.analysis.get("pickle")
    if pick is not None:
        if pick["dangerous_globals"]:
            out.append(
                _finding(
                    scan_id,
                    source,
                    "PX-PICKLE-DANGEROUS-IMPORT",
                    "HIGH",
                    f"Pickle in {f.path} imports dangerous callables: "
                    + ", ".join(pick["dangerous_globals"][:5]),
                    {**base, "kind": "unsafe_deserialization", "pickle": pick},
                )
            )
        if pick["unresolved_stack_globals"]:
            out.append(
                _finding(
                    scan_id,
                    source,
                    "PX-PICKLE-UNRESOLVED-IMPORT",
                    "MEDIUM",
                    f"Pickle in {f.path} has {pick['unresolved_stack_globals']} import(s) whose "
                    "target could not be resolved statically",
                    {**base, "kind": "unsafe_deserialization", "pickle": pick},
                )
            )
        if pick["unknown_globals"]:
            out.append(
                _finding(
                    scan_id,
                    source,
                    "PX-PICKLE-UNKNOWN-IMPORT",
                    "LOW",
                    f"Pickle in {f.path} imports callables outside the known-safe list: "
                    + ", ".join(pick["unknown_globals"][:5]),
                    {**base, "kind": "unsafe_deserialization", "pickle": pick},
                )
            )
        if pick["status"] == "parse_error":
            out.append(
                _finding(
                    scan_id,
                    source,
                    "PX-PICKLE-PARSE-ERROR",
                    "MEDIUM",
                    f"{f.path} could not be parsed as a pickle: {pick['error']}",
                    {**base, "kind": "malformed_model_file", "pickle": pick},
                )
            )
        elif pick["status"] in ("too_large", "truncated"):
            out.append(
                _finding(
                    scan_id,
                    source,
                    "PX-PICKLE-NOT-FULLY-SCANNED",
                    "LOW",
                    f"Pickle in {f.path} was not fully scanned: {pick['error']}",
                    {**base, "kind": "unsafe_deserialization", "pickle": pick},
                )
            )
        out.append(
            _finding(
                scan_id,
                source,
                "PX-CODE-EXECUTING-FORMAT",
                "LOW",
                f"{f.path} uses {f.serialization}, a format whose standard loaders can run code",
                {**base, "kind": "code_executing_format"},
            )
        )
    st = f.analysis.get("safetensors")
    if st is not None:
        if not st["valid"]:
            out.append(
                _finding(
                    scan_id,
                    source,
                    "PX-SAFETENSORS-MALFORMED",
                    "MEDIUM",
                    f"Malformed safetensors header in {f.path}: {'; '.join(st['issues'][:3])}",
                    {**base, "kind": "malformed_model_file", "safetensors": st},
                )
            )
        elif st["issues"]:
            out.append(
                _finding(
                    scan_id,
                    source,
                    "PX-SAFETENSORS-ANOMALY",
                    "LOW",
                    f"Safetensors layout anomaly in {f.path}: {'; '.join(st['issues'][:3])}",
                    {**base, "kind": "malformed_model_file", "safetensors": st},
                )
            )
    if f.format_mismatch:
        out.append(
            _finding(
                scan_id,
                source,
                "PX-MODEL-FORMAT-MISMATCH",
                "MEDIUM",
                f"{f.path}: {f.format_mismatch}",
                {**base, "kind": "format_mismatch"},
            )
        )
    return out


def _code_findings(scan_id: UUID, source: str, a: ModelAnalysis) -> list[Finding]:
    cc = a.custom_code
    out: list[Finding] = []
    if cc.remote_code_required:
        targets = sorted({t for m in cc.auto_map.values() for t in m.values()})
        out.append(
            _finding(
                scan_id,
                source,
                "PX-REMOTE-CODE-REQUIRED",
                "MEDIUM",
                "Config auto_map points to repository code; loading requires "
                "trust_remote_code=True: " + ", ".join(targets[:5]),
                {"kind": "custom_code", "auto_map": cc.auto_map, "scripts": cc.scripts},
            )
        )
    if cc.native_binaries:
        out.append(
            _finding(
                scan_id,
                source,
                "PX-NATIVE-BINARY",
                "MEDIUM",
                f"{len(cc.native_binaries)} native binary file(s) bundled with the artifact",
                {"kind": "custom_code", "files": cc.native_binaries},
            )
        )
    if (cc.scripts or cc.bytecode) and not cc.remote_code_required:
        out.append(
            _finding(
                scan_id,
                source,
                "PX-CUSTOM-CODE-PRESENT",
                "LOW",
                f"{len(cc.scripts) + len(cc.bytecode)} script/bytecode file(s) bundled with "
                "the artifact (not referenced by auto_map)",
                {"kind": "custom_code", "scripts": cc.scripts, "bytecode": cc.bytecode},
            )
        )
    return out


def _components(
    session: Session, scan_id: UUID, source: str, a: ModelAnalysis
) -> tuple[dict[str, UUID], list[ParsedComponent]]:
    ids: dict[str, UUID] = {}
    parsed: list[ParsedComponent] = []
    seen: set[str] = set()
    for req in a.runtime_deps:
        ref = package_key(req.name)
        if ref in seen:
            continue
        seen.add(ref)
        purl = f"pkg:pypi/{req.name}@{req.version}" if req.version else f"pkg:pypi/{req.name}"
        ids[ref] = cid = uuid4()
        session.add(
            Component(
                id=cid,
                scan_id=scan_id,
                bom_ref=ref,
                name=req.name,
                version=req.version,
                component_type="library",
                ecosystem="pypi",
                purl=purl,
                licenses=None,
                source=source,
                properties={"declared_in": req.file, "pinned": req.version is not None},
            )
        )
        parsed.append(
            ParsedComponent(
                bom_ref=ref,
                name=req.name,
                version=req.version,
                component_type="library",
                purl=purl,
                ecosystem="pypi",
                licenses=(),
                cpe=None,
                found_by="aibom",
                locations=(req.file,),
            )
        )
    lineage = [(b, "machine-learning-model", "model") for b in a.base_models]
    lineage += [(d, "data", "dataset") for d in a.datasets]
    for ref_obj, ctype, prefix in lineage:
        ref = f"{prefix}:{ref_obj.ref_id}"
        if ref in seen:
            continue
        seen.add(ref)
        ids[ref] = cid = uuid4()
        session.add(
            Component(
                id=cid,
                scan_id=scan_id,
                bom_ref=ref[:2048],
                name=ref_obj.ref_id[:1024],
                version=ref_obj.revision,
                component_type=ctype,
                ecosystem="huggingface",
                purl=f"pkg:huggingface/{ref_obj.ref_id}",
                licenses=None,
                source=source,
                properties={"lineage": ref_obj.to_dict()},
            )
        )
    return ids, parsed


def run_aibom_stage(
    session: Session,
    scan_id: UUID,
    workspace: Workspace,
    settings: Settings,
    ctx: ModelContext,
    input_source: str,
) -> AiBomStageOutput | None:
    """`input_source` is "mock" when the files came from the mock HF provider."""
    source = "mock" if input_source == "mock" else "aibom"
    finding_source = "mock" if input_source == "mock" else "provenancex"

    def body(scan: Scan) -> tuple[AiBomStageOutput, StageStatus, dict[str, Any]]:
        analysis = analyze_model(workspace.src_dir, ctx, settings)
        raw = json.dumps(analysis.aibom, sort_keys=True, indent=2).encode()
        _write_private(workspace.root / AIBOM_FILENAME, raw)
        scan.bom_sha256 = bom_sha256 = hashlib.sha256(raw).hexdigest()

        ids, parsed = _components(session, scan.id, source, analysis)
        findings = [
            item
            for f in analysis.inventory
            if f.downloaded
            for item in _file_findings(scan.id, finding_source, f)
        ] + _code_findings(scan.id, finding_source, analysis)
        session.add_all(findings)

        vuln_input = SbomStageOutput(
            parsed=ParsedSbom(
                spec_version="aibom",
                root_ref=None,
                root_name=ctx.name,
                tools=["provenancex-aibom"],
                components=parsed,
                edges=[],
            ),
            component_ids=ids,
            source=source,
        )
        summary = analysis.aibom["summary"]
        fields = {
            "source": source,
            "format": analysis.aibom["format"],
            "aibom_file": AIBOM_FILENAME,
            "bom_sha256": bom_sha256,
            "model": {
                "frameworks": analysis.frameworks,
                "serialization_types": analysis.serialization_counts,
                "base_models": [b.to_dict() for b in analysis.base_models],
                "datasets": [d.to_dict() for d in analysis.datasets],
                "adapters": analysis.adapters,
                "model_card": analysis.card.to_dict(),
                "custom_code": {
                    "present": analysis.custom_code.present,
                    "remote_code_required": analysis.custom_code.remote_code_required,
                    "script_count": len(analysis.custom_code.scripts),
                    "native_binary_count": len(analysis.custom_code.native_binaries),
                },
                "summary": summary,
            },
            "counts": {
                "files": summary["file_count"],
                "files_downloaded": summary["files_downloaded"],
                "weight_files": summary["weight_file_count"],
                "components": len(ids),
                "runtime_dependencies": len(parsed),
                "static_findings": len(findings),
            },
            "limitations": analysis.limitations,
        }
        output = AiBomStageOutput(analysis, source, vuln_input)
        return output, StageStatus.COMPLETED, fields

    return execute_stage(session, scan_id, STAGE, body, provider="provenancex")
