"""Pipeline step 7 (software): OSV lookup, optional NVD enrichment, vulnerability Findings.

It also annotates graph nodes with per-package vulnerability counts and fills the graph
features vulnerable_count / vulnerability_count / cvss_max. If this stage fails, those
values stay None ("not looked up"). They are never reported as 0.

A known vulnerability is not evidence of malice. The findings have
category="vulnerability" and details.kind="known_vulnerability", which keeps them
separate from the suspicious/behavioral signals that later phases add.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Finding, FindingCategory, GraphNode, Scan
from app.pipeline.providers import ScanProviders
from app.pipeline.sbom_stage import SbomStageOutput
from app.pipeline.stages import StageStatus, execute_stage
from app.scanners.vulns.base import Advisory, PackageQuery
from app.scanners.vulns.cvss import severity_rank
from app.scanners.vulns.osv import normalize_query_purl

STAGE = "vulnerabilities"


def build_queries(sbom: SbomStageOutput) -> tuple[list[PackageQuery], dict[str, int]]:
    queries: list[PackageQuery] = []
    skipped = {"packages_without_purl": 0, "packages_without_version": 0}
    for comp in sbom.parsed.components:
        purl = normalize_query_purl(comp.purl, comp.version)
        if not comp.purl:
            skipped["packages_without_purl"] += 1
        elif purl is None or comp.version is None:
            skipped["packages_without_version"] += 1
        else:
            queries.append(
                PackageQuery(comp.bom_ref, purl, comp.name, comp.version, comp.ecosystem)
            )
    return queries, skipped


def _finding(scan_id: UUID, component_id: UUID | None, pkg: PackageQuery, adv: Advisory) -> Finding:
    return Finding(
        scan_id=scan_id,
        component_id=component_id,
        category=FindingCategory.VULNERABILITY,
        identifier=adv.identifier,
        aliases=list(adv.aliases),
        title=adv.summary[:512] if adv.summary else None,
        severity=adv.severity,
        severity_source=adv.severity_source,
        cvss_score=adv.cvss_score,
        cvss_vector=adv.cvss_vector,
        cvss_version=adv.cvss_version,
        source=adv.source,
        details={
            "kind": "known_vulnerability",
            "package": {"name": pkg.name, "version": pkg.version, "purl": pkg.purl},
            "cvss_source": adv.cvss_source,
            "other_cvss_vectors": list(adv.other_vectors),
            "fixed_versions": list(adv.fixed_versions),
            "affected_ranges": [dict(r) for r in adv.affected_ranges],
            "references": list(adv.references),
            "cwe_ids": list(adv.cwe_ids),
            "published": adv.published,
            "modified": adv.modified,
            "merged_from": list(adv.merged_from),
        },
    )


def _annotate_graph(
    session: Session, scan: Scan, queried: set[str], by_ref: dict[str, list[Advisory]]
) -> dict[str, Any]:
    nodes = session.scalars(select(GraphNode).where(GraphNode.scan_id == scan.id)).all()
    for node in nodes:
        if node.node_type == "artifact":
            continue
        attrs = dict(node.attributes or {})
        if node.node_key in queried:
            advs = by_ref.get(node.node_key, [])
            scores = [a.cvss_score for a in advs if a.cvss_score is not None]
            attrs["vulnerability_count"] = len(advs)
            attrs["cvss_max"] = max(scores) if scores else None
            attrs["max_severity"] = (
                max((a.severity for a in advs), key=severity_rank) if advs else None
            )
        else:
            attrs["vulnerability_count"] = None  # not looked up (no purl/version)
        node.attributes = attrs

    all_scores = [
        a.cvss_score for advs in by_ref.values() for a in advs if a.cvss_score is not None
    ]
    summary = {
        "vulnerable_count": sum(1 for advs in by_ref.values() if advs),
        "vulnerability_count": sum(len(advs) for advs in by_ref.values()),
        "cvss_max": max(all_scores) if all_scores else None,
    }
    graph_entry = (scan.stages or {}).get("graph")
    if graph_entry and isinstance(graph_entry.get("features"), dict):
        stages = dict(scan.stages or {})
        stages["graph"] = {**graph_entry, "features": {**graph_entry["features"], **summary}}
        scan.stages = stages
    return summary


def run_vuln_stage(
    session: Session, scan_id: UUID, sbom: SbomStageOutput, providers: ScanProviders
) -> dict[str, Any] | None:
    def body(scan: Scan) -> tuple[dict[str, Any], StageStatus, dict[str, Any]]:
        queries, skipped = build_queries(sbom)
        result = providers.vulns.lookup(queries)
        by_ref = result.by_ref
        nvd_info: dict[str, Any] = {"enabled": providers.nvd is not None}
        if providers.nvd is not None and by_ref:
            by_ref, nvd_stats, nvd_warnings = providers.nvd.enrich(by_ref)
            nvd_info.update(nvd_stats, warnings=nvd_warnings)

        pkg_by_ref = {q.ref: q for q in queries}
        count = 0
        for ref, advisories in by_ref.items():
            pkg = pkg_by_ref.get(ref)
            if pkg is None:
                continue
            for adv in advisories:
                session.add(_finding(scan.id, sbom.component_ids.get(ref), pkg, adv))
                count += 1

        summary = _annotate_graph(session, scan, {q.ref for q in queries}, by_ref)
        fields = {
            "source": result.source,
            "counts": {**result.stats, **skipped, "findings": count, **summary},
            "warnings": result.warnings,
            "nvd": nvd_info,
        }
        status = StageStatus.PARTIAL if result.partial else StageStatus.COMPLETED
        return summary, status, fields

    return execute_stage(session, scan_id, STAGE, body, provider=providers.vulns.name)
