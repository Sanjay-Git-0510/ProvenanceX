"""Build the /evidence response from stored rows. Read-only: it never computes a risk result."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import Component, Finding, ProvenanceRecord, RiskDecision, Scan, ScanStatus
from app.ml.feature_schema import FEATURE_NAMES
from app.risk.policy_config import FEATURE_LAYERS
from app.schemas.evidence import (
    MAX_CHECKS,
    MAX_LIST_ITEMS,
    ComponentsSection,
    ComponentSummaryOut,
    EvidenceResponse,
    FeatureOut,
    FeatureVectorOut,
    FindingsSection,
    FindingSummaryOut,
    Hashes,
    HashValue,
    MockFlags,
    ModelInfo,
    Page,
    ProvenanceCheckSummary,
    ProvenanceSummary,
    Sanitized,
    ScanErrorSummary,
    StageOut,
    StateReason,
    sanitize,
)
from app.schemas.risk import TrainingDataLabel, no_result_training_label
from app.schemas.scans import ArtifactRecord


@dataclass(frozen=True)
class PageRequest:
    limit: int
    offset: int


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)][:MAX_LIST_ITEMS]


def _text(entry: Mapping[str, Any], key: str) -> str | None:
    value = entry.get(key)
    return value if isinstance(value, str) else None


def _stage(name: str, entry: Mapping[str, Any]) -> StageOut:
    error = entry.get("error") if isinstance(entry.get("error"), Mapping) else {}
    return StageOut(
        name=name,
        status=_text(entry, "status"),
        provider=_text(entry, "provider"),
        source=_text(entry, "source"),
        is_mock=_is_mock_stage(entry),
        started_at=_text(entry, "started_at"),
        finished_at=_text(entry, "finished_at"),
        reason=_text(entry, "reason"),
        error_code=_text(error, "code"),
        error_message=_text(error, "message"),
        incomplete_reasons=_strings(entry.get("incomplete_reasons")),
        limitations=_strings(entry.get("limitations")),
        warnings=_strings(entry.get("warnings")),
    )


def _is_mock_stage(entry: Mapping[str, Any]) -> bool:
    return entry.get("source") == "mock" or entry.get("is_mock") is True


def _stage_entries(scan: Scan) -> list[tuple[str, Mapping[str, Any]]]:
    stages = scan.stages or {}
    return [(name, stages[name]) for name in sorted(stages) if isinstance(stages[name], Mapping)]


def _feature_vector(scan: Scan, decision: RiskDecision | None) -> FeatureVectorOut:
    if scan.status in (ScanStatus.QUEUED, ScanStatus.RUNNING):
        reason = StateReason(code=f"scan_{scan.status}", message="The scan has not finished.")
        return FeatureVectorOut(status="pending", reason=reason)
    if decision is None:
        reason = StateReason(
            code="no_risk_decision", message="No risk decision is stored for this scan."
        )
        return FeatureVectorOut(status="not_computed", reason=reason)
    stored = decision.explanation.get("features")
    if not isinstance(stored, Mapping):
        reason = StateReason(
            code="features_not_recorded",
            message="This decision was stored before feature vectors were recorded.",
        )
        return FeatureVectorOut(status="not_computed", reason=reason)
    reasons = decision.explanation.get("null_reasons") or {}
    return FeatureVectorOut(
        status="available",
        features=[
            FeatureOut(
                name=name,
                layer=FEATURE_LAYERS[name],
                value=stored.get(name),
                evaluated=stored.get(name) is not None,
                null_reason=None if stored.get(name) is not None else reasons.get(name),
            )
            for name in FEATURE_NAMES
        ],
    )


def _grouped(session: Session, model: type, column: Any, scan_id: Any) -> dict[str, int]:
    rows = session.execute(
        select(column, func.count()).where(model.scan_id == scan_id).group_by(column)
    ).all()
    return {str(key): count for key, count in rows}


def _page(total: int, request: PageRequest) -> Page:
    return Page(
        total=total,
        limit=request.limit,
        offset=request.offset,
        has_more=request.offset + request.limit < total,
    )


def _findings(session: Session, scan_id: Any, request: PageRequest) -> FindingsSection:
    by_source = _grouped(session, Finding, Finding.source, scan_id)
    rows = session.scalars(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.cvss_score.desc().nulls_last(), Finding.identifier, Finding.id)
        .limit(request.limit)
        .offset(request.offset)
    ).all()
    return FindingsSection(
        page=_page(sum(by_source.values()), request),
        by_category=_grouped(session, Finding, Finding.category, scan_id),
        by_severity=_grouped(session, Finding, Finding.severity, scan_id),
        by_source=by_source,
        items=[
            FindingSummaryOut(
                finding_id=row.id,
                category=row.category,
                identifier=row.identifier,
                title=row.title,
                severity=row.severity,
                cvss_score=row.cvss_score,
                source=row.source,
                is_mock=row.source == "mock",
                component_id=row.component_id,
            )
            for row in rows
        ],
    )


def _components(session: Session, scan_id: Any, request: PageRequest) -> ComponentsSection:
    by_source = _grouped(session, Component, Component.source, scan_id)
    rows = session.scalars(
        select(Component)
        .where(Component.scan_id == scan_id)
        .order_by(Component.name, Component.id)
        .limit(request.limit)
        .offset(request.offset)
    ).all()
    return ComponentsSection(
        page=_page(sum(by_source.values()), request),
        by_source=by_source,
        items=[
            ComponentSummaryOut(
                component_id=row.id,
                name=row.name,
                version=row.version,
                component_type=row.component_type,
                ecosystem=row.ecosystem,
                purl=row.purl,
                source=row.source,
                is_mock=row.source == "mock",
            )
            for row in rows
        ],
    )


def _checks(checks: Sequence[Any]) -> list[ProvenanceCheckSummary]:
    """Check `data` is left out: it can list artifact file names and per-file detail."""
    return [
        ProvenanceCheckSummary(
            name=str(check.get("name")),
            status=str(check.get("status")),
            evidence=str(check.get("evidence", "")),
            severity=check.get("severity"),
            identifier=check.get("identifier"),
        )
        for check in checks[:MAX_CHECKS]
        if isinstance(check, Mapping)
    ]


def _provenance(row: ProvenanceRecord | None) -> ProvenanceSummary | None:
    if row is None:
        return None
    checks = row.checks or []
    return ProvenanceSummary(
        source_known=row.source_known,
        revision_pinned=row.revision_pinned,
        resolved_commit=row.resolved_commit,
        signed=row.signed,
        signature_files_present=row.signature_files_present,
        provenance_present=row.provenance_present,
        hash_changed=row.hash_changed,
        previous_scan_id=row.previous_scan_id,
        lineage_completeness=row.lineage_completeness,
        source=row.source,
        is_mock=row.source == "mock",
        checks=_checks(checks),
        checks_truncated=len(checks) > MAX_CHECKS,
        created_at=row.created_at,
    )


def _hash(value: Any, reason: str) -> HashValue:
    return HashValue(value=value, reason=None) if value else HashValue(value=None, reason=reason)


def _hashes(scan: Scan, provenance: ProvenanceRecord | None) -> Hashes:
    sandbox = (scan.stages or {}).get("sandbox")
    trace = sandbox.get("trace_sha256") if isinstance(sandbox, Mapping) else None
    return Hashes(
        artifact_sha256=_hash(scan.artifact.sha256, "The artifact was not hashed"),
        bom_sha256=_hash(scan.bom_sha256, "No SBOM hash was stored for this scan"),
        provenance_record_sha256=_hash(
            provenance.record_sha256 if provenance else None, "No provenance record was stored"
        ),
        sandbox_trace_sha256=_hash(trace, "The sandbox did not run or returned no trace"),
    )


def _training_label(decision: RiskDecision | None) -> TrainingDataLabel:
    stored = decision.explanation.get("training_data") if decision else None
    return TrainingDataLabel(**stored) if stored else no_result_training_label()


def _artifact(scan: Scan) -> ArtifactRecord:
    artifact = scan.artifact
    return ArtifactRecord(
        artifact_id=artifact.id,
        name=artifact.name,
        artifact_type=artifact.artifact_type,
        version=artifact.version,
        source=artifact.source,
        source_url=artifact.source_url,
        sha256=artifact.sha256,
        collected_at=artifact.collected_at,
        scan_id=scan.id,
    )


def build_evidence(
    session: Session, scan: Scan, findings_page: PageRequest, components_page: PageRequest
) -> EvidenceResponse:
    provenance = session.scalars(
        select(ProvenanceRecord).where(ProvenanceRecord.scan_id == scan.id)
    ).first()
    decision = session.scalars(select(RiskDecision).where(RiskDecision.scan_id == scan.id)).first()
    entries = _stage_entries(scan)
    findings = _findings(session, scan.id, findings_page)
    components = _components(session, scan.id, components_page)
    mock_stages = [name for name, entry in entries if _is_mock_stage(entry)]
    mock_findings = findings.by_source.get("mock", 0)
    mock_components = components.by_source.get("mock", 0)
    provenance_is_mock = provenance is not None and provenance.source == "mock"
    failed = scan.status == ScanStatus.FAILED
    response = EvidenceResponse(
        scan_id=scan.id,
        scan_status=scan.status,
        scan_error=(
            ScanErrorSummary(code=scan.error_code, message=scan.error_message) if failed else None
        ),
        scanner_version=scan.scanner_version,
        artifact=_artifact(scan),
        stages=[_stage(name, entry) for name, entry in entries],
        feature_vector=_feature_vector(scan, decision),
        findings=findings,
        components=components,
        provenance=_provenance(provenance),
        hashes=_hashes(scan, provenance),
        model=ModelInfo(
            model_version=decision.model_version if decision else None,
            ml_status=decision.ml_status if decision else None,
        ),
        mock=MockFlags(
            contains_mock_evidence=bool(
                mock_stages or mock_findings or mock_components or provenance_is_mock
            ),
            mock_stages=mock_stages,
            mock_findings=mock_findings,
            mock_components=mock_components,
            provenance_is_mock=provenance_is_mock,
        ),
        training_data=_training_label(decision),
        sanitized=Sanitized(),
    )
    totals = Sanitized()
    cleaned = sanitize(response.model_dump(mode="json", exclude={"sanitized"}), totals)
    return EvidenceResponse.model_validate({**cleaned, "sanitized": totals.model_dump()})
