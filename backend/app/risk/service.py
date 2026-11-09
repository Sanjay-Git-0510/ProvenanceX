"""Compute, store and return the risk result for a scan.

The result is computed once, the first time a completed scan's risk is requested, and stored.
Later reads return the stored result, so a decision does not change when models are retrained.
"""

import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import AppError
from app.db.models import (
    Finding,
    GraphEdge,
    GraphNode,
    ProvenanceRecord,
    RiskDecision,
    RiskVerdict,
    Scan,
    ScanStatus,
)
from app.ml.comparison import (
    ScanSnapshot,
    compare_snapshots,
    declared_versions,
    version_consistency,
)
from app.ml.features import FeatureExtraction, extract_features, stage_null_reason
from app.pipeline.workspace import open_workspace
from app.risk.explain import explain_random_forest, not_evaluated_features, unavailable
from app.risk.model_runtime import (
    TRAINED_ARTIFACT_TYPES,
    LoadedModels,
    ModelUnavailable,
    encode_features,
    load_models,
    score_row,
)
from app.risk.policy import assess_risk
from app.risk.policy_config import DEFAULT_POLICY, FEATURE_LAYERS, FINDING_LAYERS, RiskLayer
from app.risk.types import FindingRef, MlOutputs, RiskAssessment, RiskInputs
from app.schemas.risk import RiskResponse, RiskStatus

logger = logging.getLogger(__name__)

_NO_MODEL_NOTICE = (
    "No model contributed to this result. The only ProvenanceX models so far are trained on "
    "synthetic data."
)
_SYNTHETIC_NOTICE = (
    "These models were trained on synthetic data. Their outputs do not measure real-world "
    "detection and they make no malware-detection claim."
)
_UNVERIFIED_NOTICE = "The saved model metadata does not state that its training data is synthetic."


def _provenance_document(record: ProvenanceRecord | None) -> dict[str, Any]:
    if record is None:
        return {}
    return {
        "provenance_present": record.provenance_present,
        "source_known": record.source_known,
        "revision_pinned": record.revision_pinned,
        "hash_changed": record.hash_changed,
        "lineage_completeness": record.lineage_completeness,
        "checks": record.checks,
    }


def _provenance_row(session: Session, scan_id: Any) -> ProvenanceRecord | None:
    return session.scalars(
        select(ProvenanceRecord).where(ProvenanceRecord.scan_id == scan_id)
    ).first()


def _snapshot(session: Session, scan: Scan, record: ProvenanceRecord | None) -> ScanSnapshot:
    """What the database holds about a scan. Config digests are not persisted, so they are None."""
    usable = stage_null_reason((scan.stages or {}).get("graph")) is None
    nodes = session.scalars(select(GraphNode).where(GraphNode.scan_id == scan.id)).all()
    labels = {node.node_key: node.label for node in nodes}
    edges = session.scalars(select(GraphEdge).where(GraphEdge.scan_id == scan.id)).all()
    centralities = [
        node.attributes["betweenness_centrality"]
        for node in nodes
        if node.attributes and "betweenness_centrality" in node.attributes
    ]
    return ScanSnapshot(
        config_sha256=None,
        edges=frozenset(
            (labels.get(e.source_key, e.source_key), labels.get(e.target_key, e.target_key))
            for e in edges
        ),
        max_centrality=max(centralities) if usable and centralities else None,
        attestation_present=record.provenance_present if record else None,
    )


def _comparison(
    session: Session, scan: Scan, record: ProvenanceRecord | None
) -> dict[str, Any] | None:
    """Compare with the prior scan the provenance stage used. None when there is no prior scan."""
    if record is None or record.previous_scan_id is None:
        return None
    prior = session.get(Scan, record.previous_scan_id)
    if prior is None:
        return None
    result = compare_snapshots(
        _snapshot(session, prior, _provenance_row(session, prior.id)),
        _snapshot(session, scan, record),
    )
    if stage_null_reason((prior.stages or {}).get("graph")) is not None:
        result["new_edge_count"] = None  # no usable prior graph, so every edge would look new
    return result


def _version_consistency(scan: Scan, settings: Settings) -> bool | None:
    """Compare declared versions in the kept workspace. Files are only parsed, with size limits."""
    try:
        workspace = open_workspace(Path(settings.workspace_root), scan.id)
        return version_consistency(declared_versions(workspace.src_dir, scan.revision_requested))
    except (AppError, OSError) as exc:
        logger.warning("Scan %s: version consistency unavailable: %s", scan.id, type(exc).__name__)
        return None


def _finding_refs(session: Session, scan_id: Any) -> tuple[FindingRef, ...]:
    rows = session.scalars(select(Finding).where(Finding.scan_id == scan_id)).all()
    return tuple(
        FindingRef(
            finding_id=str(row.id),
            category=str(row.category),
            identifier=row.identifier,
            severity=row.severity,
            source=row.source,
        )
        for row in rows
    )


def _contains_mock(scan: Scan, findings: tuple[FindingRef, ...]) -> bool:
    stages = (scan.stages or {}).values()
    return any(f.source == "mock" for f in findings) or any(
        isinstance(s, Mapping) and (s.get("source") == "mock" or s.get("is_mock") is True)
        for s in stages
    )


def _training_label(models: LoadedModels | None) -> dict[str, Any]:
    if models is None:
        return {"label": "synthetic", "models_used": False, "notice": _NO_MODEL_NOTICE}
    if models.bundle.metadata.get("synthetic") is True:
        return {"label": "synthetic", "models_used": True, "notice": _SYNTHETIC_NOTICE}
    return {"label": "unverified", "models_used": True, "notice": _UNVERIFIED_NOTICE}


def _run_models(
    scan: Scan, extraction: FeatureExtraction, settings: Settings
) -> tuple[MlOutputs | None, str | None, dict[str, Any], dict[str, Any]]:
    """Return (outputs, why unavailable, SHAP result, training-data label)."""
    features, reasons = extraction.features, extraction.null_reasons
    plain = not_evaluated_features(None, features, reasons)
    artifact_type = str(scan.artifact.artifact_type)
    if artifact_type not in TRAINED_ARTIFACT_TYPES:
        reason = f"the models were not trained on artifact type {artifact_type!r}"
        return None, reason, unavailable(f"No explanation: {reason}", plain), _training_label(None)
    try:
        models = load_models(Path(settings.model_path))
    except ModelUnavailable as exc:
        return None, str(exc), unavailable(f"No explanation: {exc}", plain), _training_label(None)
    try:
        row = encode_features(models, features)
        outputs = score_row(models, row)
    except Exception as exc:  # any scoring failure falls back to the rule-based result
        logger.exception("Scan %s: model scoring failed", scan.id)
        reason = f"scoring failed ({type(exc).__name__})"
        return None, reason, unavailable(f"No explanation: {reason}", plain), _training_label(None)
    shap_result = explain_random_forest(models, row, features, reasons, outputs.rf_risk_probability)
    return outputs, None, shap_result, _training_label(models)


def _cvss_reason(extraction: FeatureExtraction) -> str | None:
    if extraction.features.get("cvss_max") is not None:
        return None
    if extraction.features.get("vulnerable_count") == 0:
        return "No known vulnerable component was found, so there is no CVSS score"
    return f"CVSS not available: {extraction.null_reasons.get('cvss_max')}"


def _hard_rule_evidence(
    assessment: RiskAssessment, findings: tuple[FindingRef, ...]
) -> dict[str, dict[str, list[str]]]:
    """For each fired rule, the evidence layers and the findings behind it."""
    rules = {rule.rule_id: rule for rule in DEFAULT_POLICY.hard_rules}
    evidence: dict[str, dict[str, list[str]]] = {}
    for fired in assessment.hard_rules_fired:
        layers: set[RiskLayer] = set()
        finding_ids: list[str] = []
        for predicate in rules[fired.rule_id].predicates:
            if predicate.feature is not None:
                layers.add(FEATURE_LAYERS[predicate.feature])
            if predicate.check is not None:
                layers.add(RiskLayer.PROVENANCE)
            for finding in findings:
                if finding.identifier == predicate.finding and finding.source != "mock":
                    finding_ids.append(finding.finding_id)
                    layers.add(FINDING_LAYERS[finding.category])
        evidence[fired.rule_id] = {
            "layers": sorted(str(layer) for layer in layers),
            "finding_ids": finding_ids,
        }
    return evidence


def _compute(session: Session, scan: Scan, settings: Settings) -> RiskDecision:
    record = _provenance_row(session, scan.id)
    findings = _finding_refs(session, scan.id)
    artifact_type = str(scan.artifact.artifact_type)
    extraction = extract_features(
        artifact_type,
        scan.stages or {},
        _provenance_document(record),
        _comparison(session, scan, record),
        _version_consistency(scan, settings),
    )
    outputs, ml_reason, shap_result, training_data = _run_models(scan, extraction, settings)
    assessment = assess_risk(
        RiskInputs(
            artifact_type=artifact_type,
            features=extraction.features,
            null_reasons=extraction.null_reasons,
            findings=findings,
            provenance_checks=record.checks if record else None,
            ml=outputs,
            ml_unavailable_reason=ml_reason,
            record_id=str(scan.id),
        )
    )
    return RiskDecision(
        scan_id=scan.id,
        risk_score=assessment.risk_score,
        rule_only_score=assessment.rule_only_score,
        decision=RiskVerdict(assessment.decision),
        decision_basis=assessment.decision_basis,
        confidence=assessment.confidence,
        confidence_label=str(assessment.confidence_label),
        cvss_max=assessment.cvss_max,
        ml_status=assessment.ml.status,
        ml_probability=assessment.ml.rf_risk_probability,
        xgb_probability=assessment.ml.xgb_risk_probability,
        anomaly_score=assessment.ml.anomaly_score,
        model_version=assessment.ml.model_version,
        policy_version=assessment.policy_version,
        layer_scores={str(layer.layer): layer.score for layer in assessment.layers},
        explanation={
            "assessment": assessment.model_dump(mode="json"),
            "shap": shap_result,
            "training_data": training_data,
            "contains_mock_evidence": _contains_mock(scan, findings),
            "cvss_reason": _cvss_reason(extraction),
            "hard_rule_evidence": _hard_rule_evidence(assessment, findings),
        },
    )


def _stored(session: Session, scan_id: Any) -> RiskDecision | None:
    return session.scalars(select(RiskDecision).where(RiskDecision.scan_id == scan_id)).first()


def _store(session: Session, scan_id: Any, decision: RiskDecision) -> RiskDecision:
    """Commit the decision. If a concurrent request stored one first, return that one."""
    session.add(decision)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        winner = _stored(session, scan_id)
        if winner is None:
            raise
        return winner
    return decision


def risk_for_scan(session: Session, scan: Scan, settings: Settings) -> RiskResponse:
    """Return the risk result, or an explicit pending or not_computed state."""
    if scan.status in (ScanStatus.QUEUED, ScanStatus.RUNNING):
        return RiskResponse.without_result(
            scan,
            RiskStatus.PENDING,
            f"scan_{scan.status}",
            f"The scan is {scan.status}. Risk is computed after the evidence stages finish.",
        )
    if scan.status == ScanStatus.FAILED:
        return RiskResponse.without_result(
            scan,
            RiskStatus.NOT_COMPUTED,
            "scan_failed",
            f"The scan failed ({scan.error_code}), so there is no evidence to score.",
        )
    decision = _stored(session, scan.id)
    if decision is None:
        try:
            computed = _compute(session, scan, settings)
        except SQLAlchemyError:
            raise
        except Exception:  # reported as an explicit state; nothing is stored, so a retry can work
            logger.exception("Scan %s: risk computation failed", scan.id)
            return RiskResponse.without_result(
                scan,
                RiskStatus.NOT_COMPUTED,
                "risk_computation_error",
                "Risk could not be computed because of an internal error.",
            )
        decision = _store(session, scan.id, computed)
    return RiskResponse.from_decision(scan, decision)
