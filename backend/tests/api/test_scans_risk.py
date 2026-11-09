"""API tests for GET /scans/{id}/risk on SQLite. Scan rows are written directly where a state
cannot be reached through the mock pipeline; saved models are trained on synthetic records."""

import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.scans import get_scan_providers, get_session_factory
from app.core.config import get_settings
from app.db.models import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Finding,
    FindingCategory,
    ProvenanceRecord,
    RiskDecision,
    Scan,
    ScanStatus,
)
from app.main import create_app
from app.pipeline.providers import build_providers
from app.risk import model_runtime, service
from tests.conftest import SIMPLE_PROJECT, zip_dir
from tests.unit.test_risk_explain import CONFIG, META, generate_records

BACKEND = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def empty_cache():
    model_runtime.clear_cache()
    yield
    model_runtime.clear_cache()


@pytest.fixture(scope="module")
def models_dir(tmp_path_factory):
    from app.ml.artifacts import save_bundle
    from app.ml.training import train_models

    records = generate_records(60, 7)
    train = [r for r in records if r.split == "train"]
    validation = [r for r in records if r.split == "validation"]
    directory = tmp_path_factory.mktemp("risk-models")
    save_bundle(train_models(train, validation, META, CONFIG), directory)
    return directory


def _client(settings, session_factory) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    app.dependency_overrides[get_scan_providers] = lambda: build_providers(settings)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def settings(test_settings, tmp_path):
    return test_settings.model_copy(update={"model_path": tmp_path / "no-models"})


@pytest.fixture
def client(settings, session_factory, public_dns):
    return _client(settings, session_factory)


def _make_scan(session_factory, *, status=ScanStatus.COMPLETED, stages=None, kind=None, **extra):
    with session_factory() as session:
        artifact = Artifact(
            artifact_type=kind or ArtifactType.SOFTWARE,
            name="a",
            source=ArtifactSource.UPLOAD,
        )
        scan = Scan(artifact=artifact, status=status, scanner_version="t", stages=stages, **extra)
        session.add_all([artifact, scan])
        session.commit()
        return scan.id


def _upload(client) -> str:
    response = client.post(
        "/api/v1/scans/software",
        files={"file": ("p.zip", zip_dir(SIMPLE_PROJECT), "application/zip")},
    )
    assert response.status_code == 202, response.text
    return response.json()["scan_id"]


def _risk(client, scan_id):
    response = client.get(f"/api/v1/scans/{scan_id}/risk")
    assert response.status_code == 200, response.text
    return response.json()


def _stored_count(session_factory):
    with session_factory() as session:
        return session.query(RiskDecision).count()


def test_unknown_scan_is_a_structured_404(client):
    response = client.get(f"/api/v1/scans/{uuid.uuid4()}/risk")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "scan_not_found"


@pytest.mark.parametrize("status", [ScanStatus.QUEUED, ScanStatus.RUNNING])
def test_unfinished_scan_is_pending_with_null_values(client, session_factory, status):
    body = _risk(client, _make_scan(session_factory, status=status))
    assert body["status"] == "pending"
    assert body["reason"]["code"] == f"scan_{status}"
    assert body["risk_score"] is None
    assert body["decision"] is None
    assert body["scores"]["provenancex_risk"]["value"] is None
    assert body["scores"]["provenancex_risk"]["reason"]
    assert _stored_count(session_factory) == 0


def test_failed_scan_is_not_computed(client, session_factory):
    scan_id = _make_scan(session_factory, status=ScanStatus.FAILED, error_code="clone_failed")
    body = _risk(client, scan_id)
    assert body["status"] == "not_computed"
    assert body["reason"]["code"] == "scan_failed"
    assert "clone_failed" in body["reason"]["message"]
    assert body["risk_score"] is None
    assert body["decision"] is None
    assert _stored_count(session_factory) == 0


def test_no_scorable_layer_gives_null_score_not_zero(client, session_factory):
    body = _risk(client, _make_scan(session_factory, stages={}))
    assert body["status"] == "not_computed"
    assert body["reason"]["code"] == "no_rule_layer_scored"
    assert body["risk_score"] is None
    assert body["rule_only_score"] is None
    assert body["scores"]["provenancex_risk"]["value"] is None
    assert body["scores"]["provenancex_risk"]["reason"]
    assert body["decision"] == "REVIEW"
    assert body["decision_basis"] == "insufficient_evidence"
    assert body["confidence"] == 0.0
    assert body["confidence_label"] == "LOW"
    with session_factory() as session:
        assert session.query(RiskDecision).one().risk_score is None


def test_completed_scan_reports_every_section(client):
    body = _risk(client, _upload(client))
    assert body["status"] == "computed"
    assert body["reason"] is None
    assert 0.0 <= body["risk_score"] <= 1.0
    assert body["decision"] in {"ALLOW", "REVIEW", "BLOCK"}
    assert body["confidence_label"] in {"LOW", "MEDIUM", "HIGH"}
    assert {"not_evaluated", "fired"} <= set(body["hard_rules"])
    assert {layer["layer"] for layer in body["layers"]} >= {
        "vulnerability",
        "provenance_integrity",
        "static",
        "behavioral",
        "ml_supervised",
        "ml_anomaly",
    }
    assert set(body["scores"]) == {
        "provenancex_risk",
        "cvss_max",
        "ml_probability",
        "anomaly_score",
    }
    assert body["evidence_links"]


def test_contributions_trace_the_score(client):
    body = _risk(client, _upload(client))
    total = sum(layer["contribution"] or 0.0 for layer in body["layers"])
    assert total + body["ml_band_adjustment"] == pytest.approx(body["risk_score"])


def test_no_model_states_ml_unavailable_with_null_values(client):
    body = _risk(client, _upload(client))
    assert body["ml"]["status"] == "unavailable"
    assert "ML model unavailable" in body["ml"]["message"]
    assert body["scores"]["ml_probability"]["value"] is None
    assert "ML model unavailable" in body["scores"]["ml_probability"]["reason"]
    assert body["scores"]["anomaly_score"]["value"] is None
    assert body["explanation"]["status"] == "unavailable"
    assert body["explanation"]["top_factors"] == []
    assert body["training_data"]["label"] == "synthetic"
    assert body["training_data"]["models_used"] is False


def test_mock_evidence_is_labeled_and_not_scored(client):
    body = _risk(client, _upload(client))
    assert body["contains_mock_evidence"] is True
    vulnerability = next(lay for lay in body["layers"] if lay["layer"] == "vulnerability")
    assert vulnerability["score"] is None
    assert vulnerability["not_evaluated"]["vulnerable_count"] == "mock_evidence"
    assert vulnerability["mock_findings_ignored"] > 0


def test_result_is_stored_once(client, session_factory, monkeypatch):
    scan_id = _upload(client)
    first = _risk(client, scan_id)

    def fail(*_args):
        raise AssertionError("must not recompute")

    monkeypatch.setattr(service, "compute_decision", fail)
    second = _risk(client, scan_id)
    first.pop("computed_at"), second.pop("computed_at")  # SQLite drops the timezone on re-read
    assert second == first
    assert _stored_count(session_factory) == 1


def test_computation_error_is_explicit_and_not_stored(client, session_factory, monkeypatch):
    def fail(*_args):
        raise RuntimeError("boom")

    monkeypatch.setattr(service, "compute_decision", fail)
    monkeypatch.setattr("app.pipeline.risk_stage.compute_decision", fail)
    scan_id = _upload(client)
    scan = client.get(f"/api/v1/scans/{scan_id}").json()
    assert scan["status"] == "completed"  # a failed risk stage never fails the scan
    assert scan["stages"]["risk"]["status"] == "error"
    assert "boom" not in str(scan["stages"]["risk"])
    body = _risk(client, scan_id)
    assert body["status"] == "not_computed"
    assert body["reason"]["code"] == "risk_computation_error"
    assert "boom" not in str(body)
    assert body["risk_score"] is None
    assert _stored_count(session_factory) == 0


def test_risk_stage_stores_the_decision_during_the_scan(client, session_factory):
    scan_id = _upload(client)
    with session_factory() as session:
        decision = session.query(RiskDecision).one()
        assert str(decision.scan_id) == scan_id
        assert decision.model_version is None  # no model was used
    stage = client.get(f"/api/v1/scans/{scan_id}").json()["stages"]["risk"]
    assert stage["status"] == "completed"
    assert stage["ml_status"] == "unavailable"
    assert stage["decision"] == decision.decision
    snapshot = stage["comparison_snapshot"]
    assert set(snapshot) == {
        "config_sha256",
        "max_centrality",
        "attestation_present",
        "edge_count",
    }
    assert snapshot["edge_count"] > 0


def test_model_version_is_stored_with_the_decision(
    settings, session_factory, public_dns, models_dir
):
    client = _client(settings.model_copy(update={"model_path": models_dir}), session_factory)
    scan_id = _upload(client)
    stage = client.get(f"/api/v1/scans/{scan_id}").json()["stages"]["risk"]
    with session_factory() as session:
        stored = session.query(RiskDecision).one().model_version
    assert stored.startswith("models-sha256:")
    assert stage["model_version"] == stored
    assert _risk(client, scan_id)["ml"]["model_version"] == stored


def test_with_models_values_are_separate_and_labeled_synthetic(
    settings, session_factory, public_dns, models_dir
):
    client = _client(settings.model_copy(update={"model_path": models_dir}), session_factory)
    body = _risk(client, _upload(client))
    scores = body["scores"]
    assert 0.0 <= scores["ml_probability"]["value"] <= 1.0
    assert scores["anomaly_score"]["value"] is not None
    assert scores["ml_probability"]["value"] != body["risk_score"]
    assert body["ml"]["status"] == "available"
    assert body["ml"]["model_version"].startswith("models-sha256:")
    assert body["training_data"] == {
        "label": "synthetic",
        "models_used": True,
        "notice": body["training_data"]["notice"],
    }
    assert "synthetic data" in body["training_data"]["notice"]
    explanation = body["explanation"]
    assert explanation["status"] == "available"
    assert explanation["top_factors"]
    assert "not the ProvenanceX risk score" in explanation["explains"]
    for factor in explanation["top_factors"]:
        assert factor["evaluated"] is (factor["value"] is not None)
        assert factor["evaluated"] or factor["null_reason"]
    assert {f["null_reason"] for f in explanation["not_evaluated_features"]} >= {"no_data_source"}


def test_ml_cannot_change_the_decision(settings, session_factory, public_dns, models_dir):
    without = _client(settings, session_factory)
    decision_a = _risk(without, _upload(without))
    withm = _client(settings.model_copy(update={"model_path": models_dir}), session_factory)
    decision_b = _risk(withm, _upload(withm))
    assert decision_a["decision"] == decision_b["decision"]


def test_dataset_scans_are_outside_the_trained_types(
    settings, session_factory, public_dns, models_dir
):
    client = _client(settings.model_copy(update={"model_path": models_dir}), session_factory)
    body = _risk(client, _make_scan(session_factory, stages={}, kind=ArtifactType.DATASET))
    assert body["ml"]["status"] == "unavailable"
    assert "not trained on artifact type" in body["ml"]["message"]


def test_scoring_failure_falls_back_to_rules(settings, session_factory, public_dns, monkeypatch):
    client = _client(settings, session_factory)

    def fake_load(_path):
        return object()

    def fail(_models, _features):
        raise ValueError("bad value")

    monkeypatch.setattr(service, "load_models", fake_load)
    monkeypatch.setattr(service, "encode_features", fail)
    body = _risk(client, _upload(client))
    assert body["status"] == "computed"
    assert body["ml"]["status"] == "unavailable"
    assert "ValueError" in body["ml"]["message"]


def test_cvss_is_separate_and_null_when_nothing_is_vulnerable(client, session_factory):
    graph = {"status": "completed", "features": {"vulnerable_count": 0, "cvss_max": None}}
    stages = {"graph": graph, "vulnerabilities": {"status": "completed"}}
    body = _risk(client, _make_scan(session_factory, stages=stages))
    assert body["scores"]["cvss_max"]["value"] is None
    assert "No known vulnerable" in body["scores"]["cvss_max"]["reason"]


def _scan_with_evidence(session_factory, identifier):
    scan_id = _make_scan(
        session_factory,
        stages={"provenance": {"status": "completed", "source": "provenancex"}},
    )
    with session_factory() as session:
        session.add(
            ProvenanceRecord(
                scan_id=scan_id,
                source_known=True,
                revision_pinned=True,
                signature_files_present=False,
                provenance_present=False,
                checks=[{"name": "hash_consistency", "status": "fail"}],
                record_sha256="0" * 64,
                source="provenancex",
            )
        )
        finding = Finding(
            scan_id=scan_id,
            category=FindingCategory.BEHAVIORAL,
            identifier=identifier,
            severity="HIGH",
            source="provenancex",
        )
        session.add(finding)
        session.commit()
        return scan_id, str(finding.id)


def test_layers_link_to_their_evidence(client, session_factory):
    scan_id, _ = _scan_with_evidence(session_factory, "PX-BEHAV-SHELL-SPAWN")
    body = _risk(client, scan_id)
    layer = next(lay for lay in body["layers"] if lay["layer"] == "provenance_integrity")
    hrefs = {link["href"] for link in layer["evidence_links"]}
    assert f"/api/v1/scans/{scan_id}/findings?category=provenance" in hrefs
    assert f"/api/v1/scans/{scan_id}" in hrefs


def test_fired_hard_rules_link_to_their_evidence(client, session_factory):
    scan_id, finding_id = _scan_with_evidence(session_factory, "PX-BEHAV-SHELL-SPAWN")
    body = _risk(client, scan_id)
    assert body["decision"] == "BLOCK"
    fired = {rule["rule_id"]: rule for rule in body["hard_rules"]["fired"]}
    hashes = {link["href"] for link in fired["hash_consistency_failed"]["evidence_links"]}
    assert f"/api/v1/scans/{scan_id}/findings?category=provenance" in hashes
    shell = fired["shell_spawn"]
    assert shell["finding_ids"] == [finding_id]
    assert f"/api/v1/scans/{scan_id}/findings?category=behavioral" in {
        link["href"] for link in shell["evidence_links"]
    }


def test_null_score_still_reports_a_fired_hard_rule(client, session_factory):
    """A hard rule keeps its force when nothing can be scored, and the score stays null."""
    scan_id = _make_scan(session_factory, stages={})
    with session_factory() as session:
        session.add(
            ProvenanceRecord(
                scan_id=scan_id,
                source_known=True,
                revision_pinned=True,
                signature_files_present=False,
                provenance_present=False,
                checks=[{"name": "hash_consistency", "status": "fail"}],
                record_sha256="0" * 64,
                source="provenancex",
            )
        )
        session.commit()
    body = _risk(client, scan_id)
    assert body["risk_score"] is None
    assert body["status"] == "not_computed"
    assert body["decision"] == "BLOCK"
    assert body["decision_basis"] == "hard_rule"


def test_api_starts_without_ml_packages():
    """The API image has no ML packages, so nothing may import them at startup."""
    code = (
        "import sys\n"
        "for name in ('numpy', 'sklearn', 'xgboost', 'skops', 'shap', 'scipy'):\n"
        "    sys.modules[name] = None\n"
        "import app.main\n"
        "from app.risk.model_runtime import ModelUnavailable, load_models\n"
        "from pathlib import Path\n"
        "try:\n"
        "    load_models(Path('absent'))\n"
        "except ModelUnavailable as exc:\n"
        "    assert 'not installed' in str(exc), exc\n"
        "else:\n"
        "    raise SystemExit('expected ModelUnavailable')\n"
    )
    result = subprocess.run(  # noqa: S603 - fixed code, no untrusted input
        [sys.executable, "-c", code], cwd=BACKEND, capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
