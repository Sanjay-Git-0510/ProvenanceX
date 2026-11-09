"""API tests for GET /scans/{id}/evidence: content, bounds, errors, and that nothing leaks."""

import re
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api.scans import get_scan_providers, get_session_factory
from app.core.config import get_settings
from app.db.models import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Component,
    Finding,
    FindingCategory,
    ProvenanceRecord,
    Scan,
    ScanStatus,
)
from app.main import create_app
from app.pipeline.providers import build_providers
from app.risk import model_runtime
from app.schemas.evidence import MAX_PAGE, MAX_TEXT, REDACTED, Sanitized, sanitize
from tests.conftest import SIMPLE_PROJECT, build_zip, zip_dir

CANARY = "PX_FILE_CONTENT_CANARY_7f3a"
NVD_KEY = "nvd-settings-key-value-6b1c"
CHAIN_KEY = "0x" + "ab" * 32
HOST_PATH = re.compile(
    r"(?<![\w:.\-/])/(?:home|root|app|tmp|var|etc|mnt|workspace|workspaces|usr|opt|srv|Users)/"
)
SECRET_LIKE = re.compile(
    r"ghp_[A-Za-z0-9]{20}|hf_[A-Za-z0-9]{20}|AKIA[A-Z0-9]{16}|BEGIN [A-Z ]*PRIVATE KEY"
    r"|(?i:password\s*=)|(?i:api_key\s*=)|0x[0-9a-f]{64}|[A-Z]:\\\\"
)
SECRETS = {
    "path": "/home/victim/provenancex/workspace/scan/src/app.py",
    "windows": r"C:\Users\victim\secrets.txt",
    "github": "ghp_" + "a1B2" * 9,
    "huggingface": "hf_" + "Zz9y" * 8,
    "aws": "AKIA" + "ABCDEFGHIJKLMNOP",
    "pem": "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
    "assignment": "password=hunter2",
    "url_credentials": "https://user:hunter2@example.test/x",
    "chain": CHAIN_KEY,
}
ALL_SECRETS = " | ".join(SECRETS.values())


@pytest.fixture(autouse=True)
def empty_cache():
    model_runtime.clear_cache()
    yield
    model_runtime.clear_cache()


@pytest.fixture
def settings(test_settings, tmp_path):
    return test_settings.model_copy(
        update={
            "model_path": tmp_path / "secret-model-dir",
            "nvd_api_key": NVD_KEY,
            "blockchain_private_key": CHAIN_KEY,
        }
    )


def _client(settings, session_factory) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    app.dependency_overrides[get_scan_providers] = lambda: build_providers(settings)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def client(settings, session_factory, public_dns):
    return _client(settings, session_factory)


def _url(scan_id):
    return f"/api/v1/scans/{scan_id}/evidence"


def _evidence(client, scan_id, **params):
    response = client.get(_url(scan_id), params=params)
    assert response.status_code == 200, response.text
    return response.json()


def _upload(client, data=None) -> str:
    payload = data if data is not None else zip_dir(SIMPLE_PROJECT)
    response = client.post(
        "/api/v1/scans/software", files={"file": ("p.zip", payload, "application/zip")}
    )
    assert response.status_code == 202, response.text
    return response.json()["scan_id"]


def _make_scan(session_factory, status=ScanStatus.COMPLETED, **extra):
    with session_factory() as session:
        artifact = Artifact(
            artifact_type=ArtifactType.SOFTWARE, name="a", source=ArtifactSource.UPLOAD
        )
        scan = Scan(artifact=artifact, status=status, scanner_version="t", **extra)
        session.add_all([artifact, scan])
        session.commit()
        return scan.id


def test_unknown_scan_is_a_structured_404(client):
    response = client.get(_url(uuid.uuid4()))
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "scan_not_found"


def test_malformed_scan_id_is_a_structured_error(client):
    response = client.get(_url("not-a-uuid"))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


@pytest.mark.parametrize(
    "params",
    [
        {"findings_limit": MAX_PAGE + 1},
        {"components_limit": MAX_PAGE + 1},
        {"findings_limit": 0},
        {"components_limit": 0},
        {"findings_offset": -1},
        {"components_offset": -1},
        {"findings_offset": 2**31},
        {"findings_limit": "many"},
    ],
    ids=str,
)
def test_out_of_range_paging_is_a_structured_error(client, session_factory, params):
    response = client.get(_url(_make_scan(session_factory)), params=params)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_completed_scan_reports_every_section(client):
    scan_id = _upload(client)
    body = _evidence(client, scan_id)
    assert body["scan_id"] == scan_id
    assert body["scan_status"] == "completed"
    assert body["scan_error"] is None
    stages = {stage["name"]: stage for stage in body["stages"]}
    assert {"sbom", "graph", "vulnerabilities", "provenance", "static", "sandbox", "risk"} <= set(
        stages
    )
    assert stages["sandbox"]["status"] == "skipped"
    assert stages["sandbox"]["reason"]
    assert body["findings"]["page"]["total"] > 0
    assert body["findings"]["by_source"]
    assert body["components"]["page"]["total"] > 0
    assert all(item["source"] for item in body["components"]["items"])
    assert body["provenance"]["checks"]
    assert body["hashes"]["artifact_sha256"]["value"]
    assert body["hashes"]["bom_sha256"]["value"]
    assert body["hashes"]["provenance_record_sha256"]["value"]
    assert body["sanitized"]["redacted_values"] == 0


def test_feature_vector_has_a_reason_for_every_null(client):
    vector = _evidence(client, _upload(client))["feature_vector"]
    assert vector["status"] == "available"
    assert len(vector["features"]) > 30
    for feature in vector["features"]:
        assert feature["evaluated"] is (feature["value"] is not None)
        assert feature["evaluated"] or feature["null_reason"]
    by_name = {f["name"]: f for f in vector["features"]}
    assert by_name["vulnerable_count"]["null_reason"] == "mock_evidence"
    assert by_name["signed"]["null_reason"] == "no_data_source"


def test_mock_evidence_is_flagged(client):
    body = _evidence(client, _upload(client))
    assert body["mock"]["contains_mock_evidence"] is True
    assert {"sbom", "vulnerabilities"} <= set(body["mock"]["mock_stages"])
    assert body["mock"]["mock_findings"] > 0
    assert body["mock"]["mock_components"] > 0
    assert all(item["is_mock"] for item in body["components"]["items"])
    assert any(item["is_mock"] for item in body["findings"]["items"])
    stages = {stage["name"]: stage for stage in body["stages"]}
    assert stages["sbom"]["is_mock"] is True
    assert stages["static"]["is_mock"] is False


def test_trace_hash_is_reported_without_the_trace(settings, session_factory, public_dns):
    client = _client(settings.model_copy(update={"sandbox_provider": "mock"}), session_factory)
    response = client.get(_url(_upload(client)))
    body = response.json()
    assert re.fullmatch(r"[0-9a-f]{64}", body["hashes"]["sandbox_trace_sha256"]["value"])
    assert "strace_lines" not in response.text
    assert "trace_file" not in response.text


def test_missing_hashes_are_null_with_a_reason(client, session_factory):
    hashes = _evidence(client, _make_scan(session_factory))["hashes"]
    for value in hashes.values():
        assert value["value"] is None
        assert value["reason"]


def test_without_a_model_the_version_is_null_and_label_says_no_model(client):
    body = _evidence(client, _upload(client))
    assert body["model"] == {"model_version": None, "ml_status": "unavailable"}
    assert body["training_data"]["label"] == "synthetic"
    assert body["training_data"]["models_used"] is False


def test_with_models_the_version_and_synthetic_label_are_reported(
    settings, session_factory, public_dns, tmp_path
):
    from app.ml.artifacts import save_bundle
    from app.ml.dataset.generator import generate_records
    from app.ml.training import TrainingConfig, train_models

    records = generate_records(60, 7)
    directory = tmp_path / "models"
    save_bundle(
        train_models(
            [r for r in records if r.split == "train"],
            [r for r in records if r.split == "validation"],
            {"synthetic": True, "notice": "SYNTHETIC", "dataset_sha256": "abc"},
            TrainingConfig(rf_estimators=5, xgb_estimators=3, iforest_estimators=5, n_jobs=1),
        ),
        directory,
    )
    client = _client(settings.model_copy(update={"model_path": directory}), session_factory)
    body = _evidence(client, _upload(client))
    assert body["model"]["model_version"].startswith("models-sha256:")
    assert body["model"]["ml_status"] == "available"
    assert body["training_data"]["label"] == "synthetic"
    assert body["training_data"]["models_used"] is True


@pytest.mark.parametrize(
    ("status", "expected"),
    [(ScanStatus.QUEUED, "pending"), (ScanStatus.RUNNING, "pending")],
)
def test_unfinished_scan_has_no_feature_vector(client, session_factory, status, expected):
    body = _evidence(client, _make_scan(session_factory, status=status))
    assert body["feature_vector"]["status"] == expected
    assert body["feature_vector"]["reason"]["code"] == f"scan_{status}"
    assert body["feature_vector"]["features"] == []
    assert body["model"] == {"model_version": None, "ml_status": None}


def test_failed_scan_reports_its_error_without_details(client, session_factory):
    scan_id = _make_scan(
        session_factory,
        status=ScanStatus.FAILED,
        error_code="clone_failed",
        error_message="The clone failed",
        error_details={"stderr": "PX_DETAIL_ONLY"},
    )
    response = client.get(_url(scan_id))
    body = response.json()
    assert body["scan_error"] == {"code": "clone_failed", "message": "The clone failed"}
    assert body["feature_vector"]["status"] == "not_computed"
    assert "PX_DETAIL_ONLY" not in response.text


def test_evidence_does_not_compute_a_result(client, session_factory):
    body = _evidence(client, _make_scan(session_factory, stages={}))
    assert body["feature_vector"]["reason"]["code"] == "no_risk_decision"
    with session_factory() as session:
        from app.db.models import RiskDecision

        assert session.query(RiskDecision).count() == 0


def _bulk_scan(session_factory, count):
    scan_id = _make_scan(session_factory)
    with session_factory() as session:
        for index in range(count):
            session.add(
                Finding(
                    scan_id=scan_id,
                    category=FindingCategory.STATIC,
                    identifier=f"PX-{index:04d}",
                    title="t" * 512,
                    severity="LOW",
                    source="provenancex",
                )
            )
            session.add(
                Component(
                    scan_id=scan_id,
                    bom_ref=f"r{index}",
                    name=f"{index:04d}-" + "n" * 1000,
                    component_type="library",
                    purl="pkg:pypi/" + "p" * 2000,
                    source="syft",
                )
            )
        session.commit()
    return scan_id


def test_pages_are_separate_and_do_not_overlap(client, session_factory):
    scan_id = _bulk_scan(session_factory, 7)
    first = _evidence(client, scan_id, findings_limit=3, components_limit=2)
    second = _evidence(
        client,
        scan_id,
        findings_limit=3,
        findings_offset=3,
        components_limit=2,
        components_offset=2,
    )
    assert first["findings"]["page"] == {"total": 7, "limit": 3, "offset": 0, "has_more": True}
    assert first["components"]["page"]["limit"] == 2
    ids = [i["finding_id"] for i in first["findings"]["items"] + second["findings"]["items"]]
    assert len(set(ids)) == 6
    names = [
        i["component_id"] for i in first["components"]["items"] + second["components"]["items"]
    ]
    assert len(set(names)) == 4
    last = _evidence(client, scan_id, findings_limit=3, findings_offset=6)
    assert last["findings"]["page"]["has_more"] is False
    assert len(last["findings"]["items"]) == 1


def test_summaries_count_everything_beyond_the_page(client, session_factory):
    body = _evidence(client, _bulk_scan(session_factory, 7), findings_limit=1)
    assert body["findings"]["by_category"] == {"static": 7}
    assert body["findings"]["by_severity"] == {"LOW": 7}
    assert body["findings"]["by_source"] == {"provenancex": 7}
    assert body["components"]["by_source"] == {"syft": 7}


def test_response_size_is_bounded(client, session_factory):
    scan_id = _bulk_scan(session_factory, MAX_PAGE + 40)
    default = client.get(_url(scan_id))
    assert len(default.json()["findings"]["items"]) == 50
    largest = client.get(_url(scan_id), params={"findings_limit": 200, "components_limit": 200})
    body = largest.json()
    assert len(body["findings"]["items"]) == MAX_PAGE
    assert len(body["components"]["items"]) == MAX_PAGE
    assert body["sanitized"]["truncated_values"] > 0
    assert all(len(i["purl"]) <= MAX_TEXT + 20 for i in body["components"]["items"])
    assert len(largest.content) < 2 * 1024 * 1024


def _hostile_scan(session_factory, settings):
    stage = {
        "status": "error",
        "source": "provenancex",
        "reason": ALL_SECRETS,
        "error": {"code": "x", "message": ALL_SECRETS, "details": {"raw": "PX_DETAIL_ONLY"}},
        "limitations": [ALL_SECRETS],
        "incomplete_reasons": [ALL_SECRETS],
        "warnings": [ALL_SECRETS],
        "trace_file": str(settings.workspace_root / "trace.json"),
        "sbom_file": "/app/workspace/sbom.cdx.json",
        "raw": "PX_DETAIL_ONLY",
        "trace_sha256": "a" * 64,
    }
    scan_id = _make_scan(
        session_factory,
        status=ScanStatus.FAILED,
        error_code="internal",
        error_message=ALL_SECRETS,
        error_details={"path": ALL_SECRETS},
        ingest_metadata={"hf": {"token": ALL_SECRETS}},
        stages={"sandbox": stage},
    )
    with session_factory() as session:
        session.add(
            Finding(
                scan_id=scan_id,
                category=FindingCategory.STATIC,
                identifier=SECRETS["github"],
                title=ALL_SECRETS[:512],
                severity="HIGH",
                source="provenancex",
                details={"snippet": "PX_DETAIL_ONLY", "file": ALL_SECRETS},
            )
        )
        session.add(
            Component(
                scan_id=scan_id,
                bom_ref="r",
                name=ALL_SECRETS,
                version=SECRETS["assignment"],
                component_type="library",
                purl=SECRETS["url_credentials"],
                source="syft",
                properties={"x": "PX_DETAIL_ONLY"},
            )
        )
        session.add(
            ProvenanceRecord(
                scan_id=scan_id,
                source_known=True,
                revision_pinned=False,
                signature_files_present=False,
                provenance_present=False,
                checks=[
                    {
                        "name": "n",
                        "status": "fail",
                        "evidence": ALL_SECRETS,
                        "data": {"files": ["PX_DETAIL_ONLY"]},
                    }
                ],
                record_sha256="b" * 64,
                source="provenancex",
            )
        )
        session.commit()
    return scan_id


def test_no_host_path_or_secret_like_string_appears(client, session_factory, settings):
    response = client.get(_url(_hostile_scan(session_factory, settings)))
    assert response.status_code == 200, response.text
    text = response.text
    for name, value in SECRETS.items():
        assert value not in text, name
    assert "hunter2" not in text
    assert HOST_PATH.search(text) is None, HOST_PATH.search(text)
    assert SECRET_LIKE.search(text) is None, SECRET_LIKE.search(text)
    assert "PX_DETAIL_ONLY" not in text
    body = response.json()
    assert body["sanitized"]["redacted_values"] > 0
    assert REDACTED in body["scan_error"]["message"]
    assert body["hashes"]["sandbox_trace_sha256"]["value"] == "a" * 64


def test_real_scan_exposes_no_paths_settings_or_file_contents(client, settings):
    files = [
        ("requirements.txt", "requests==2.32.3\n"),
        ("setup.py", f"# {CANARY}\nimport os\nos.system('true')\n"),
        ("config.json", '{"note": "' + CANARY + '"}'),
    ]
    scan_id = _upload(client, build_zip(files))
    response = client.get(
        _url(scan_id), params={"findings_limit": MAX_PAGE, "components_limit": MAX_PAGE}
    )
    text = response.text
    assert CANARY not in text
    assert str(settings.workspace_root) not in text
    assert str(settings.model_path) not in text
    assert NVD_KEY not in text
    assert CHAIN_KEY not in text
    assert HOST_PATH.search(text) is None, HOST_PATH.search(text)
    assert SECRET_LIKE.search(text) is None, SECRET_LIKE.search(text)
    assert "bomFormat" not in text
    assert "strace" not in text


@pytest.mark.parametrize(
    "value",
    [
        "a" * 64,
        "pkg:pypi/requests@2.32.3",
        "pkg:npm/%40scope/app@1.0.0",
        "https://github.com/app/home",
        "https://huggingface.co/root/tmp-model",
        "and/or the etc/home folder",
        "No HF token is used",
        "2026-11-09T05:41:06+00:00",
    ],
)
def test_ordinary_values_are_not_redacted(value):
    totals = Sanitized()
    assert sanitize(value, totals) == value
    assert totals.redacted_values == 0


@pytest.mark.parametrize("value", list(SECRETS.values()) + ["/app/workspace", "/root", "file:///x"])
def test_sensitive_values_are_redacted(value):
    totals = Sanitized()
    assert value not in sanitize(f"before {value} after", totals)
    assert totals.redacted_values == 1
