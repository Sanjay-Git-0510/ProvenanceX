"""API tests for Phase 2: SBOM/graph/vulnerability stages, /findings and /graph.

They run on in-memory SQLite with the mock providers (recorded real Syft/OSV data,
tagged source="mock"). Stage-failure tests inject failing providers.
"""

import hashlib
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api.scans import get_scan_providers, get_session_factory
from app.core.config import get_settings
from app.core.errors import AppError, ErrorCode
from app.main import create_app
from app.pipeline.providers import ScanProviders, build_providers
from app.scanners.sbom.base import SbomResult
from app.scanners.sbom.mock import MOCK_SBOM_PATH, MockSbomProvider
from app.scanners.vulns.mock import MockVulnProvider
from tests.conftest import SIMPLE_PROJECT, zip_dir

URL = "/api/v1/scans/software"


def _run_scan(client) -> dict:
    resp = client.post(URL, files={"file": ("p.zip", zip_dir(SIMPLE_PROJECT), "application/zip")})
    assert resp.status_code == 202, resp.text
    scan_id = resp.json()["scan_id"]
    body = client.get(f"/api/v1/scans/{scan_id}").json()
    return body


def _client(test_settings, session_factory, providers) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: test_settings
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    app.dependency_overrides[get_scan_providers] = lambda: providers
    return TestClient(app, raise_server_exceptions=False)


class FailingSbom:
    name = "syft"

    def __init__(self, exc):
        self.exc = exc

    def generate(self, src_dir, work_dir):
        raise self.exc


class RawSbom:
    name = "syft"

    def __init__(self, raw: bytes):
        self.raw = raw

    def generate(self, src_dir, work_dir):
        return SbomResult(raw=self.raw, source="syft", tool_name="syft", tool_version="x")


class FailingVulns:
    name = "osv"

    def __init__(self, exc):
        self.exc = exc

    def lookup(self, packages):
        raise self.exc


# ------------------------------------------------------------------ happy path (mock)
@pytest.fixture
def completed(scan_client):
    return scan_client, _run_scan(scan_client)


def test_scan_records_all_stages(completed, test_settings):
    _, body = completed
    assert body["status"] == "completed", body
    stages = body["stages"]
    assert {k: v["status"] for k, v in stages.items()} == {
        "sbom": "completed",
        "graph": "completed",
        "vulnerabilities": "completed",
        "provenance": "completed",
        "static": "completed",
    }
    assert stages["sbom"]["source"] == "mock" and stages["sbom"]["provider"] == "mock"
    assert stages["vulnerabilities"]["source"] == "mock"
    assert body["bom_sha256"] == hashlib.sha256(MOCK_SBOM_PATH.read_bytes()).hexdigest()
    assert body["component_count"] == 4
    # 10 known vulnerabilities (mock OSV) + 3 provenance failures for an upload:
    # unknown source, no signature files, no attestation.
    assert body["finding_count"] == 13
    sbom_file = test_settings.workspace_root / body["scan_id"] / "sbom.cdx.json"
    assert sbom_file.read_bytes() == MOCK_SBOM_PATH.read_bytes()
    assert oct(sbom_file.stat().st_mode & 0o777) == "0o600"


def test_findings_are_labeled_mock_and_sorted(completed):
    client, body = completed
    data = client.get(
        f"/api/v1/scans/{body['scan_id']}/findings", params={"category": "vulnerability"}
    ).json()
    assert data["total"] == 10 and data["contains_mock"] is True
    assert data["stage"]["status"] == "completed"
    items = data["items"]
    assert all(i["is_mock"] and i["source"] == "mock" for i in items)
    assert all(
        i["category"] == "vulnerability" and i["kind"] == "known_vulnerability" for i in items
    )
    scores = [i["cvss"]["score"] for i in items]
    assert scores == sorted(scores, reverse=True)
    top = items[0]
    assert top["cvss"]["score"] == 7.5 and top["severity"] == "HIGH"
    assert top["component"]["name"] in {"body-parser", "qs"}
    assert top["component"]["purl"].startswith("pkg:npm/")
    assert top["details"]["references"]


def test_findings_filters_and_paging(completed):
    client, body = completed
    base = f"/api/v1/scans/{body['scan_id']}/findings"
    assert client.get(base, params={"severity": "HIGH"}).json()["total"] == 3
    assert client.get(base, params={"source": "osv"}).json()["total"] == 0
    assert client.get(base, params={"category": "static"}).json()["total"] == 0
    assert client.get(base, params={"category": "provenance"}).json()["total"] == 3
    vuln = {"category": "vulnerability"}
    page = client.get(base, params={**vuln, "limit": 4, "offset": 8}).json()
    assert page["total"] == 10 and len(page["items"]) == 2
    assert client.get(base, params={"severity": "SEVERE"}).status_code == 422
    assert client.get(base, params={"limit": 0}).status_code == 422
    assert client.get(base, params={"source": "osv; drop"}).status_code == 422


def test_graph_endpoint(completed):
    client, body = completed
    g = client.get(f"/api/v1/scans/{body['scan_id']}/graph").json()
    assert g["is_mock"] is True and g["source"] == "mock"
    assert len(g["nodes"]) == 5 and len(g["edges"]) == 5
    root = next(n for n in g["nodes"] if n["key"] == g["root_key"])
    assert root["node_type"] == "artifact"
    f = g["features"]
    assert f["dependency_count"] == 4 and f["transitive_depth"] == 3
    assert f["transitive_resolution"] == "complete"
    assert f["vulnerable_count"] == 3 and f["vulnerability_count"] == 10
    assert f["cvss_max"] == 7.5
    by_label = {n["label"]: n for n in g["nodes"]}
    assert by_label["qs@6.7.0"]["attributes"]["vulnerability_count"] == 5
    assert by_label["demo-app@1.0.0"]["attributes"]["vulnerability_count"] == 0
    assert by_label["qs@6.7.0"]["component_id"] is not None
    assert g["limitations"] == []
    origins = {e["origin"] for e in g["edges"]}
    assert origins == {"sbom", "inferred_top_level"}


@pytest.mark.parametrize("suffix", ["findings", "graph"])
def test_unknown_scan_404(scan_client, suffix):
    resp = scan_client.get(f"/api/v1/scans/{uuid.uuid4()}/{suffix}")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "scan_not_found"


# ------------------------------------------------------------------ stage failures
def test_sbom_tool_missing_marks_unavailable_and_skips(test_settings, session_factory, public_dns):
    providers = ScanProviders(
        sbom=FailingSbom(AppError(ErrorCode.SBOM_TOOL_UNAVAILABLE, "Syft missing", 503)),
        vulns=MockVulnProvider(),
        nvd=None,
    )
    client = _client(test_settings, session_factory, providers)
    body = _run_scan(client)
    assert body["status"] == "completed"  # ingestion evidence is still valid
    st = body["stages"]
    assert st["sbom"]["status"] == "unavailable"
    assert st["sbom"]["error"]["code"] == "sbom_tool_unavailable"
    assert st["graph"]["status"] == "skipped" and st["vulnerabilities"]["status"] == "skipped"
    assert body["component_count"] == 0 and body["bom_sha256"] is None
    findings = client.get(
        f"/api/v1/scans/{body['scan_id']}/findings", params={"category": "vulnerability"}
    ).json()
    assert findings["total"] == 0 and findings["stage"]["status"] == "skipped"
    assert st["provenance"]["status"] == "completed"  # provenance does not need the SBOM
    graph = client.get(f"/api/v1/scans/{body['scan_id']}/graph").json()
    assert graph["nodes"] == [] and graph["features"] is None


def test_real_settings_with_missing_syft_binary(test_settings, session_factory, public_dns):
    settings = test_settings.model_copy(
        update={"sbom_provider": "syft", "syft_path": "no-such-syft-binary-xyz"}
    )
    client = _client(settings, session_factory, build_providers(settings))
    body = _run_scan(client)
    assert body["stages"]["sbom"]["status"] == "unavailable"
    assert body["stages"]["sbom"]["provider"] == "syft"


def test_sbom_parse_error_is_error(test_settings, session_factory, public_dns):
    providers = ScanProviders(sbom=RawSbom(b"{not json"), vulns=MockVulnProvider(), nvd=None)
    body = _run_scan(_client(test_settings, session_factory, providers))
    assert body["stages"]["sbom"]["status"] == "error"
    assert body["stages"]["sbom"]["error"]["code"] == "sbom_parse_error"


def test_vuln_source_down_keeps_graph_and_unknown_counts(
    test_settings, session_factory, public_dns
):
    providers = ScanProviders(
        sbom=MockSbomProvider(),
        vulns=FailingVulns(AppError(ErrorCode.VULN_SOURCE_UNAVAILABLE, "OSV down", 503)),
        nvd=None,
    )
    client = _client(test_settings, session_factory, providers)
    body = _run_scan(client)
    st = body["stages"]
    assert st["sbom"]["status"] == "completed" and st["graph"]["status"] == "completed"
    assert st["vulnerabilities"]["status"] == "unavailable"
    assert body["component_count"] == 4
    vulns = client.get(
        f"/api/v1/scans/{body['scan_id']}/findings", params={"category": "vulnerability"}
    ).json()
    assert vulns["total"] == 0 and vulns["stage"]["status"] == "unavailable"
    f = client.get(f"/api/v1/scans/{body['scan_id']}/graph").json()["features"]
    # Not looked up -> None, never a reassuring 0.
    assert f["vulnerable_count"] is None and f["cvss_max"] is None


def test_unexpected_vuln_exception_recorded_as_internal_error(
    test_settings, session_factory, public_dns
):
    providers = ScanProviders(
        sbom=MockSbomProvider(), vulns=FailingVulns(RuntimeError("bug")), nvd=None
    )
    body = _run_scan(_client(test_settings, session_factory, providers))
    v = body["stages"]["vulnerabilities"]
    assert v["status"] == "error" and v["error"]["code"] == "internal_error"
    assert "bug" not in v["error"]["message"]  # internals not leaked
    assert body["component_count"] == 4


def test_requirements_only_sbom_reports_limitation(test_settings, session_factory, public_dns):
    from tests.conftest import FIXTURES

    raw = (FIXTURES / "sbom" / "syft_requirements_only.cdx.json").read_bytes()
    providers = ScanProviders(sbom=RawSbom(raw), vulns=MockVulnProvider(), nvd=None)
    client = _client(test_settings, session_factory, providers)
    body = _run_scan(client)
    g = client.get(f"/api/v1/scans/{body['scan_id']}/graph").json()
    assert g["features"]["transitive_resolution"] == "none"
    assert g["limitations"] and "never installed" in g["limitations"][0]
    assert g["is_mock"] is False and g["source"] == "syft"
