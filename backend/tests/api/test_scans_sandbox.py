"""API tests for the sandbox stage, with mock and stub providers. Nothing is executed."""

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from app.api.scans import get_scan_providers, get_session_factory
from app.core.config import get_settings
from app.core.errors import AppError, ErrorCode
from app.main import create_app
from app.pipeline.providers import ScanProviders, build_providers
from app.scanners.hf.mock import MockHfProvider
from app.scanners.sandbox.base import SandboxRun
from app.scanners.sandbox.mock import MOCK_TRACE_PATH, MockSandboxProvider
from app.scanners.sbom.mock import MockSbomProvider
from app.scanners.vulns.mock import MockVulnProvider
from tests.conftest import FIXTURES, build_zip

SOFTWARE = "/api/v1/scans/software"
MODEL = "/api/v1/scans/model"


class Stub:
    name = "docker"

    def __init__(self, result=None, exc=None):
        self.result, self.exc = result, exc

    def run(self, request):
        if self.exc:
            raise self.exc
        return self.result


def client_for(settings, factory, sandbox) -> TestClient:
    providers = ScanProviders(
        sbom=MockSbomProvider(),
        vulns=MockVulnProvider(),
        nvd=None,
        hf=MockHfProvider(),
        sandbox=sandbox,
    )
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_session_factory] = lambda: factory
    app.dependency_overrides[get_scan_providers] = lambda: providers
    return TestClient(app, raise_server_exceptions=False)


def scan(client, url=SOFTWARE):
    data = build_zip([("a.txt", "x")])
    resp = client.post(url, files={"file": ("a.zip", data, "application/zip")})
    assert resp.status_code == 202, resp.text
    return client.get(f"/api/v1/scans/{resp.json()['scan_id']}").json()


def behavioral(client, body):
    return client.get(
        f"/api/v1/scans/{body['scan_id']}/findings", params={"category": "behavioral"}
    ).json()


@pytest.fixture
def mock_client(test_settings, session_factory, public_dns):
    return client_for(test_settings, session_factory, MockSandboxProvider())


@pytest.mark.parametrize("url", [SOFTWARE, MODEL])
def test_disabled_by_default_is_skipped(scan_client, url):
    stage = scan(scan_client, url)["stages"]["sandbox"]
    assert stage["status"] == "skipped" and "SANDBOX_PROVIDER=disabled" in stage["reason"]
    assert "features" not in stage


@pytest.mark.parametrize("url", [SOFTWARE, MODEL])
def test_mock_is_labeled_everywhere(mock_client, url):
    body = scan(mock_client, url)
    stage = body["stages"]["sandbox"]
    assert stage["status"] == "completed", stage
    assert stage["source"] == "mock" and stage["is_mock"] is True and stage["synthetic"] is True
    assert stage["provider"] == "mock"
    data = behavioral(mock_client, body)
    assert data["contains_mock"] is True and data["stages"]["behavioral"]["status"] == "completed"
    [item] = data["items"]
    assert item["is_mock"] is True and item["source"] == "mock"
    assert item["details"]["synthetic"] is True


def test_mock_comes_only_from_explicit_settings(test_settings, session_factory, public_dns):
    settings = test_settings.model_copy(update={"sandbox_provider": "mock"})
    assert isinstance(build_providers(settings).sandbox, MockSandboxProvider)
    assert build_providers(test_settings).sandbox is None


def test_behavior_findings_have_no_cvss_and_stay_separate(mock_client):
    body = scan(mock_client)
    [item] = behavioral(mock_client, body)["items"]
    assert item["category"] == "behavioral" and item["kind"] == "external_connection_attempt"
    assert item["cvss"] is None or item["cvss"].get("score") is None


def test_trace_is_stored_off_chain_with_only_its_hash_recorded(mock_client, test_settings):
    body = scan(mock_client)
    stage = body["stages"]["sandbox"]
    trace = test_settings.workspace_root / body["scan_id"] / stage["trace_file"]
    assert trace.read_bytes() == MOCK_TRACE_PATH.read_bytes()
    assert oct(trace.stat().st_mode & 0o777) == "0o600"
    assert oct(trace.parent.stat().st_mode & 0o777) == "0o700"
    assert stage["trace_sha256"] == hashlib.sha256(trace.read_bytes()).hexdigest()
    assert "strace_lines" not in json.dumps(body)


def test_features_are_stored_on_the_stage(mock_client):
    f = scan(mock_client)["stages"]["sandbox"]["features"]
    assert f["network_count"] == 1 and f["external_destination_count"] == 1
    assert f["process_count"] == 1 and f["file_write_count"] == 1


@pytest.mark.parametrize(
    ("exc", "status", "code"),
    [
        (
            AppError(ErrorCode.SANDBOX_UNAVAILABLE, "no docker", 503),
            "unavailable",
            "sandbox_unavailable",
        ),
        (AppError(ErrorCode.SANDBOX_REFUSED, "refused", 400), "error", "sandbox_refused"),
        (AppError(ErrorCode.SANDBOX_FAILED, "failed", 502), "error", "sandbox_failed"),
        (AppError(ErrorCode.SANDBOX_TRACE_ERROR, "bad", 502), "error", "sandbox_trace_error"),
    ],
)
def test_sandbox_failures_keep_the_scan_and_report_no_behavior(
    test_settings, session_factory, public_dns, exc, status, code
):
    client = client_for(test_settings, session_factory, Stub(exc=exc))
    body = scan(client)
    stage = body["stages"]["sandbox"]
    assert body["status"] == "completed"
    assert stage["status"] == status and stage["error"]["code"] == code
    assert "features" not in stage
    data = behavioral(client, body)
    assert data["total"] == 0  # no behavior was observed, and none is invented


def test_unexpected_exception_is_internal_error(test_settings, session_factory, public_dns):
    client = client_for(test_settings, session_factory, Stub(exc=RuntimeError("secret detail")))
    stage = scan(client)["stages"]["sandbox"]
    assert stage["status"] == "error" and stage["error"]["code"] == "internal_error"
    assert "secret" not in json.dumps(stage)


def test_real_settings_without_docker_never_use_the_mock(
    test_settings, session_factory, public_dns
):
    settings = test_settings.model_copy(
        update={"sandbox_provider": "docker", "sandbox_docker_path": "no-such-docker-xyz"}
    )
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    client = TestClient(app, raise_server_exceptions=False)
    body = scan(client)
    stage = body["stages"]["sandbox"]
    assert body["status"] == "completed" and stage["status"] == "unavailable"
    assert stage["provider"] == "docker"
    assert behavioral(client, body)["total"] == 0  # the mock bundle's finding is absent


def test_host_deadline_with_no_trace_is_partial_with_null_features(
    test_settings, session_factory, public_dns
):
    client = client_for(
        test_settings, session_factory, Stub(result=SandboxRun(None, True, "sandbox"))
    )
    stage = scan(client)["stages"]["sandbox"]
    assert stage["status"] == "partial" and stage["timed_out"] is True
    assert stage["features"] is None and "trace_file" not in stage


def test_supervisor_timeout_is_partial_and_trace_is_kept(
    test_settings, session_factory, public_dns
):
    raw = (FIXTURES / "sandbox" / "resource_spike.trace.json").read_bytes()
    client = client_for(
        test_settings, session_factory, Stub(result=SandboxRun(raw, False, "sandbox"))
    )
    body = scan(client)
    stage = body["stages"]["sandbox"]
    assert stage["status"] == "partial" and stage["timed_out"] is True
    assert stage["trace_file"] and stage["features"]["resource_spike"] is True
    assert behavioral(client, body)["items"][0]["details"]["kind"] == "resource_spike"


def test_malformed_trace_is_an_error(test_settings, session_factory, public_dns):
    client = client_for(
        test_settings, session_factory, Stub(result=SandboxRun(b"{not json", False, "sandbox"))
    )
    stage = scan(client)["stages"]["sandbox"]
    assert stage["status"] == "error" and stage["error"]["code"] == "sandbox_trace_error"


def test_run_with_no_targets_is_partial_with_null_features(
    test_settings, session_factory, public_dns
):
    raw = json.dumps(
        {
            "format": "provenancex-trace-v1",
            "meta": {"timed_out": False, "targets": []},
            "strace_lines": [],
            "resource_samples": [],
        }
    ).encode()
    client = client_for(
        test_settings, session_factory, Stub(result=SandboxRun(raw, False, "sandbox"))
    )
    stage = scan(client)["stages"]["sandbox"]
    assert stage["status"] == "partial" and stage["features"]["syscall_count"] is None
    assert stage["targets"] == []


def _bundle(lines, exit_code=0):
    target = {"kind": "setup_py", "path": "setup.py", "exit_code": exit_code, "ran": True}
    return json.dumps(
        {
            "format": "provenancex-trace-v1",
            "meta": {"timed_out": False, "exit_code": exit_code, "targets": [target]},
            "strace_lines": lines,
            "resource_samples": [],
        }
    ).encode()


@pytest.mark.parametrize("code", [-9, 137])
def test_killed_target_is_partial_with_a_reason(test_settings, session_factory, public_dns, code):
    run = SandboxRun(_bundle(["getpid() = 1"], code), False, "sandbox")
    stage = scan(client_for(test_settings, session_factory, Stub(result=run)))["stages"]["sandbox"]
    assert stage["status"] == "partial" and "killed" in stage["incomplete_reasons"][0]


def test_malformed_trace_lines_are_partial_with_a_reason(
    test_settings, session_factory, public_dns
):
    run = SandboxRun(_bundle(["getpid() = 1", "\x00\x00 garbage"]), False, "sandbox")
    stage = scan(client_for(test_settings, session_factory, Stub(result=run)))["stages"]["sandbox"]
    assert stage["status"] == "partial" and "malformed" in stage["incomplete_reasons"][0]


def test_clean_run_is_completed_with_no_reasons(test_settings, session_factory, public_dns):
    run = SandboxRun(_bundle(["getpid() = 1"]), False, "sandbox")
    stage = scan(client_for(test_settings, session_factory, Stub(result=run)))["stages"]["sandbox"]
    assert stage["status"] == "completed" and stage["incomplete_reasons"] == []


def test_non_zero_exit_alone_is_not_incomplete(test_settings, session_factory, public_dns):
    run = SandboxRun(_bundle(["getpid() = 1"], 1), False, "sandbox")
    stage = scan(client_for(test_settings, session_factory, Stub(result=run)))["stages"]["sandbox"]
    assert stage["status"] == "completed"


def test_non_mock_source_is_not_labeled_mock(test_settings, session_factory, public_dns):
    raw = (FIXTURES / "sandbox" / "network_beacon.trace.json").read_bytes()
    client = client_for(
        test_settings, session_factory, Stub(result=SandboxRun(raw, False, "sandbox"))
    )
    body = scan(client)
    stage = body["stages"]["sandbox"]
    assert stage["source"] == "sandbox" and stage["is_mock"] is False
    assert behavioral(client, body)["items"][0]["is_mock"] is False
