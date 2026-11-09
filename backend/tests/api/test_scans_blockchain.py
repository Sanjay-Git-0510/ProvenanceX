"""API tests for /anchor, /blockchain and /verify, and the pipeline's anchor step."""

import uuid
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from app.api.blockchain import get_chain_provider
from app.api.scans import get_scan_providers, get_session_factory
from app.blockchain.mock import MockChainProvider
from app.core.config import get_settings
from app.core.errors import AppError, ErrorCode
from app.main import create_app
from app.pipeline.providers import build_providers
from tests.conftest import SIMPLE_PROJECT, make_anchorable_scan, write_scan_evidence, zip_dir

KEY = "0x" + "ab" * 32
ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
BLOCK = "0x" + "0b" * 32


class Chain(MockChainProvider):
    source = "web3"
    error = None

    def location(self):
        if self.error:
            raise self.error
        return 31337, ADDRESS

    def block_hash_at(self, number):
        return BLOCK

    def submit(self, record):
        receipt = replace(
            super().submit(record),
            source="web3",
            block_number=5,
            block_hash=BLOCK,
            chain_id=31337,
            contract_address=ADDRESS,
        )
        self._receipts[(record.artifact_id, receipt.anchor_index)] = receipt
        return receipt


@pytest.fixture
def settings(test_settings):
    return test_settings.model_copy(update={"blockchain_private_key": KEY})


def _client(settings, session_factory, chain, pipeline_chain=None) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    app.dependency_overrides[get_chain_provider] = lambda: chain

    def providers():
        built = build_providers(settings)
        built.chain = pipeline_chain
        return built

    app.dependency_overrides[get_scan_providers] = providers
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def chain():
    return Chain()


@pytest.fixture
def client(settings, session_factory, chain, public_dns):
    return _client(settings, session_factory, chain)


@pytest.fixture
def scan_id(session_factory, settings):
    with session_factory() as session:
        new_id = make_anchorable_scan(session)
        write_scan_evidence(session, new_id, settings)
    return new_id


def _post(client, scan_id, action):
    return client.post(f"/api/v1/scans/{scan_id}/{action}")


def test_anchor_then_verify(client, scan_id):
    anchored = _post(client, scan_id, "anchor")
    assert anchored.status_code == 200, anchored.text
    assert anchored.json()["status"] == "confirmed"
    body = _post(client, scan_id, "verify").json()
    assert body["state"] == "VERIFIED"
    assert body["reason"]["code"] == "verified"
    assert body["tx_hash"] == anchored.json()["tx_hash"]


def test_each_field_carries_every_value(client, scan_id):
    _post(client, scan_id, "anchor")
    for field in _post(client, scan_id, "verify").json()["fields"]:
        assert {"stored", "source_table", "recomputed", "chain", "status"} <= set(field)


def test_a_scan_can_be_anchored_once(client, scan_id, chain):
    assert _post(client, scan_id, "anchor").status_code == 200
    again = _post(client, scan_id, "anchor")
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "anchor_already_exists"
    assert len(chain._anchors) == 1


def test_anchor_refusal_uses_the_error_envelope(client, session_factory):
    with session_factory() as session:
        new_id = make_anchorable_scan(session, status="running")
    response = _post(client, new_id, "anchor")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "anchor_scan_not_completed"


def test_mock_evidence_is_refused_on_the_real_chain(client, session_factory):
    with session_factory() as session:
        new_id = make_anchorable_scan(
            session, stages={"sbom": {"status": "completed", "source": "mock"}}
        )
    assert _post(client, new_id, "anchor").json()["error"]["code"] == (
        "anchor_refused_mock_evidence"
    )


def test_disabled_chain_refuses_anchor_and_verifies_unknown(settings, session_factory, scan_id):
    disabled = _client(settings, session_factory, None)
    response = _post(disabled, scan_id, "anchor")
    assert (response.status_code, response.json()["error"]["code"]) == (503, "blockchain_disabled")
    verify = _post(disabled, scan_id, "verify")
    assert verify.status_code == 200
    assert verify.json()["state"] == "UNKNOWN"


def test_default_settings_use_no_chain(test_settings):
    from app.pipeline.providers import build_chain_provider

    assert get_chain_provider(test_settings) is None
    assert build_chain_provider(test_settings) is None


def test_chain_outage_returns_unknown_not_an_error(client, scan_id, chain):
    _post(client, scan_id, "anchor")
    chain.error = AppError(ErrorCode.CHAIN_UNAVAILABLE, "down", 503)
    response = _post(client, scan_id, "verify")
    assert response.status_code == 200
    assert response.json()["state"] == "UNKNOWN"


def test_not_anchored_state_uses_the_exact_label(client, scan_id):
    assert _post(client, scan_id, "verify").json()["state"] == "NOT ANCHORED"


@pytest.mark.parametrize("action", ["anchor", "verify"])
def test_unknown_scan_is_404(client, action):
    response = _post(client, uuid.uuid4(), action)
    assert (response.status_code, response.json()["error"]["code"]) == (404, "scan_not_found")


def test_unknown_scan_blockchain_is_404(client):
    assert client.get(f"/api/v1/scans/{uuid.uuid4()}/blockchain").status_code == 404


def test_invalid_scan_id_is_a_validation_error(client):
    assert _post(client, "not-a-uuid", "verify").json()["error"]["code"] == "validation_error"


def test_blockchain_before_anchoring(client, scan_id):
    body = client.get(f"/api/v1/scans/{scan_id}/blockchain").json()
    assert body["anchor_recorded"] is False
    assert body["record"] is None


def test_blockchain_shows_stored_data_and_claims_nothing(client, scan_id, chain):
    _post(client, scan_id, "anchor")
    chain.error = AppError(ErrorCode.CHAIN_UNAVAILABLE, "down", 503)
    response = client.get(f"/api/v1/scans/{scan_id}/blockchain")
    assert response.status_code == 200
    body = response.json()
    assert body["anchor_recorded"] is True
    assert body["record"]["risk_score_scaled"] == 700_000
    assert "state" not in body
    assert "VERIFIED" not in response.text.replace("not a verification", "")
    assert "not a verification result" in body["note"]


def test_null_score_is_null_through_the_api(client, session_factory, settings):
    with session_factory() as session:
        new_id = make_anchorable_scan(session, score=None, decision="BLOCK")
        write_scan_evidence(session, new_id, settings)
    assert _post(client, new_id, "anchor").json()["risk_score"] is None
    record = client.get(f"/api/v1/scans/{new_id}/blockchain").json()["record"]
    assert (record["risk_score"], record["risk_score_scaled"]) == (None, None)
    assert _post(client, new_id, "verify").json()["state"] == "VERIFIED"


def test_key_never_appears_in_any_response(client, scan_id, chain, session_factory):
    bodies = [
        _post(client, scan_id, "verify").text,
        _post(client, scan_id, "anchor").text,
        _post(client, scan_id, "anchor").text,
        _post(client, scan_id, "verify").text,
        client.get(f"/api/v1/scans/{scan_id}/blockchain").text,
        client.get(f"/api/v1/scans/{scan_id}").text,
    ]
    chain.error = AppError(ErrorCode.CHAIN_UNAVAILABLE, "down", 503)
    bodies.append(_post(client, scan_id, "verify").text)
    assert all(KEY not in body and KEY[2:] not in body for body in bodies)


def test_unexpected_chain_error_does_not_leak_its_text(client, scan_id, chain):
    _post(client, scan_id, "anchor")
    chain.error = RuntimeError(f"raw transaction {KEY}")
    response = _post(client, scan_id, "verify")
    assert response.json()["state"] == "UNKNOWN"
    assert KEY not in response.text


def test_unexpected_anchor_error_returns_a_generic_500(settings, session_factory, scan_id):
    class Broken(Chain):
        def submit(self, record):
            raise RuntimeError(f"leak {KEY}")

    response = _post(_client(settings, session_factory, Broken()), scan_id, "anchor")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert KEY not in response.text


# ------------------------------------------------------------------ the pipeline's anchor step
def _upload(client) -> str:
    response = client.post(
        "/api/v1/scans/software",
        files={"file": ("p.zip", zip_dir(SIMPLE_PROJECT), "application/zip")},
    )
    assert response.status_code == 202, response.text
    return response.json()["scan_id"]


def _scan(client, scan_id):
    return client.get(f"/api/v1/scans/{scan_id}").json()


def _pipeline_client(settings, session_factory, chain, on_scan=True):
    configured = settings.model_copy(update={"blockchain_anchor_on_scan": on_scan})
    return _client(configured, session_factory, chain, pipeline_chain=chain)


def test_anchor_step_is_off_by_default(client, chain, public_dns):
    body = _scan(client, _upload(client))
    assert body["status"] == "completed"
    assert body["stages"]["anchor"]["status"] == "skipped"
    assert chain._anchors == {}


def test_off_setting_ignores_a_configured_chain(settings, session_factory, public_dns):
    chain = MockChainProvider()
    client = _pipeline_client(settings, session_factory, chain, on_scan=False)
    assert _scan(client, _upload(client))["stages"]["anchor"]["status"] == "skipped"
    assert chain._anchors == {}


def test_full_scan_anchors_and_verifies_on_the_mock_chain(settings, session_factory, public_dns):
    """Also shows that the pipeline leaves files whose hashes can really be recomputed."""
    chain = MockChainProvider()
    client = _pipeline_client(settings, session_factory, chain)
    scan_id = _upload(client)
    body = _scan(client, scan_id)
    assert body["status"] == "completed"
    stage = body["stages"]["anchor"]
    assert (stage["status"], stage["source"], stage["is_mock"]) == ("completed", "mock", True)
    assert "tx_hash" not in stage
    verify = _post(client, scan_id, "verify").json()
    assert (verify["state"], verify["is_mock"]) == ("VERIFIED", True)
    assert {f["status"] for f in verify["fields"]} == {"match"}


def test_full_scan_file_tampering_is_detected(settings, session_factory, public_dns):
    chain = MockChainProvider()
    client = _pipeline_client(settings, session_factory, chain)
    scan_id = _upload(client)
    src = settings.workspace_root / scan_id / "src"
    next(path for path in sorted(src.rglob("*")) if path.is_file()).write_text("changed")
    assert _post(client, scan_id, "verify").json()["state"] == "MISMATCH"


def test_mock_evidence_stays_off_the_real_chain_in_the_pipeline(
    settings, session_factory, public_dns
):
    chain = Chain()
    client = _pipeline_client(settings, session_factory, chain)
    body = _scan(client, _upload(client))
    assert body["status"] == "completed"
    assert body["stages"]["anchor"]["status"] == "error"
    assert body["stages"]["anchor"]["error"]["code"] == "anchor_refused_mock_evidence"
    assert chain._anchors == {}


def test_on_setting_with_no_chain_is_unavailable_not_mock(settings, session_factory, public_dns):
    client = _pipeline_client(settings, session_factory, None)
    body = _scan(client, _upload(client))
    assert body["status"] == "completed"
    stage = body["stages"]["anchor"]
    assert (stage["status"], stage["error"]["code"]) == ("unavailable", "blockchain_disabled")
    assert stage.get("source") != "mock"


def test_chain_outage_does_not_fail_the_scan(settings, session_factory, public_dns):
    class Down(MockChainProvider):
        def anchors(self, artifact_id):
            raise AppError(ErrorCode.CHAIN_UNAVAILABLE, "down", 503)

    client = _pipeline_client(settings, session_factory, Down())
    body = _scan(client, _upload(client))
    assert body["status"] == "completed"
    assert body["stages"]["anchor"]["status"] == "unavailable"


def test_a_crashing_step_cannot_fail_the_scan(settings, session_factory, public_dns, monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("app.pipeline.software.run_anchor_stage", boom)
    client = _pipeline_client(settings, session_factory, MockChainProvider())
    assert _scan(client, _upload(client))["status"] == "completed"


def test_anchor_step_runs_only_after_the_scan_is_completed(settings, session_factory, public_dns):
    seen = []

    class Watching(MockChainProvider):
        def submit(self, record):
            with session_factory() as other:
                from app.db.models import Scan

                seen.extend(row.status for row in other.query(Scan).all())
            return super().submit(record)

    client = _pipeline_client(settings, session_factory, Watching())
    _upload(client)
    assert [str(status) for status in seen] == ["completed"]
