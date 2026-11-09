"""Live tests against the local Hardhat chain and PostgreSQL.

Run with PROVENANCEX_CHAIN_TESTS=1 plus BLOCKCHAIN_RPC_URL, BLOCKCHAIN_CONTRACT_ADDRESS,
BLOCKCHAIN_PRIVATE_KEY and DATABASE_URL in the environment. The key is read only from there.
"""

import os
from datetime import timedelta
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from eth_account import Account
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from app.blockchain.anchoring import anchor_scan
from app.blockchain.base import AnchorRecord
from app.blockchain.web3_provider import Web3ChainProvider
from app.core.config import get_settings
from app.core.errors import AppError
from app.db.models import AnchorStatus, Artifact, BlockchainEvidence, Scan, utcnow
from tests.conftest import make_anchorable_scan

pytestmark = pytest.mark.chain


def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        pytest.fail(f"{name} must be set for the live chain tests")
    return value


def _provider(key: str | None = None, url=None, address=None) -> Web3ChainProvider:
    return Web3ChainProvider(
        url or _env("BLOCKCHAIN_RPC_URL"),
        address or _env("BLOCKCHAIN_CONTRACT_ADDRESS"),
        _env("BLOCKCHAIN_PRIVATE_KEY") if key is None else key,
        20.0,
    )


def _record(**overrides) -> AnchorRecord:
    values = {
        "artifact_id": uuid4(),
        "artifact_hash": "a" * 64,
        "bom_hash": "b" * 64,
        "provenance_hash": "c" * 64,
        "risk_score_scaled": 700_000,
        "decision": "REVIEW",
        "scanner_version": "0.1.0",
        "timestamp": 1_790_000_000,
    }
    return AnchorRecord(**{**values, **overrides})


@pytest.fixture(scope="module")
def engine():
    eng = create_engine(_env("DATABASE_URL"), connect_args={"connect_timeout": 3})
    command.upgrade(Config("alembic.ini"), "head")
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine):
    created = []
    with Session(engine, expire_on_commit=False) as active:
        active.info["created"] = created
        yield active
        active.rollback()
    with engine.begin() as conn:
        for artifact_id in created:
            conn.execute(text("DELETE FROM artifacts WHERE id = :id"), {"id": artifact_id})


def _scan(session, **kwargs):
    scan_id = make_anchorable_scan(session, **kwargs)
    session.info["created"].append(session.get(Scan, scan_id).artifact_id)
    return scan_id


@pytest.fixture
def settings():
    return get_settings().model_copy(update={"blockchain_timeout_seconds": 20.0})


def _code(call, *args) -> str:
    with pytest.raises(AppError) as caught:
        call(*args)
    return caught.value.code


def test_anchor_round_trip():
    provider, record = _provider(), _record()
    receipt = provider.submit(record)
    assert receipt.source == "web3"
    assert receipt.chain_id == 31337
    assert receipt.tx_hash.startswith("0x") and len(receipt.tx_hash) == 66
    assert receipt.block_number > 0
    assert [(a.index, a.record) for a in provider.anchors(record.artifact_id)] == [(0, record)]


def test_null_score_and_real_zero_stay_distinct():
    provider = _provider()
    null, zero = _record(risk_score_scaled=None, decision="BLOCK"), _record(risk_score_scaled=0)
    provider.submit(null)
    provider.submit(zero)
    assert provider.anchors(null.artifact_id)[0].record.risk_score_scaled is None
    assert provider.anchors(zero.artifact_id)[0].record.risk_score_scaled == 0


def test_absent_hashes_come_back_as_none():
    provider, record = _provider(), _record(bom_hash=None, provenance_hash=None)
    provider.submit(record)
    stored = provider.anchors(record.artifact_id)[0].record
    assert (stored.bom_hash, stored.provenance_hash) == (None, None)


def test_history_is_append_only():
    provider, record = _provider(), _record()
    provider.submit(record)
    second = _record(artifact_id=record.artifact_id, artifact_hash="d" * 64)
    assert provider.submit(second).anchor_index == 1
    anchors = provider.anchors(record.artifact_id)
    assert [a.record for a in anchors] == [record, second]


def test_receipt_lookup_matches_the_submit():
    provider, record = _provider(), _record()
    receipt = provider.submit(record)
    assert provider.receipt_for(record.artifact_id, 0) == receipt


def test_unknown_artifact_has_no_anchors():
    assert _provider().anchors(uuid4()) == []


def test_account_that_is_not_the_anchorer_is_refused():
    record = _record()
    assert _code(_provider(key=Account.create().key.hex()).submit, record) == "chain_refused"
    assert _provider().anchors(record.artifact_id) == []


def test_address_without_a_contract_is_refused():
    provider = _provider(address=Account.create().address)
    assert _code(provider.anchors, uuid4()) == "chain_refused"


def test_unreachable_chain_is_unavailable():
    provider = _provider(url="http://127.0.0.1:1")
    assert _code(provider.anchors, uuid4()) == "chain_unavailable"


def test_anchor_scan_on_postgres(session, settings):
    scan_id = _scan(session)
    provider = _provider()
    result = anchor_scan(session, scan_id, provider, settings)
    assert (result.status, result.is_mock, result.source) == ("confirmed", False, "web3")
    stored = provider.anchors(result.artifact_id)[0].record
    assert stored.artifact_hash == result.artifact_hash
    assert stored.risk_score_scaled == 700_000
    assert stored.timestamp == result.evidence_timestamp
    row = session.scalars(
        select(BlockchainEvidence).where(BlockchainEvidence.scan_id == scan_id)
    ).one()
    assert row.tx_hash == result.tx_hash
    assert row.block_hash.startswith("0x")
    assert _code(lambda: anchor_scan(session, scan_id, provider, settings)) == (
        "anchor_already_exists"
    )


def test_null_score_scan_with_absent_evidence_on_postgres(session, settings):
    scan_id = _scan(session, score=None, decision="REVIEW", bom_sha256=None)
    provider = _provider()
    result = anchor_scan(session, scan_id, provider, settings)
    assert result.risk_score is None
    assert result.missing_evidence == ["bom_hash"]
    stored = provider.anchors(result.artifact_id)[0].record
    assert stored.risk_score_scaled is None
    assert stored.bom_hash is None


def test_mock_evidence_never_reaches_the_chain(session, settings):
    scan_id = _scan(session, stages={"sbom": {"status": "completed", "source": "mock"}})
    artifact_id = session.get(Artifact, session.get(Scan, scan_id).artifact_id).id
    provider = _provider()
    assert _code(lambda: anchor_scan(session, scan_id, provider, settings)) == (
        "anchor_refused_mock_evidence"
    )
    assert provider.anchors(artifact_id) == []


def test_crash_recovery_adopts_the_real_anchor(session, settings):
    scan_id = _scan(session)
    provider = _provider()
    original = anchor_scan(session, scan_id, provider, settings)
    row = session.scalars(
        select(BlockchainEvidence).where(BlockchainEvidence.scan_id == scan_id)
    ).one()
    row.status = AnchorStatus.PENDING
    row.tx_hash = None
    row.reserved_at = utcnow() - timedelta(seconds=10_000)
    session.commit()
    adopted = anchor_scan(session, scan_id, provider, settings)
    assert adopted.adopted_existing_anchor is True
    assert adopted.tx_hash == original.tx_hash
    assert len(provider.anchors(original.artifact_id)) == 1
