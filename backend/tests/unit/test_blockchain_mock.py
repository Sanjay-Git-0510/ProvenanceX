"""The mock chain is labeled, and is chosen only by explicit configuration."""

from uuid import uuid4

import pytest

from app.blockchain.base import AnchorRecord
from app.blockchain.mock import MockChainProvider
from app.blockchain.web3_provider import Web3ChainProvider
from app.core.config import Settings
from app.core.errors import AppError
from app.pipeline.providers import build_chain_provider, build_providers


def _record(artifact_id=None) -> AnchorRecord:
    return AnchorRecord(
        artifact_id or uuid4(), "a" * 64, None, None, None, "REVIEW", "0.1.0", 1_790_000_000
    )


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


def test_receipt_is_labeled_and_has_no_fake_chain_data():
    receipt = MockChainProvider().submit(_record())
    assert receipt.source == "mock"
    assert receipt.tx_hash.startswith("mock-tx-")
    assert not receipt.tx_hash.startswith("0x")
    assert receipt.block_number is None
    assert receipt.block_hash is None
    assert receipt.chain_id is None
    assert receipt.contract_address is None


def test_history_is_append_only_and_kept_per_artifact():
    chain = MockChainProvider()
    artifact_id = uuid4()
    first, second = chain.submit(_record(artifact_id)), chain.submit(_record(artifact_id))
    assert (first.anchor_index, second.anchor_index) == (0, 1)
    assert [a.index for a in chain.anchors(artifact_id)] == [0, 1]
    assert chain.anchors(uuid4()) == []


def test_receipt_lookup():
    chain = MockChainProvider()
    record = _record()
    assert chain.receipt_for(record.artifact_id, chain.submit(record).anchor_index).source == "mock"


def test_unknown_receipt_is_an_error():
    with pytest.raises(AppError) as caught:
        MockChainProvider().receipt_for(uuid4(), 0)
    assert caught.value.code == "chain_refused"


def test_anchors_returns_a_copy():
    chain = MockChainProvider()
    record = _record()
    chain.submit(record)
    chain.anchors(record.artifact_id).clear()
    assert len(chain.anchors(record.artifact_id)) == 1


def test_provider_is_disabled_by_default():
    settings = _settings()
    assert settings.blockchain_provider == "disabled"
    assert settings.blockchain_anchor_on_scan is False
    assert build_chain_provider(settings) is None


def test_disabled_scan_providers_have_no_chain():
    settings = _settings(sbom_provider="mock", vuln_provider="mock", hf_provider="mock")
    assert build_providers(settings).chain is None


def test_mock_is_used_only_when_selected():
    assert build_chain_provider(_settings(blockchain_provider="mock")).source == "mock"


def test_mock_ledger_is_shared_between_builds():
    first = build_chain_provider(_settings(blockchain_provider="mock"))
    assert first is build_chain_provider(_settings(blockchain_provider="mock"))


def test_web3_selection_never_returns_a_mock():
    provider = build_chain_provider(_settings(blockchain_provider="web3"))
    assert isinstance(provider, Web3ChainProvider)
    assert provider.source == "web3"


def test_a_bad_chain_configuration_does_not_break_provider_building():
    settings = _settings(
        blockchain_provider="web3",
        blockchain_rpc_url="https://mainnet.example.org",
        sbom_provider="mock",
        vuln_provider="mock",
        hf_provider="mock",
    )
    assert build_providers(settings).chain.source == "web3"


def test_private_key_is_not_in_settings_repr():
    secret = "0x" + "ab" * 32
    assert secret not in repr(_settings(blockchain_private_key=secret))
