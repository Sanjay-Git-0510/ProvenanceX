"""The real provider against a fake web3, so that no chain is needed."""

import json
import logging
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
import requests
from eth_account import Account
from web3.exceptions import ContractLogicError, TimeExhausted, Web3RPCError

from app.blockchain.base import AnchorRecord
from app.blockchain.encoding import NO_SCORE, to_chain_arguments
from app.blockchain.web3_provider import ABI, Web3ChainProvider, validate_rpc_url
from app.core.errors import AppError

ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
ACCOUNT = Account.create()
BLOCK_HASH = b"\x0b" * 32
TX_HASH = b"\x0a" * 32


def _record(**overrides) -> AnchorRecord:
    values = {
        "artifact_id": uuid4(),
        "artifact_hash": "a" * 64,
        "bom_hash": None,
        "provenance_hash": "c" * 64,
        "risk_score_scaled": None,
        "decision": "BLOCK",
        "scanner_version": "0.1.0",
        "timestamp": 1_790_000_000,
    }
    return AnchorRecord(**{**values, **overrides})


class _Call:
    def __init__(self, result=None, error=None, transaction=None):
        self._result, self._error, self._transaction = result, error, transaction

    def call(self):
        if self._error:
            raise self._error
        return self._result

    def build_transaction(self, params):
        if self._error:
            raise self._error
        self._transaction.append(params)
        return {
            "to": ADDRESS,
            "value": 0,
            "gas": 200_000,
            "gasPrice": 1,
            "data": "0x",
            "nonce": params["nonce"],
            "chainId": params["chainId"],
        }


class FakeWeb3:
    """Stands in for Web3. Behavior is set through the attributes below."""

    def __init__(self):
        self.chain_id = 31337
        self.code = b"\x60"
        self.anchorer = ACCOUNT.address
        self.stored: dict[bytes, list[tuple]] = {}
        self.status = 1
        self.fail_with = None
        self.call_error = None
        self.send_error = None
        self.event_id = None
        self.event_count = 1
        self.logs = None
        self.transactions = []
        self.sent = []
        self.eth = self

    def contract(self, address, abi):
        assert address == ADDRESS
        assert abi == ABI
        functions = SimpleNamespace(
            anchorer=lambda: _Call(self.anchorer),
            anchorCount=lambda key: _Call(len(self.stored.get(key, []))),
            getAnchor=lambda key, index: _Call(self.stored[key][index]),
            anchor=self._anchor,
        )
        return SimpleNamespace(
            functions=functions, events=SimpleNamespace(EvidenceAnchored=lambda: self)
        )

    def _anchor(self, *args):
        self.pending_args = args
        return _Call(error=self.call_error, transaction=self.transactions)

    def get_code(self, _address):
        if self.fail_with:
            raise self.fail_with
        return self.code

    def get_transaction_count(self, _address, _block):
        return 7

    def send_raw_transaction(self, raw):
        if self.send_error:
            raise self.send_error
        self.sent.append(bytes(raw))
        key = self.pending_args[0]
        self.stored.setdefault(key, []).append(self.pending_args)
        self.event_id = key
        return TX_HASH

    def wait_for_transaction_receipt(self, tx_hash, timeout):
        self.waited = timeout
        return self._tx_receipt(tx_hash)

    def get_transaction_receipt(self, tx_hash):
        return self._tx_receipt(tx_hash)

    def _tx_receipt(self, tx_hash):
        return {
            "status": self.status,
            "transactionHash": tx_hash,
            "blockNumber": 5,
            "blockHash": BLOCK_HASH,
        }

    def get_block(self, _number):
        return {"timestamp": 1_790_000_100}

    def process_receipt(self, _receipt, errors):
        self.errors = errors
        args = {"artifactId": self.event_id, "anchorIndex": len(self.stored[self.event_id]) - 1}
        return [{"args": args}] * self.event_count

    def get_logs(self, from_block, argument_filters):
        self.filters = (from_block, argument_filters)
        return [{"transactionHash": TX_HASH}] if self.logs is None else self.logs


@pytest.fixture
def fake():
    return FakeWeb3()


def _provider(fake, url="http://localhost:8545", address=ADDRESS, key=None, timeout=9.0):
    key = ACCOUNT.key.hex() if key is None else key
    return Web3ChainProvider(url, address, key, timeout, web3_factory=lambda _u, _t: fake)


def _code(call, *args):
    with pytest.raises(AppError) as caught:
        call(*args)
    return caught.value


@pytest.mark.parametrize(
    "url",
    ["http://localhost:8545", "http://127.0.0.1:8545", "http://hardhat:8545", "http://localhost"],
)
def test_local_urls_are_accepted(url):
    assert validate_rpc_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost:8545",
        "http://mainnet.example.org:8545",
        "http://10.0.0.5:8545",
        "http://169.254.169.254/",
        "http://[::1]:8545",
        "http://localhost.example.org:8545",
        "http://user:pw@localhost:8545",
        "http://localhost:8545/rpc",
        "http://localhost:8545?x=1",
        "http://localhost:notaport",
        "ws://localhost:8545",
        "",
        "not a url",
    ],
)
def test_other_urls_are_refused(url):
    assert _code(validate_rpc_url, url).code == "chain_refused"


def test_non_local_url_is_refused_before_connecting():
    def factory(_url, _timeout):
        raise AssertionError("must not connect")

    provider = Web3ChainProvider("https://rpc.example.org", ADDRESS, "", 9.0, web3_factory=factory)
    assert _code(provider.anchors, uuid4()).code == "chain_refused"


@pytest.mark.parametrize("chain_id", [1, 11155111, 31338])
def test_other_chains_are_refused(fake, chain_id):
    fake.chain_id = chain_id
    assert _code(_provider(fake).anchors, uuid4()).code == "chain_refused"
    assert _code(_provider(fake).submit, _record()).code == "chain_refused"
    assert fake.sent == []


def test_missing_contract_code_is_refused(fake):
    fake.code = b""
    assert _code(_provider(fake).anchors, uuid4()).code == "chain_refused"


@pytest.mark.parametrize("address", ["", "0x123", "not-an-address"])
def test_invalid_contract_address_is_refused(fake, address):
    assert _code(_provider(fake, address=address).anchors, uuid4()).code == "chain_refused"


@pytest.mark.parametrize(
    "error",
    [
        requests.ConnectionError("down"),
        requests.Timeout("slow"),
        OSError("reset"),
        ValueError("not json"),
        Web3RPCError("rpc"),
    ],
)
def test_transport_failures_are_unavailable(fake, error):
    fake.fail_with = error
    failure = _code(_provider(fake).anchors, uuid4())
    assert (failure.code, failure.status_code) == ("chain_unavailable", 503)


def test_submit_sends_encoded_fields_and_returns_real_chain_data(fake):
    record = _record()
    receipt = _provider(fake).submit(record)
    assert fake.pending_args == to_chain_arguments(record).as_tuple()
    assert fake.pending_args[4] == NO_SCORE
    assert fake.pending_args[2] == bytes(32)
    assert fake.transactions[0]["from"] == ACCOUNT.address
    assert fake.transactions[0]["nonce"] == 7
    assert fake.transactions[0]["chainId"] == 31337
    assert len(fake.sent) == 1
    assert fake.waited == 9.0
    assert receipt.source == "web3"
    assert receipt.tx_hash == "0x" + TX_HASH.hex()
    assert receipt.block_hash == "0x" + BLOCK_HASH.hex()
    assert (receipt.block_number, receipt.chain_id, receipt.anchor_index) == (5, 31337, 0)
    assert receipt.contract_address == ADDRESS
    assert int(receipt.anchored_at.timestamp()) == 1_790_000_100


def test_anchors_decode_the_chain_values(fake):
    record = _record()
    fake.stored[record.artifact_id.bytes] = [to_chain_arguments(record).as_tuple()]
    anchors = _provider(fake).anchors(record.artifact_id)
    assert [(a.index, a.record) for a in anchors] == [(0, record)]


def test_anchors_work_without_a_key(fake):
    assert _provider(fake, key="").anchors(uuid4()) == []


def test_too_many_anchors_is_refused(fake):
    record = _record()
    fake.stored[record.artifact_id.bytes] = [to_chain_arguments(record).as_tuple()] * 257
    assert _code(_provider(fake).anchors, record.artifact_id).code == "chain_refused"


def test_submit_without_a_key_is_refused(fake):
    assert _code(_provider(fake, key="").submit, _record()).code == "chain_refused"
    assert fake.sent == []


def test_invalid_key_is_refused_without_echoing_it(fake, caplog):
    secret = "zz-not-a-key-value-canary"  # noqa: S105
    with caplog.at_level(logging.DEBUG):
        failure = _code(_provider(fake, key=secret).submit, _record())
    assert failure.code == "chain_refused"
    assert secret not in failure.message + caplog.text


def test_key_that_is_not_the_anchorer_is_refused(fake):
    fake.anchorer = Account.create().address
    assert _code(_provider(fake).submit, _record()).code == "chain_refused"
    assert fake.sent == []


def test_reverted_call_is_refused(fake):
    fake.call_error = ContractLogicError("execution reverted")
    assert _code(_provider(fake).submit, _record()).code == "chain_refused"
    assert fake.sent == []


def test_reverted_receipt_is_refused(fake):
    fake.status = 0
    assert _code(_provider(fake).submit, _record()).code == "chain_refused"


def test_receipt_timeout_is_unavailable(fake):
    def timed_out(_hash, timeout):
        raise TimeExhausted("no receipt")

    fake.wait_for_transaction_receipt = timed_out
    assert _code(_provider(fake).submit, _record()).code == "chain_unavailable"


@pytest.mark.parametrize("count", [0, 2])
def test_unexpected_event_count_is_refused(fake, count):
    fake.event_count = count
    assert _code(_provider(fake).submit, _record()).code == "chain_refused"


def test_event_for_another_artifact_is_refused(fake):
    original = fake.send_raw_transaction

    def send(raw):
        result = original(raw)
        fake.stored[b"\x09" * 16] = [("x",)]
        fake.event_id = b"\x09" * 16
        return result

    fake.send_raw_transaction = send
    assert _code(_provider(fake).submit, _record()).code == "chain_refused"


def test_receipt_for_filters_on_artifact_and_index(fake):
    artifact_id = uuid4()
    receipt = _provider(fake).receipt_for(artifact_id, 3)
    assert fake.filters == (0, {"artifactId": artifact_id.bytes, "anchorIndex": 3})
    assert receipt.anchor_index == 3


@pytest.mark.parametrize("logs", [[], [{"transactionHash": TX_HASH}] * 2])
def test_receipt_for_needs_exactly_one_event(fake, logs):
    fake.logs = logs
    assert _code(_provider(fake).receipt_for, uuid4(), 0).code == "chain_refused"


def test_failures_do_not_expose_exception_text_or_the_key(fake, caplog):
    secret = ACCOUNT.key.hex()
    fake.send_error = Web3RPCError(f"raw tx leak {secret}")
    with caplog.at_level(logging.DEBUG):
        failure = _code(_provider(fake).submit, _record())
    assert failure.code == "chain_unavailable"
    assert secret not in f"{failure.message} {failure.details} {caplog.text}"
    assert secret not in repr(_provider(fake))


def test_default_transport_blocks_redirects_and_proxies():
    from app.blockchain.web3_provider import _default_web3

    provider = _default_web3("http://localhost:8545", 4.0).provider
    kwargs = dict(provider.get_request_kwargs())
    assert kwargs["allow_redirects"] is False
    assert kwargs["timeout"] == 4.0


def test_abi_file_has_the_expected_surface():
    path = Path(__file__).resolve().parents[2] / "app" / "blockchain" / "abi.json"
    abi = json.loads(path.read_text(encoding="utf-8"))
    names = {item.get("name") for item in abi if item["type"] == "function"}
    assert {"anchor", "anchorCount", "getAnchor", "anchorer"} <= names
