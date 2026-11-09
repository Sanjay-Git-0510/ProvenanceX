"""The real chain provider: web3.py talking to the local Hardhat chain.

Checked on every operation: the RPC URL is local, the chain id is 31337, and the contract has
code. Exception text from web3 is never passed on, because it can quote raw transactions.
"""

import json
import logging
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import requests
from eth_account import Account
from web3 import HTTPProvider, Web3
from web3.exceptions import ContractLogicError, Web3Exception
from web3.logs import DISCARD

from app.blockchain.base import SOURCE_WEB3, AnchorReceipt, AnchorRecord, ChainAnchor
from app.blockchain.encoding import LOCAL_CHAIN_ID, record_from_chain, to_chain_arguments
from app.core.errors import AppError, ErrorCode

logger = logging.getLogger(__name__)

ABI = json.loads(Path(__file__).with_name("abi.json").read_text(encoding="utf-8"))
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "hardhat"})
# The contract has one authorized sender, so this limit is a defense against a corrupt chain.
MAX_ANCHORS_READ = 256
_STATUS_REFUSED = 409
_STATUS_UNAVAILABLE = 503
_STATUS_SUCCESS = 1

# One key means one nonce sequence, so sends within a process must not overlap.
_send_lock = threading.Lock()

Web3Factory = Callable[[str, float], Any]


def _refused(message: str) -> AppError:
    return AppError(ErrorCode.CHAIN_REFUSED, message, _STATUS_REFUSED)


def _unavailable() -> AppError:
    return AppError(ErrorCode.CHAIN_UNAVAILABLE, "The chain is unavailable", _STATUS_UNAVAILABLE)


def validate_rpc_url(url: str) -> str:
    """Accept only plain http to a known local host, with no credentials or path."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
        _ = parts.port
    except ValueError:
        raise _refused("BLOCKCHAIN_RPC_URL is not a valid URL") from None
    if (
        parts.scheme != "http"
        or host not in LOCAL_HOSTS
        or parts.username is not None
        or parts.password is not None
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise _refused("BLOCKCHAIN_RPC_URL must be a local http URL")
    return url


def _default_web3(url: str, timeout: float) -> Web3:
    # trust_env=False: proxy variables must not route a local RPC call somewhere else.
    session = requests.Session()
    session.trust_env = False
    return Web3(
        HTTPProvider(
            url,
            request_kwargs={"timeout": timeout, "allow_redirects": False},
            session=session,
            exception_retry_configuration=None,
        )
    )


def _hex(value: bytes) -> str:
    return "0x" + bytes(value).hex()


@contextmanager
def _rpc_errors() -> Iterator[None]:
    """Turn web3 failures into structured errors. Only the exception class is logged."""
    try:
        yield
    except AppError:
        raise
    except ContractLogicError:
        logger.warning("The chain contract refused a call")
        raise _refused("The contract refused the call") from None
    except (OSError, ValueError, Web3Exception) as exc:
        logger.warning("Chain call failed: %s", type(exc).__name__)
        raise _unavailable() from None


class Web3ChainProvider:
    source = SOURCE_WEB3

    def __init__(
        self,
        rpc_url: str,
        contract_address: str,
        private_key: str,
        timeout_seconds: float,
        web3_factory: Web3Factory = _default_web3,
    ) -> None:
        self._rpc_url = rpc_url
        self._contract_address = contract_address
        self._private_key = private_key
        self._timeout = timeout_seconds
        self._web3_factory = web3_factory

    def _connect(self) -> tuple[Any, Any, str]:
        url = validate_rpc_url(self._rpc_url)
        if not Web3.is_address(self._contract_address):
            raise _refused("BLOCKCHAIN_CONTRACT_ADDRESS is not a valid address")
        address = Web3.to_checksum_address(self._contract_address)
        with _rpc_errors():
            w3 = self._web3_factory(url, self._timeout)
            chain_id = w3.eth.chain_id
            if chain_id != LOCAL_CHAIN_ID:
                raise _refused(f"Only chain id {LOCAL_CHAIN_ID} is allowed")
            if len(w3.eth.get_code(address)) == 0:
                raise _refused("No contract exists at BLOCKCHAIN_CONTRACT_ADDRESS")
            return w3, w3.eth.contract(address=address, abi=ABI), address

    def _account(self) -> Any:
        if not self._private_key:
            raise _refused("BLOCKCHAIN_PRIVATE_KEY is not set")
        try:
            return Account.from_key(self._private_key)
        except Exception:  # noqa: BLE001 - the library error could describe the key
            logger.warning("BLOCKCHAIN_PRIVATE_KEY could not be parsed")
            raise _refused("BLOCKCHAIN_PRIVATE_KEY is not a valid key") from None

    def anchors(self, artifact_id: UUID) -> list[ChainAnchor]:
        _, contract, _ = self._connect()
        key = artifact_id.bytes
        with _rpc_errors():
            count = contract.functions.anchorCount(key).call()
            if count > MAX_ANCHORS_READ:
                raise _refused("The artifact has more anchors than can be read")
            return [
                ChainAnchor(i, record_from_chain(*contract.functions.getAnchor(key, i).call()))
                for i in range(count)
            ]

    def _receipt(self, w3: Any, address: str, tx_receipt: Any, index: int) -> AnchorReceipt:
        block = w3.eth.get_block(tx_receipt["blockNumber"])
        return AnchorReceipt(
            anchor_index=index,
            tx_hash=_hex(tx_receipt["transactionHash"]),
            source=SOURCE_WEB3,
            anchored_at=datetime.fromtimestamp(block["timestamp"], UTC),
            block_number=tx_receipt["blockNumber"],
            block_hash=_hex(tx_receipt["blockHash"]),
            chain_id=LOCAL_CHAIN_ID,
            contract_address=address,
        )

    def receipt_for(self, artifact_id: UUID, index: int) -> AnchorReceipt:
        w3, contract, address = self._connect()
        with _rpc_errors():
            logs = contract.events.EvidenceAnchored().get_logs(
                from_block=0,
                argument_filters={"artifactId": artifact_id.bytes, "anchorIndex": index},
            )
            if len(logs) != 1:
                raise _refused("The anchor's event could not be found")
            tx_receipt = w3.eth.get_transaction_receipt(logs[0]["transactionHash"])
            return self._receipt(w3, address, tx_receipt, index)

    def submit(self, record: AnchorRecord) -> AnchorReceipt:
        account = self._account()
        with _send_lock:
            w3, contract, address = self._connect()
            with _rpc_errors():
                if contract.functions.anchorer().call() != account.address:
                    raise _refused("BLOCKCHAIN_PRIVATE_KEY is not the contract's anchorer")
                call = contract.functions.anchor(*to_chain_arguments(record).as_tuple())
                transaction = call.build_transaction(
                    {
                        "from": account.address,
                        "nonce": w3.eth.get_transaction_count(account.address, "pending"),
                        "chainId": LOCAL_CHAIN_ID,
                    }
                )
                signed = account.sign_transaction(transaction)
                tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
                tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=self._timeout)
                if tx_receipt["status"] != _STATUS_SUCCESS:
                    raise _refused("The anchor transaction was reverted")
                events = contract.events.EvidenceAnchored().process_receipt(
                    tx_receipt, errors=DISCARD
                )
                if len(events) != 1 or bytes(events[0]["args"]["artifactId"]) != (
                    record.artifact_id.bytes
                ):
                    raise _refused("The anchor transaction emitted an unexpected event")
                return self._receipt(w3, address, tx_receipt, events[0]["args"]["anchorIndex"])
