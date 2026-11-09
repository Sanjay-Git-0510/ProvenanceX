"""The chain provider interface and the values that cross it.

A real and a mock provider implement `ChainProvider`. A mock is used only when configured
explicitly, never as a fallback when the real chain is unavailable.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

SOURCE_WEB3 = "web3"
SOURCE_MOCK = "mock"


@dataclass(frozen=True)
class AnchorRecord:
    """The eight anchored fields, as encoded values.

    `risk_score_scaled` of None means no score was computed; 0 is a real score of 0. A hash of
    None means the evidence is absent.
    """

    artifact_id: UUID
    artifact_hash: str
    bom_hash: str | None
    provenance_hash: str | None
    risk_score_scaled: int | None
    decision: str
    scanner_version: str
    timestamp: int


@dataclass(frozen=True)
class ChainAnchor:
    index: int
    record: AnchorRecord


@dataclass(frozen=True)
class AnchorReceipt:
    """Where an anchor landed. A mock has no chain, so its chain fields are None."""

    anchor_index: int
    tx_hash: str
    source: str
    anchored_at: datetime
    block_number: int | None = None
    block_hash: str | None = None
    chain_id: int | None = None
    contract_address: str | None = None


class ChainProvider(Protocol):
    source: str

    def anchors(self, artifact_id: UUID) -> list[ChainAnchor]:
        """Every anchor stored for an artifact, oldest first."""
        ...

    def receipt_for(self, artifact_id: UUID, index: int) -> AnchorReceipt:
        """The receipt of an anchor that already exists."""
        ...

    def submit(self, record: AnchorRecord) -> AnchorReceipt:
        """Append one anchor and wait until it is stored."""
        ...
