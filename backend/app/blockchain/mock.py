"""In-memory chain for development and tests. Everything it returns is tagged source="mock".

No real transaction or block exists, so transaction ids are visibly not hashes and block fields
stay None. The ledger is lost when the process exits.
"""

import threading
from uuid import UUID, uuid4

from app.blockchain.base import SOURCE_MOCK, AnchorReceipt, AnchorRecord, ChainAnchor
from app.core.errors import AppError, ErrorCode
from app.db.models import utcnow


class MockChainProvider:
    source = SOURCE_MOCK

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._anchors: dict[UUID, list[ChainAnchor]] = {}
        self._receipts: dict[tuple[UUID, int], AnchorReceipt] = {}

    def anchors(self, artifact_id: UUID) -> list[ChainAnchor]:
        with self._lock:
            return list(self._anchors.get(artifact_id, []))

    def receipt_for(self, artifact_id: UUID, index: int) -> AnchorReceipt:
        with self._lock:
            receipt = self._receipts.get((artifact_id, index))
        if receipt is None:
            raise AppError(ErrorCode.CHAIN_REFUSED, "The mock ledger has no such anchor", 502)
        return receipt

    def submit(self, record: AnchorRecord) -> AnchorReceipt:
        with self._lock:
            history = self._anchors.setdefault(record.artifact_id, [])
            index = len(history)
            history.append(ChainAnchor(index, record))
            receipt = AnchorReceipt(
                anchor_index=index,
                tx_hash=f"mock-tx-{uuid4().hex}",
                source=SOURCE_MOCK,
                anchored_at=utcnow(),
            )
            self._receipts[(record.artifact_id, index)] = receipt
        return receipt
