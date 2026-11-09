"""Validation and encoding of the eight anchored fields, and the deterministic record hash.

Record hash format (``provenancex-anchor-v1``):

    sha256( b"provenancex-anchor-v1\\n" + canonical JSON of the eight encoded fields )

Canonical JSON has sorted keys, no whitespace and ASCII-only output. The hash covers encoded
integers rather than floats, so it does not depend on float formatting. It stays off-chain.
"""

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_HALF_EVEN, Decimal
from uuid import UUID

from app.blockchain.base import AnchorRecord
from app.core.errors import AppError, ErrorCode

RECORD_HASH_VERSION = "provenancex-anchor-v1"
SCORE_SCALE = 1_000_000
NO_SCORE = 2**32 - 1  # Matches ProvenanceEvidence.NO_SCORE.
MAX_SCANNER_VERSION_BYTES = 32
LOCAL_CHAIN_ID = 31337
ZERO_BYTES32 = bytes(32)
DECISION_CODES = {"ALLOW": 1, "REVIEW": 2, "BLOCK": 3}
DECISIONS_BY_CODE = {code: name for name, code in DECISION_CODES.items()}

_HASH_RE = re.compile(r"[0-9a-f]{64}")
_ZERO_HASH = "0" * 64
_STATUS_INVALID = 422


def _invalid_record(message: str) -> AppError:
    return AppError(ErrorCode.ANCHOR_INVALID_RECORD, message, _STATUS_INVALID)


def validate_hash(value: object, field: str) -> str:
    """Return a valid SHA-256 hex digest or refuse it.

    fullmatch is deliberate: `$` would also accept a trailing newline. An all-zero digest is
    refused because on-chain it would read as "absent".
    """
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None or value == _ZERO_HASH:
        raise AppError(
            ErrorCode.ANCHOR_INVALID_HASH,
            f"{field} is not a valid SHA-256 digest",
            _STATUS_INVALID,
            {"field": field},
        )
    return value


def validate_optional_hash(value: object, field: str) -> str | None:
    return None if value is None else validate_hash(value, field)


def encode_score(score: float | None) -> int | None:
    """Scale a 0..1 score to millionths. None stays None, and is never turned into 0."""
    if score is None:
        return None
    if isinstance(score, bool) or not isinstance(score, int | float) or not math.isfinite(score):
        raise _invalid_record("risk_score is not a finite number")
    if not 0 <= score <= 1:
        raise _invalid_record("risk_score is outside 0..1")
    scaled = (Decimal(repr(float(score))) * SCORE_SCALE).quantize(
        Decimal(1), rounding=ROUND_HALF_EVEN
    )
    return int(scaled)


def decode_score(scaled: int | None) -> float | None:
    return None if scaled is None else scaled / SCORE_SCALE


def score_to_chain(scaled: int | None) -> int:
    return NO_SCORE if scaled is None else scaled


def score_from_chain(value: int) -> int | None:
    if value == NO_SCORE:
        return None
    if not 0 <= value <= SCORE_SCALE:
        raise AppError(ErrorCode.CHAIN_REFUSED, "The chain returned an invalid risk score", 502)
    return value


def validate_decision(decision: object) -> str:
    text = str(decision)
    if text not in DECISION_CODES:
        raise _invalid_record("decision is not ALLOW, REVIEW or BLOCK")
    return text


def validate_scanner_version(version: object) -> str:
    if not isinstance(version, str) or not 1 <= len(version.encode()) <= MAX_SCANNER_VERSION_BYTES:
        raise _invalid_record(f"scanner_version must be 1 to {MAX_SCANNER_VERSION_BYTES} bytes")
    return version


def validate_artifact_id(artifact_id: UUID) -> UUID:
    if artifact_id.int == 0:
        raise _invalid_record("artifact_id must be non-zero")
    return artifact_id


def timestamp_seconds(moment: datetime) -> int:
    """UTC seconds. A naive value is UTC: SQLite drops the timezone that PostgreSQL keeps."""
    aware = moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)
    seconds = math.floor(aware.timestamp())
    if seconds <= 0:
        raise _invalid_record("timestamp must be positive")
    return seconds


def hash_to_bytes32(value: str | None) -> bytes:
    return ZERO_BYTES32 if value is None else bytes.fromhex(value)


def hash_from_bytes32(value: bytes) -> str | None:
    raw = bytes(value)
    return None if raw == ZERO_BYTES32 else raw.hex()


@dataclass(frozen=True)
class ChainArguments:
    artifact_id: bytes
    artifact_hash: bytes
    bom_hash: bytes
    provenance_hash: bytes
    risk_score: int
    decision: int
    scanner_version: str
    timestamp: int

    def as_tuple(self) -> tuple[bytes, bytes, bytes, bytes, int, int, str, int]:
        return (
            self.artifact_id,
            self.artifact_hash,
            self.bom_hash,
            self.provenance_hash,
            self.risk_score,
            self.decision,
            self.scanner_version,
            self.timestamp,
        )


def to_chain_arguments(record: AnchorRecord) -> ChainArguments:
    return ChainArguments(
        artifact_id=record.artifact_id.bytes,
        artifact_hash=hash_to_bytes32(record.artifact_hash),
        bom_hash=hash_to_bytes32(record.bom_hash),
        provenance_hash=hash_to_bytes32(record.provenance_hash),
        risk_score=score_to_chain(record.risk_score_scaled),
        decision=DECISION_CODES[record.decision],
        scanner_version=record.scanner_version,
        timestamp=record.timestamp,
    )


def record_from_chain(
    artifact_id: bytes,
    artifact_hash: bytes,
    bom_hash: bytes,
    provenance_hash: bytes,
    risk_score: int,
    decision: int,
    scanner_version: str,
    timestamp: int,
) -> AnchorRecord:
    stored_hash = hash_from_bytes32(artifact_hash)
    if stored_hash is None or decision not in DECISIONS_BY_CODE:
        raise AppError(ErrorCode.CHAIN_REFUSED, "The chain returned an invalid anchor", 502)
    return AnchorRecord(
        artifact_id=UUID(bytes=bytes(artifact_id)),
        artifact_hash=stored_hash,
        bom_hash=hash_from_bytes32(bom_hash),
        provenance_hash=hash_from_bytes32(provenance_hash),
        risk_score_scaled=score_from_chain(risk_score),
        decision=DECISIONS_BY_CODE[decision],
        scanner_version=scanner_version,
        timestamp=timestamp,
    )


def canonical_record(record: AnchorRecord) -> bytes:
    document = {
        "artifact_hash": record.artifact_hash,
        "artifact_id": str(record.artifact_id),
        "bom_hash": record.bom_hash,
        "decision": record.decision,
        "provenance_hash": record.provenance_hash,
        "risk_score": record.risk_score_scaled,
        "scanner_version": record.scanner_version,
        "timestamp": record.timestamp,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")


def record_hash(record: AnchorRecord) -> str:
    preimage = f"{RECORD_HASH_VERSION}\n".encode() + canonical_record(record)
    return hashlib.sha256(preimage).hexdigest()


def missing_evidence(record: AnchorRecord) -> list[str]:
    """Absent hashes, named so that a zero marker can never be read as clean."""
    return [
        name
        for name, value in (
            ("bom_hash", record.bom_hash),
            ("provenance_hash", record.provenance_hash),
        )
        if value is None
    ]
