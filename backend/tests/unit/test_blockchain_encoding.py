"""Encoding of the eight anchored fields and the deterministic record hash."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest

from app.blockchain import encoding
from app.blockchain.base import AnchorRecord
from app.core.errors import AppError

ID = UUID("11111111-1111-1111-1111-111111111111")
A, B, C = "a" * 64, "b" * 64, "c" * 64
RECORD = AnchorRecord(ID, A, B, C, 700_000, "REVIEW", "0.1.0", 1_790_000_000)
EMPTY = AnchorRecord(ID, A, None, None, None, "BLOCK", "0.1.0", 1_790_000_000)


def _code(call, *args) -> str:
    with pytest.raises(AppError) as caught:
        call(*args)
    return caught.value.code


# Both digests were computed with sha256sum over the literal preimage, not with this code.
@pytest.mark.parametrize(
    ("record", "expected"),
    [
        (RECORD, "4a7266bdb047aadfaa5406a5e99b18aff16da1c0089df57b0505b44a94d3f342"),
        (EMPTY, "24009327175a05c4867b053b6c4b13959f98f613518dce0204f988ca1c5d13e3"),
    ],
)
def test_record_hash_golden_vectors(record, expected):
    assert encoding.record_hash(record) == expected


@pytest.mark.parametrize(
    "change",
    [
        {"artifact_id": UUID(int=2)},
        {"artifact_hash": "d" * 64},
        {"bom_hash": "d" * 64},
        {"bom_hash": None},
        {"provenance_hash": "d" * 64},
        {"provenance_hash": None},
        {"risk_score_scaled": 700_001},
        {"risk_score_scaled": None},
        {"risk_score_scaled": 0},
        {"decision": "BLOCK"},
        {"scanner_version": "0.1.1"},
        {"timestamp": 1_790_000_001},
    ],
)
def test_every_field_changes_the_record_hash(change):
    assert encoding.record_hash(replace(RECORD, **change)) != encoding.record_hash(RECORD)


def test_null_and_zero_scores_hash_differently():
    assert encoding.record_hash(replace(EMPTY, risk_score_scaled=0)) != encoding.record_hash(EMPTY)


@pytest.mark.parametrize(
    ("score", "scaled"),
    [
        (0.0, 0),
        (0, 0),
        (1.0, 1_000_000),
        (0.7, 700_000),
        (0.306, 306_000),
        (0.1234565, 123_456),
        (0.1234575, 123_458),
        (0.000001, 1),
    ],
)
def test_score_scaling(score, scaled):
    assert encoding.encode_score(score) == scaled


def test_null_score_is_never_zero():
    assert encoding.encode_score(None) is None
    assert encoding.score_to_chain(None) == encoding.NO_SCORE
    assert encoding.score_from_chain(encoding.NO_SCORE) is None
    assert encoding.decode_score(None) is None


def test_real_zero_stays_zero():
    assert encoding.score_to_chain(0) == 0
    assert encoding.score_from_chain(0) == 0
    assert encoding.decode_score(0) == 0.0


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -0.01, 1.01, True, "0.5"])
def test_invalid_scores_are_refused(bad):
    assert _code(encoding.encode_score, bad) == "anchor_invalid_record"


@pytest.mark.parametrize("value", [1_000_001, encoding.NO_SCORE - 1, -1])
def test_invalid_chain_scores_are_refused(value):
    assert _code(encoding.score_from_chain, value) == "chain_refused"


@pytest.mark.parametrize(
    "bad",
    [
        "A" * 64,
        "a" * 63,
        "a" * 65,
        "a" * 64 + "\n",
        "0x" + "a" * 62,
        "g" * 64,
        "[REDACTED]",
        "",
        "0" * 64,
        None,
        123,
    ],
)
def test_invalid_hashes_are_refused(bad):
    assert _code(encoding.validate_hash, bad, "x") == "anchor_invalid_hash"


def test_valid_hash_is_returned():
    assert encoding.validate_hash(A, "x") == A


def test_optional_hash_keeps_none_and_still_validates():
    assert encoding.validate_optional_hash(None, "x") is None
    assert _code(encoding.validate_optional_hash, "0" * 64, "x") == "anchor_invalid_hash"


def test_zero_marker_round_trip():
    assert encoding.hash_to_bytes32(None) == bytes(32)
    assert encoding.hash_from_bytes32(bytes(32)) is None
    assert encoding.hash_from_bytes32(encoding.hash_to_bytes32(A)) == A


@pytest.mark.parametrize("decision", ["ALLOW", "REVIEW", "BLOCK"])
def test_decisions_are_accepted(decision):
    assert encoding.validate_decision(decision) == decision


@pytest.mark.parametrize("decision", ["allow", "", None, "NONE"])
def test_other_decisions_are_refused(decision):
    assert _code(encoding.validate_decision, decision) == "anchor_invalid_record"


def test_decision_codes_match_the_contract():
    assert encoding.DECISION_CODES == {"ALLOW": 1, "REVIEW": 2, "BLOCK": 3}


@pytest.mark.parametrize("version", ["", "v" * 33, "é" * 17, None])
def test_invalid_scanner_versions_are_refused(version):
    assert _code(encoding.validate_scanner_version, version) == "anchor_invalid_record"


def test_longest_scanner_version_is_accepted():
    assert encoding.validate_scanner_version("v" * 32) == "v" * 32


def test_zero_artifact_id_is_refused():
    assert _code(encoding.validate_artifact_id, UUID(int=0)) == "anchor_invalid_record"


def test_timestamp_drops_fractions_and_treats_naive_as_utc():
    aware = datetime(2026, 11, 9, 12, 0, 30, 999999, tzinfo=UTC)
    naive = aware.replace(tzinfo=None)
    assert encoding.timestamp_seconds(aware) == encoding.timestamp_seconds(naive)
    assert encoding.timestamp_seconds(aware) == int(aware.replace(microsecond=0).timestamp())


def test_timestamp_respects_other_offsets():
    utc = datetime(2026, 11, 9, 12, tzinfo=UTC)
    shifted = utc.astimezone(timezone(timedelta(hours=5, minutes=30)))
    assert encoding.timestamp_seconds(shifted) == encoding.timestamp_seconds(utc)


def test_pre_epoch_timestamp_is_refused():
    moment = datetime(1960, 1, 1, tzinfo=UTC)
    assert _code(encoding.timestamp_seconds, moment) == "anchor_invalid_record"


def test_chain_round_trip_preserves_every_field():
    for record in (RECORD, EMPTY, replace(RECORD, risk_score_scaled=0)):
        assert encoding.record_from_chain(*encoding.to_chain_arguments(record).as_tuple()) == record


def test_chain_arguments_use_the_markers():
    args = encoding.to_chain_arguments(EMPTY)
    assert args.bom_hash == bytes(32)
    assert args.provenance_hash == bytes(32)
    assert args.risk_score == encoding.NO_SCORE
    assert args.decision == 3


@pytest.mark.parametrize("change", [{"artifact_hash": bytes(32)}, {"decision": 0}, {"decision": 4}])
def test_invalid_chain_anchors_are_refused(change):
    values = {
        "artifact_id": ID.bytes,
        "artifact_hash": bytes.fromhex(A),
        "bom_hash": bytes(32),
        "provenance_hash": bytes(32),
        "risk_score": 1,
        "decision": 1,
        "scanner_version": "0.1.0",
        "timestamp": 1,
        **change,
    }
    assert _code(lambda: encoding.record_from_chain(**values)) == "chain_refused"


def test_missing_evidence_names_absent_hashes():
    assert encoding.missing_evidence(RECORD) == []
    assert encoding.missing_evidence(EMPTY) == ["bom_hash", "provenance_hash"]
