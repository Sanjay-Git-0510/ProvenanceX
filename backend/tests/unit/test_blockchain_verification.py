"""Verification states: every tamper case, every chain failure, and what never gives VERIFIED."""

from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.blockchain.anchoring import anchor_scan
from app.blockchain.base import ChainAnchor
from app.blockchain.mock import MockChainProvider
from app.blockchain.verification import verify_scan
from app.core.errors import AppError, ErrorCode
from app.db.models import AnchorStatus, ArtifactType, BlockchainEvidence, RiskDecision, Scan
from tests.conftest import make_anchorable_scan, write_scan_evidence

ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
BLOCK = "0x" + "0b" * 32


class Chain(MockChainProvider):
    """A ledger that behaves like the real chain, with switches for each failure."""

    source = "web3"

    def __init__(self):
        super().__init__()
        self.error = None
        self.chain_location = (31337, ADDRESS)
        self.block = BLOCK

    def location(self):
        if self.error:
            raise self.error
        return self.chain_location

    def block_hash_at(self, number):
        return self.block

    def submit(self, record):
        receipt = super().submit(record)
        final = replace(
            receipt,
            source="web3",
            block_number=5,
            block_hash=BLOCK,
            chain_id=31337,
            contract_address=ADDRESS,
        )
        self._receipts[(record.artifact_id, receipt.anchor_index)] = final
        return final

    def wipe(self):
        self._anchors.clear()


@pytest.fixture
def chain():
    return Chain()


@pytest.fixture
def session(session_factory):
    with session_factory() as active:
        yield active


class Anchored:
    def __init__(self, session, settings, chain, **kwargs):
        self.session, self.settings, self.chain = session, settings, chain
        bom = kwargs.pop("bom", True)
        provenance = kwargs.pop("provenance", True)
        if not bom:
            kwargs["bom_sha256"] = None
        if not provenance:
            kwargs["provenance_sha256"] = None
        self.scan_id = make_anchorable_scan(session, **kwargs)
        self.workspace = write_scan_evidence(
            session, self.scan_id, settings, bom=bom, provenance=provenance
        )
        self.result = anchor_scan(session, self.scan_id, chain, settings)

    @property
    def scan(self):
        self.session.expire_all()
        return self.session.get(Scan, self.scan_id)

    @property
    def row(self):
        self.session.expire_all()
        return self.session.scalars(
            select(BlockchainEvidence).where(BlockchainEvidence.scan_id == self.scan_id)
        ).one()

    @property
    def decision(self):
        self.session.expire_all()
        return self.session.scalars(
            select(RiskDecision).where(RiskDecision.scan_id == self.scan_id)
        ).one()

    def verify(self, provider="default"):
        chain = self.chain if provider == "default" else provider
        return verify_scan(self.session, self.scan_id, chain, self.settings)

    def field(self, response, name):
        return next(item for item in response.fields if item.field == name)


@pytest.fixture
def anchored(session, test_settings, chain):
    return Anchored(session, test_settings, chain)


def _state(response):
    return str(response.state), response.reason.code


def test_untouched_scan_is_verified(anchored):
    response = anchored.verify()
    assert _state(response) == ("VERIFIED", "verified")
    assert response.source == "web3"
    assert response.is_mock is False
    assert {item.status for item in response.fields} == {"match"}
    assert response.tx_hash == anchored.result.tx_hash
    assert "does not show" in response.note


def test_every_field_is_reported_with_all_values(anchored):
    response = anchored.verify()
    assert [item.field for item in response.fields] == [
        "artifact_id",
        "artifact_hash",
        "bom_hash",
        "provenance_hash",
        "risk_score",
        "decision",
        "scanner_version",
        "timestamp",
        "record_hash",
    ]
    for item in response.fields:
        assert None not in (item.stored, item.source_table, item.recomputed, item.chain), item


def test_score_is_shown_raw_and_encoded(anchored):
    field = anchored.field(anchored.verify(), "risk_score")
    assert (field.stored, field.source_table, field.recomputed, field.chain) == (
        700_000,
        0.7,
        700_000,
        700_000,
    )


def test_hashes_are_really_recomputed_from_files(anchored):
    (anchored.workspace.src_dir / "app.py").write_text("changed", encoding="utf-8")
    field = anchored.field(anchored.verify(), "artifact_hash")
    assert field.recomputed != field.stored
    assert field.stored == field.source_table == field.chain


def _set(entity, attribute, value):
    def apply(case):
        target = getattr(case, entity)
        setattr(target, attribute, value)
        case.session.commit()

    return apply


def _set_artifact_sha(case):
    case.scan.artifact.sha256 = "d" * 64
    case.session.commit()


def _set_provenance_hash(case):
    case.scan.provenance.record_sha256 = "d" * 64
    case.session.commit()


def _delete_provenance(case):
    case.session.delete(case.scan.provenance)
    case.session.commit()


def _delete_decision(case):
    case.session.delete(case.decision)
    case.session.commit()


def _set_timestamp(case):
    case.decision.created_at = datetime(2026, 11, 9, 12, 0, 31, tzinfo=UTC)
    case.session.commit()


def _set_nan_score(case):
    decision = case.decision
    decision.risk_score = float("nan")
    case.session.commit()


DATABASE_TAMPERING = {
    "artifact_hash_in_table": (_set_artifact_sha, "artifact_hash"),
    "bom_hash_in_table": (_set("scan", "bom_sha256", "d" * 64), "bom_hash"),
    "bom_hash_removed_from_table": (_set("scan", "bom_sha256", None), "bom_hash"),
    "provenance_hash_in_table": (_set_provenance_hash, "provenance_hash"),
    "provenance_record_deleted": (_delete_provenance, "provenance_hash"),
    "artifact_hash_in_row": (_set("row", "artifact_hash", "d" * 64), "artifact_hash"),
    "bom_hash_in_row": (_set("row", "bom_hash", "d" * 64), "bom_hash"),
    "provenance_hash_in_row": (_set("row", "provenance_hash", "d" * 64), "provenance_hash"),
    "score_in_table": (_set("decision", "risk_score", 0.1), "risk_score"),
    "score_in_row": (_set("row", "risk_score_scaled", 100_000), "risk_score"),
    "score_nulled_in_table": (_set("decision", "risk_score", None), "risk_score"),
    "score_zeroed_in_table": (_set("decision", "risk_score", 0.0), "risk_score"),
    "score_nulled_in_row": (_set("row", "risk_score_scaled", None), "risk_score"),
    "score_zeroed_in_row": (_set("row", "risk_score_scaled", 0), "risk_score"),
    "score_not_a_number": (_set_nan_score, "risk_score"),
    "decision_in_table": (_set("decision", "decision", "ALLOW"), "decision"),
    "decision_in_row": (_set("row", "decision", "ALLOW"), "decision"),
    "decision_deleted": (_delete_decision, "decision"),
    "version_in_table": (_set("scan", "scanner_version", "9.9.9"), "scanner_version"),
    "version_in_row": (_set("row", "scanner_version", "9.9.9"), "scanner_version"),
    "timestamp_in_table": (_set_timestamp, "timestamp"),
    "timestamp_in_row": (_set("row", "evidence_timestamp", 1), "timestamp"),
    "record_hash_in_row": (_set("row", "record_hash", "d" * 64), "record_hash"),
}


@pytest.mark.parametrize(("tamper", "field"), DATABASE_TAMPERING.values(), ids=DATABASE_TAMPERING)
def test_database_tampering_is_a_mismatch(anchored, tamper, field):
    tamper(anchored)
    response = anchored.verify()
    assert _state(response) == ("MISMATCH", "evidence_mismatch")
    assert anchored.field(response, field).status == "mismatch"
    assert field in response.reason.message


def test_null_score_replaced_by_zero_is_a_mismatch(session, test_settings, chain):
    case = Anchored(session, test_settings, chain, score=None, decision="BLOCK")
    assert _state(case.verify())[0] == "VERIFIED"
    assert case.field(case.verify(), "risk_score").chain is None
    case.decision.risk_score = 0.0
    session.commit()
    response = case.verify()
    assert _state(response) == ("MISMATCH", "evidence_mismatch")
    assert case.field(response, "risk_score").recomputed == 0
    assert case.field(response, "risk_score").chain is None


def test_real_zero_replaced_by_null_is_a_mismatch(session, test_settings, chain):
    case = Anchored(session, test_settings, chain, score=0.0, decision="ALLOW")
    assert _state(case.verify())[0] == "VERIFIED"
    case.decision.risk_score = None
    session.commit()
    assert _state(case.verify()) == ("MISMATCH", "evidence_mismatch")


def _edit_src(case):
    (case.workspace.src_dir / "app.py").write_text("tampered", encoding="utf-8")


def _add_src(case):
    (case.workspace.src_dir / "new.py").write_text("x", encoding="utf-8")


def _remove_src(case):
    (case.workspace.src_dir / "app.py").unlink()


def _symlink_src(case):
    (case.workspace.src_dir / "link").symlink_to("/etc/hostname")


def _edit_root(name):
    def apply(case):
        (case.workspace.root / name).write_text("tampered", encoding="utf-8")

    return apply


def _symlink_root(name):
    def apply(case):
        path = case.workspace.root / name
        path.unlink()
        path.symlink_to("/etc/hostname")

    return apply


def _directory_root(name):
    def apply(case):
        path = case.workspace.root / name
        path.unlink()
        path.mkdir()

    return apply


FILE_TAMPERING = {
    "artifact_file_edited": (_edit_src, "artifact_hash"),
    "artifact_file_added": (_add_src, "artifact_hash"),
    "artifact_file_removed": (_remove_src, "artifact_hash"),
    "artifact_symlink_planted": (_symlink_src, "artifact_hash"),
    "bom_file_edited": (_edit_root("sbom.cdx.json"), "bom_hash"),
    "bom_replaced_by_symlink": (_symlink_root("sbom.cdx.json"), "bom_hash"),
    "bom_replaced_by_directory": (_directory_root("sbom.cdx.json"), "bom_hash"),
    "provenance_file_edited": (_edit_root("provenance.json"), "provenance_hash"),
    "provenance_replaced_by_symlink": (_symlink_root("provenance.json"), "provenance_hash"),
}


@pytest.mark.parametrize(("tamper", "field"), FILE_TAMPERING.values(), ids=FILE_TAMPERING)
def test_file_tampering_is_a_mismatch(anchored, tamper, field):
    tamper(anchored)
    response = anchored.verify()
    assert _state(response) == ("MISMATCH", "evidence_mismatch")
    assert anchored.field(response, field).status == "mismatch"


def test_aibom_file_is_used_for_model_artifacts(anchored):
    anchored.scan.artifact.artifact_type = ArtifactType.MODEL
    anchored.session.commit()
    assert _state(anchored.verify())[1] == "offchain_evidence_unavailable"
    aibom = anchored.workspace.root / "aibom.json"
    aibom.write_bytes((anchored.workspace.root / "sbom.cdx.json").read_bytes())
    assert _state(anchored.verify())[0] == "VERIFIED"
    aibom.write_text("tampered", encoding="utf-8")
    assert _state(anchored.verify())[0] == "MISMATCH"


def test_paths_stored_in_the_database_are_never_followed(anchored):
    anchored.scan.stages = {"sbom": {"sbom_file": "../../../../etc/hostname"}}
    anchored.session.commit()
    assert anchored.field(anchored.verify(), "bom_hash").status == "match"


def _chain_change(anchored, **changes):
    key = anchored.result.artifact_id
    anchor = anchored.chain._anchors[key][0]
    anchored.chain._anchors[key][0] = ChainAnchor(anchor.index, replace(anchor.record, **changes))


@pytest.mark.parametrize(
    ("changes", "field"),
    [
        ({"artifact_hash": "d" * 64}, "artifact_hash"),
        ({"bom_hash": None}, "bom_hash"),
        ({"provenance_hash": "d" * 64}, "provenance_hash"),
        ({"risk_score_scaled": 1}, "risk_score"),
        ({"risk_score_scaled": None}, "risk_score"),
        ({"decision": "ALLOW"}, "decision"),
        ({"scanner_version": "other"}, "scanner_version"),
        ({"timestamp": 2}, "timestamp"),
    ],
)
def test_changed_chain_value_is_a_mismatch(anchored, changes, field):
    _chain_change(anchored, **changes)
    response = anchored.verify()
    assert _state(response) == ("MISMATCH", "evidence_mismatch")
    assert anchored.field(response, field).status == "mismatch"


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("tx_hash", "0x" + "ff" * 32),
        ("block_hash", "0x" + "ff" * 32),
        ("block_number", 99),
        ("anchor_index", 3),
    ],
)
def test_changed_receipt_is_a_mismatch(anchored, attribute, value):
    setattr(anchored.row, attribute, value)
    anchored.session.commit()
    assert _state(anchored.verify()) == ("MISMATCH", "receipt_mismatch")


def test_changed_artifact_id_in_row_is_a_mismatch(anchored):
    anchored.row.artifact_id = uuid4()
    anchored.session.commit()
    assert _state(anchored.verify()) == ("MISMATCH", "anchor_missing")


def test_anchor_missing_from_an_intact_chain_is_a_mismatch(anchored):
    anchored.chain.wipe()
    assert _state(anchored.verify()) == ("MISMATCH", "anchor_missing")


def test_extra_anchor_is_a_mismatch(anchored):
    record = anchored.chain.anchors(anchored.result.artifact_id)[0].record
    anchored.chain.submit(record)
    assert _state(anchored.verify()) == ("MISMATCH", "anchor_count_mismatch")


def test_anchor_without_a_row_is_a_mismatch(anchored):
    anchored.session.delete(anchored.row)
    anchored.session.commit()
    assert _state(anchored.verify()) == ("MISMATCH", "anchor_without_row")


def test_definite_mismatch_beats_a_missing_file(anchored):
    (anchored.workspace.root / "provenance.json").unlink()
    _edit_src(anchored)
    assert _state(anchored.verify()) == ("MISMATCH", "evidence_mismatch")


def _missing(name):
    def apply(case):
        (case.workspace.root / name).unlink()

    return apply


def _remove_tree(case, path):
    import shutil

    shutil.rmtree(path)


MISSING_FILES = {
    "whole_workspace": lambda c: _remove_tree(c, c.workspace.root),
    "artifact_tree": lambda c: _remove_tree(c, c.workspace.src_dir),
    "bom_file": _missing("sbom.cdx.json"),
    "provenance_file": _missing("provenance.json"),
}


@pytest.mark.parametrize("remove", MISSING_FILES.values(), ids=MISSING_FILES)
def test_missing_off_chain_files_are_unknown(anchored, remove):
    remove(anchored)
    response = anchored.verify()
    assert _state(response) == ("UNKNOWN", "offchain_evidence_unavailable")
    assert "unavailable" in {item.status for item in response.fields}


def _refused(details=None):
    return AppError(ErrorCode.CHAIN_REFUSED, "refused", 409, details)


CHAIN_FAILURES = {
    "unreachable": (AppError(ErrorCode.CHAIN_UNAVAILABLE, "down", 503), "chain_unavailable"),
    "wrong_chain_id": (_refused(), "chain_refused"),
    "contract_gone": (_refused({"reason": "no_contract"}), "chain_state_lost"),
    "unexpected": (RuntimeError("boom"), "chain_unavailable"),
}


@pytest.mark.parametrize(("error", "code"), CHAIN_FAILURES.values(), ids=CHAIN_FAILURES)
def test_chain_failures_are_unknown_never_verified(anchored, error, code):
    anchored.chain.error = error
    response = anchored.verify()
    assert _state(response) == ("UNKNOWN", code)
    assert {item.chain for item in response.fields} == {None}


def test_chain_failure_stays_unknown_even_with_tampered_files(anchored):
    _edit_src(anchored)
    anchored.chain.error = AppError(ErrorCode.CHAIN_UNAVAILABLE, "down", 503)
    response = anchored.verify()
    assert _state(response) == ("UNKNOWN", "chain_unavailable")
    assert anchored.field(response, "artifact_hash").status == "mismatch"


def test_disabled_provider_is_unknown_and_never_a_mock(anchored):
    response = anchored.verify(provider=None)
    assert _state(response) == ("UNKNOWN", "chain_provider_disabled")
    assert response.is_mock is False


def test_reset_chain_is_unknown(anchored):
    anchored.chain.wipe()
    anchored.chain.block = "0x" + "aa" * 32
    assert _state(anchored.verify()) == ("UNKNOWN", "chain_state_lost")


def test_reset_chain_shorter_than_the_anchor_block_is_unknown(anchored):
    anchored.chain.wipe()
    anchored.chain.block = None
    assert _state(anchored.verify()) == ("UNKNOWN", "chain_state_lost")


def test_different_contract_is_unknown(anchored):
    anchored.chain.chain_location = (31337, "0x" + "11" * 20)
    assert _state(anchored.verify()) == ("UNKNOWN", "contract_changed")


def test_anchor_made_by_another_provider_is_unknown(session, test_settings, chain):
    case = Anchored(session, test_settings, MockChainProvider())
    assert _state(case.verify(provider=chain)) == ("UNKNOWN", "provider_mismatch")


def test_mock_verification_is_labeled(session, test_settings):
    case = Anchored(session, test_settings, MockChainProvider())
    response = case.verify()
    assert _state(response) == ("VERIFIED", "verified")
    assert (response.source, response.is_mock) == ("mock", True)
    assert response.tx_hash.startswith("mock-tx-")


def test_lost_mock_ledger_is_unknown(session, test_settings):
    case = Anchored(session, test_settings, MockChainProvider())
    assert _state(case.verify(provider=MockChainProvider())) == ("UNKNOWN", "chain_state_lost")


@pytest.mark.parametrize("status", ["queued", "running", "failed"])
def test_unfinished_scan_is_not_anchored(session, test_settings, chain, status):
    scan_id = make_anchorable_scan(session, status=status)
    response = verify_scan(session, scan_id, chain, test_settings)
    assert _state(response) == ("NOT ANCHORED", "scan_not_anchorable")
    assert response.fields == []


def test_scan_without_a_decision_is_not_anchored(session, test_settings, chain):
    scan_id = make_anchorable_scan(session, with_decision=False)
    assert _state(verify_scan(session, scan_id, chain, test_settings)) == (
        "NOT ANCHORED",
        "scan_not_anchorable",
    )


def test_completed_scan_with_no_anchor_is_not_anchored(session, test_settings, chain):
    scan_id = make_anchorable_scan(session)
    assert _state(verify_scan(session, scan_id, chain, test_settings)) == (
        "NOT ANCHORED",
        "no_anchor",
    )


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (AppError(ErrorCode.CHAIN_UNAVAILABLE, "down", 503), "chain_unavailable"),
        (_refused(), "chain_refused"),
    ],
)
def test_no_row_with_a_bad_chain_is_unknown(session, test_settings, chain, error, code):
    scan_id = make_anchorable_scan(session)
    chain.error = error
    assert _state(verify_scan(session, scan_id, chain, test_settings)) == ("UNKNOWN", code)


def test_no_row_and_disabled_provider_is_unknown(session, test_settings):
    scan_id = make_anchorable_scan(session)
    assert _state(verify_scan(session, scan_id, None, test_settings)) == (
        "UNKNOWN",
        "chain_provider_disabled",
    )


@pytest.mark.parametrize("status", [AnchorStatus.PENDING, AnchorStatus.FAILED])
def test_unconfirmed_row_without_anchor_is_not_anchored(anchored, status):
    anchored.row.status = status
    anchored.session.commit()
    anchored.chain.wipe()
    assert _state(anchored.verify()) == ("NOT ANCHORED", "anchor_not_confirmed")


@pytest.mark.parametrize("status", [AnchorStatus.PENDING, AnchorStatus.FAILED])
def test_unconfirmed_row_with_anchor_is_unknown(anchored, status):
    anchored.row.status = status
    anchored.session.commit()
    assert _state(anchored.verify()) == ("UNKNOWN", "anchor_unconfirmed")


@pytest.mark.parametrize(
    ("options", "missing"),
    [
        ({"bom": False}, ["bom_hash"]),
        ({"provenance": False}, ["provenance_hash"]),
        ({"bom": False, "provenance": False}, ["bom_hash", "provenance_hash"]),
    ],
)
def test_absent_evidence_is_listed_and_can_verify(session, test_settings, chain, options, missing):
    case = Anchored(session, test_settings, chain, **options)
    response = case.verify()
    assert _state(response)[0] == "VERIFIED"
    assert response.missing_evidence == missing
    for name in missing:
        field = case.field(response, name)
        assert (field.status, field.stored, field.chain) == ("absent", None, None)


def test_evidence_added_after_an_absent_anchor_is_a_mismatch(session, test_settings, chain):
    case = Anchored(session, test_settings, chain, bom=False)
    case.scan.bom_sha256 = "d" * 64
    session.commit()
    assert _state(case.verify())[0] == "MISMATCH"


def test_unknown_scan_is_not_found(session, test_settings, chain):
    with pytest.raises(AppError) as caught:
        verify_scan(session, uuid4(), chain, test_settings)
    assert caught.value.code == "scan_not_found"
