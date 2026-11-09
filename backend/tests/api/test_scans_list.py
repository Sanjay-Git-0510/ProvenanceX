"""API tests for GET /scans: paging, order, filter, null handling, and that nothing leaks."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import event

from app.db.models import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    RiskDecision,
    RiskVerdict,
    Scan,
    ScanStatus,
)
from app.schemas.evidence import REDACTED
from app.schemas.scan_list import DEFAULT_SCAN_PAGE, MAX_SCAN_PAGE
from tests.api.test_scans_evidence import HOST_PATH, SECRET_LIKE, SECRETS

URL = "/api/v1/scans"
BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)
ITEM_KEYS = {
    "scan_id",
    "status",
    "created_at",
    "finished_at",
    "artifact",
    "decision",
    "risk_score",
    "confidence",
}


def _make_scan(
    session_factory,
    *,
    name="fixture",
    status=ScanStatus.COMPLETED,
    created_at=BASE_TIME,
    scan_id=None,
    **scan_fields,
):
    with session_factory() as session:
        artifact = Artifact(
            artifact_type=ArtifactType.SOFTWARE,
            name=name,
            source=ArtifactSource.UPLOAD,
        )
        scan = Scan(
            id=scan_id or uuid.uuid4(),
            artifact=artifact,
            status=status,
            scanner_version="t",
            created_at=created_at,
            **scan_fields,
        )
        session.add_all([artifact, scan])
        session.commit()
        return scan.id


def _add_decision(session_factory, scan_id, *, score, decision, confidence):
    with session_factory() as session:
        session.add(
            RiskDecision(
                scan_id=scan_id,
                risk_score=score,
                decision=decision,
                decision_basis="test",
                confidence=confidence,
                confidence_label="LOW",
                ml_status="unavailable",
                policy_version="t",
                layer_scores={},
                explanation={},
            )
        )
        session.commit()


def _list(client, **params):
    response = client.get(URL, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_empty_list(scan_client):
    assert _list(scan_client) == {
        "page": {"total": 0, "limit": DEFAULT_SCAN_PAGE, "offset": 0, "has_more": False},
        "items": [],
    }


def test_newest_first_with_id_tiebreak(scan_client, session_factory):
    low, high = uuid.UUID(int=1), uuid.UUID(int=2)
    _make_scan(session_factory, scan_id=low, created_at=BASE_TIME)
    _make_scan(session_factory, scan_id=high, created_at=BASE_TIME)
    newest = _make_scan(session_factory, created_at=BASE_TIME + timedelta(hours=1))
    oldest = _make_scan(session_factory, created_at=BASE_TIME - timedelta(hours=1))

    ids = [item["scan_id"] for item in _list(scan_client)["items"]]

    assert ids == [str(newest), str(high), str(low), str(oldest)]


def test_default_page_size_and_has_more(scan_client, session_factory):
    for index in range(DEFAULT_SCAN_PAGE + 1):
        _make_scan(session_factory, created_at=BASE_TIME + timedelta(minutes=index))

    body = _list(scan_client)

    assert len(body["items"]) == DEFAULT_SCAN_PAGE
    assert body["page"] == {
        "total": DEFAULT_SCAN_PAGE + 1,
        "limit": DEFAULT_SCAN_PAGE,
        "offset": 0,
        "has_more": True,
    }


def test_pages_do_not_overlap_and_end_cleanly(scan_client, session_factory):
    created = [
        str(_make_scan(session_factory, created_at=BASE_TIME + timedelta(minutes=index)))
        for index in range(3)
    ]

    first = _list(scan_client, limit=2)
    second = _list(scan_client, limit=2, offset=2)
    past_end = _list(scan_client, limit=2, offset=9)

    assert [i["scan_id"] for i in first["items"]] == [created[2], created[1]]
    assert first["page"]["has_more"] is True
    assert [i["scan_id"] for i in second["items"]] == [created[0]]
    assert second["page"]["has_more"] is False
    assert past_end["items"] == []
    assert past_end["page"] == {"total": 3, "limit": 2, "offset": 9, "has_more": False}


def test_maximum_limit_is_accepted(scan_client):
    assert _list(scan_client, limit=MAX_SCAN_PAGE)["page"]["limit"] == MAX_SCAN_PAGE


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": -1},
        {"limit": MAX_SCAN_PAGE + 1},
        {"limit": "many"},
        {"offset": -1},
        {"offset": "x"},
        {"offset": 2_147_483_648},
        {"status": "done"},
        {"status": "COMPLETED"},
    ],
)
def test_bad_query_returns_structured_422(scan_client, params):
    response = scan_client.get(URL, params=params)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_status_filter_narrows_items_and_total(scan_client, session_factory):
    failed = _make_scan(session_factory, status=ScanStatus.FAILED)
    _make_scan(session_factory, status=ScanStatus.COMPLETED)

    body = _list(scan_client, status="failed")

    assert [item["scan_id"] for item in body["items"]] == [str(failed)]
    assert body["page"]["total"] == 1


def test_item_has_only_the_allowed_fields(scan_client, session_factory):
    finished = BASE_TIME + timedelta(minutes=2)
    scan_id = _make_scan(session_factory, name="demo", finished_at=finished)
    _add_decision(session_factory, scan_id, score=0.42, decision=RiskVerdict.REVIEW, confidence=0.7)

    item = _list(scan_client)["items"][0]

    assert set(item) == ITEM_KEYS
    assert item["scan_id"] == str(scan_id)
    assert item["status"] == "completed"
    assert item["finished_at"] is not None
    assert item["artifact"] == {"name": "demo", "artifact_type": "software", "source": "upload"}
    assert (item["decision"], item["risk_score"], item["confidence"]) == ("REVIEW", 0.42, 0.7)


def test_null_score_stays_null_beside_a_real_decision(scan_client, session_factory):
    scan_id = _make_scan(session_factory)
    _add_decision(session_factory, scan_id, score=None, decision=RiskVerdict.BLOCK, confidence=0.3)

    item = _list(scan_client)["items"][0]

    assert item["risk_score"] is None
    assert item["decision"] == "BLOCK"


def test_real_zero_score_stays_zero(scan_client, session_factory):
    scan_id = _make_scan(session_factory)
    _add_decision(session_factory, scan_id, score=0.0, decision=RiskVerdict.ALLOW, confidence=0.9)

    assert _list(scan_client)["items"][0]["risk_score"] == 0.0


@pytest.mark.parametrize("status", list(ScanStatus))
def test_scan_without_a_decision_has_nulls(scan_client, session_factory, status):
    _make_scan(session_factory, status=status)

    item = _list(scan_client)["items"][0]

    assert (item["decision"], item["risk_score"], item["confidence"]) == (None, None, None)


def test_listing_never_computes_or_stores_a_decision(scan_client, session_factory):
    scan_id = _make_scan(session_factory)

    _list(scan_client)

    with session_factory() as session:
        assert session.get(Scan, scan_id).risk_decision is None


def test_sensitive_columns_are_not_queried(scan_client, session_factory):
    _make_scan(session_factory)
    statements = []
    engine = session_factory.kw["bind"]

    def record(_conn, _cursor, statement, *_rest):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        _list(scan_client)
    finally:
        event.remove(engine, "before_cursor_execute", record)

    sql = " ".join(statements).lower()
    assert sql
    for column in ("ingest_metadata", "error_message", "error_details", "source_url", "stages"):
        assert column not in sql


@pytest.mark.parametrize("kind", sorted(SECRETS))
def test_name_is_sanitized(scan_client, session_factory, kind):
    _make_scan(session_factory, name=SECRETS[kind])

    response = scan_client.get(URL)

    assert response.status_code == 200
    assert SECRETS[kind] not in response.text
    assert REDACTED in response.json()["items"][0]["artifact"]["name"]
    assert not HOST_PATH.search(response.text)
    assert not SECRET_LIKE.search(response.text)


def test_fields_outside_the_allowlist_do_not_appear(scan_client, session_factory):
    canary = "PX_LIST_CANARY_91c2"
    _make_scan(
        session_factory,
        status=ScanStatus.FAILED,
        ingest_metadata={"workspace": f"/home/victim/{canary}"},
        error_code="px_error",
        error_message=f"failed at /home/victim/{canary}",
        error_details={"path": f"/srv/{canary}"},
        stages={"sbom": {"error": f"/var/{canary}"}},
    )

    response = scan_client.get(URL)

    assert response.status_code == 200
    assert canary not in response.text
    assert "px_error" not in response.text
    assert not HOST_PATH.search(response.text)
