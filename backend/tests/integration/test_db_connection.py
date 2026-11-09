"""Integration tests against a real PostgreSQL at DATABASE_URL.

Skipped (with an explicit reason) when the database is unreachable, e.g. on a dev
machine without Docker. CI runs them against a Postgres service container.
"""

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

from app.core.config import get_settings

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def engine():
    eng = create_engine(get_settings().database_url, connect_args={"connect_timeout": 3})
    try:
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable at DATABASE_URL: {exc.__class__.__name__}")
    yield eng
    eng.dispose()


def test_select_one(engine):
    with engine.connect() as conn:
        assert conn.execute(text("SELECT 1")).scalar() == 1


def test_is_postgres(engine):
    assert engine.dialect.name == "postgresql"


def test_alembic_upgrade_head(engine):
    from alembic import command
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")
    head = ScriptDirectory.from_config(cfg).get_current_head()
    with engine.connect() as conn:
        version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    assert head == "0006"  # bump when a new migration is added
    assert version == head


def test_phase1_tables_exist_after_upgrade(engine):
    from sqlalchemy import inspect

    tables = set(inspect(engine).get_table_names())
    assert {"artifacts", "scans"} <= tables


def test_phase2_tables_exist_after_upgrade(engine):
    from sqlalchemy import inspect

    insp = inspect(engine)
    assert {"components", "findings", "graph_nodes", "graph_edges"} <= set(insp.get_table_names())
    scan_cols = {c["name"] for c in insp.get_columns("scans")}
    assert {"stages", "bom_sha256"} <= scan_cols


def test_phase3_tables_exist_after_upgrade(engine):
    from sqlalchemy import inspect

    insp = inspect(engine)
    assert "provenance_records" in insp.get_table_names()
    columns = {c["name"] for c in insp.get_columns("provenance_records")}
    assert {"scan_id", "checks", "record_sha256", "source", "hash_changed"} <= columns


def test_readiness_endpoint_with_real_db(engine):
    from fastapi.testclient import TestClient

    from app.main import create_app

    resp = TestClient(create_app()).get("/api/v1/health/ready")
    assert resp.status_code == 200
    assert resp.json()["db"] == "ok"


def _insert_risk(engine, risk_score):
    import uuid

    from sqlalchemy.orm import Session

    from app.db.models import (
        Artifact,
        ArtifactSource,
        ArtifactType,
        RiskDecision,
        RiskVerdict,
        Scan,
    )

    with Session(engine) as session:
        artifact = Artifact(
            artifact_type=ArtifactType.SOFTWARE, name="t", source=ArtifactSource.UPLOAD
        )
        scan = Scan(id=uuid.uuid4(), artifact=artifact, scanner_version="t")
        decision = RiskDecision(
            scan=scan,
            risk_score=risk_score,
            decision=RiskVerdict.REVIEW,
            decision_basis="insufficient_evidence",
            confidence=0.0,
            confidence_label="LOW",
            ml_status="unavailable",
            policy_version="t",
            layer_scores={},
            explanation={},
        )
        session.add_all([artifact, scan, decision])
        session.commit()
        return artifact.id, decision.id


def _delete_artifact(engine, artifact_id):
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM artifacts WHERE id = :id"), {"id": artifact_id})


def test_risk_decision_stores_null_score_as_null(engine):
    from alembic import command
    from alembic.config import Config

    command.upgrade(Config("alembic.ini"), "head")
    artifact_id, decision_id = _insert_risk(engine, None)
    try:
        with engine.connect() as conn:
            stored = conn.execute(
                text("SELECT risk_score FROM risk_decisions WHERE id = :id"), {"id": decision_id}
            ).scalar()
        assert stored is None
    finally:
        _delete_artifact(engine, artifact_id)
    with engine.connect() as conn:
        left = conn.execute(
            text("SELECT count(*) FROM risk_decisions WHERE id = :id"), {"id": decision_id}
        ).scalar()
    assert left == 0  # cascades with the scan


def test_risk_decision_rejects_out_of_range_score(engine):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy.exc import IntegrityError

    command.upgrade(Config("alembic.ini"), "head")
    with pytest.raises(IntegrityError, match="ck_risk_decisions_score_range"):
        _insert_risk(engine, 1.5)


def test_risk_endpoint_on_postgres_returns_null_not_zero(engine, tmp_path):
    from alembic import command
    from alembic.config import Config
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import Session, sessionmaker

    from app.api.scans import get_session_factory
    from app.core.config import Settings
    from app.db.models import Artifact, ArtifactSource, ArtifactType, Scan, ScanStatus
    from app.main import create_app

    command.upgrade(Config("alembic.ini"), "head")
    with Session(engine) as session:
        artifact = Artifact(
            artifact_type=ArtifactType.SOFTWARE, name="t", source=ArtifactSource.UPLOAD
        )
        scan = Scan(artifact=artifact, status=ScanStatus.COMPLETED, scanner_version="t", stages={})
        session.add_all([artifact, scan])
        session.commit()
        artifact_id, scan_id = artifact.id, scan.id
    settings = Settings(_env_file=None, workspace_root=tmp_path, model_path=tmp_path / "no-models")
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_session_factory] = lambda: sessionmaker(bind=engine)
    client = TestClient(app)
    try:
        first = client.get(f"/api/v1/scans/{scan_id}/risk").json()
        second = client.get(f"/api/v1/scans/{scan_id}/risk").json()
    finally:
        _delete_artifact(engine, artifact_id)
    assert first["status"] == "not_computed"
    assert first["risk_score"] is None
    assert first == second


def test_evidence_endpoint_on_postgres(engine, tmp_path):
    from alembic import command
    from alembic.config import Config
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import Session, sessionmaker

    from app.api.scans import get_session_factory
    from app.db.models import (
        Artifact,
        ArtifactSource,
        ArtifactType,
        Finding,
        FindingCategory,
        Scan,
        ScanStatus,
    )
    from app.main import create_app

    command.upgrade(Config("alembic.ini"), "head")
    with Session(engine) as session:
        artifact = Artifact(
            artifact_type=ArtifactType.SOFTWARE, name="t", source=ArtifactSource.UPLOAD
        )
        scan = Scan(artifact=artifact, status=ScanStatus.COMPLETED, scanner_version="t", stages={})
        finding = Finding(
            scan=scan,
            category=FindingCategory.STATIC,
            identifier="PX-1",
            severity="LOW",
            source="provenancex",
        )
        session.add_all([artifact, scan, finding])
        session.commit()
        artifact_id, scan_id = artifact.id, scan.id
    app = create_app()
    app.dependency_overrides[get_session_factory] = lambda: sessionmaker(bind=engine)
    client = TestClient(app)
    try:
        response = client.get(f"/api/v1/scans/{scan_id}/evidence")
    finally:
        _delete_artifact(engine, artifact_id)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["findings"]["by_category"] == {"static": 1}
    assert body["feature_vector"]["reason"]["code"] == "no_risk_decision"


def _insert_anchor_row(engine, score):
    """Store a scan and one row in blockchain_evidence. Returns the three ids."""
    from alembic import command
    from alembic.config import Config
    from sqlalchemy.orm import Session

    from app.db.models import AnchorStatus, BlockchainEvidence, Scan, utcnow
    from tests.conftest import make_anchorable_scan

    command.upgrade(Config("alembic.ini"), "head")
    with Session(engine) as session:
        scan_id = make_anchorable_scan(session)
        artifact_id = session.get(Scan, scan_id).artifact_id
        try:
            row = _anchor_row(BlockchainEvidence, AnchorStatus, utcnow, scan_id, artifact_id, score)
            session.add(row)
            session.commit()
            return artifact_id, row.id, scan_id
        except Exception:
            session.rollback()
            _delete_artifact(engine, artifact_id)
            raise


def _anchor_row(model, status, now, scan_id, artifact_id, score):
    return model(
        scan_id=scan_id,
        artifact_id=artifact_id,
        artifact_hash="a" * 64,
        risk_score_scaled=score,
        decision="REVIEW",
        scanner_version="0.1.0",
        evidence_timestamp=1_790_000_000,
        record_hash="d" * 64,
        status=status.PENDING,
        source="web3",
        reserved_at=now(),
    )


@pytest.mark.parametrize("score", [None, 0])
def test_blockchain_evidence_keeps_null_and_zero_distinct(engine, score):
    artifact_id, row_id, _ = _insert_anchor_row(engine, score)
    try:
        with engine.connect() as conn:
            stored = conn.execute(
                text("SELECT risk_score_scaled FROM blockchain_evidence WHERE id = :id"),
                {"id": row_id},
            ).scalar()
        assert stored == score
    finally:
        _delete_artifact(engine, artifact_id)
    with engine.connect() as conn:
        left = conn.execute(
            text("SELECT count(*) FROM blockchain_evidence WHERE id = :id"), {"id": row_id}
        ).scalar()
    assert left == 0  # cascades with the scan


def test_blockchain_evidence_rejects_out_of_range_score(engine):
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError, match="ck_blockchain_evidence_score_range"):
        _insert_anchor_row(engine, 1_000_001)


def test_blockchain_evidence_allows_one_row_per_scan(engine):
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import Session

    from app.db.models import AnchorStatus, BlockchainEvidence, utcnow

    artifact_id, _, scan_id = _insert_anchor_row(engine, None)
    try:
        with Session(engine) as session:
            session.add(
                _anchor_row(BlockchainEvidence, AnchorStatus, utcnow, scan_id, artifact_id, 1)
            )
            with pytest.raises(IntegrityError, match="ix_blockchain_evidence_scan_id"):
                session.commit()
    finally:
        _delete_artifact(engine, artifact_id)
