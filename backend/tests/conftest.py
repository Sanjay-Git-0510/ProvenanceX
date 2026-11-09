import io
import os
import stat
import zipfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.scans import get_session_factory
from app.core.config import Settings, get_settings
from app.db import models  # noqa: F401  (registers tables on Base.metadata)
from app.db.base import Base
from app.db.database import get_db
from app.db.models import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    ProvenanceRecord,
    RiskDecision,
    Scan,
    ScanStatus,
)
from app.main import create_app

FIXTURES = Path(__file__).parent / "fixtures"
SIMPLE_PROJECT = FIXTURES / "software" / "simple_python_project"
PUBLIC_IP = "140.82.112.3"


# --------------------------------------------------------------------------- pytest hooks
def pytest_configure(config):
    config.addinivalue_line(
        "markers", "network: needs real internet access (set PROVENANCEX_NETWORK_TESTS=1)"
    )
    config.addinivalue_line(
        "markers", "sandbox: runs the real Docker sandbox (set PROVENANCEX_SANDBOX_TESTS=1)"
    )
    config.addinivalue_line(
        "markers", "chain: needs the local Hardhat chain (set PROVENANCEX_CHAIN_TESTS=1)"
    )


def pytest_collection_modifyitems(config, items):
    gates = (
        ("network", "PROVENANCEX_NETWORK_TESTS"),
        ("sandbox", "PROVENANCEX_SANDBOX_TESTS"),
        ("chain", "PROVENANCEX_CHAIN_TESTS"),
    )
    for marker, variable in gates:
        if os.environ.get(variable) == "1":
            continue
        skip = pytest.mark.skip(reason=f"{marker} test: set {variable}=1 to run")
        for item in items:
            if item.get_closest_marker(marker) is not None:
                item.add_marker(skip)


# --------------------------------------------------------------------------- health (Phase 0)
class _FakeSession:
    """Minimal stand-in for a Session; `fail=True` simulates an unreachable database."""

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    def execute(self, *_args, **_kwargs):
        if self.fail:
            raise OperationalError("SELECT 1", {}, Exception("connection refused"))
        return None

    def close(self) -> None:
        pass


def _client_with_session(session: _FakeSession) -> TestClient:
    app = create_app()

    def _override() -> Iterator[_FakeSession]:
        yield session

    app.dependency_overrides[get_db] = _override
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def client() -> TestClient:
    return _client_with_session(_FakeSession())


@pytest.fixture
def client_db_down() -> TestClient:
    return _client_with_session(_FakeSession(fail=True))


# --------------------------------------------------------------------------- scans (Phase 1)
@pytest.fixture
def public_dns(monkeypatch):
    """Resolve every host to a public IP so tests never touch real DNS."""
    monkeypatch.setattr("app.security.url_validation.resolve_host", lambda host: [PUBLIC_IP])


@pytest.fixture
def test_settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        workspace_root=tmp_path / "workspaces",
        max_upload_mb=1,
        max_artifact_size_mb=2,
        max_artifact_files=50,
        max_compression_ratio=100,
        git_clone_timeout_seconds=10,
        # Phase 2: deterministic, offline providers (output is tagged source="mock").
        sbom_provider="mock",
        vuln_provider="mock",
        nvd_enabled=False,
        hf_provider="mock",
    )


@pytest.fixture
def session_factory():
    """In-memory SQLite shared across threads (background tasks run in a threadpool)."""
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def scan_client(test_settings, session_factory, public_dns) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: test_settings
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    return TestClient(app, raise_server_exceptions=False)


# --------------------------------------------------------------------------- ZIP helpers
def build_zip(entries, *, compression=zipfile.ZIP_DEFLATED) -> bytes:
    """Build a ZIP in memory from (name | ZipInfo, bytes | str) pairs."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compression) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def zip_dir(root: Path, *, reverse: bool = False) -> bytes:
    files = sorted(p for p in root.rglob("*") if p.is_file())
    if reverse:
        files.reverse()
    return build_zip([(p.relative_to(root).as_posix(), p.read_bytes()) for p in files])


def special_info(name: str, file_type: int) -> zipfile.ZipInfo:
    """A ZipInfo whose unix mode marks it as a symlink / fifo / device."""
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (file_type | 0o777) << 16
    return info


def symlink_info(name: str) -> zipfile.ZipInfo:
    return special_info(name, stat.S_IFLNK)


# --------------------------------------------------------------------------- blockchain (Phase 7)
def make_anchorable_scan(
    session,
    *,
    status="completed",
    score=0.7,
    decision="REVIEW",
    artifact_sha256="a" * 64,
    bom_sha256="b" * 64,
    provenance_sha256="c" * 64,
    with_decision=True,
    stages=None,
    scanner_version="0.1.0",
):
    """Store a scan with the rows anchoring reads. A None hash leaves that evidence absent."""
    artifact = Artifact(
        artifact_type=ArtifactType.SOFTWARE,
        name="fixture",
        source=ArtifactSource.UPLOAD,
        sha256=artifact_sha256,
    )
    scan = Scan(
        artifact=artifact,
        status=ScanStatus(status),
        scanner_version=scanner_version,
        stages=stages or {},
        bom_sha256=bom_sha256,
    )
    session.add_all([artifact, scan])
    if provenance_sha256 is not None:
        session.add(
            ProvenanceRecord(
                scan=scan,
                source_known=True,
                revision_pinned=False,
                signature_files_present=False,
                provenance_present=False,
                checks=[],
                record_sha256=provenance_sha256,
                source="provenancex",
            )
        )
    if with_decision:
        session.add(
            RiskDecision(
                scan=scan,
                risk_score=score,
                decision=decision,
                decision_basis="test",
                confidence=0.5,
                confidence_label="MEDIUM",
                ml_status="unavailable",
                policy_version="test",
                layer_scores={},
                explanation={},
                created_at=datetime(2026, 11, 9, 12, 0, 30, 750000, tzinfo=UTC),
            )
        )
    session.commit()
    return scan.id
