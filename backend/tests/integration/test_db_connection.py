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
    assert head == "0002"  # bump when a new migration is added
    assert version == head


def test_phase1_tables_exist_after_upgrade(engine):
    from sqlalchemy import inspect

    tables = set(inspect(engine).get_table_names())
    assert {"artifacts", "scans"} <= tables


def test_readiness_endpoint_with_real_db(engine):
    from fastapi.testclient import TestClient

    from app.main import create_app

    resp = TestClient(create_app()).get("/api/v1/health/ready")
    assert resp.status_code == 200
    assert resp.json()["db"] == "ok"
