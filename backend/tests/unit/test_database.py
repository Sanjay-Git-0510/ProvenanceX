"""Regression tests for engine construction.

Before the fix, get_engine() always passed the psycopg-only `connect_timeout`, so any
non-PostgreSQL DATABASE_URL failed on every connect with
`TypeError: Connection() got an unexpected keyword argument 'connect_timeout'`.
"""

import pytest
from sqlalchemy import text

from app.core.config import get_settings
from app.db import database
from app.db.database import CONNECT_TIMEOUT_SECONDS, connect_args_for


@pytest.fixture
def fresh_engine_cache():
    """get_settings/get_engine/get_sessionmaker are lru_cached; isolate this test from them."""
    caches = (get_settings, database.get_engine, database.get_sessionmaker)
    for fn in caches:
        fn.cache_clear()
    yield
    engine = database.get_engine()
    engine.dispose()
    for fn in caches:
        fn.cache_clear()


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+psycopg://u:p@localhost:5432/db",
        "postgresql://u:p@localhost/db",
        "postgresql+psycopg2://u:p@localhost/db",
    ],
)
def test_postgres_gets_connect_timeout(url):
    assert connect_args_for(url) == {"connect_timeout": CONNECT_TIMEOUT_SECONDS}


@pytest.mark.parametrize("url", ["sqlite://", "sqlite:///tmp/x.db", "sqlite+pysqlite:///:memory:"])
def test_non_postgres_gets_no_connect_timeout(url):
    assert connect_args_for(url) == {}


def test_get_engine_connects_with_sqlite_url(tmp_path, monkeypatch, fresh_engine_cache):
    """The original live-upload failure: a sqlite DATABASE_URL must connect, not TypeError."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'regression.db'}")
    engine = database.get_engine()
    assert engine.dialect.name == "sqlite"
    with engine.connect() as conn:
        assert conn.execute(text("SELECT 1")).scalar() == 1


def test_get_db_session_works_with_sqlite_url(tmp_path, monkeypatch, fresh_engine_cache):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'regression.db'}")
    gen = database.get_db()
    session = next(gen)
    database.check_database(session)  # raised TypeError before the fix
    gen.close()
