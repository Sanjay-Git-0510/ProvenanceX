"""Engine and session management."""

from collections.abc import Iterator
from functools import lru_cache
from typing import Any

from sqlalchemy import Engine, create_engine, make_url, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

CONNECT_TIMEOUT_SECONDS = 5


def connect_args_for(database_url: str) -> dict[str, Any]:
    """Driver-specific connect args.

    `connect_timeout` is a libpq/psycopg option and makes other drivers fail (for example,
    sqlite3 raises TypeError on every connect), so it is only passed for PostgreSQL.
    """
    if make_url(database_url).get_backend_name() == "postgresql":
        return {"connect_timeout": CONNECT_TIMEOUT_SECONDS}
    return {}


@lru_cache
def get_engine() -> Engine:
    # pool_pre_ping detects dropped connections; short connect timeout keeps health checks fast.
    url = get_settings().database_url
    return create_engine(url, pool_pre_ping=True, connect_args=connect_args_for(url))


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a session that is always closed."""
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


def check_database(session: Session) -> None:
    """Raise if the database is not reachable."""
    session.execute(text("SELECT 1"))
