from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.db.database import get_db
from app.main import create_app


class _FakeSession:
    """Minimal stand-in for a Session; `fail=True` simulates an unreachable database."""

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    def execute(self, *_args, **_kwargs):
        if self.fail:
            from sqlalchemy.exc import OperationalError

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
