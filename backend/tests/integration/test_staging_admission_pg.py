"""Staging admission on real PostgreSQL: concurrent runners cannot over-admit the RAM budget.

Needs DATABASE_URL pointing at PostgreSQL (skipped otherwise; SQLite has no advisory locks).
Each "runner" checks the budget and creates its volume under `pg_advisory_lock`, exactly as
DockerStaging.create does; the volume store is shared in memory here so that only the lock is
under test.
"""

import os
import threading
import time

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError

from app.analysis.staging import LOCK_STAGING, advisory_lock, wait_for_capacity
from app.core.errors import AppError, ErrorCode


@pytest.fixture
def engine():
    url = os.environ.get("DATABASE_URL", "")
    if not url.startswith("postgresql"):
        pytest.skip("needs DATABASE_URL pointing at PostgreSQL")
    eng = create_engine(url, pool_size=10)
    try:
        with eng.connect():
            pass
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable at DATABASE_URL: {exc.__class__.__name__}")
    yield eng
    eng.dispose()


def test_concurrent_admission_never_exceeds_the_budget(engine):
    volumes: list[int] = []  # the shared "docker volume ls"
    budget, size = 3, 1
    admitted, refused = [], []

    def runner(i: int) -> None:
        def has_room() -> bool:
            used = len(volumes) * size
            time.sleep(0.05)  # widen the race window between listing and creating
            return used + size <= budget

        def admit() -> None:
            volumes.append(i)

        try:
            wait_for_capacity(
                has_room,
                0,
                AppError(ErrorCode.STAGING_BUDGET_EXCEEDED, "full", 503),
                lock=lambda: advisory_lock(engine, LOCK_STAGING),
                admit=admit,
            )
            admitted.append(i)
        except AppError:
            refused.append(i)

    threads = [threading.Thread(target=runner, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert len(volumes) == budget
    assert len(admitted) == budget and len(refused) == 8 - budget


def test_without_the_lock_the_same_race_over_admits(engine):
    """Control: proves the test above would catch a missing lock."""
    volumes: list[int] = []

    def runner(i: int) -> None:
        used = len(volumes)
        time.sleep(0.05)
        if used + 1 <= 3:
            volumes.append(i)

    threads = [threading.Thread(target=runner, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert len(volumes) > 3
