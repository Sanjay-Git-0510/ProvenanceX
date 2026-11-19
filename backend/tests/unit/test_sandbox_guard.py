"""The worker guard and the in-container self-check."""

import pytest

from app.core.config import Settings
from app.core.errors import AppError
from app.sandbox_worker.selfcheck import is_isolated, isolation_report
from app.security import sandbox_guard
from app.security.sandbox_guard import inprocess_test_context, require_worker_context


def test_worker_code_is_refused_on_the_host():
    with pytest.raises(AppError) as info:
        require_worker_context()
    assert info.value.code == "sandbox_refused"


def test_inprocess_context_allows_it_only_inside_pytest(monkeypatch):
    with inprocess_test_context():
        require_worker_context()
    monkeypatch.delenv("PYTEST_CURRENT_TEST")
    with pytest.raises(AppError), inprocess_test_context():
        pass


def test_context_does_not_leak_after_exit():
    with inprocess_test_context():
        pass
    with pytest.raises(AppError):
        require_worker_context()


def test_worker_env_alone_is_not_enough(monkeypatch, tmp_path):
    """PX_ANALYZER_WORKER=1 outside a container (no /.dockerenv) is refused."""
    monkeypatch.setenv(sandbox_guard.WORKER_ENV, "1")
    monkeypatch.setattr(sandbox_guard, "Path", lambda _p: tmp_path / "no-dockerenv")
    with pytest.raises(AppError):
        require_worker_context()


def test_host_is_not_reported_as_isolated():
    """The self-check must fail on an ordinary host (writable root, real network)."""
    report = isolation_report()
    assert set(report) == {
        "non_root",
        "no_new_privileges",
        "capabilities_dropped",
        "rootfs_read_only",
        "network_isolated",
        "no_docker_socket",
    }
    assert not is_isolated(report)
    assert not is_isolated({})


@pytest.mark.parametrize(
    ("field", "value"),
    [("analyzer_provider", "inprocess_test"), ("scan_dispatch", "inline_test")],
)
def test_test_only_modes_are_refused_outside_app_env_test(field, value):
    with pytest.raises(ValueError, match="APP_ENV=test"):
        Settings(_env_file=None, **{field: value})
    for env in ("development", "production"):
        with pytest.raises(ValueError):
            Settings(_env_file=None, app_env=env, **{field: value})
    Settings(_env_file=None, app_env="test", **{field: value})


def test_there_is_no_disabled_analyzer():
    with pytest.raises(ValueError):
        Settings(_env_file=None, analyzer_provider="disabled")
    assert Settings(_env_file=None).analyzer_provider == "docker"
    assert Settings(_env_file=None).scan_dispatch == "runner"
