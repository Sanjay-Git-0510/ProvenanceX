"""Audit findings L2 (strict self-check reports) and L3 (complete docker-inspect verification)."""

import pytest
from pydantic import ValidationError

from app.analysis.docker_analyzer import DockerAnalyzer
from app.analysis.runtime_checks import common_hardening_problems
from app.core.errors import AppError
from app.fetch_worker.protocol import FetchResult
from app.sandbox_worker.protocol import WorkerResult
from app.sandbox_worker.selfcheck import (
    ANALYZER_CHECKS,
    FETCHER_CHECKS,
    failed_checks,
    fetcher_isolation_report,
    is_isolated,
    isolation_report,
)
from tests.analyzer_helpers import ISOLATED, FakeDocker, analyzer_settings, make_job, worker_output

ALL_TRUE = dict.fromkeys(ANALYZER_CHECKS, True)


# --------------------------------------------------------------------------- L2
def test_exact_report_passes():
    assert is_isolated(ALL_TRUE, ANALYZER_CHECKS)
    assert ISOLATED == ALL_TRUE  # the canned test result is the real key set


@pytest.mark.parametrize(
    "report",
    [
        {},
        None,
        [],
        "all good",
        {k: v for k, v in ALL_TRUE.items() if k != "seccomp_filtered"},  # missing key
        {**ALL_TRUE, "extra_check": True},  # unexpected key
        {**ALL_TRUE, "non_root": "true"},  # truthy string
        {**ALL_TRUE, "non_root": 1},  # truthy int
        {**ALL_TRUE, "non_root": False},
        {**ALL_TRUE, "network_isolated": None},
    ],
)
def test_incomplete_or_malformed_reports_fail_closed(report):
    assert not is_isolated(report, ANALYZER_CHECKS)
    assert failed_checks(report, ANALYZER_CHECKS)


def test_fetcher_report_needs_its_own_keys():
    assert not is_isolated(ALL_TRUE, FETCHER_CHECKS)
    assert is_isolated(dict.fromkeys(FETCHER_CHECKS, True), FETCHER_CHECKS)
    assert "unexpected:network_isolated" in failed_checks(ALL_TRUE, FETCHER_CHECKS)


def test_reports_produced_here_have_exactly_the_expected_keys():
    # On the host the values are mostly False; the key sets must still be exact.
    assert set(isolation_report()) == ANALYZER_CHECKS
    assert set(fetcher_isolation_report()) == FETCHER_CHECKS


def test_result_schemas_refuse_non_boolean_isolation_values():
    base = {
        "format": "provenancex-analyzer-result-v1",
        "mode": "extract",
        "status": "ok",
        "isolation_mode": "container",
    }
    with pytest.raises(ValidationError):
        WorkerResult.model_validate({**base, "isolation": {"non_root": "true"}})
    with pytest.raises(ValidationError):
        WorkerResult.model_validate({**base, "isolation": {"non_root": 1}})
    with pytest.raises(ValidationError):
        FetchResult.model_validate(
            {
                "format": "provenancex-fetch-result-v1",
                "status": "error",
                "isolation_mode": "container",
                "isolation": {"non_root": "yes"},
                "source": "github",
                "error": {"code": "x", "message": "m"},
            }
        )


@pytest.mark.parametrize(
    "isolation",
    [
        {k: v for k, v in ISOLATED.items() if k != "no_secret_env"},
        {**ISOLATED, "made_up": True},
        {},
    ],
)
def test_docker_analyzer_refuses_incomplete_self_checks(tmp_path, monkeypatch, isolation):
    fake = FakeDocker(tmp_path, monkeypatch)
    out = worker_output(tmp_path / "out", "extract", isolation=isolation)
    fake.configure(start="ok", output_file=str(out))
    settings = analyzer_settings(tmp_path, fake.path)
    with pytest.raises(AppError) as info:
        DockerAnalyzer(settings).run(make_job(settings), "extract")
    assert info.value.code == "sandbox_refused"


# --------------------------------------------------------------------------- L3
@pytest.mark.parametrize(
    ("tamper", "problem"),
    [
        ("seccomp", "seccomp"),
        ("apparmor", "AppArmor"),
        ("masked", "masked"),
        ("readonly_paths", "read-only"),
        ("runtime", "runtime"),
        ("missing_runtime", "Runtime could not be verified"),
        ("ulimits", "ulimits"),
        ("oomkill", "OOM killer"),
        ("sysctls", "Sysctls"),
        ("shm", "/dev/shm"),  # noqa: S108
        ("cgroupns", "cgroup namespace"),
        ("devices_req", "devices"),
        ("entrypoint", "entrypoint"),
    ],
)
def test_l3_drift_is_refused_before_start(tmp_path, monkeypatch, tamper, problem):
    fake = FakeDocker(tmp_path, monkeypatch)
    fake.configure(
        start="ok", tamper=[tamper], output_file=str(worker_output(tmp_path / "o", "extract"))
    )
    settings = analyzer_settings(tmp_path, fake.path)
    with pytest.raises(AppError) as info:
        DockerAnalyzer(settings).run(make_job(settings), "extract")
    assert info.value.code == "sandbox_refused"
    assert any(problem in p for p in info.value.details["failed"]), info.value.details
    assert "start" not in fake.verbs()  # never started
    assert fake.calls()[-1][0] == "rm"  # always cleaned up


def _inspect(**host) -> dict:
    base = {
        "Runtime": "runc",
        "OomKillDisable": False,
        "ShmSize": 64 * 1024 * 1024,
        "MaskedPaths": [
            "/proc/kcore",
            "/proc/keys",
            "/proc/timer_list",
            "/proc/sched_debug",
            "/proc/acpi",
            "/proc/scsi",
            "/sys/firmware",
        ],
        "ReadonlyPaths": ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"],
        "Ulimits": [{"Name": "core", "Hard": 0, "Soft": 0}],
        "CgroupnsMode": "private",
        "SecurityOpt": ["no-new-privileges"],
        "Privileged": False,
        "OomScoreAdj": 0,
    }
    base.update(host)
    return {"HostConfig": base, "Config": {}}


def test_reference_values_pass():
    assert common_hardening_problems(_inspect()) == []


@pytest.mark.parametrize(
    "key",
    [
        "Runtime",
        "OomKillDisable",
        "ShmSize",
        "MaskedPaths",
        "ReadonlyPaths",
        "Ulimits",
        "CgroupnsMode",
        "SecurityOpt",
        "Privileged",
    ],
)
def test_unverifiable_properties_fail_closed(key):
    info = _inspect()
    del info["HostConfig"][key]
    assert any("could not be verified" in p for p in common_hardening_problems(info))


@pytest.mark.parametrize(
    "host",
    [
        {"SecurityOpt": ["no-new-privileges", "seccomp=/custom/profile.json"]},
        {"SecurityOpt": ["no-new-privileges", "label=disable"]},
        {"SecurityOpt": ["no-new-privileges", "systempaths=unconfined"]},
        {"OomScoreAdj": -1000},
        {"PortBindings": {"80/tcp": [{"HostPort": "80"}]}},
        {"ExtraHosts": ["db:10.0.0.5"]},
        {"Init": True},
        {"ShmSize": True},
        {"GroupAdd": ["999"]},
        {"Dns": ["10.0.0.53"]},
        {"MaskedPaths": "all"},
    ],
)
def test_other_weakenings_are_refused(host):
    assert common_hardening_problems(_inspect(**host))


def test_inspect_without_host_config_fails_closed():
    assert common_hardening_problems({}) == ["inspect output has no HostConfig/Config"]
