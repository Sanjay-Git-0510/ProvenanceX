"""Staging volumes (L1), the fetcher's docker-create allowlist and DockerFetcher (H1), with a fake
Docker CLI. The real-Docker versions of these checks are in tests/integration/test_fetcher_live.py.
"""

import json
import uuid

import pytest

from app.analysis.staging import DockerStaging, mount_option_string, volume_name
from app.core.errors import AppError
from app.fetch.base import FetchJob
from app.fetch.docker_fetcher import DockerFetcher
from app.fetch.hardening import (
    FetcherLimits,
    FetcherSpec,
    assert_fetch_hardened,
    build_fetch_argv,
    verify_network,
)
from app.pipeline.workspace import create_workspace
from tests.analyzer_helpers import FETCHER_ISOLATED, FakeDocker, analyzer_settings, fetch_output

SCAN = uuid.UUID("12345678-1234-1234-1234-123456789abc")
NETWORK = "provenancex_fetch"


@pytest.fixture
def fake(tmp_path, monkeypatch):
    return FakeDocker(tmp_path, monkeypatch)


def _runner(fake):
    import subprocess

    def run(args):
        done = subprocess.run(  # noqa: S603 - the test fixture CLI
            [str(fake.path), *args], capture_output=True, check=False
        )
        return done.returncode, done.stdout

    return run


# --------------------------------------------------------------------------- staging
def _staging(tmp_path, fake, **overrides) -> DockerStaging:
    settings = analyzer_settings(tmp_path, fake.path, **overrides)
    return DockerStaging(settings, docker=_runner(fake), sleep=lambda _s: None)


def test_staging_volume_is_a_size_capped_tmpfs_owned_by_the_scan_user(tmp_path, fake):
    staging = _staging(tmp_path, fake, staging_mb=256, staging_total_mb=1024)
    volume = staging.create(SCAN, "tok", 1000, 1000)
    assert volume.name == volume_name(SCAN)
    create = next(c for c in fake.calls() if c[:2] == ["volume", "create"])
    assert ["--opt", "type=tmpfs"] == create[4:6] or "type=tmpfs" in create
    assert f"o={mount_option_string(256, 1000, 1000)}" in create
    assert "o=size=256m,uid=1000,gid=1000,mode=0700,nosuid,nodev,noexec" in create
    # A leftover with the same name is removed first: create would silently reuse it.
    verbs = [c[:2] for c in fake.calls()]
    assert verbs.index(["volume", "rm"]) < verbs.index(["volume", "create"])
    assert ["volume", "inspect", volume.name] in fake.calls()


@pytest.mark.parametrize("tamper", ["type", "size", "labels"])
def test_a_volume_that_is_not_as_requested_is_refused_and_removed(tmp_path, fake, tamper):
    fake.configure(volume_tamper=[tamper])
    staging = _staging(tmp_path, fake)
    with pytest.raises(AppError) as info:
        staging.create(SCAN, "tok", 1000, 1000)
    assert info.value.code == "sandbox_refused"
    assert fake.calls()[-1] == ["volume", "rm", "--force", volume_name(SCAN)]


def test_root_owned_staging_is_refused(tmp_path, fake):
    with pytest.raises(AppError):
        _staging(tmp_path, fake).create(SCAN, "tok", 0, 0)


def test_aggregate_budget_waits_then_fails_without_creating(tmp_path, fake):
    """Two 512 MB volumes already exist; a third does not fit in 1024 MB."""
    lines = [
        "\t".join(
            [
                volume_name(uuid.uuid4()),
                "staging",
                "provenancex_workspace",
                str(uuid.uuid4()),
                "tok",
                "512",
            ]
        )
        for _ in range(2)
    ]
    fake.configure(volume_ls=lines)
    staging = _staging(
        tmp_path, fake, staging_mb=512, staging_total_mb=1024, staging_wait_seconds=0
    )
    with pytest.raises(AppError) as info:
        staging.create(SCAN, "tok", 1000, 1000)
    assert info.value.code == "staging_budget_exceeded"
    assert not any(c[:2] == ["volume", "create"] for c in fake.calls())


def test_unreadable_size_labels_count_as_full_volumes(tmp_path, fake):
    fake.configure(
        volume_ls=[
            "\t".join(
                [
                    volume_name(uuid.uuid4()),
                    "staging",
                    "provenancex_workspace",
                    str(uuid.uuid4()),
                    "t",
                    "??",
                ]
            )
        ]
    )
    staging = _staging(tmp_path, fake, staging_mb=512, staging_total_mb=1024)
    assert staging.used_mb() == 512


def test_other_deployments_volumes_do_not_count(tmp_path, fake):
    fake.configure(
        volume_ls=[
            "\t".join(
                [volume_name(uuid.uuid4()), "staging", "other_ws", str(uuid.uuid4()), "t", "512"]
            )
        ]
    )
    assert _staging(tmp_path, fake).used_mb() == 0


def test_remove_refuses_names_that_are_not_staging_volumes(tmp_path, fake):
    staging = _staging(tmp_path, fake)
    assert staging.remove("provenancex_workspace") is False
    assert not any(c[:2] == ["volume", "rm"] for c in fake.calls())


# --------------------------------------------------------------------------- fetcher argv
LIMITS = FetcherLimits(timeout_seconds=150, memory_mb=1024, cpus=1.0, pids=64, tmp_mb=64)


def _spec(**changes) -> FetcherSpec:
    values = {
        "scan_id": SCAN,
        "image": "provenancex-fetcher:0.1.0",
        "network": NETWORK,
        "staging_volume": volume_name(SCAN),
        "uid": 1000,
        "gid": 1000,
        "limits": LIMITS,
        "instance": "provenancex_workspace",
    }
    values.update(changes)
    return FetcherSpec(**values)


def _refused(argv, network=NETWORK):
    with pytest.raises(AppError) as info:
        assert_fetch_hardened(argv, network)
    assert info.value.code == "sandbox_refused"


def test_built_fetch_command_passes():
    argv = build_fetch_argv("docker", _spec())
    assert_fetch_hardened(argv, NETWORK)
    assert f"--network={NETWORK}" in argv
    assert not any(a.startswith("--env") or "docker.sock" in a for a in argv)
    assert argv[-6:] == ["--deadline", "150", "--cpu-seconds", "180", "--mode", "fetch"]


@pytest.mark.parametrize(
    "flag",
    [
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=64",
        "--memory=1024m",
        "--pull=never",
        "--ipc=none",
        "--log-driver=none",
        "--ulimit=core=0",
    ],
)
def test_each_fetcher_restriction_is_required(flag):
    argv = build_fetch_argv("docker", _spec())
    argv.remove(flag)
    _refused(argv)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (f"--network={NETWORK}", "--network=bridge"),
        (f"--network={NETWORK}", "--network=host"),
        (f"--network={NETWORK}", "--network=none"),
        (f"--network={NETWORK}", "--network=provenancex_default"),
        (f"--network={NETWORK}", "--network=container:px-api"),
        ("--user=1000:1000", "--user=0:0"),
        ("--memory-swap=1024m", "--memory-swap=4096m"),
        (
            f"--mount=type=volume,src=px-stg-{SCAN},dst=/out/src,volume-nocopy",
            "--mount=type=volume,src=px-stg-87654321-1234-1234-1234-123456789abc,dst=/out/src,"
            "volume-nocopy",
        ),
        (
            f"--mount=type=volume,src=px-stg-{SCAN},dst=/out/src,volume-nocopy",
            "--mount=type=bind,src=/var/run/docker.sock,dst=/out/src",
        ),
        (
            f"--mount=type=volume,src=px-stg-{SCAN},dst=/out/src,volume-nocopy",
            "--mount=type=volume,src=provenancex_workspace,dst=/out/src",
        ),
    ],
)
def test_wrong_fetcher_values_are_refused(old, new):
    argv = [new if a == old else a for a in build_fetch_argv("docker", _spec())]
    _refused(argv)


@pytest.mark.parametrize(
    "extra",
    [
        "--env=NVD_API_KEY=x",
        "--env-file=/app/.env",
        "--privileged",
        "--cap-add=NET_ADMIN",
        "--volume=/var/run/docker.sock:/var/run/docker.sock",
        "--dns=10.0.0.53",
        "--add-host=db:10.0.0.5",
        "--publish=8080:80",
        "--network-alias=egress-proxy",
    ],
)
def test_extra_fetcher_flags_are_refused(extra):
    argv = build_fetch_argv("docker", _spec())
    argv.insert(2, extra)
    _refused(argv)


def test_non_internal_fetch_network_is_refused():
    with pytest.raises(AppError):
        verify_network([{"Name": NETWORK, "Driver": "bridge", "Internal": False}], NETWORK)
    verify_network([{"Name": NETWORK, "Driver": "bridge", "Internal": True}], NETWORK)


# --------------------------------------------------------------------------- DockerFetcher
def _fetch(tmp_path, fake, *, source="github", **overrides):
    values = {
        "git_clone_timeout_seconds": 5,
        "fetcher_setup_seconds": 1,
        "fetcher_host_grace_seconds": 2,
        "fetcher_wait_seconds": 0,
    }
    values.update(overrides)
    settings = analyzer_settings(tmp_path, fake.path, **values)
    workspace = create_workspace(settings.workspace_root, SCAN)
    job = FetchJob(
        scan_id=SCAN,
        workspace=workspace,
        source=source,
        url="https://github.com/acme/widget"
        if source == "github"
        else "https://huggingface.co/acme/tiny",
        revision=None,
        staging_volume=volume_name(SCAN),
        uid=1000,
        gid=1000,
    )
    return DockerFetcher(settings, sleep=lambda _s: None).run(job)


def _fetch_error(tmp_path, fake, **kw) -> AppError:
    with pytest.raises(AppError) as info:
        _fetch(tmp_path, fake, **kw)
    return info.value


def test_fetch_happy_path_verifies_runs_and_removes(tmp_path, fake, monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "nvd-secret")
    monkeypatch.setenv("BLOCKCHAIN_PRIVATE_KEY", "0xsecret")
    fake.configure(start="ok", output_file=str(fetch_output(tmp_path / "out")))
    run = _fetch(tmp_path, fake)
    assert run.result.commit_sha == "c" * 40
    assert run.record["runtime_verified"] is True
    assert run.record["runtime"]["network_internal"] is True
    assert run.record["isolation"] == FETCHER_ISOLATED
    request = (fake.state / "stdin.json").read_text()
    assert "nvd-secret" not in request and "0xsecret" not in request
    assert json.loads(request)["proxy_url"] == "http://egress-proxy:3128"
    create = next(c for c in fake.calls() if c[0] == "create")
    assert not any(a.startswith("--env") for a in create)
    assert fake.calls()[-1] == ["rm", "-f", f"px-fetch-{SCAN}"]


def test_a_non_internal_network_is_refused_before_anything_is_created(tmp_path, fake):
    fake.configure(network_internal=False)
    assert _fetch_error(tmp_path, fake).code == "sandbox_refused"
    assert "create" not in fake.verbs()


def test_missing_fetcher_image_is_unavailable(tmp_path, fake):
    fake.configure(image_exit=1)
    err = _fetch_error(tmp_path, fake)
    assert err.code == "sandbox_unavailable" and "fetcher image" in err.message


def test_concurrency_cap_waits_then_fails_without_creating(tmp_path, fake):
    fake.configure(ps_quiet=["c1", "c2"])
    err = _fetch_error(tmp_path, fake, fetcher_max_concurrent=2)
    assert err.code == "staging_budget_exceeded"
    assert "create" not in fake.verbs()


@pytest.mark.parametrize(
    ("tamper", "problem"),
    [
        ("network", "fetch network"),
        ("extra_network", "unexpected network"),
        ("proxy_env", "proxy environment"),
        ("secret_env", "secret-like"),
        ("seccomp", "seccomp"),
        ("socket", "Docker socket"),
        ("user", "user differs"),
        ("entrypoint", "entrypoint"),
    ],
)
def test_fetcher_runtime_drift_is_refused_before_start(tmp_path, fake, tamper, problem):
    fake.configure(tamper=[tamper], start="ok", output_file=str(fetch_output(tmp_path / "o")))
    err = _fetch_error(tmp_path, fake)
    assert err.code == "sandbox_refused"
    assert any(problem in p for p in err.details["failed"]), err.details
    assert "start" not in fake.verbs()


def test_hung_download_is_stopped_at_the_host_deadline(tmp_path, fake):
    fake.configure(start="sleep")
    err = _fetch_error(
        tmp_path,
        fake,
        git_clone_timeout_seconds=1,
        fetcher_setup_seconds=1,
        fetcher_host_grace_seconds=1,
    )
    assert err.code == "fetch_timeout"
    assert ["kill", f"px-fetch-{SCAN}"] in fake.calls()
    assert fake.calls()[-1][0] == "rm"


def test_in_container_deadline_exit_is_a_timeout(tmp_path, fake):
    fake.configure(start="ok", exit_code=124, output_file=str(fetch_output(tmp_path / "o")))
    assert _fetch_error(tmp_path, fake).code == "fetch_timeout"


@pytest.mark.parametrize(
    "isolation",
    [
        {**FETCHER_ISOLATED, "direct_egress_blocked": False},
        {**FETCHER_ISOLATED, "external_dns_blocked": False},
        {k: v for k, v in FETCHER_ISOLATED.items() if k != "single_interface"},
    ],
)
def test_fetcher_that_could_reach_the_internet_directly_is_refused(tmp_path, fake, isolation):
    fake.configure(start="ok", output_file=str(fetch_output(tmp_path / "o", isolation=isolation)))
    assert _fetch_error(tmp_path, fake).code == "sandbox_refused"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"raw": b"not json"},
        {"raw": b'{"format": "provenancex-fetch-result-v1"}'},
        {"raw": b"plain", "frame": False},
        {"source": "huggingface"},  # answer for the wrong source
        {"commit_sha": "not-a-sha"},
        {"unexpected": True},
    ],
)
def test_malformed_fetcher_output_is_refused(tmp_path, fake, kwargs):
    fake.configure(start="ok", output_file=str(fetch_output(tmp_path / "o", **kwargs)))
    assert _fetch_error(tmp_path, fake).code == "fetch_output_invalid"


def test_fetcher_error_result_fails_with_its_code(tmp_path, fake):
    out = fetch_output(
        tmp_path / "o",
        status="error",
        error={"code": "egress_denied", "message": "CONNECT refused", "details": None},
    )
    fake.configure(start="ok", output_file=str(out))
    run = _fetch(tmp_path, fake)  # recorded by the pipeline first, then raised
    assert run.result.status == "error"
    from app.fetch.base import raise_if_fetch_error

    with pytest.raises(AppError) as info:
        raise_if_fetch_error(run.result)
    assert info.value.code == "egress_denied"


def test_oversized_fetcher_output_is_refused(tmp_path, fake):
    fake.configure(start="huge")
    assert _fetch_error(tmp_path, fake).code == "fetch_output_invalid"
