"""The generated `docker run` command and its required restrictions."""

import re
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
import yaml

from app.core.errors import AppError, ErrorCode
from app.scanners.sandbox.hardening import (
    SandboxLimits,
    SandboxSpec,
    assert_hardened,
    build_docker_argv,
    resolve_artifact_source,
)

LIMITS = SandboxLimits(60, 512, 1.5, 128, 64, 32)
SCAN = UUID("12345678-1234-5678-1234-567812345678")
REPO = Path(__file__).resolve().parents[3]


def spec(**kw) -> SandboxSpec:
    base = {
        "scan_id": SCAN,
        "image": "provenancex-sandbox:0.1.0",
        "src_dir": Path("/data/ws/x/src"),
        "uid": 1000,
        "gid": 1000,
        "kind": "software",
        "limits": LIMITS,
    }
    return SandboxSpec(**{**base, **kw})


def argv(**kw) -> list[str]:
    return build_docker_argv("docker", spec(**kw))


def test_generated_command_passes_the_independent_check():
    assert_hardened(argv())
    assert_hardened(argv(kind="model"))


def test_argv_has_network_none():
    assert "--network=none" in argv()


def test_argv_mount_is_readonly():
    mounts = [a for a in argv() if a.startswith("--mount=")]
    assert mounts == ["--mount=type=bind,src=/data/ws/x/src,dst=/artifact,readonly"]
    assert "--read-only" in argv()


def test_argv_has_user():
    assert "--user=1000:1000" in argv()


@pytest.mark.parametrize(("uid", "gid"), [(0, 1000), (1000, 0), (0, 0)])
def test_uid_zero_refused(uid, gid):
    with pytest.raises(AppError) as exc:
        argv(uid=uid, gid=gid)
    assert exc.value.code == ErrorCode.SANDBOX_REFUSED


def test_argv_has_cap_drop_and_no_new_privileges():
    args = argv()
    assert "--cap-drop=ALL" in args
    assert "--security-opt=no-new-privileges" in args


def test_argv_has_no_new_privileges():
    assert [a for a in argv() if a.startswith("--security-opt")] == [
        "--security-opt=no-new-privileges"
    ]


def test_argv_pids_matches_config():
    assert "--pids-limit=128" in argv()


def test_argv_memory_matches_config():
    assert "--memory=512m" in argv()


def test_memory_swap_equals_memory():
    assert "--memory-swap=512m" in argv()


def test_argv_cpus_matches_config():
    assert "--cpus=1.5" in argv()


def test_additional_hardening():
    args = argv()
    for flag in ("--rm", "--pull=never", "--ipc=none", "--ulimit=core=0"):
        assert flag in args
    assert "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m" in args
    assert "--tmpfs=/trace:rw,noexec,nosuid,nodev,size=32m" in args


def test_only_one_mount_and_no_environment():
    args = argv()
    assert sum(a.startswith("--mount") for a in args) == 1
    assert not any(a.startswith(("-v", "--volume", "-e", "--env")) for a in args)


def test_container_name_is_unique_per_scan():
    assert f"--name=px-sbx-{SCAN}" in argv()


def test_network_is_not_a_setting():
    from app.core.config import Settings

    assert not [name for name in Settings.model_fields if "network" in name and "sandbox" in name]


def test_sandbox_is_disabled_by_default():
    from app.core.config import Settings

    assert Settings(_env_file=None).sandbox_provider == "disabled"


# ------------------------------------------------------------------ mount source
def test_valid_source(tmp_path):
    src = tmp_path / "ws" / "a" / "src"
    src.mkdir(parents=True)
    path, uid, gid = resolve_artifact_source(src, tmp_path / "ws")
    assert path == src.resolve() and uid == src.stat().st_uid and gid == src.stat().st_gid


def test_symlinked_or_outside_source_refused(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "link"
    link.symlink_to(outside)
    for bad in (outside, link, root, root / "missing"):
        with pytest.raises(AppError) as exc:
            resolve_artifact_source(bad, root)
        assert exc.value.code == ErrorCode.SANDBOX_REFUSED


@pytest.mark.parametrize("name", ["a,b", "docker.sock"])
def test_source_with_disallowed_characters_refused(tmp_path, name):
    src = tmp_path / "ws" / name
    src.mkdir(parents=True)
    with pytest.raises(AppError):
        resolve_artifact_source(src, tmp_path / "ws")


def test_root_owned_workspace_is_refused(tmp_path):
    class RootOwned(type(tmp_path)):
        def stat(self, **_kw):
            return SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o700)

    root = tmp_path / "ws"
    (root / "src").mkdir(parents=True)
    with pytest.raises(AppError) as exc:
        resolve_artifact_source(RootOwned(root / "src"), root)
    assert exc.value.code == ErrorCode.SANDBOX_REFUSED and "root" in exc.value.message


# ------------------------------------------------------------------ compose and image
def test_compose_api_has_no_docker_socket():
    compose = yaml.safe_load((REPO / "docker-compose.yml").read_text())
    assert "docker.sock" not in (REPO / "docker-compose.yml").read_text()
    # Exactly two mounts are allowed: the trusted model directory, read-only, and the named
    # workspace volume that verification reads. The volume must stay plain and named.
    assert compose["services"]["api"]["volumes"] == [
        "./ml/models:/app/ml/models:ro",
        "workspace:/app/workspace",
    ]
    assert compose["volumes"]["workspace"] is None
    api = compose["services"]["api"]
    assert not {"tmpfs", "volumes_from", "devices", "privileged", "cap_add"} & set(api)
    assert not [key for key in ("network_mode", "pid", "ipc") if api.get(key) == "host"]


_SOCKET = "/var/run/docker.sock"
_MODELS = "./ml/models:/app/ml/models:ro"
_WORKSPACE = "workspace:/app/workspace"
_API_MOUNT_VIOLATIONS = {
    "socket_added": [_MODELS, _WORKSPACE, f"{_SOCKET}:{_SOCKET}"],
    "socket_added_read_only": [_MODELS, _WORKSPACE, f"{_SOCKET}:{_SOCKET}:ro"],
    "socket_replaces_models": [f"{_SOCKET}:/app/ml/models:ro", _WORKSPACE],
    "socket_replaces_workspace": [_MODELS, f"{_SOCKET}:/app/workspace"],
    "socket_long_form": [
        _MODELS,
        _WORKSPACE,
        {"type": "bind", "source": _SOCKET, "target": _SOCKET},
    ],
    "models_read_write": ["./ml/models:/app/ml/models:rw", _WORKSPACE],
    "models_default_mode_is_writable": ["./ml/models:/app/ml/models", _WORKSPACE],
    "models_long_form_writable": [
        {"type": "bind", "source": "./ml/models", "target": "/app/ml/models"},
        _WORKSPACE,
    ],
    "extra_writable_bind": [_MODELS, _WORKSPACE, "./backend:/app/extra"],
    "extra_writable_named_volume": [_MODELS, _WORKSPACE, "pgdata:/app/extra"],
    "extra_read_only_bind": [_MODELS, _WORKSPACE, "./backend:/app/extra:ro"],
    "extra_mount_only": ["./backend:/app/extra:ro"],
    "models_mounted_twice": [_MODELS, _WORKSPACE, _MODELS],
    "wrong_source": ["./ml:/app/ml/models:ro", _WORKSPACE],
    "wrong_target": ["./ml/models:/app/other:ro", _WORKSPACE],
    "workspace_missing": [_MODELS],
    "workspace_only": [_WORKSPACE],
    "workspace_host_bind": [_MODELS, "./workspace:/app/workspace"],
    "workspace_absolute_host_bind": [_MODELS, "/srv/px:/app/workspace"],
    "workspace_wrong_target": [_MODELS, "workspace:/app/other"],
    "workspace_other_volume": [_MODELS, "pgdata:/app/workspace"],
    "workspace_mounted_twice": [_MODELS, _WORKSPACE, _WORKSPACE],
    "workspace_long_form": [
        _MODELS,
        {"type": "volume", "source": "workspace", "target": "/app/workspace"},
    ],
    "second_named_volume": [_MODELS, _WORKSPACE, "extra:/app/extra"],
}


def _compose_copy(tmp_path, monkeypatch, mutate=None):
    """Point the compose tests at a copy of the real file, changed by `mutate`."""
    compose = yaml.safe_load((REPO / "docker-compose.yml").read_text())
    if mutate is not None:
        mutate(compose)
    (tmp_path / "docker-compose.yml").write_text(yaml.safe_dump(compose))
    monkeypatch.setattr(sys.modules[__name__], "REPO", tmp_path)


def test_only_the_api_mounts_the_workspace_volume():
    services = yaml.safe_load((REPO / "docker-compose.yml").read_text())["services"]
    users = [
        name
        for name, service in services.items()
        if any("workspace:" in str(volume) for volume in service.get("volumes", []))
    ]
    assert users == ["api"]


def test_api_mount_check_rejects_a_workspace_volume_with_a_host_path(tmp_path, monkeypatch):
    def mutate(compose):
        compose["volumes"]["workspace"] = {
            "driver_opts": {"type": "none", "o": "bind", "device": "/srv/px"}
        }

    _compose_copy(tmp_path, monkeypatch, mutate)
    with pytest.raises(AssertionError):
        test_compose_api_has_no_docker_socket()


def test_api_mount_check_accepts_the_real_compose_file(tmp_path, monkeypatch):
    """Control: the violations below fail because of the mutation, not because of the copy."""
    _compose_copy(tmp_path, monkeypatch)
    test_compose_api_has_no_docker_socket()


@pytest.mark.parametrize("volumes", _API_MOUNT_VIOLATIONS.values(), ids=_API_MOUNT_VIOLATIONS)
def test_api_mount_check_rejects_violation(volumes, tmp_path, monkeypatch):
    def mutate(compose):
        compose["services"]["api"]["volumes"] = volumes

    _compose_copy(tmp_path, monkeypatch, mutate)
    with pytest.raises(AssertionError):
        test_compose_api_has_no_docker_socket()


_API_HOST_ACCESS_VIOLATIONS = {
    "tmpfs": ("tmpfs", ["/app/extra"]),
    "volumes_from": ("volumes_from", ["postgres"]),
    "devices": ("devices", ["/dev/sda:/dev/sda"]),
    "privileged": ("privileged", True),
    "cap_add": ("cap_add", ["SYS_ADMIN"]),
    "network_mode_host": ("network_mode", "host"),
    "pid_host": ("pid", "host"),
    "ipc_host": ("ipc", "host"),
}


@pytest.mark.parametrize(
    ("key", "value"), _API_HOST_ACCESS_VIOLATIONS.values(), ids=_API_HOST_ACCESS_VIOLATIONS
)
def test_api_mount_check_rejects_host_access(key, value, tmp_path, monkeypatch):
    def mutate(compose):
        compose["services"]["api"][key] = value

    _compose_copy(tmp_path, monkeypatch, mutate)
    with pytest.raises(AssertionError):
        test_compose_api_has_no_docker_socket()


def test_api_mount_check_rejects_socket_on_another_service(tmp_path, monkeypatch):
    def mutate(compose):
        compose["services"]["postgres"]["volumes"].append(f"{_SOCKET}:{_SOCKET}")

    _compose_copy(tmp_path, monkeypatch, mutate)
    with pytest.raises(AssertionError, match="docker.sock"):
        test_compose_api_has_no_docker_socket()


def test_compose_defaults_to_disabled_and_builds_image_only_on_request():
    compose = yaml.safe_load((REPO / "docker-compose.yml").read_text())
    assert compose["services"]["api"]["environment"]["SANDBOX_PROVIDER"].endswith(":-disabled}")
    assert compose["services"]["sandbox-image"]["profiles"] == ["sandbox-image"]


def test_dockerfile_pins_base_and_strace_and_has_no_secrets():
    text = (REPO / "docker" / "sandbox" / "Dockerfile").read_text()
    assert re.search(r"^FROM python:[\d.]+-slim-bookworm@sha256:[0-9a-f]{64}$", text, re.M)
    assert re.search(r"strace=\d", text)
    assert not re.search(r"(?i)\b(password|secret|token|api_key)\s*=", text)
    assert re.search(r"^USER [1-9]\d*:[1-9]\d*$", text, re.M)
