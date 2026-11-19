"""Deployment boundaries: only scan-runner gets the Docker socket, the API gets no Docker at all,
and the analyzer image is pinned and non-root."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
SERVICES = COMPOSE["services"]


def _volumes(service: dict) -> list[str]:
    return [str(v) for v in service.get("volumes", [])]


def test_only_the_scan_runner_mounts_the_docker_socket():
    with_socket = {n for n, s in SERVICES.items() if any("docker.sock" in v for v in _volumes(s))}
    assert with_socket == {"scan-runner"}


def test_api_has_no_docker_and_only_queues():
    api = SERVICES["api"]
    assert api["build"]["target"] == "api"
    assert "group_add" not in api
    assert api["environment"]["SCAN_DISPATCH"] == "runner"
    assert api["environment"]["ANALYZER_PROVIDER"] == "docker"


def test_scan_runner_is_locked_down():
    runner = SERVICES["scan-runner"]
    assert "ports" not in runner and "expose" not in runner
    assert runner["build"]["target"] == "runner"
    assert runner["read_only"] is True
    assert runner["cap_drop"] == ["ALL"]
    assert runner["security_opt"] == ["no-new-privileges:true"]
    assert runner["command"] == ["python", "-m", "app.runner"]
    assert runner["environment"]["ANALYZER_WORKSPACE_MOUNT"] == "volume"
    assert "workspace:/app/workspace" in _volumes(runner)


def test_workspace_volume_name_matches_what_analyzers_mount():
    name = COMPOSE["volumes"]["workspace"]["name"]
    assert name == SERVICES["scan-runner"]["environment"]["ANALYZER_WORKSPACE_VOLUME"]


def _stages(dockerfile: str) -> dict[str, str]:
    """Stage name -> its instructions (comments removed)."""
    code = "\n".join(line for line in dockerfile.splitlines() if not line.lstrip().startswith("#"))
    parts = re.split(r"^FROM ", code, flags=re.M)[1:]
    out = {}
    for part in parts:
        header = part.splitlines()[0]
        name = header.split(" AS ")[-1].strip() if " AS " in header else header.strip()
        out[name] = part
    return out


def test_docker_cli_exists_only_in_the_runner_stage():
    stages = _stages((ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8"))
    assert set(stages) == {"base", "runner", "api"}
    assert "download.docker.com" in stages["runner"] and "sha256sum -c" in stages["runner"]
    for stage in ("base", "api"):
        assert "download.docker.com" not in stages[stage]
        assert "/usr/local/bin/docker" not in stages[stage]
    assert stages["api"].startswith("base AS api")
    assert list(stages)[-1] == "api", "the default build target must stay the API"


def test_analyzer_image_is_pinned_minimal_and_non_root():
    text = (ROOT / "docker" / "analyzer" / "Dockerfile").read_text(encoding="utf-8")
    final = text.split("# --- Stage 2")[1]
    assert re.search(r"^FROM python:[\d.]+-slim-bookworm@sha256:[0-9a-f]{64}$", final, re.M)
    assert "USER 65534:65534" in final
    assert "PX_ANALYZER_WORKER=1" in final
    assert "pip install --no-deps -r" in final
    assert "curl" not in final.replace("curl never", "")
    reqs = (ROOT / "backend" / "requirements-analyzer.txt").read_text(encoding="utf-8")
    pins = [line for line in reqs.splitlines() if line and not line.startswith("#")]
    assert pins and all(re.match(r"^[A-Za-z0-9_.-]+==[\w.]+$", p) for p in pins)
    banned = ("psycopg", "sqlalchemy", "web3", "httpx", "fastapi", "torch", "joblib", "dill")
    assert not any(p.lower().startswith(banned) for p in pins)
