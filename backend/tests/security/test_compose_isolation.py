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
    # C3 (audit M6): the CLI is fetched and verified in a build stage, copied into the runner.
    assert set(stages) == {"docker-cli", "base", "runner", "api"}
    cli = stages["docker-cli"]
    assert "download.docker.com" in cli and "sha256sum -c" in cli
    assert "COPY --from=docker-cli /out/docker /usr/local/bin/docker" in stages["runner"]
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
    assert "pip install --require-hashes --no-deps -r" in final  # audit M6
    assert "curl" not in final.replace("curl never", "")
    reqs = (ROOT / "backend" / "requirements-analyzer.txt").read_text(encoding="utf-8")
    pins = [line for line in reqs.splitlines() if line and not line.startswith("#")]
    assert pins and all(re.match(r"^[A-Za-z0-9_.-]+==[\w.]+$", p) for p in pins)
    banned = ("psycopg", "sqlalchemy", "web3", "httpx", "fastapi", "torch", "joblib", "dill")
    assert not any(p.lower().startswith(banned) for p in pins)


# --------------------------------------------------------------------------- Milestone B
_SECRETS = ("DATABASE_URL", "POSTGRES_PASSWORD", "BLOCKCHAIN_PRIVATE_KEY", "NVD_API_KEY")


def _networks(service: dict) -> set[str]:
    nets = service.get("networks")
    if nets is None:
        return {"default"}
    return set(nets) if isinstance(nets, dict) else set(nets)


def test_fetch_network_is_internal_and_named_like_the_runner_expects():
    fetch = COMPOSE["networks"]["fetch"]
    assert fetch["internal"] is True
    assert fetch["name"] == SERVICES["scan-runner"]["environment"]["FETCHER_NETWORK"]
    assert "internal" not in COMPOSE["networks"]["egress"]


def test_egress_proxy_is_isolated_from_internal_services():
    proxy = SERVICES["egress-proxy"]
    assert _networks(proxy) == {"fetch", "egress"}  # never "default" (postgres, api, chain)
    assert proxy["networks"]["fetch"]["aliases"] == ["egress-proxy"]
    for name in ("postgres", "api", "scan-runner", "hardhat", "frontend"):
        assert not _networks(SERVICES[name]) & {"fetch", "egress"}, name
    assert "ports" not in proxy and "volumes" not in proxy
    assert proxy["read_only"] is True and proxy["cap_drop"] == ["ALL"]
    assert proxy["security_opt"] == ["no-new-privileges:true"]
    assert proxy["user"] == "65534:65534"
    assert proxy["mem_limit"] and proxy["pids_limit"]
    env = proxy["environment"]
    assert not any(secret in env for secret in _SECRETS)
    hosts = env["EGRESS_ALLOWED_HOSTS"].split(":-", 1)[-1].rstrip("}").split(",")
    assert "github.com" in hosts and "huggingface.co" in hosts
    assert not any("*" in h for h in hosts)


def test_runner_uses_the_isolated_fetcher_and_has_a_memory_limit():
    runner = SERVICES["scan-runner"]
    env = runner["environment"]
    assert env["FETCHER_PROVIDER"] == "docker"
    assert env["FETCHER_PROXY_URL"] == "http://egress-proxy:3128"
    assert runner["mem_limit"] and runner["memswap_limit"] == runner["mem_limit"]
    assert "egress-proxy" in runner["depends_on"]


def test_fetcher_image_is_pinned_minimal_and_non_root():
    text = (ROOT / "docker" / "fetcher" / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^FROM python:[\d.]+-slim-bookworm@sha256:[0-9a-f]{64}$", text, re.M)
    assert "USER 65534:65534" in text
    assert "PX_FETCH_WORKER=1" in text
    assert "pip install --require-hashes --no-deps -r" in text  # audit M6
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "docker" not in code.replace("Dockerfile", "").lower()
    reqs = (ROOT / "backend" / "requirements-fetcher.txt").read_text(encoding="utf-8")
    pins = [line for line in reqs.splitlines() if line and not line.startswith("#")]
    assert pins and all(re.match(r"^[A-Za-z0-9_.-]+==[\w.]+$", p) for p in pins)
    banned = ("psycopg", "sqlalchemy", "web3", "fastapi", "torch", "pydantic-settings", "dotenv")
    assert not any(p.lower().startswith(banned) for p in pins)


def test_egress_proxy_image_contains_only_the_proxy():
    text = (ROOT / "docker" / "egress-proxy" / "Dockerfile").read_text(encoding="utf-8")
    copies = [line for line in text.splitlines() if line.startswith("COPY")]
    assert copies == [
        "COPY app/__init__.py /opt/px/app/__init__.py",
        "COPY app/egress_proxy /opt/px/app/egress_proxy",
    ]
    assert "pip install" not in text and "USER 65534:65534" in text


def test_egress_proxy_package_uses_only_the_standard_library():
    import ast
    import sys

    for path in (ROOT / "backend" / "app" / "egress_proxy").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import | ast.ImportFrom):
                names = (
                    [a.name for a in node.names]
                    if isinstance(node, ast.Import)
                    else [node.module or ""]
                )
                for name in names:
                    top = name.split(".")[0]
                    assert top in sys.stdlib_module_names or name.startswith("app.egress_proxy"), (
                        f"{path.name} imports {name}"
                    )
