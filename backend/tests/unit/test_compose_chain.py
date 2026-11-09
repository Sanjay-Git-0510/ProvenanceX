"""The local chain stays local and hardened, and no key is written into the repository."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
CONTRACTS = ROOT / "contracts"
PRIVATE_KEY = re.compile(r"\b0x[0-9a-fA-F]{64}\b")
LOCKFILE = "package-lock.json"
GENERATED_DIRS = {"node_modules", "artifacts", "cache"}


def _services() -> dict:
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))["services"]


def _source_files() -> list[Path]:
    paths = [ROOT / "docker-compose.yml", ROOT / ".env.example"]
    for path in CONTRACTS.rglob("*"):
        relative = path.relative_to(CONTRACTS)
        if path.is_file() and path.name != LOCKFILE and not GENERATED_DIRS & set(relative.parts):
            paths.append(path)
    return paths


def _is_hardened(service: dict) -> bool:
    return (
        service.get("read_only") is True
        and service.get("cap_drop") == ["ALL"]
        and service.get("security_opt") == ["no-new-privileges:true"]
        and "volumes" not in service
        and "privileged" not in service
        and "cap_add" not in service
    )


@pytest.mark.parametrize("name", ["hardhat", "hardhat-deploy"])
def test_chain_services_are_hardened(name):
    assert _is_hardened(_services()[name])


@pytest.mark.parametrize(
    "change",
    [
        {"read_only": False},
        {"cap_drop": []},
        {"security_opt": []},
        {"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]},
        {"privileged": True},
        {"cap_add": ["NET_ADMIN"]},
    ],
)
def test_hardening_check_rejects_weakened_service(change):
    assert not _is_hardened({**_services()["hardhat"], **change})


def test_chain_port_is_bound_to_loopback_only():
    assert _services()["hardhat"]["ports"] == ["127.0.0.1:${BLOCKCHAIN_HOST_PORT:-8545}:8545"]


def test_chain_image_runs_as_non_root():
    dockerfile = (CONTRACTS / "Dockerfile").read_text(encoding="utf-8")
    assert re.findall(r"^USER\s+(\S+)", dockerfile, re.M)[-1] == "node"


def test_chain_image_excludes_env_files():
    assert ".env" in (CONTRACTS / ".dockerignore").read_text(encoding="utf-8").splitlines()


def test_chain_node_receives_no_key():
    assert "environment" not in _services()["hardhat"]


def test_deploy_key_comes_only_from_the_environment():
    deploy = _services()["hardhat-deploy"]
    assert deploy["environment"]["BLOCKCHAIN_PRIVATE_KEY"] == "${BLOCKCHAIN_PRIVATE_KEY:-}"
    assert deploy["profiles"] == ["chain-deploy"]


def test_deploy_targets_the_compose_chain():
    assert _services()["hardhat-deploy"]["environment"]["BLOCKCHAIN_RPC_URL"] == (
        "http://hardhat:8545"
    )


def test_api_can_start_without_the_chain():
    assert "hardhat" not in _services()["api"].get("depends_on", {})


def test_env_example_has_no_key_value():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert re.search(r"^BLOCKCHAIN_PRIVATE_KEY=$", text, re.M)


def test_source_scan_sees_the_contract_files():
    names = {path.name for path in _source_files()}
    assert {"ProvenanceEvidence.sol", "hardhat.config.js", "deploy.js"} <= names


def test_no_private_key_is_committed_with_the_chain_files():
    offenders = [
        str(path.relative_to(ROOT))
        for path in _source_files()
        if PRIVATE_KEY.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []


def test_key_pattern_detects_a_key():
    assert PRIVATE_KEY.search(f"key = 0x{'ab' * 32}")
