"""Supply-chain rules for every image (Milestone C3, audit findings M6, I1, L9). Static checks of
the Dockerfiles, lock files and Compose file; the image builds themselves are checked by the
CI job that builds them and by tests/integration (PROVENANCEX_SANDBOX_TESTS=1)."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
BACKEND = ROOT / "backend"
DOCKERFILES = [
    BACKEND / "Dockerfile",
    ROOT / "docker" / "analyzer" / "Dockerfile",
    ROOT / "docker" / "fetcher" / "Dockerfile",
    ROOT / "docker" / "egress-proxy" / "Dockerfile",
    ROOT / "docker" / "sandbox" / "Dockerfile",
    ROOT / "frontend" / "Dockerfile",
    ROOT / "contracts" / "Dockerfile",
]
LOCKS = [
    "requirements.lock",
    "requirements-ml.lock",
    "requirements-analyzer.lock",
    "requirements-fetcher.lock",
]
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?==([^\s;\\]+)")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _instructions(path: Path) -> list[str]:
    """Dockerfile instructions with line continuations joined and comments removed."""
    out, current = [], ""
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        current += " " + line.rstrip("\\").strip()
        if not line.endswith("\\"):
            out.append(current.strip())
            current = ""
    return out


def _stages(path: Path) -> dict[str, list[str]]:
    """Instructions per stage name (unnamed stages get their index)."""
    stages: dict[str, list[str]] = {}
    name = None
    for index, ins in enumerate(_instructions(path)):
        if ins.upper().startswith("FROM "):
            parts = ins.split()
            name = parts[3] if len(parts) >= 4 and parts[2].upper() == "AS" else str(index)
            stages[name] = [ins]
        elif name is not None:
            stages[name].append(ins)
    return stages


def _lock(name: str) -> dict[str, str]:
    """{package: version} of a lock file; every entry must carry at least one hash."""
    text = (BACKEND / name).read_text()
    entries: dict[str, str] = {}
    for block in re.split(r"\n(?=\S)", text):
        first = block.splitlines()[0].strip() if block.strip() else ""
        if not first or first.startswith("#"):
            continue
        m = REQ.match(first)
        assert m, f"{name}: not an exact pin: {first!r}"
        assert "--hash=sha256:" in block, f"{name}: {first} has no hash"
        entries[_norm(m.group(1))] = m.group(2)
    return entries


def _pins(name: str) -> dict[str, str]:
    pins = {}
    for line in (BACKEND / name).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-r")):
            continue
        m = REQ.match(line)
        assert m, f"{name}: not an exact pin: {line!r} (audit M6: no ranges)"
        pins[_norm(m.group(1))] = m.group(2)
    return pins


# --------------------------------------------------------------------------- bases
@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_every_base_image_is_pinned_by_digest(dockerfile):
    args = {}
    for ins in _instructions(dockerfile):
        if ins.upper().startswith("ARG ") and "=" in ins:
            key, _, value = ins[4:].partition("=")
            args[key.strip()] = value.strip()
    stage_names = set(_stages(dockerfile))
    for ins in _instructions(dockerfile):
        if not ins.upper().startswith("FROM "):
            continue
        image = ins.split()[1]
        image = re.sub(r"\$\{(\w+)\}", lambda m: args.get(m.group(1), ""), image)
        if image in stage_names:
            continue
        assert DIGEST.search(image), f"{dockerfile}: {image} is not digest-pinned"


def test_compose_pulls_only_digest_pinned_third_party_images():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    for name, service in compose["services"].items():
        image = service.get("image", "")
        if image and not image.startswith(("provenancex-", "${")):
            assert DIGEST.search(image), f"service {name}: {image} is not digest-pinned"


# --------------------------------------------------------------------------- python packages
@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_every_pip_install_requires_hashes(dockerfile):
    for ins in _instructions(dockerfile):
        for command in re.findall(r"pip install[^&;]*", ins):
            assert "--require-hashes" in command and "--no-deps" in command, (
                f"{dockerfile}: {command!r} must use --require-hashes --no-deps"
            )


@pytest.mark.parametrize("lock", LOCKS)
def test_lock_files_are_exact_and_hashed(lock):
    assert _lock(lock)


def test_direct_dependencies_are_exact_and_locked_at_the_same_version():
    runtime = {**_lock("requirements.lock"), **_lock("requirements-ml.lock")}
    for source in ("requirements.txt", "requirements-ml.txt"):
        for name, version in _pins(source).items():
            assert runtime.get(name) == version, (
                f"{source}: {name} is locked at {runtime.get(name)}"
            )


def test_ml_lock_agrees_with_the_runtime_lock():
    runtime, ml = _lock("requirements.lock"), _lock("requirements-ml.lock")
    for name in runtime.keys() & ml.keys():
        assert runtime[name] == ml[name], f"{name}: two different versions"


@pytest.mark.parametrize("image", ["analyzer", "fetcher"])
def test_sandbox_locks_match_their_exact_pins(image):
    assert _lock(f"requirements-{image}.lock") == _pins(f"requirements-{image}.txt")


def test_images_install_only_lock_files():
    for dockerfile in DOCKERFILES:
        for ins in _instructions(dockerfile):
            for target in re.findall(r"-r\s+(\S+)", ins):
                assert target.endswith(".lock") or target == "/tmp/req.txt", (  # noqa: S108 - a Dockerfile path
                    dockerfile,
                    target,
                )


# --------------------------------------------------------------------------- backend image
def test_final_backend_stages_have_no_downloader_or_build_tools():
    stages = _stages(BACKEND / "Dockerfile")
    assert {"docker-cli", "base", "runner", "api"} <= stages.keys()
    for name in ("base", "runner", "api"):
        text = " ".join(stages[name])
        for tool in ("curl", "wget", "apt-get", "gcc", "build-essential", "gnupg", "syft"):
            assert tool not in text, f"stage {name} uses {tool}"
    assert any("COPY --from=docker-cli /out/docker" in ins for ins in stages["runner"])
    assert not any("--from=docker-cli" in ins for ins in stages["api"])


def test_docker_cli_is_verified_against_a_pinned_key_and_hash():
    text = " ".join(_stages(BACKEND / "Dockerfile")["docker-cli"])
    assert re.search(r"DOCKER_GPG_FINGERPRINT=[0-9A-F]{40}\b", text)
    assert re.search(r"DOCKER_CLI_DEB_SHA256_AMD64=[0-9a-f]{64}\b", text)
    assert re.search(r"DOCKER_CLI_DEB_SHA256_ARM64=[0-9a-f]{64}\b", text)
    assert "signed-by=/etc/apt/keyrings/docker.gpg" in text
    assert "--show-keys --with-colons" in text and "sha256sum -c" in text
    assert "https://download.docker.com/linux/debian" in text


# --------------------------------------------------------------------------- I1, L9
@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_setuid_and_setgid_bits_are_stripped_and_checked(dockerfile):
    text = " ".join(_instructions(dockerfile))
    assert "-perm /6000 -type f -exec chmod a-s" in text, f"{dockerfile}: no setuid strip"
    assert "! find / -xdev -perm /6000 -type f | grep -q ." in text


def test_shared_resource_names_default_to_the_compose_project():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    expected = {
        ("volumes", "workspace"): "${ANALYZER_WORKSPACE_VOLUME:-${COMPOSE_PROJECT_NAME}_workspace}",
        ("networks", "fetch"): "${FETCHER_NETWORK:-${COMPOSE_PROJECT_NAME}_fetch}",
        ("networks", "egress"): "${EGRESS_NETWORK:-${COMPOSE_PROJECT_NAME}_egress}",
    }
    for (section, key), name in expected.items():
        assert compose[section][key]["name"] == name
    runner = compose["services"]["scan-runner"]["environment"]
    assert runner["ANALYZER_WORKSPACE_VOLUME"] == expected[("volumes", "workspace")]
