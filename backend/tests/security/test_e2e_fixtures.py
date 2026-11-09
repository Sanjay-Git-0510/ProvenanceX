"""The end-to-end fixtures stay benign and text only, and the runner cannot leak its key."""

import ast
import re
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[2]
FIXTURES = BACKEND / "tests" / "fixtures" / "e2e"
E2E_TESTS = BACKEND / "tests" / "e2e"
RUNNER = BACKEND.parent / "scripts" / "run_e2e.sh"

MAX_BYTES = 64 * 1024
BINARY_SUFFIXES = frozenset(
    ".pkl .pickle .pt .pth .bin .ckpt .safetensors .h5 .hdf5 .onnx .gguf .npy .npz .joblib .skops "
    ".dill .zip .tar .gz .tgz .bz2 .xz .7z .rar .whl .egg .so .dll .dylib .exe .pyc .pyo".split()
)
BANNED_IMPORTS = frozenset(
    "os subprocess socket ssl urllib http httpx requests aiohttp ftplib smtplib telnetlib ctypes "
    "pickle marshal shelve dill joblib torch importlib multiprocessing pty".split()
)
BANNED_CALLS = frozenset({"exec", "eval", "compile", "__import__"})
EXPECTED = {
    "software_clean",
    "software_risky_config",
    "model_clean",
    "model_risky_config",
    "README.md",
}


def python_problems(path: Path, text: str) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return [f"{path.name}: not valid Python"]
    problems = []
    for node in ast.walk(tree):
        modules = []
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = [node.module or ""]
        problems += [
            f"{path.name}: imports {name}"
            for name in modules
            if name.split(".")[0] in BANNED_IMPORTS
        ]
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in BANNED_CALLS
        ):
            problems.append(f"{path.name}: calls {node.func.id}")
    return problems


def fixture_problems(root: Path) -> list[str]:
    problems = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            problems.append(f"{path.name}: symlink")
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() in BINARY_SUFFIXES:
            problems.append(f"{path.name}: binary or archive type")
        data = path.read_bytes()
        if len(data) > MAX_BYTES:
            problems.append(f"{path.name}: too large")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            problems.append(f"{path.name}: not UTF-8 text")
            continue
        if "\x00" in text:
            problems.append(f"{path.name}: contains NUL bytes")
        if path.suffix == ".py":
            problems += python_problems(path, text)
    return problems


def e2e_source_problems(root: Path) -> list[str]:
    problems = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            problems += [
                f"{path.name}: imports {name}"
                for name in names
                if name.split(".")[0] in {"pickle", "torch", "dill", "joblib"}
            ]
    return problems


KEY_VARIABLE = "HARDHAT_KEY"


def runner_problems(text: str) -> list[str]:
    problems = []
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    if re.search(r"\bset\s+-[a-z]*x|xtrace|bash\s+-x", code):
        problems.append("traces commands")
    for line in code.splitlines():
        if KEY_VARIABLE not in line and "BLOCKCHAIN_PRIVATE_KEY" not in line:
            continue
        if re.search(r"\becho\b|\bprintf\b|\btee\b|<<<|>\s*[^&]|\.env", line):
            problems.append("may print or store the key")
    if "-p provenancex-e2e" not in code and 'PROJECT="provenancex-e2e"' not in code:
        problems.append("does not use the disposable project")
    # The script changes directory, so a relative Compose path breaks its cleanup.
    if "--project-directory ." in code:
        problems.append("uses a relative Compose path")
    if "trap " not in code:
        problems.append("does not clean up")
    return problems


def test_expected_fixtures_exist():
    assert EXPECTED <= {path.name for path in FIXTURES.iterdir()}


def test_fixtures_are_benign_text():
    assert fixture_problems(FIXTURES) == []


def test_e2e_tests_cannot_load_a_pickle():
    assert e2e_source_problems(E2E_TESTS) == []


def test_runner_is_safe():
    assert runner_problems(RUNNER.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("model.pkl", b"text"),
        ("weights.safetensors", b"text"),
        ("bundle.zip", b"text"),
        ("disguised.txt", b"\x80\x04\x95\xff"),
        ("nul.txt", b"a\x00b"),
        ("big.txt", b"a" * (MAX_BYTES + 1)),
        ("a.py", b"import os\n"),
        ("b.py", b"from subprocess import run\n"),
        ("c.py", b"import socket\n"),
        ("d.py", b"import urllib.request\n"),
        ("e.py", b"exec('1')\n"),
        ("f.py", b"def (\n"),
    ],
)
def test_detects_a_bad_fixture(tmp_path, name, data):
    (tmp_path / name).write_bytes(data)
    assert fixture_problems(tmp_path)


def test_detects_a_symlink(tmp_path):
    (tmp_path / "link").symlink_to(tmp_path / "gone")
    assert fixture_problems(tmp_path)


def test_detects_a_pickle_import_in_e2e_code(tmp_path):
    (tmp_path / "test_x.py").write_text("import pickle\n", encoding="utf-8")
    assert e2e_source_problems(tmp_path)


@pytest.mark.parametrize(
    "line",
    [
        "set -x",
        "set -eux",
        'echo "$HARDHAT_KEY"',
        'printf %s "$HARDHAT_KEY"',
        'printf %s "$HARDHAT_KEY" > key.txt',
        "BLOCKCHAIN_PRIVATE_KEY=$HARDHAT_KEY >> .env",
        'cat <<< "$HARDHAT_KEY"',
        "docker compose --project-directory . down",
    ],
)
def test_detects_an_unsafe_runner(line):
    safe = 'PROJECT="provenancex-e2e"\ntrap cleanup EXIT\n'
    assert runner_problems(f"{safe}{line}\n")


def test_detects_a_runner_without_cleanup_or_project():
    assert len(runner_problems("true\n")) == 2
