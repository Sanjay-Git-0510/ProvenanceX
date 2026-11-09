"""The whole pipeline over real HTTP: Postgres, Syft, live OSV and the local Hardhat chain.

Run it with scripts/run_e2e.sh, which starts a disposable database and chain. Local only: CI
deselects the `chain` and `network` markers. Results are wiring checks on benign fixtures, so a
test asserts only what a rule guarantees and never assumes the decision for a clean artifact.
"""

import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

pytestmark = [pytest.mark.chain, pytest.mark.network]

BACKEND = Path(__file__).resolve().parents[2]
REPO = BACKEND.parent
FIXTURES = BACKEND / "tests" / "fixtures" / "e2e"
GATE = REPO / "scripts" / "ci_gate.py"
REQUIRED_ENV = (
    "DATABASE_URL",
    "BLOCKCHAIN_RPC_URL",
    "BLOCKCHAIN_CONTRACT_ADDRESS",
    "BLOCKCHAIN_PRIVATE_KEY",
)
SCAN_TIMEOUT_SECONDS = 240
DECISIONS = {"ALLOW", "REVIEW", "BLOCK"}
TX_HASH = re.compile(r"^0x[0-9a-f]{64}$")

# Written to a temporary file by the test: a global reference and STOP, with no call. Nothing
# in this test loads it, and the scanner only walks its opcodes with pickletools.
INERT_GLOBAL_REFERENCE = b"cos\nsystem\n."


def _load_gate():
    spec = importlib.util.spec_from_file_location("ci_gate_e2e", GATE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _report(case: str, risk: dict) -> None:
    """Record the observed result for the run's summary. Not an assertion."""
    path = os.environ.get("PROVENANCEX_E2E_REPORT")
    if not path:
        return
    row = {
        "case": case,
        "decision": risk.get("decision"),
        "risk_score": risk.get("risk_score"),
        "confidence": risk.get("confidence"),
        "not_evaluated_layers": risk.get("not_evaluated_layers"),
        "hard_rules": [r["rule_id"] for r in risk["hard_rules"]["fired"]],
    }
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row) + "\n")


class Api:
    def __init__(self, base_url: str, workspace: Path) -> None:
        self.base_url = base_url
        self.workspace = workspace
        self.client = httpx.Client(base_url=base_url, timeout=120.0)

    def scan(self, kind: str, root: Path) -> str:
        payload = gate.zip_directory(root, 10 * 1024 * 1024)
        response = self.client.post(
            f"/scans/{kind}",
            data={"name": root.name},
            files={"file": ("artifact.zip", payload, "application/zip")},
        )
        assert response.status_code == 202, response.text
        scan_id = response.json()["scan_id"]
        deadline = time.monotonic() + SCAN_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            body = self.client.get(f"/scans/{scan_id}").json()
            if body["status"] == "completed":
                return scan_id
            assert body["status"] != "failed", body
            time.sleep(1)
        pytest.fail(f"scan {scan_id} did not finish")

    def risk(self, scan_id: str) -> dict:
        response = self.client.get(f"/scans/{scan_id}/risk")
        assert response.status_code == 200, response.text
        return response.json()

    def anchor(self, scan_id: str) -> dict:
        response = self.client.post(f"/scans/{scan_id}/anchor")
        assert response.status_code == 200, response.text
        return response.json()

    def verify(self, scan_id: str) -> dict:
        response = self.client.post(f"/scans/{scan_id}/verify")
        assert response.status_code == 200, response.text
        return response.json()

    def require_live_osv(self, scan_id: str) -> None:
        """An unavailable OSV is reported as "not run", so it can never count as a pass."""
        stages = self.client.get(f"/scans/{scan_id}/evidence").json()["stages"]
        stage = next(item for item in stages if item["name"] == "vulnerabilities")
        if stage["status"] != "completed" or stage["source"] != "osv":
            pytest.skip(f"OSV was unavailable: {stage['status']}")


@pytest.fixture(scope="module")
def api(tmp_path_factory):
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        pytest.skip(f"Use scripts/run_e2e.sh. Not set: {', '.join(missing)}")
    workspace = tmp_path_factory.mktemp("e2e-workspaces")
    port = _free_port()
    env = {**os.environ, "WORKSPACE_ROOT": str(workspace), "BLOCKCHAIN_PROVIDER": "web3"}
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter and arguments
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=BACKEND,
        env=env,
    )
    base_url = f"http://127.0.0.1:{port}/api/v1"
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                if httpx.get(f"{base_url}/health/ready", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            assert process.poll() is None, "the API exited during startup"
            time.sleep(0.5)
        else:
            pytest.fail("the API did not become ready")
        yield Api(base_url, workspace)
    finally:
        process.terminate()
        process.wait(timeout=20)


@pytest.mark.parametrize(
    ("kind", "fixture", "edited_file"),
    [("software", "software_clean", "main.py"), ("model", "model_clean", "config.json")],
)
def test_clean_scan_anchors_verifies_and_detects_tampering(api, kind, fixture, edited_file):
    scan_id = api.scan(kind, FIXTURES / fixture)
    if kind == "software":
        api.require_live_osv(scan_id)

    risk = api.risk(scan_id)
    _report(fixture, risk)
    assert risk["decision"] in DECISIONS
    assert risk["contains_mock_evidence"] is False

    anchor = api.anchor(scan_id)
    assert anchor["status"] == "confirmed"
    assert anchor["source"] == "web3"
    assert anchor["is_mock"] is False
    assert TX_HASH.fullmatch(anchor["tx_hash"])
    assert anchor["chain_id"] == 31337

    verified = api.verify(scan_id)
    assert verified["state"] == "VERIFIED", verified["reason"]
    assert verified["is_mock"] is False
    assert {field["status"] for field in verified["fields"]} <= {"match", "absent"}

    target = api.workspace / scan_id / "src" / edited_file
    original = target.read_bytes()
    target.write_bytes(original + b"\n")
    tampered = api.verify(scan_id)
    assert tampered["state"] == "MISMATCH"
    assert tampered["reason"]["code"] == "evidence_mismatch"
    by_name = {field["field"]: field["status"] for field in tampered["fields"]}
    assert by_name["artifact_hash"] == "mismatch"
    assert by_name["record_hash"] == "mismatch"

    target.write_bytes(original)
    assert api.verify(scan_id)["state"] == "VERIFIED"


@pytest.mark.parametrize(
    ("kind", "fixture", "rule"),
    [
        ("software", "software_risky_config", "install_hook_present"),
        ("model", "model_risky_config", "custom_model_code"),
    ],
)
def test_risky_config_fires_its_rule(api, kind, fixture, rule):
    scan_id = api.scan(kind, FIXTURES / fixture)
    if kind == "software":
        api.require_live_osv(scan_id)
    risk = api.risk(scan_id)
    _report(fixture, risk)
    assert rule in [item["rule_id"] for item in risk["hard_rules"]["fired"]]
    # The rule forces at least REVIEW. A higher score could legitimately make it BLOCK.
    assert risk["decision"] in {"REVIEW", "BLOCK"}


@pytest.fixture
def dangerous_global_model(tmp_path):
    root = tmp_path / "model_dangerous_global"
    shutil.copytree(FIXTURES / "model_clean", root)
    (root / "weights.pkl").write_bytes(INERT_GLOBAL_REFERENCE)
    return root


def test_dangerous_global_blocks(api, dangerous_global_model):
    scan_id = api.scan("model", dangerous_global_model)
    risk = api.risk(scan_id)
    _report("model_dangerous_global", risk)
    assert "dangerous_pickle_globals" in [item["rule_id"] for item in risk["hard_rules"]["fired"]]
    assert risk["decision"] == "BLOCK"


def test_gate_exits_1_on_a_live_block(api, dangerous_global_model, tmp_path):
    summary = tmp_path / "summary.md"
    env = {
        key: value
        for key, value in os.environ.items()
        if key != "BLOCKCHAIN_PRIVATE_KEY" and key != "GITHUB_ACTIONS"
    }
    result = subprocess.run(  # noqa: S603 - fixed interpreter and arguments
        [
            sys.executable,
            str(GATE),
            str(dangerous_global_model),
            "--kind",
            "model",
            "--api-url",
            api.base_url,
            "--poll",
            "1",
            "--timeout",
            str(SCAN_TIMEOUT_SECONDS),
        ],
        env={**env, "GITHUB_STEP_SUMMARY": str(summary)},
        capture_output=True,
        text=True,
        timeout=SCAN_TIMEOUT_SECONDS + 30,
    )
    assert result.returncode == 1, result.stdout
    text = summary.read_text(encoding="utf-8")
    assert "**FAIL** (exit 1)" in text
    assert "| Decision | BLOCK |" in text
    assert "dangerous\\_pickle\\_globals" in text
    assert "Not-evaluated layers" in text
    assert "| Mock evidence | None |" in text
