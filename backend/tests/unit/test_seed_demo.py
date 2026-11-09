"""The demo seed script, and safety properties of the demo runner and its Compose override."""

import argparse
import ast
import importlib.util
import pickletools
import re
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[3]
SCRIPTS = REPO / "scripts"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ci_gate = _load("ci_gate")
seed = _load("seed_demo")

CALL_OPCODES = {"REDUCE", "OBJ", "NEWOBJ", "NEWOBJ_EX", "INST", "BUILD"}
SCAN_ID = "11111111-2222-4333-8444-555555555555"


class FakeClient:
    def __init__(self, *, status="completed", decision="REVIEW", anchors=("confirmed",)):
        self.status = status
        self.decision = decision
        self.anchors = list(anchors)
        self.submitted = []

    def submit(self, kind, name, payload):
        self.submitted.append((kind, name, payload))
        return SCAN_ID

    def get(self, path):
        if path.endswith("/risk"):
            return {
                "decision": self.decision,
                "risk_score": 0.5,
                "confidence": 0.6,
                "not_evaluated_layers": ["behavioral"],
            }
        if path.endswith("/blockchain"):
            status = self.anchors.pop(0) if len(self.anchors) > 1 else self.anchors[0]
            return {"record": {"status": status} if status else None}
        return {"status": self.status}


def run(client, *extra):
    return seed.main(["--poll", "0", "--timeout", "1", "--anchor-wait", "0.05", *extra], client)


# ---- what is submitted


def test_only_the_milestone_b_fixtures_are_listed():
    assert seed.COMMITTED_CASES == (
        ("software", "software_clean"),
        ("software", "software_risky_config"),
        ("model", "model_clean"),
        ("model", "model_risky_config"),
    )
    assert all((seed.FIXTURES / name).is_dir() for _, name in seed.COMMITTED_CASES)


def test_no_argument_can_name_another_path():
    options = {action.dest for action in seed.build_parser()._actions}
    assert options == {"help", "api_url", "timeout", "poll", "anchor_wait"}


def test_submits_each_case_once():
    client = FakeClient()
    assert run(client) == 0
    assert [(kind, name) for kind, name, _ in client.submitted] == [
        ("software", "demo-software_clean"),
        ("software", "demo-software_risky_config"),
        ("model", "demo-model_clean"),
        ("model", "demo-model_risky_config"),
        ("model", "demo-model_dangerous_global"),
    ]


# ---- the generated BLOCK case


def test_generated_bytes_hold_a_reference_and_no_call():
    names = [op.name for op, _, _ in pickletools.genops(seed.INERT_GLOBAL_REFERENCE)]
    assert names == ["GLOBAL", "STOP"]
    assert not CALL_OPCODES & set(names)


def test_generated_case_is_written_outside_the_repository(tmp_path):
    root = seed.write_generated_case(tmp_path)
    assert (root / "weights.pkl").read_bytes() == seed.INERT_GLOBAL_REFERENCE
    assert not root.resolve().is_relative_to(REPO)


def test_generated_case_is_removed_afterwards(monkeypatch):
    created = []
    original = seed.write_generated_case

    def spy(parent):
        root = original(parent)
        created.append(root)
        return root

    monkeypatch.setattr(seed, "write_generated_case", spy)
    assert run(FakeClient()) == 0
    assert not created[0].exists()
    assert not created[0].parent.exists()


@pytest.mark.parametrize("script", ["seed_demo.py", "ci_gate.py"])
def test_scripts_cannot_load_a_pickle(script):
    tree = ast.parse((SCRIPTS / script).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert not imported & {"pickle", "torch", "dill", "joblib", "marshal", "shelve"}


def test_generated_binary_is_not_committed_as_a_file():
    assert not list((REPO / "backend" / "tests" / "fixtures" / "e2e").rglob("*.pkl"))
    assert not list(SCRIPTS.rglob("*.pkl"))


# ---- reporting


@pytest.mark.parametrize("decision", ["ALLOW", "REVIEW", "BLOCK"])
def test_reports_whatever_decision_the_api_gave(decision, capsys):
    assert run(FakeClient(decision=decision)) == 0
    out = capsys.readouterr().out
    assert f"decision={decision}" in out
    assert "not detection results" in out


def test_failed_scan_fails_the_seed():
    assert run(FakeClient(status="failed")) == 1


@pytest.mark.parametrize("decision", [None, "SAFE", "allow"])
def test_missing_or_unknown_decision_fails_the_seed(decision, capsys):
    assert run(FakeClient(decision=decision)) == 1
    assert "decision=none" in capsys.readouterr().out


@pytest.mark.parametrize("anchors", [("failed",), (None,), ("pending",)])
def test_unconfirmed_anchor_fails_the_seed(anchors):
    assert run(FakeClient(anchors=anchors)) == 1


def test_waits_for_an_anchor_that_is_still_pending():
    assert run(FakeClient(anchors=(None, "pending", "confirmed"))) == 0


def test_api_failure_fails_the_seed(capsys):
    class Down(FakeClient):
        def submit(self, *_):
            raise ci_gate.GateError("api_unreachable", "The API could not be reached")

    assert run(Down()) == 1
    assert "The API could not be reached" in capsys.readouterr().out


def test_hostile_api_text_is_not_printed(capsys):
    hostile = "::error::x\n<script>"

    class Hostile(FakeClient):
        def get(self, path):
            body = super().get(path)
            if path.endswith("/risk"):
                body["not_evaluated_layers"] = [hostile]
            if path.endswith("/blockchain"):
                body["record"]["status"] = hostile
            return body

    args = argparse.Namespace(timeout=1, poll=0, anchor_wait=0)
    result = seed.seed_case(Hostile(), "software", seed.FIXTURES / "software_clean", "demo-x", args)
    seed.print_results([result])
    out = capsys.readouterr().out
    assert "::error" not in out
    assert "<script>" not in out


# ---- the runner and Compose override


OVERRIDE = REPO / "docker-compose.demo.yml"
DEMO = SCRIPTS / "demo.sh"
PORTS = {"postgres": 15435, "hardhat": 18546, "api": 18080, "frontend": 15173}


class _Override(yaml.SafeLoader):
    pass


_Override.add_constructor("!override", lambda loader, node: loader.construct_sequence(node))


def _code():
    lines = DEMO.read_text(encoding="utf-8").splitlines()
    return [line for line in lines if not line.lstrip().startswith("#")]


def test_override_changes_only_ports_on_loopback():
    services = yaml.load(OVERRIDE.read_text(encoding="utf-8"), Loader=_Override)["services"]  # noqa: S506
    assert set(services) == set(PORTS)
    for name, service in services.items():
        assert set(service) == {"ports"}
        assert service["ports"][0].startswith(f"127.0.0.1:{PORTS[name]}:")


def test_override_replaces_the_base_ports():
    assert OVERRIDE.read_text(encoding="utf-8").count("!override") == len(PORTS)


def test_demo_uses_only_its_own_project_with_absolute_paths():
    code = "\n".join(_code())
    assert 'PROJECT="provenancex-demo"' in code
    assert '-p "$PROJECT"' in code
    assert "--project-directory ." not in code
    calls = re.findall(r"docker compose[^\n]*", code)
    assert len(calls) == 1


@pytest.mark.parametrize("port", PORTS.values())
def test_demo_defines_every_port(port):
    assert f"_PORT={port}" in DEMO.read_text(encoding="utf-8")


def test_demo_refuses_when_any_port_is_busy():
    text = DEMO.read_text(encoding="utf-8")
    loop = re.search(r"for port in ([^;]+); do\n\s+if \(exec 3<>", text)
    assert loop
    for name in ("UI_PORT", "API_PORT", "DB_PORT", "CHAIN_PORT"):
        assert f'"${name}"' in loop.group(1)


def test_demo_refuses_on_a_busy_port_or_no_osv():
    text = DEMO.read_text(encoding="utf-8")
    assert "NOT_RUN=3" in text
    assert "DEMO NOT RUN" in text
    assert "https://api.osv.dev/v1/query" in text
    assert text.index("/dev/tcp") < text.index("compose up")
    assert text.index("api.osv.dev") < text.index("compose up")


def test_demo_cannot_leak_the_key():
    code = _code()
    joined = "\n".join(code)
    assert not re.search(r"\bset\s+-[a-z]*x|xtrace", joined)
    for line in code:
        if "HARDHAT_KEY" in line or "BLOCKCHAIN_PRIVATE_KEY" in line:
            assert not re.search(r"\becho\b|\bprintf\b|\btee\b|<<<|>\s*[^&]|\.env", line)


def test_demo_uses_real_providers():
    code = "\n".join(_code())
    assert "SBOM_PROVIDER=syft" in code
    assert "VULN_PROVIDER=osv" in code
    assert "BLOCKCHAIN_PROVIDER=web3" in code


def test_make_demo_down_targets_only_the_demo_project():
    makefile = (REPO / "Makefile").read_text(encoding="utf-8")
    recipe = makefile.split("demo-down:", 1)[1].split("\n\n", 1)[0]
    assert "-p provenancex-demo" in recipe
    assert "docker-compose.demo.yml" in recipe
    assert "down -v" in recipe


def test_env_example_comment_is_current():
    text = (REPO / ".env.example").read_text(encoding="utf-8")
    assert "not wired in yet" not in text
