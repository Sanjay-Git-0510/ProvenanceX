"""Security properties of the GitHub Actions workflows, read from the YAML itself."""

import re
from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[3] / ".github" / "workflows"
FILES = sorted(WORKFLOWS.glob("*.yml"))
GATE = WORKFLOWS / "provenancex-gate.yml"
PINNED = re.compile(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")


def load(path):
    return yaml.safe_load(path.read_text())


def triggers(document):
    # YAML 1.1 reads the bare key `on` as true.
    return document.get("on", document.get(True))


def steps(document):
    return [step for job in document["jobs"].values() for step in job["steps"]]


def test_both_workflows_are_checked():
    assert {path.name for path in FILES} >= {"ci.yml", "provenancex-gate.yml"}


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_least_privilege(path):
    document = load(path)
    assert document["permissions"] == {"contents": "read"}
    assert all("permissions" not in job for job in document["jobs"].values())


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_secrets_or_privileged_triggers(path):
    text = path.read_text()
    assert "secrets." not in text
    assert "secrets[" not in text
    assert "github.token" not in text
    assert "pull_request_target" not in text
    assert "workflow_run" not in text


def test_gate_pins_every_action_by_sha():
    uses = [step["uses"] for step in steps(load(GATE)) if "uses" in step]
    assert uses
    assert all(PINNED.fullmatch(item) for item in uses)


def test_gate_checkout_keeps_no_credentials():
    checkout = next(step for step in steps(load(GATE)) if "uses" in step)
    assert checkout["with"]["persist-credentials"] is False


def test_gate_runs_on_pull_requests_and_by_hand():
    assert set(triggers(load(GATE))) == {"pull_request", "workflow_dispatch"}


def test_inputs_never_reach_a_shell_directly():
    assert all("${{" not in step.get("run", "") for step in steps(load(GATE)))


def test_gate_does_not_opt_out_of_failure():
    document = load(GATE)
    gate_step = next(step for step in steps(document) if step.get("name") == "Run the gate")
    assert "continue-on-error" not in gate_step
    assert all("continue-on-error" not in job for job in document["jobs"].values())
    assert "|| true" not in gate_step["run"]
    assert "--allow-mock" not in gate_step["run"]


def test_gate_has_a_time_limit_and_always_cleans_up():
    document = load(GATE)
    assert document["jobs"]["gate"]["timeout-minutes"] > 0
    assert any(
        step.get("if") == "always()" and "down -v" in step["run"] for step in steps(document)
    )


def test_ci_keeps_host_only_suites_out():
    pytest_step = next(
        step
        for step in load(WORKFLOWS / "ci.yml")["jobs"]["backend"]["steps"]
        if step.get("name", "").startswith("pytest")
    )
    match = re.search(r'-m "([^"]+)"', pytest_step["run"])
    assert match
    for marker in ("network", "sandbox", "chain"):
        assert f"not {marker}" in match.group(1)


def test_ci_lints_the_gate_script():
    runs = " ".join(
        step.get("run", "") for step in load(WORKFLOWS / "ci.yml")["jobs"]["backend"]["steps"]
    )
    assert runs.count("../scripts") == 2
