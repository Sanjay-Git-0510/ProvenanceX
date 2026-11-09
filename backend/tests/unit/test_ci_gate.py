"""The CI gate script. Responses come from a local fake server or from the real schema."""

import argparse
import importlib.util
import io
import json
import os
import re
import sys
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from app.db.models import ScanStatus
from app.schemas.risk import RiskResponse, RiskStatus, SeparateScores, TrainingDataLabel

REPO = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("ci_gate", REPO / "scripts" / "ci_gate.py")
gate = importlib.util.module_from_spec(_spec)
sys.modules["ci_gate"] = gate
_spec.loader.exec_module(gate)

SCAN_ID = "11111111-2222-4333-8444-555555555555"


def risk(**overrides):
    values = {
        "scan_status": "completed",
        "status": "computed",
        "decision": "ALLOW",
        "risk_score": 0.3,
        "confidence": 0.61,
        "confidence_label": "MEDIUM",
        "not_evaluated_layers": ["behavioral", "vulnerability"],
        "partial_layers": [],
        "hard_rules": {"fired": []},
        "contains_mock_evidence": False,
        "ml": {"status": "available"},
        "training_data": {"notice": "Models were trained on synthetic data."},
    }
    return {**values, **overrides}


def no_score(decision):
    return risk(decision=decision, status="not_computed", risk_score=None)


# ---- policy


@pytest.mark.parametrize(
    ("result", "options", "code"),
    [
        (risk(), {}, 0),
        (risk(risk_score=0), {}, 0),
        (risk(decision="REVIEW"), {}, 0),
        (risk(decision="REVIEW"), {"fail_on_review": True}, 1),
        (risk(fail_on_review=True), {"fail_on_review": True}, 0),
        (risk(decision="BLOCK"), {}, 1),
        (no_score("BLOCK"), {}, 1),
        (no_score("REVIEW"), {}, 2),
        (no_score("REVIEW"), {"fail_on_review": True}, 2),
        (no_score("ALLOW"), {}, 2),
        (risk(risk_score=None), {}, 2),
        (risk(decision="REVIEW", risk_score=None), {}, 2),
        (risk(risk_score=True), {}, 2),
        (risk(risk_score="0.3"), {}, 2),
        (risk(risk_score=1.5), {}, 2),
        (risk(risk_score=-0.1), {}, 2),
        (risk(risk_score=float("nan")), {}, 2),
        (risk(status="pending"), {}, 2),
        (risk(decision=None), {}, 2),
        (risk(decision="allow"), {}, 2),
        (risk(decision="constructor"), {}, 2),
        (risk(decision="SAFE"), {}, 2),
        (risk(scan_status="running"), {}, 2),
        (None, {}, 2),
        ([], {}, 2),
    ],
)
def test_policy(result, options, code):
    assert gate.evaluate("completed", result, **options).exit_code == code


@pytest.mark.parametrize("status", ["failed", "running", "queued", None, 5])
@pytest.mark.parametrize("decision", ["ALLOW", "REVIEW"])
def test_unfinished_scan_never_passes(status, decision):
    assert gate.evaluate(status, risk(decision=decision)).exit_code == 2


@pytest.mark.parametrize("decision", ["ALLOW", "REVIEW", "BLOCK"])
@pytest.mark.parametrize("flag", [True, None, "false", 0])
def test_mock_evidence_exits_2_without_allow_mock(decision, flag):
    verdict = gate.evaluate("completed", risk(decision=decision, contains_mock_evidence=flag))
    assert verdict.exit_code == 2
    assert verdict.label == "INCONCLUSIVE"


def test_missing_mock_flag_counts_as_mock():
    result = risk()
    del result["contains_mock_evidence"]
    assert gate.evaluate("completed", result).exit_code == 2


@pytest.mark.parametrize(("decision", "code"), [("ALLOW", 0), ("REVIEW", 0), ("BLOCK", 1)])
def test_allow_mock_applies_the_normal_policy(decision, code):
    result = risk(decision=decision, contains_mock_evidence=True)
    assert gate.evaluate("completed", result, allow_mock=True).exit_code == code


def test_allow_mock_does_not_excuse_a_null_score():
    result = risk(decision="REVIEW", risk_score=None, contains_mock_evidence=True)
    assert gate.evaluate("completed", result, allow_mock=True).exit_code == 2


# ---- the real response schema


def _real_response(status, decision, score, *, mock=False):
    message = "x"
    empty = {"label": "x", "value": None, "reason": message}
    response = RiskResponse(
        scan_id=uuid4(),
        scan_status=ScanStatus.COMPLETED,
        status=status,
        risk_score=score,
        decision=decision,
        not_evaluated_layers=["behavioral"],
        scores=SeparateScores(
            provenancex_risk=empty, cvss_max=empty, ml_probability=empty, anomaly_score=empty
        ),
        training_data=TrainingDataLabel(label="synthetic", models_used=False, notice="n"),
        contains_mock_evidence=mock,
    )
    return json.loads(response.model_dump_json())


def test_the_gate_reads_fields_the_api_really_has():
    read = {
        "scan_status",
        "status",
        "decision",
        "risk_score",
        "confidence",
        "confidence_label",
        "not_evaluated_layers",
        "partial_layers",
        "hard_rules",
        "contains_mock_evidence",
        "ml",
        "training_data",
        "reason",
    }
    assert read <= set(RiskResponse.model_fields)


@pytest.mark.parametrize(
    ("status", "decision", "score", "mock", "code"),
    [
        (RiskStatus.COMPUTED, "ALLOW", 0.2, False, 0),
        (RiskStatus.COMPUTED, "REVIEW", 0.5, False, 0),
        (RiskStatus.COMPUTED, "BLOCK", 0.9, False, 1),
        (RiskStatus.NOT_COMPUTED, "REVIEW", None, False, 2),
        (RiskStatus.NOT_COMPUTED, "BLOCK", None, False, 1),
        (RiskStatus.COMPUTED, "ALLOW", 0.2, True, 2),
    ],
)
def test_real_schema_output(status, decision, score, mock, code):
    result = _real_response(status, decision, score, mock=mock)
    assert gate.evaluate("completed", result).exit_code == code


def test_real_without_result_has_no_pass():
    scan = SimpleNamespace(id=uuid4(), status=ScanStatus.FAILED)
    result = json.loads(
        RiskResponse.without_result(
            scan, RiskStatus.NOT_COMPUTED, "scan_failed", "m"
        ).model_dump_json()
    )
    assert gate.evaluate("failed", result).exit_code == 2
    assert gate.evaluate("completed", result).exit_code == 2


# ---- URL and input validation


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000/api/v1",
        "http://localhost/api",
        "http://[::1]:8000/x",
        "https://px.example/api/v1/",
    ],
)
def test_accepts(url):
    assert gate.validate_api_url(url) == url.rstrip("/")


@pytest.mark.parametrize(
    "url",
    [
        "http://px.example/api",
        "http://10.0.0.1/api",
        "ftp://localhost/api",
        "file:///etc/passwd",
        "https://user:pass@px.example/api",
        "https://token@px.example/api",
        "https://px.example/api?x=1",
        "https://px.example/api#x",
        "http://[::1/x",
        "",
    ],
)
def test_rejects(url):
    with pytest.raises(gate.GateError) as caught:
        gate.validate_api_url(url)
    assert caught.value.code == "invalid_api_url"


def test_zip_contains_relative_files_and_skips_git(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = 1\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("secret\n")
    with zipfile.ZipFile(io.BytesIO(gate.zip_directory(tmp_path, 1024 * 1024))) as archive:
        assert archive.namelist() == ["src/a.py"]


def test_zip_is_deterministic(tmp_path):
    (tmp_path / "a.txt").write_text("a")
    first = gate.zip_directory(tmp_path, 1024)
    os.utime(tmp_path / "a.txt", (1, 1))
    assert gate.zip_directory(tmp_path, 1024) == first


def _expect(root, code, limit=1024 * 1024):
    with pytest.raises(gate.GateError) as caught:
        gate.zip_directory(root, limit)
    assert caught.value.code == code


def test_zip_refuses_file_symlink(tmp_path):
    (tmp_path / "a").write_text("a")
    (tmp_path / "link").symlink_to(tmp_path / "a")
    _expect(tmp_path, "unsafe_path")


def test_zip_refuses_directory_symlink(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "a").write_text("a")
    (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    _expect(tmp_path, "unsafe_path")


def test_zip_refuses_dangling_symlink(tmp_path):
    (tmp_path / "a").write_text("a")
    (tmp_path / "link").symlink_to(tmp_path / "gone")
    _expect(tmp_path, "unsafe_path")


def test_zip_refuses_fifo(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    _expect(tmp_path, "unsafe_path")


def test_zip_refuses_root_symlink(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    _expect(tmp_path / "link", "invalid_path")


def test_zip_refuses_missing_empty_and_oversize(tmp_path):
    _expect(tmp_path / "nope", "invalid_path")
    _expect(tmp_path, "empty_path")
    (tmp_path / "a").write_bytes(b"x" * 100)
    _expect(tmp_path, "too_large", limit=10)


# ---- output safety


HOSTILE = "::set-output name=x::1\n| x | <img src=x> [a](http://e.example) @octocat"


def test_markdown_escape_breaks_markup():
    text = gate.escape_markdown(HOSTILE)
    assert "\n" not in text
    assert not re.search(r"(?<!\\)[<|@\[]", text)
    assert "http://" not in text


def test_markdown_escape_handles_non_text_and_long_text():
    assert gate.escape_markdown(None) == ""
    assert gate.escape_markdown({"a": 1}) == ""
    assert len(gate.escape_markdown("a" * 5000)) == gate.MAX_NOTICE_CHARS


def test_safe_log_cannot_issue_a_workflow_command(capsys):
    gate.safe_log("a\n::error::bad")
    out = capsys.readouterr().out
    assert "::" not in out
    assert out.count("\n") == 1


def test_summary_shows_required_fields():
    verdict = gate.evaluate("completed", risk())
    text = gate.render_summary(SCAN_ID, verdict, risk())
    assert "behavioral, vulnerability" in text
    assert "0.610 (MEDIUM)" in text
    assert "Not\\-evaluated" not in text
    assert "Not-evaluated layers" in text
    assert "missing evidence, not a clean result" in text
    assert "| Mock evidence | None |" in text


def test_summary_labels_mock():
    result = risk(contains_mock_evidence=True)
    text = gate.render_summary(SCAN_ID, gate.evaluate("completed", result), result)
    assert "MOCK EVIDENCE PRESENT" in text
    assert "source=mock" in text


def test_summary_shows_null_score_in_words_never_zero():
    result = no_score("REVIEW")
    text = gate.render_summary(SCAN_ID, gate.evaluate("completed", result), result)
    assert "| ProvenanceX risk score | Not computed |" in text
    assert "0.000" not in text


def test_summary_states_ml_unavailable():
    result = risk(ml={"status": "unavailable"})
    text = gate.render_summary(SCAN_ID, gate.evaluate("completed", result), result)
    assert "ML model unavailable" in text


def test_summary_marks_missing_not_evaluated_list():
    result = risk()
    del result["not_evaluated_layers"]
    assert "| Not-evaluated layers | Not reported |" in gate.render_summary(
        SCAN_ID, gate.evaluate("completed", result), result
    )


def test_summary_does_not_echo_hostile_api_text():
    result = risk(
        not_evaluated_layers=[HOSTILE],
        hard_rules={"fired": [{"rule_id": HOSTILE}]},
        confidence_label=HOSTILE,
        reason={"code": HOSTILE, "message": HOSTILE},
        decision_reasons=[HOSTILE],
        training_data={"notice": HOSTILE},
    )
    text = gate.render_summary(SCAN_ID, gate.evaluate("completed", result), result)
    assert not re.search(r"(?<!\\)<img", text)
    assert "::set-output" not in text
    assert "unrecognized" in text


# ---- the HTTP flow against a local server


class FakeApi:
    def __init__(self):
        self.statuses = ["queued", "running", "completed"]
        self.risk = risk()
        self.create = (202, {"scan_id": SCAN_ID, "status": "queued"})
        self.requests = []
        self.bodies = []
        self.headers = []
        self.get_override = None

    def start(self):
        api = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def _send(self, code, body, headers=None):
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                api.bodies.append(self.rfile.read(length))
                api.requests.append(("POST", self.path))
                api.headers.append(dict(self.headers))
                self._send(*api.create)

            def do_GET(self):
                api.requests.append(("GET", self.path))
                api.headers.append(dict(self.headers))
                if self.path == "/elsewhere":
                    self._send(200, {"status": "completed"})
                elif api.get_override:
                    self._send(*api.get_override)
                elif self.path.endswith("/risk"):
                    self._send(200, api.risk)
                else:
                    status = api.statuses.pop(0) if len(api.statuses) > 1 else api.statuses[0]
                    self._send(200, {"status": status})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{self.server.server_address[1]}/api/v1"


@pytest.fixture
def api():
    fake = FakeApi()
    url = fake.start()
    fake.url = url
    yield fake
    fake.server.shutdown()
    fake.server.server_close()


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "demo-app"
    root.mkdir()
    (root / "main.py").write_text("print('hello')\n")
    return root


@pytest.fixture
def summary(tmp_path, monkeypatch):
    path = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(path))
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    return path


def run(api, project, *extra):
    return gate.main([str(project), "--api-url", api.url, "--poll", "0", "--timeout", "5", *extra])


def test_flow_submits_polls_and_passes(api, project, summary):
    assert run(api, project) == 0
    assert api.requests[0] == ("POST", "/api/v1/scans/software")
    assert api.requests[-1] == ("GET", f"/api/v1/scans/{SCAN_ID}/risk")
    assert ("GET", f"/api/v1/scans/{SCAN_ID}") in api.requests
    assert b'name="file"; filename="artifact.zip"' in api.bodies[0]
    assert b"demo-app" in api.bodies[0]
    assert "PASS" in summary.read_text()


def test_flow_uses_the_model_endpoint(api, project, summary):
    assert run(api, project, "--kind", "model") == 0
    assert api.requests[0] == ("POST", "/api/v1/scans/model")


@pytest.mark.parametrize(
    ("result", "extra", "code"),
    [
        (risk(decision="BLOCK"), [], 1),
        (risk(decision="REVIEW"), [], 0),
        (risk(decision="REVIEW"), ["--fail-on-review"], 1),
        (no_score("REVIEW"), [], 2),
        (risk(contains_mock_evidence=True), [], 2),
        (risk(contains_mock_evidence=True), ["--allow-mock"], 0),
    ],
)
def test_flow_exit_codes(api, project, summary, result, extra, code):
    api.risk = result
    assert run(api, project, *extra) == code


def test_flow_failed_scan_exits_2(api, project, summary):
    api.statuses = ["failed"]
    api.risk = risk(scan_status="failed", decision=None, risk_score=None, status="not_computed")
    assert run(api, project) == 2
    assert "INCONCLUSIVE" in summary.read_text()


def test_flow_timeout_exits_2(api, project, summary):
    api.statuses = ["running"]
    code = gate.main([str(project), "--api-url", api.url, "--poll", "0.01", "--timeout", "0.05"])
    assert code == 2
    assert "did not finish" in summary.read_text()
    assert SCAN_ID in summary.read_text()


def test_flow_rejected_submission_exits_2(api, project, summary):
    api.create = (413, {"error": {"code": "too_large", "message": "no"}})
    assert run(api, project) == 2


@pytest.mark.parametrize(
    "created", [(202, {}), (202, {"scan_id": "../../x"}), (202, []), (202, b"not json")]
)
def test_flow_bad_create_response_exits_2(api, project, summary, created):
    api.create = created
    assert run(api, project) == 2


def test_flow_unreachable_api_exits_2(project, summary):
    assert gate.main([str(project), "--api-url", "http://127.0.0.1:1/api/v1", "--poll", "0"]) == 2


def test_flow_retries_temporary_errors():
    calls = iter([gate.GateError("api_error", "x", 503), gate.GateError("api_unreachable", "x")])

    class Client:
        def get(self, _):
            for item in calls:
                raise item
            return {"status": "completed"}

    assert gate.wait_for_scan(Client(), SCAN_ID, 5, 0, sleep=lambda _: None) == "completed"


def test_flow_does_not_retry_a_404():
    class Client:
        count = 0

        def get(self, _):
            Client.count += 1
            raise gate.GateError("api_error", "x", 404)

    with pytest.raises(gate.GateError):
        gate.wait_for_scan(Client(), SCAN_ID, 5, 0, sleep=lambda _: None)
    assert Client.count == 1


def test_flow_does_not_follow_redirects(api, project, summary):
    api.get_override = (302, b"", {"Location": "/elsewhere"})
    assert run(api, project) == 2
    assert not [r for r in api.requests if "elsewhere" in r[1]]


def test_flow_refuses_oversized_response(api, project, summary, monkeypatch):
    monkeypatch.setattr(gate, "MAX_RESPONSE_BYTES", 8)
    assert run(api, project) == 2


def test_flow_non_json_risk_exits_2(api, project, summary):
    api.risk = "not an object"
    assert run(api, project) == 2


def test_flow_sends_no_credentials(api, project, summary, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "PX_TOKEN_CANARY")
    assert run(api, project) == 0
    assert "PX_TOKEN_CANARY" not in json.dumps(api.headers)
    assert not any("authorization" in key.lower() for headers in api.headers for key in headers)


def test_error_annotation_uses_fixed_text(api, project, summary, monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    api.risk = risk(decision="BLOCK", hard_rules={"fired": [{"rule_id": HOSTILE}]})
    assert run(api, project) == 1
    out = capsys.readouterr().out
    assert "::error title=ProvenanceX gate::The decision is BLOCK" in out
    assert "set-output" not in out


def test_unexpected_crash_is_not_a_pass(project, summary, monkeypatch):
    def boom(*_):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(gate, "run_gate", boom)
    assert gate.main([str(project)]) == 2
    assert "secret detail" not in summary.read_text()


def test_unwritable_summary_keeps_the_exit_code(api, project, tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "missing" / "summary.md"))
    api.risk = risk(decision="BLOCK")
    assert run(api, project) == 1


def test_unsafe_name_falls_back(api, project, summary):
    assert run(api, project, "--name", 'x"\r\nInjected: 1') == 0
    assert b"Injected" not in api.bodies[0]
    assert b'name="name"\r\n\r\nartifact\r\n' in api.bodies[0]


def test_scan_id_is_normalized(api, project, summary):
    args = argparse.Namespace(
        path=str(project),
        name=None,
        api_url=api.url,
        kind="software",
        max_upload_mb=1,
        timeout=5,
        poll=0,
        fail_on_review=False,
        allow_mock=False,
    )
    scan_id, _, _ = gate.run_gate(args)
    assert UUID(scan_id).version == 4


def test_script_has_no_third_party_imports():
    source = (REPO / "scripts" / "ci_gate.py").read_text()
    imported = {
        line.split()[1].split(".")[0]
        for line in source.splitlines()
        if line.startswith(("import ", "from "))
    }
    assert imported <= set(sys.stdlib_module_names)
