"""Behavior findings, built from synthetic fixtures in tests/fixtures/sandbox."""

from uuid import uuid4

import pytest

from app.db.models import FindingCategory
from app.scanners.sandbox.behavior_findings import behavior_finding, build_behavior_signals
from app.scanners.sandbox.telemetry import SpikeThresholds, TraceLimits, parse_trace_bundle
from tests.conftest import FIXTURES

LIMITS = TraceLimits(max_bytes=1024 * 1024, max_lines=1000)
SPIKE = SpikeThresholds(0.9, 0.9, 0.9, 3)


def signals(name):
    raw = (FIXTURES / "sandbox" / name).read_bytes()
    return build_behavior_signals(parse_trace_bundle(raw, LIMITS, SPIKE))


def test_benign_run_has_no_signals():
    assert signals("benign_run.trace.json") == []


def test_external_connections():
    [s] = signals("network_beacon.trace.json")
    assert s.kind == "external_connection_attempt" and s.severity == "HIGH"
    assert s.identifier == "PX-BEHAV-EXTERNAL-CONNECT" and s.evidence["total"] == 3
    assert "3 public" in s.title


def test_credential_probe_signals():
    by_kind = {s.kind: s for s in signals("credential_probe.trace.json")}
    assert set(by_kind) == {"sensitive_file_access", "shell_spawn"}
    assert by_kind["sensitive_file_access"].severity == "HIGH"
    assert by_kind["shell_spawn"].severity == "MEDIUM"
    assert by_kind["shell_spawn"].evidence == {"tools": {"sh": 1}}


def test_resource_spike_signal():
    [s] = signals("resource_spike.trace.json")
    assert s.kind == "resource_spike" and s.severity == "LOW"
    assert "timed out" in s.title and s.evidence["peak_pids"] == 97


@pytest.mark.parametrize("source", ["sandbox", "mock"])
def test_finding_is_behavioral_with_no_cvss(source):
    [s] = signals("network_beacon.trace.json")
    scan_id = uuid4()
    f = behavior_finding(scan_id, source, s, synthetic=True)
    assert f.category == FindingCategory.BEHAVIORAL and f.scan_id == scan_id
    assert f.source == source and f.severity_source == "provenancex_rule"
    assert f.cvss_score is None and f.cvss_vector is None and f.cvss_version is None
    assert f.details["kind"] == "external_connection_attempt"
    assert f.details["synthetic"] is True


def test_synthetic_defaults_to_false():
    [s] = signals("network_beacon.trace.json")
    assert behavior_finding(uuid4(), "sandbox", s).details["synthetic"] is False
