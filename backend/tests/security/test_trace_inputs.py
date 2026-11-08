# ruff: noqa: S108, E501 - strace lines and /tmp paths here are test data
"""Telemetry parser against hostile bundles. All traces are synthetic and built here."""

import json
import time

import pytest

from app.core.errors import AppError, ErrorCode
from app.scanners.sandbox.behavior_findings import build_behavior_signals
from app.scanners.sandbox.telemetry import (
    MAX_LINE_CHARS,
    MAX_LISTED,
    SpikeThresholds,
    TraceLimits,
    parse_trace_bundle,
)

LIMITS = TraceLimits(max_bytes=4 * 1024 * 1024, max_lines=5000)
SPIKE = SpikeThresholds(0.9, 0.9, 0.9, 3)
RUN_LIMITS = {"memory_bytes": 1000, "pids": 100, "cpus": 1.0}


def bundle(lines=(), samples=(), **meta) -> bytes:
    return json.dumps(
        {
            "format": "provenancex-trace-v1",
            "meta": {"timed_out": False, "limits": RUN_LIMITS, **meta},
            "strace_lines": list(lines),
            "resource_samples": list(samples),
        }
    ).encode()


def parse(lines=(), samples=(), **meta):
    return parse_trace_bundle(bundle(lines, samples, **meta), LIMITS, SPIKE)


# ------------------------------------------------------------------ bad envelopes
@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{not json",
        b"\xff\xfe\x00binary",
        b"[" * 200_000,
        b'{"a":' * 100_000,
        b"[]",
        b"7",
        b"null",
        b'{"format": "other"}',
        b'{"format": "provenancex-trace-v1"}',
        b'{"format": "provenancex-trace-v1", "meta": 1, "strace_lines": [], "resource_samples": []}',
        b'{"format": "provenancex-trace-v1", "meta": {}, "strace_lines": "x", "resource_samples": []}',
        b'{"format": "provenancex-trace-v1", "meta": {}, "strace_lines": [], "resource_samples": 1}',
        b'{"format": "provenancex-trace-v1", "meta": {}, "strace_lines": [], "resource_samples": []}',
        b'{"format": "provenancex-trace-v1", "meta": {"timed_out": "no"}, "strace_lines": [], '
        b'"resource_samples": []}',
    ],
)
def test_bad_envelopes_are_structured_errors(raw):
    with pytest.raises(AppError) as exc:
        parse_trace_bundle(raw, LIMITS, SPIKE)
    assert exc.value.code == ErrorCode.SANDBOX_TRACE_ERROR


def test_oversized_bundle_is_refused_before_parsing(monkeypatch):
    def no_parse(*_a, **_k):
        raise AssertionError("an oversized trace must not be parsed")

    monkeypatch.setattr("app.scanners.sandbox.telemetry.json.loads", no_parse)
    with pytest.raises(AppError) as exc:
        parse_trace_bundle(b"x" * 101, TraceLimits(100, 10), SPIKE)
    assert exc.value.code == ErrorCode.SANDBOX_TRACE_ERROR


# ------------------------------------------------------------------ malformed content
@pytest.mark.parametrize(
    "line",
    [
        "garbage",
        "connect(",
        "connect(3",
        "connect(3, {sa_family=AF_INET",
        ") = 0",
        "= 0",
        "\x00\x01\x02",
        "\ud800",
        "a" * 50_000,
        "x" * 33 + "() = 0",
    ],
)
def test_malformed_lines_are_counted_not_fatal(line):
    assert parse([line]).features["malformed_line_count"] == 1


@pytest.mark.parametrize("item", [7, None, ["x"], {"a": 1}, True])
def test_non_string_lines(item):
    assert parse([item]).features["malformed_line_count"] == 1


@pytest.mark.parametrize(
    "bad",
    [
        7,
        None,
        [],
        {},
        {"t": "x", "memory_bytes": 1, "pids": 1, "cpu_usec": 1},
        {"t": True, "memory_bytes": 1, "pids": 1, "cpu_usec": 1},
        {"t": -1, "memory_bytes": 1, "pids": 1, "cpu_usec": 1},
        {"t": 1, "memory_bytes": float("inf"), "pids": 1, "cpu_usec": 1},
        {"t": 1, "memory_bytes": float("nan"), "pids": 1, "cpu_usec": 1},
    ],
)
def test_malformed_samples_are_counted_and_cannot_fake_a_peak(bad):
    f = parse(["x() = 0"], [bad]).features
    assert f["malformed_sample_count"] == 1 and f["peak_memory_bytes"] is None


@pytest.mark.parametrize(
    "line",
    [
        'connect(3, {sa_family=AF_INET, sin_port=htons(99999), sin_addr=inet_addr("1.1.1.1")}, 16) = 0',
        'connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("999.1.1.1")}, 16) = 0',
        'connect(3, {sa_family=AF_INET6, sin6_port=htons(80), inet_pton(AF_INET6, ":::::", &a)}, 28) = 0',
    ],
)
def test_impossible_addresses_are_malformed(line):
    f = parse([line]).features
    assert f["malformed_line_count"] == 1 and f["network_count"] == 0


@pytest.mark.parametrize("limits", [{"memory_bytes": "x", "pids": -1, "cpus": 0}, 7, None])
def test_invalid_limits_cannot_produce_a_verdict(limits):
    r = parse(["x() = 0"], [{"t": 0, "memory_bytes": 1, "pids": 1, "cpu_usec": 1}], limits=limits)
    assert r.features["resource_spike"] is None


# ------------------------------------------------------------------ forged strings
FAKE_ADDR = '{sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\\"8.8.8.8\\")}'


@pytest.mark.parametrize(
    "line",
    [
        f'write(1, "{FAKE_ADDR}", 60) = 60',
        f'openat(AT_FDCWD, "/tmp/{FAKE_ADDR}", O_RDONLY) = 3',
        f'sendto(3, "{FAKE_ADDR}", 60, 0, NULL, 0) = 60',
        f'connect(3, {{sa_family=AF_UNIX, sun_path="{FAKE_ADDR}"}}, 110) = 0',
    ],
)
def test_string_contents_cannot_create_network_events(line):
    f = parse([line]).features
    assert f["network_count"] == 0 and f["external_destination_count"] == 0


def test_string_contents_cannot_create_writes():
    f = parse(['read(3, ", O_WRONLY|O_CREAT, 0644) = 3", 30) = 30']).features
    assert f["file_write_count"] == 0


def test_string_contents_cannot_change_the_result():
    line = 'write(1, "x) = -1 EPERM", 13) = 13'
    assert parse([line]).features["malformed_line_count"] == 0


def test_comma_in_path_keeps_argument_positions():
    r = parse(['openat(AT_FDCWD, "/tmp/a, O_RDONLY", O_WRONLY|O_CREAT, 0644) = 3'])
    assert r.features["file_write_count"] == 1 and r.write_samples == ["/tmp/a, O_RDONLY"]


# ------------------------------------------------------------------ bounds
def test_line_cap_reports_truncation():
    r = parse_trace_bundle(bundle(["x() = 0"] * 20), TraceLimits(10**6, 5), SPIKE)
    assert r.truncated is True and r.features["syscall_count"] == 5
    assert any("exceeded 5 lines" in lim for lim in r.limitations)


def test_listed_evidence_is_bounded():
    lines = [
        f'connect(3, {{sa_family=AF_INET, sin_port=htons({p}), sin_addr=inet_addr("1.1.1.1")}}, 16) = 0'
        for p in range(1, 200)
    ]
    lines += [f'openat(AT_FDCWD, "/root/{i}", O_RDONLY) = 3' for i in range(200)]
    lines += [f'unlink("/tmp/{i}") = 0' for i in range(200)]
    r = parse(lines)
    assert r.features["external_destination_count"] == 199  # the feature counts everything
    assert r.features["sensitive_file_access_count"] == 200
    assert r.features["file_write_count"] == 200
    assert len(r.destinations) == MAX_LISTED and len(r.write_samples) == MAX_LISTED
    assert len(r.sensitive_paths) == MAX_LISTED


def test_unbounded_pending_calls_are_capped():
    lines = [f"{i} read(3, <unfinished ...>" for i in range(4500)]
    f = parse(lines).features
    assert f["malformed_line_count"] == 4500 - 4096 and f["syscall_count"] == 4096


def test_evidence_is_safe_to_store_in_postgres():
    r = parse(['openat(AT_FDCWD, "/root/a\x00b\ud800c' + "x" * 500 + '", O_WRONLY) = 3'])
    for text in [*r.sensitive_paths, *r.write_samples]:
        assert text.isprintable() and len(text) <= 256
    for signal in build_behavior_signals(r):
        json.dumps(signal.evidence)


# ------------------------------------------------------------------ performance
@pytest.mark.parametrize(
    "line",
    [
        "connect(" + "{" * MAX_LINE_CHARS,
        'write(1, "' + "\\" * MAX_LINE_CHARS,
        "x(" + ") = " * 2000,
        "1 " * 4000,
        "<... x resumed>" + ")" * MAX_LINE_CHARS,
        "connect(3, {sa_family=AF_INET6, sin6_port=htons(80)," + " " * MAX_LINE_CHARS,
    ],
)
def test_pathological_lines_stay_fast(line):
    begin = time.monotonic()
    parse_trace_bundle(bundle([line] * 1000), TraceLimits(64 * 1024 * 1024, 5000), SPIKE)
    assert time.monotonic() - begin < 10
