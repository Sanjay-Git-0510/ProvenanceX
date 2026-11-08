# ruff: noqa: S108, E501 - strace lines and /tmp paths here are test data
"""Telemetry parser. All traces are synthetic, built here or in tests/fixtures/sandbox."""

import json

import pytest

from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.scanners.sandbox.telemetry import (
    SpikeThresholds,
    TraceLimits,
    parse_trace_bundle,
    split_args,
    storable,
)
from tests.conftest import FIXTURES

LIMITS = TraceLimits(max_bytes=1024 * 1024, max_lines=1000)
SPIKE = SpikeThresholds(0.9, 0.9, 0.9, 3)
RUN_LIMITS = {"memory_bytes": 1000, "pids": 100, "cpus": 1.0}
SANDBOX = FIXTURES / "sandbox"


def bundle(lines=(), samples=(), **meta) -> bytes:
    return json.dumps(
        {
            "format": "provenancex-trace-v1",
            "synthetic": True,
            "meta": {"exit_code": 0, "timed_out": False, "limits": RUN_LIMITS, **meta},
            "strace_lines": list(lines),
            "resource_samples": list(samples),
        }
    ).encode()


def parse(lines=(), samples=(), **meta):
    return parse_trace_bundle(bundle(lines, samples, **meta), LIMITS, SPIKE)


def fixture(name):
    return parse_trace_bundle((SANDBOX / name).read_bytes(), LIMITS, SPIKE)


def sample(t, memory=10, pids=1, cpu=0):
    return {"t": t, "memory_bytes": memory, "pids": pids, "cpu_usec": cpu}


V4 = 'sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")'


# ------------------------------------------------------------------ fixtures
@pytest.mark.parametrize("path", sorted(SANDBOX.glob("*.trace.json")), ids=lambda p: p.name)
def test_every_fixture_is_labeled_synthetic(path):
    assert json.loads(path.read_text())["synthetic"] is True
    assert parse_trace_bundle(path.read_bytes(), LIMITS, SPIKE).synthetic is True


def test_benign_fixture():
    r = fixture("benign_run.trace.json")
    f = r.features
    assert f["syscall_count"] == 7 and f["process_count"] == 1 and f["file_write_count"] == 1
    assert f["network_count"] == 1 and f["external_destination_count"] == 0
    assert f["resource_spike"] is False and r.destinations == {}
    assert r.write_samples == ["/tmp/out.txt"]


def test_network_fixture():
    r = fixture("network_beacon.trace.json")
    f = r.features
    assert f["network_count"] == 5 and f["network_failed_count"] == 4
    assert f["external_destination_count"] == 3
    assert r.destinations["93.184.216.34:443"] == {"attempts": 2, "succeeded": 0}
    assert r.destinations["[2606:4700:4700::1111]:80"]["attempts"] == 1
    assert "8.8.8.8:53" in r.destinations


def test_credential_fixture():
    r = fixture("credential_probe.trace.json")
    f = r.features
    assert set(r.sensitive_paths) == {"/home/user/.ssh/id_rsa", "/etc/shadow", "/proc/self/environ"}
    assert f["sensitive_file_access_count"] == 3
    assert r.shell_spawns == {"sh": 1}
    # One fork (not the CLONE_THREAD) and one successful exec (not the failed PATH lookup).
    assert f["process_count"] == 2
    assert f["file_write_count"] == 3 and f["file_write_failed_count"] == 1


def test_spike_fixture():
    r = fixture("resource_spike.trace.json")
    assert r.features["resource_spike"] is True and r.features["timed_out"] is True
    assert r.spike_reasons == [
        "timed out",
        "memory near limit",
        "pids near limit",
        "sustained CPU near limit",
    ]
    assert r.features["peak_memory_bytes"] == 970 and r.features["peak_pids"] == 97
    assert r.meta["exit_code"] is None


# ------------------------------------------------------------------ line formats
@pytest.mark.parametrize(
    "prefix", ["", "100 ", "[pid 100] ", "1700000000.123456 ", "100 1700000000.123456 "]
)
def test_line_prefixes(prefix):
    r = parse([f"{prefix}getpid() = 5"])
    assert r.features["syscall_count"] == 1 and r.features["malformed_line_count"] == 0


def test_signals_and_exits_are_not_syscalls():
    r = parse(["100 --- SIGCHLD {si_signo=SIGCHLD} ---", "100 +++ exited with 0 +++"])
    assert r.features["syscall_count"] == 0 and r.features["malformed_line_count"] == 0


def test_unfinished_resumed_counts_once_across_pids():
    r = parse(
        [
            f"1 connect(3, {{{V4}}}, 16 <unfinished ...>",
            "2 getpid() = 2",
            "1 <... connect resumed>) = -1 ENETUNREACH (Network is unreachable)",
        ]
    )
    assert r.features["syscall_count"] == 2 and r.features["network_failed_count"] == 1
    assert r.features["external_destination_count"] == 1


def test_orphan_resumed_is_malformed():
    assert parse(["1 <... connect resumed>) = 0"]).features["malformed_line_count"] == 1


def test_call_open_at_kill_still_counts_as_a_syscall():
    assert parse(["1 read(3, <unfinished ...>"]).features["syscall_count"] == 1


# ------------------------------------------------------------------ network
@pytest.mark.parametrize(
    ("ip", "external"),
    [
        ("93.184.216.34", True),
        ("127.0.0.1", False),
        ("10.0.0.1", False),
        ("192.168.1.1", False),
        ("169.254.169.254", False),
        ("0.0.0.0", False),  # noqa: S104 - trace data, not a bind address
    ],
)
def test_external_means_globally_routable(ip, external):
    line = (
        f'connect(3, {{sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("{ip}")}}, 16) = 0'
    )
    f = parse([line]).features
    assert f["network_count"] == 1 and f["external_destination_count"] == int(external)


def test_ipv4_mapped_v6_is_normalized():
    line = (
        "connect(3, {sa_family=AF_INET6, sin6_port=htons(80), sin6_flowinfo=htonl(0), "
        'inet_pton(AF_INET6, "::ffff:10.0.0.1", &sin6_addr), sin6_scope_id=0}, 28) = 0'
    )
    assert parse([line]).features["external_destination_count"] == 0


def test_distinct_destinations_are_ip_and_port():
    lines = [
        f'connect(3, {{sa_family=AF_INET, sin_port=htons({p}), sin_addr=inet_addr("1.1.1.1")}}, 16) = 0'
        for p in (80, 443, 443)
    ]
    r = parse(lines)
    assert r.features["external_destination_count"] == 2
    assert r.destinations["1.1.1.1:443"] == {"attempts": 2, "succeeded": 2}


def test_bind_counts_as_network_but_not_a_destination():
    f = parse([f"bind(3, {{{V4}}}, 16) = 0"]).features
    assert f["network_count"] == 1 and f["external_destination_count"] == 0


def test_sendmsg_address():
    line = f'sendmsg(3, {{msg_name={{{V4}}}, msg_namelen=16, msg_iov=[{{iov_base="x", iov_len=1}}]}}, 0) = 1'
    assert parse([line]).features["external_destination_count"] == 1


@pytest.mark.parametrize(
    "line",
    [
        'connect(3, {sa_family=AF_UNIX, sun_path="/run/x"}, 110) = 0',
        'connect(3, {sa_family=AF_UNSPEC, sa_data=""}, 16) = 0',
        'sendto(3, "x", 1, 0, NULL, 0) = 1',
    ],
)
def test_non_internet_sockets_are_not_network(line):
    assert parse([line]).features["network_count"] == 0


# ------------------------------------------------------------------ files
@pytest.mark.parametrize(
    "line",
    [
        'openat(AT_FDCWD, "/tmp/a", O_WRONLY|O_CREAT, 0644) = 3',
        'openat(AT_FDCWD, "/tmp/a", O_RDWR) = 3',
        'openat(AT_FDCWD, "/tmp/a", O_RDONLY|O_CREAT, 0644) = 3',
        'open("/tmp/a", O_WRONLY|O_APPEND) = 3',
        'creat("/tmp/a", 0644) = 3',
        'truncate("/tmp/a", 0) = 0',
        'unlink("/tmp/a") = 0',
        'unlinkat(AT_FDCWD, "/tmp/a", 0) = 0',
        'mkdir("/tmp/a", 0755) = 0',
        'mkdirat(AT_FDCWD, "/tmp/a", 0755) = 0',
        'rename("/tmp/a", "/tmp/b") = 0',
        'renameat(AT_FDCWD, "/tmp/a", AT_FDCWD, "/tmp/b") = 0',
        'chmod("/tmp/a", 0755) = 0',
        'fchmodat(AT_FDCWD, "/tmp/a", 0755) = 0',
        'symlink("/tmp/a", "/tmp/b") = 0',
    ],
)
def test_write_operations(line):
    assert parse([line]).features["file_write_count"] == 1


@pytest.mark.parametrize(
    "line",
    [
        'openat(AT_FDCWD, "/tmp/a", O_RDONLY|O_CLOEXEC) = 3',
        'openat(AT_FDCWD, "/dev/null", O_WRONLY) = 3',
        'write(1, "O_CREAT", 7) = 7',
        'stat("/tmp/a", {st_mode=S_IFREG}) = 0',
    ],
)
def test_non_write_operations(line):
    assert parse([line]).features["file_write_count"] == 0


@pytest.mark.parametrize(
    "path",
    [
        "/etc/shadow",
        "/etc/sudoers.d/x",
        "/home/u/.aws/credentials",
        "/home/u/.netrc",
        "/proc/1/environ",
        "/var/run/docker.sock",
        "/root/x",
        "../../etc/shadow",
    ],
)
def test_sensitive_paths(path):
    r = parse([f'openat(AT_FDCWD, "{path}", O_RDONLY) = -1 ENOENT (No such file)'])
    assert path in r.sensitive_paths


@pytest.mark.parametrize("path", ["/etc/hostname", "/tmp/ssh", "/artifact/root/x", "/proc/1/stat"])
def test_ordinary_paths_are_not_sensitive(path):
    assert parse([f'openat(AT_FDCWD, "{path}", O_RDONLY) = 3']).sensitive_paths == {}


# ------------------------------------------------------------------ processes
@pytest.mark.parametrize(
    ("line", "count"),
    [
        ("fork() = 5", 1),
        ("vfork() = 5", 1),
        ("clone(child_stack=NULL, flags=SIGCHLD) = 5", 1),
        ("clone3({flags=CLONE_VFORK, exit_signal=SIGCHLD}, 88) = 5", 1),
        ("clone(child_stack=0x1, flags=CLONE_VM|CLONE_THREAD) = 5", 0),
        ("clone3({flags=CLONE_VM|CLONE_THREAD, exit_signal=0}, 88) = 5", 0),
        ("fork() = -1 EAGAIN (Resource temporarily unavailable)", 0),
        ('execve("/usr/bin/python", ["python"], 0x1) = 0', 1),
        ('execve("/nope/python", ["python"], 0x1) = -1 ENOENT (No such file)', 0),
    ],
)
def test_process_counting(line, count):
    assert parse([line]).features["process_count"] == count


@pytest.mark.parametrize("tool", ["sh", "bash", "dash", "nc", "curl", "wget"])
def test_shell_and_network_tools(tool):
    assert parse([f'execve("/bin/{tool}", ["{tool}"], 0x1) = 0']).shell_spawns == {tool: 1}


def test_other_programs_are_not_shells():
    assert parse(['execve("/usr/bin/python", ["sh"], 0x1) = 0']).shell_spawns == {}


# ------------------------------------------------------------------ resource spike
def test_no_spike():
    samples = [sample(0), sample(1, memory=100, cpu=100_000)]
    r = parse(samples=samples, lines=["getpid() = 1"])
    assert r.features["resource_spike"] is False and r.spike_reasons == []


@pytest.mark.parametrize(
    ("samples", "reason"),
    [
        ([sample(0, memory=900)], "memory near limit"),
        ([sample(0, pids=90)], "pids near limit"),
        (
            [sample(i, cpu=i * 1_000_000) for i in range(4)],
            "sustained CPU near limit",
        ),
    ],
)
def test_each_spike_reason(samples, reason):
    r = parse(samples=samples, lines=["getpid() = 1"])
    assert r.features["resource_spike"] is True and r.spike_reasons == [reason]


def test_brief_cpu_burst_is_not_sustained():
    samples = [sample(0), sample(1, cpu=1_000_000), sample(2, cpu=1_000_000)]
    assert parse(samples=samples, lines=["x() = 0"]).features["resource_spike"] is False


def test_cpu_share_accounts_for_multiple_cores():
    samples = [sample(i, cpu=i * 1_000_000) for i in range(5)]
    limits = {**RUN_LIMITS, "cpus": 4.0}
    r = parse(samples=samples, lines=["x() = 0"], limits=limits)
    assert r.features["resource_spike"] is False


def test_timeout_alone_is_a_spike():
    assert parse(timed_out=True).features["resource_spike"] is True


def test_no_samples_means_unknown_not_false():
    assert parse(lines=["getpid() = 1"]).features["resource_spike"] is None


def test_missing_limits_means_unknown_not_false():
    r = parse(samples=[sample(0)], lines=["x() = 0"], limits={})
    assert r.features["resource_spike"] is None and r.features["peak_memory_bytes"] == 10


# ------------------------------------------------------------------ honesty
def test_empty_trace_reports_none_not_zero():
    r = parse()
    for key in (
        "network_count",
        "process_count",
        "file_write_count",
        "syscall_count",
        "external_destination_count",
    ):
        assert r.features[key] is None, key
    assert any("could not be evaluated" in lim for lim in r.limitations)


def test_real_bundle_is_not_marked_synthetic():
    data = json.loads(bundle(["x() = 0"]))
    del data["synthetic"]
    assert parse_trace_bundle(json.dumps(data).encode(), LIMITS, SPIKE).synthetic is False


def test_limitations_state_the_observer_limits():
    text = " ".join(parse(["x() = 0"]).limitations)
    assert "hostnames" in text and "forge" in text


# ------------------------------------------------------------------ helpers and settings
def test_split_args_respects_quotes_and_brackets():
    assert split_args('3, "a,b\\",c", {x=1, y=[2, 3]}, 16') == [
        "3",
        '"a,b\\",c"',
        "{x=1, y=[2, 3]}",
        "16",
    ]


def test_storable_replaces_what_postgres_rejects():
    assert storable("a\x00b\ud800c") == "a?b?c"
    assert len(storable("x" * 1000)) == 256


def test_trace_error_code_is_structured():
    with pytest.raises(AppError) as exc:
        parse_trace_bundle(b"{", LIMITS, SPIKE)
    assert exc.value.code == ErrorCode.SANDBOX_TRACE_ERROR


def test_default_settings_are_valid():
    s = Settings(_env_file=None)
    assert 0 < s.sandbox_spike_memory_fraction <= 1 and s.sandbox_max_trace_lines > 0
