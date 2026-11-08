"""Parser for recorded sandbox traces (`provenancex-trace-v1`).

A bundle is one JSON document:
    {"format": "provenancex-trace-v1",
     "meta": {"exit_code": int|null, "timed_out": bool, "duration_seconds": number,
              "targets": [...], "limits": {"memory_bytes", "pids", "cpus"}},
     "strace_lines": ["<strace -f -ttt text>", ...],
     "resource_samples": [{"t": seconds, "memory_bytes", "pids", "cpu_usec"}, ...]}

Bundles are UNTRUSTED, because code under observation influences them. A bad envelope
raises sandbox_trace_error. Inside a valid envelope, malformed lines and samples are
counted and skipped. Quoted strace strings are artifact-controlled, so arguments are
split with a quote-aware tokenizer and addresses are only read from the argument position
that holds them. A string containing fake address text cannot create a network event.

A feature that could not be evaluated is None, never a reassuring 0 or False.
"""

import ipaddress
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any

from app.core.errors import AppError, ErrorCode

TRACE_FORMAT = "provenancex-trace-v1"
MAX_LINE_CHARS = 8192
MAX_ARGS = 8
MAX_PENDING = 4096
MAX_LISTED = 20
MAX_EVIDENCE_CHARS = 256

_LINE_RE = re.compile(
    r"^(?:\[pid\s+(?P<pid1>\d{1,10})\]\s+|(?P<pid2>\d{1,10})\s+)?"
    r"(?:\d{1,12}\.\d{1,9}\s+)?"
    r"(?:<\.\.\.\s(?P<resumed>\w{1,32})\sresumed>(?P<rest>.*)"
    r"|(?P<name>\w{1,32})\((?P<args>.*))$",
    re.S,
)
_NOISE_RE = re.compile(
    r"^(?:\[pid\s+\d{1,10}\]\s+|\d{1,10}\s+)?(?:\d{1,12}\.\d{1,9}\s+)?(?:---|\+\+\+)"
)
_RESULT_RE = re.compile(r"^(?P<args>.*)\)\s+=\s+(?P<ret>\S+)(?:\s+(?P<err>E[A-Z0-9_]+))?", re.S)
_UNFINISHED = " <unfinished ...>"

_V4_RE = re.compile(
    r"\{sa_family=AF_INET,\s*sin_port=htons\((?P<port>\d{1,6})\),\s*"
    r'sin_addr=inet_addr\("(?P<ip>[0-9.]{1,15})"\)'
)
_V6_RE = re.compile(
    r"\{sa_family=AF_INET6,\s*sin6_port=htons\((?P<port>\d{1,6})\),.{0,64}?"
    r'inet_pton\(AF_INET6,\s*"(?P<ip>[0-9a-fA-F:.]{2,45})"',
    re.S,
)

CONNECT_SYSCALLS = frozenset({"connect", "bind"})
EXEC_SYSCALLS = frozenset({"execve", "execveat"})
FORK_SYSCALLS = frozenset({"fork", "vfork", "clone", "clone3"})
_WRITE_FLAGS = frozenset({"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "O_TMPFILE"})
_OPEN_PATH_INDEX = {"open": (0, 1), "openat": (1, 2)}
# Syscall -> index of the path it changes.
_PATH_WRITE_INDEX = {
    "creat": 0,
    "truncate": 0,
    "unlink": 0,
    "unlinkat": 1,
    "mkdir": 0,
    "mkdirat": 1,
    "rmdir": 0,
    "rename": 0,
    "renameat": 1,
    "renameat2": 1,
    "chmod": 0,
    "fchmodat": 1,
    "symlink": 1,
    "symlinkat": 2,
    "link": 1,
    "linkat": 3,
}
_IGNORED_WRITE_PATHS = frozenset({"/dev/null", "/dev/zero", "/dev/tty"})
_SENSITIVE_PATH_RES = (
    re.compile(r"(?:^|/)etc/(?:shadow|gshadow|sudoers)(?:$|/|\.)"),
    re.compile(r"(?:^|/)\.(?:ssh|aws|gnupg|docker|kube)(?:/|$)"),
    re.compile(r"(?:^|/)\.(?:netrc|git-credentials|pypirc|npmrc)$"),
    re.compile(r"^/proc/(?:\d+|self)/environ$"),
    re.compile(r"docker\.sock$"),
    re.compile(r"^/root(?:/|$)"),
)
SHELL_AND_NETWORK_TOOLS = frozenset(
    {"sh", "bash", "dash", "zsh", "ksh", "nc", "ncat", "socat", "curl", "wget"}
)


@dataclass(frozen=True)
class TraceLimits:
    max_bytes: int
    max_lines: int


@dataclass(frozen=True)
class SpikeThresholds:
    """Research parameters. Each fraction is a share of the configured sandbox limit."""

    memory_fraction: float
    pids_fraction: float
    cpu_fraction: float
    cpu_min_intervals: int


@dataclass
class TelemetryResult:
    features: dict[str, Any]
    destinations: dict[str, dict[str, int]]  # "ip:port" -> {"attempts", "succeeded"}
    sensitive_paths: dict[str, int]
    shell_spawns: dict[str, int]
    write_samples: list[str]
    spike_reasons: list[str]
    limitations: list[str]
    meta: dict[str, Any]
    synthetic: bool = False
    truncated: bool = False


@dataclass
class _Counters:
    syscalls: int = 0
    network: int = 0
    network_failed: int = 0
    processes: int = 0
    file_writes: int = 0
    file_writes_failed: int = 0
    malformed: int = 0
    noise: int = 0
    sensitive_total: int = 0
    destinations: dict[str, dict[str, int]] = field(default_factory=dict)
    sensitive: dict[str, int] = field(default_factory=dict)
    shells: dict[str, int] = field(default_factory=dict)
    write_samples: list[str] = field(default_factory=list)


def _trace_error(message: str, details: Any = None) -> AppError:
    return AppError(ErrorCode.SANDBOX_TRACE_ERROR, message, 502, details)


def storable(text: str) -> str:
    """Bound artifact text, replacing characters PostgreSQL rejects (NUL, lone surrogates)."""
    return "".join(ch if ch.isprintable() else "?" for ch in text[:MAX_EVIDENCE_CHARS])


def split_args(text: str) -> list[str]:
    """Split a strace argument list on top-level commas, respecting quotes and brackets."""
    args: list[str] = []
    depth = 0
    in_string = False
    escaped = False
    start = 0
    for index, ch in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            args.append(text[start:index].strip())
            start = index + 1
            if len(args) >= MAX_ARGS:
                return args
    args.append(text[start:].strip())
    return args


def _unquote(token: str) -> str | None:
    """The contents of a strace string token (a trailing `...` means strace cut it short)."""
    if not token.startswith('"'):
        return None
    end = token.rfind('"')
    if end <= 0:
        return None
    return token[1:end].replace('\\"', '"').replace("\\\\", "\\")


def _parse_address(token: str) -> tuple[str, int] | None:
    """(ip, port) from a sockaddr argument. The match is anchored at the argument start."""
    match = _V4_RE.match(token) or _V6_RE.match(token)
    if match is None:
        return None
    port = int(match.group("port"))
    if port > 65535:
        raise ValueError("port out of range")
    ip = ipaddress.ip_address(match.group("ip"))
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip), port


def _message_address(name: str, args: list[str]) -> str | None:
    if name in CONNECT_SYSCALLS:
        return args[1] if len(args) > 1 else None
    if name == "sendto":
        return args[4] if len(args) > 4 else None
    if name == "sendmsg" and args and len(args) > 1:
        return args[1][len("{msg_name=") :] if args[1].startswith("{msg_name=") else None
    return None


def _handle_network(c: _Counters, name: str, args: list[str], ok: bool) -> None:
    token = _message_address(name, args)
    if token is None:
        return
    try:
        address = _parse_address(token)
    except ValueError:
        c.malformed += 1
        return
    if address is None:
        return  # AF_UNIX, AF_NETLINK, AF_UNSPEC: not internet traffic
    c.network += 1
    c.network_failed += int(not ok)
    ip, port = address
    if name != "bind" and ipaddress.ip_address(ip).is_global:
        key = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
        entry = c.destinations.setdefault(key, {"attempts": 0, "succeeded": 0})
        entry["attempts"] += 1
        entry["succeeded"] += int(ok)


def _record_write(c: _Counters, path: str | None, ok: bool) -> None:
    if path in _IGNORED_WRITE_PATHS:
        return
    c.file_writes += 1
    c.file_writes_failed += int(not ok)
    if path and len(c.write_samples) < MAX_LISTED:
        c.write_samples.append(storable(path))


def _handle_files(c: _Counters, name: str, args: list[str], ok: bool) -> None:
    if name in _OPEN_PATH_INDEX:
        path_index, flags_index = _OPEN_PATH_INDEX[name]
        if len(args) <= flags_index:
            c.malformed += 1
            return
        path = _unquote(args[path_index])
        if path is not None and any(rx.search(path) for rx in _SENSITIVE_PATH_RES):
            c.sensitive_total += 1
            key = storable(path)
            if key in c.sensitive or len(c.sensitive) < MAX_LISTED:
                c.sensitive[key] = c.sensitive.get(key, 0) + 1
        if _WRITE_FLAGS & set(args[flags_index].split("|")):
            _record_write(c, path, ok)
    elif name in _PATH_WRITE_INDEX:
        index = _PATH_WRITE_INDEX[name]
        if len(args) <= index:
            c.malformed += 1
            return
        _record_write(c, _unquote(args[index]), ok)


def _handle_process(c: _Counters, name: str, args: list[str], ok: bool) -> None:
    if not ok:
        return  # exec walks PATH and fails often; only real process creation counts
    if name in FORK_SYSCALLS:
        if not any("CLONE_THREAD" in a for a in args):
            c.processes += 1
    elif name in EXEC_SYSCALLS:
        c.processes += 1
        path = _unquote(args[1] if name == "execveat" and len(args) > 1 else args[0])
        tool = path.rsplit("/", 1)[-1] if path else ""
        if tool in SHELL_AND_NETWORK_TOOLS:
            c.shells[tool] = c.shells.get(tool, 0) + 1


def _complete(c: _Counters, name: str, body: str) -> None:
    """Handle one syscall. `body` is everything after `name(`, including the result."""
    match = _RESULT_RE.match(body)
    if match is None:
        c.malformed += 1
        return
    c.syscalls += 1
    ret = match.group("ret")
    # "?" is the normal result of exit_group and of a successful exec in a thread.
    ok = ret != "-1" and match.group("err") is None
    args = split_args(match.group("args"))
    _handle_network(c, name, args, ok)
    _handle_files(c, name, args, ok)
    if args and args[0]:
        _handle_process(c, name, args, ok)
    elif name in ("fork", "vfork") and ok:
        c.processes += 1


def _parse_lines(lines: list[Any]) -> _Counters:
    c = _Counters()
    pending: dict[str | None, tuple[str, str]] = {}
    for raw in lines:
        if not isinstance(raw, str):
            c.malformed += 1
            continue
        line = raw[:MAX_LINE_CHARS].rstrip("\r\n")
        if not line.strip():
            continue
        if _NOISE_RE.match(line):
            c.noise += 1
            continue
        match = _LINE_RE.match(line)
        if match is None:
            c.malformed += 1
            continue
        pid = match.group("pid1") or match.group("pid2")
        if match.group("resumed"):
            started = pending.pop(pid, None)
            if started is None or started[0] != match.group("resumed"):
                c.malformed += 1
                continue
            _complete(c, started[0], started[1] + match.group("rest"))
        elif line.endswith(_UNFINISHED):
            if len(pending) >= MAX_PENDING:
                c.malformed += 1
                continue
            args = match.group("args")
            pending[pid] = (match.group("name"), args[: -len(_UNFINISHED)])
        else:
            _complete(c, match.group("name"), match.group("args"))
    # Calls still open when the process was killed happened, but have no result.
    c.syscalls += len(pending)
    return c


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = float(value)
    return number if math.isfinite(number) and number >= 0 else None


def _clean_samples(samples: list[Any]) -> tuple[list[dict[str, float]], int]:
    clean: list[dict[str, float]] = []
    bad = 0
    for sample in samples:
        values = (
            {k: _number(sample.get(k)) for k in ("t", "memory_bytes", "pids", "cpu_usec")}
            if isinstance(sample, dict)
            else None
        )
        if values is None or any(v is None for v in values.values()):
            bad += 1
            continue
        clean.append(values)  # type: ignore[arg-type]
    return clean, bad


def _sustained_cpu(samples: list[dict[str, float]], cpus: float, t: SpikeThresholds) -> bool:
    run = 0
    for before, after in zip(samples, samples[1:], strict=False):
        elapsed = after["t"] - before["t"]
        if elapsed <= 0:
            run = 0
            continue
        share = (after["cpu_usec"] - before["cpu_usec"]) / (elapsed * 1_000_000 * cpus)
        run = run + 1 if share >= t.cpu_fraction else 0
        if run >= t.cpu_min_intervals:
            return True
    return False


def _resource_spike(
    samples: list[dict[str, float]],
    limits: dict[str, Any],
    timed_out: bool,
    t: SpikeThresholds,
) -> tuple[bool | None, list[str], dict[str, float | None]]:
    peak_memory = max((s["memory_bytes"] for s in samples), default=None)
    peak_pids = max((s["pids"] for s in samples), default=None)
    peaks = {"peak_memory_bytes": peak_memory, "peak_pids": peak_pids}
    memory = _number(limits.get("memory_bytes"))
    pids = _number(limits.get("pids"))
    cpus = _number(limits.get("cpus"))
    reasons: list[str] = []
    if timed_out:
        reasons.append("timed out")
    if memory and peak_memory is not None and peak_memory >= memory * t.memory_fraction:
        reasons.append("memory near limit")
    if pids and peak_pids is not None and peak_pids >= pids * t.pids_fraction:
        reasons.append("pids near limit")
    if cpus and _sustained_cpu(samples, cpus, t):
        reasons.append("sustained CPU near limit")
    if reasons:
        return True, reasons, peaks
    if samples and memory and pids and cpus:
        return False, [], peaks
    return None, [], peaks  # no evidence to judge by: unknown, not "no spike"


def _clean_targets(targets: Any) -> list[dict[str, Any]]:
    """Bounded, storable target records. Paths and names come from the artifact."""
    if not isinstance(targets, list):
        return []
    clean: list[dict[str, Any]] = []
    for target in targets[:MAX_LISTED]:
        if not isinstance(target, dict):
            continue
        code = target.get("exit_code")
        clean.append(
            {
                "kind": storable(str(target.get("kind"))),
                "path": storable(str(target.get("path"))),
                "member": storable(str(target["member"])) if target.get("member") else None,
                "exit_code": code if isinstance(code, int) and not isinstance(code, bool) else None,
                "ran": target.get("ran") is True,
            }
        )
    return clean


def _load(raw: bytes, limits: TraceLimits) -> dict[str, Any]:
    if len(raw) > limits.max_bytes:
        raise _trace_error("Sandbox trace exceeds the size limit", {"max_bytes": limits.max_bytes})
    try:
        bundle = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise _trace_error("Sandbox trace is not valid JSON") from exc
    if not isinstance(bundle, dict) or bundle.get("format") != TRACE_FORMAT:
        raise _trace_error("Sandbox trace has an unknown format")
    return bundle


def parse_trace_bundle(
    raw: bytes, limits: TraceLimits, thresholds: SpikeThresholds
) -> TelemetryResult:
    """Parse an untrusted bundle into behavior features and bounded evidence."""
    bundle = _load(raw, limits)
    meta = bundle.get("meta")
    lines = bundle.get("strace_lines")
    samples = bundle.get("resource_samples")
    if not isinstance(meta, dict) or not isinstance(lines, list) or not isinstance(samples, list):
        raise _trace_error("Sandbox trace is missing required sections")
    timed_out = meta.get("timed_out")
    if not isinstance(timed_out, bool):
        raise _trace_error("Sandbox trace has an invalid timed_out value")

    truncated = len(lines) > limits.max_lines or meta.get("trace_truncated") is True
    counters = _parse_lines(lines[: limits.max_lines])
    clean, bad_samples = _clean_samples(samples[: limits.max_lines])
    raw_limits = meta.get("limits") if isinstance(meta.get("limits"), dict) else {}
    spike, reasons, peaks = _resource_spike(clean, raw_limits, timed_out, thresholds)

    has_trace = bool(lines)
    features: dict[str, Any] = {
        "network_count": counters.network if has_trace else None,
        "process_count": counters.processes if has_trace else None,
        "file_write_count": counters.file_writes if has_trace else None,
        "syscall_count": counters.syscalls if has_trace else None,
        "external_destination_count": len(counters.destinations) if has_trace else None,
        "resource_spike": spike,
        "network_failed_count": counters.network_failed if has_trace else None,
        "file_write_failed_count": counters.file_writes_failed if has_trace else None,
        "sensitive_file_access_count": counters.sensitive_total if has_trace else None,
        "shell_spawn_count": sum(counters.shells.values()) if has_trace else None,
        "malformed_line_count": counters.malformed,
        "malformed_sample_count": bad_samples,
        "timed_out": timed_out,
        **peaks,
    }
    limitations = [
        "The sandbox has no network, so hostnames never resolve and destinations known only by "
        "name are undercounted.",
        "Code under observation can detect tracing or forge its own trace lines; quiet telemetry "
        "is not proof of safety.",
    ]
    if not has_trace:
        limitations.append("The trace has no syscall lines, so behavior could not be evaluated.")
    if truncated:
        limitations.append(
            "The trace was cut off at its size or line limit; counts cover only the part parsed."
        )
    exit_code = meta.get("exit_code")
    duration = _number(meta.get("duration_seconds"))
    return TelemetryResult(
        features=features,
        destinations=dict(sorted(counters.destinations.items())[:MAX_LISTED]),
        sensitive_paths=counters.sensitive,
        shell_spawns=counters.shells,
        write_samples=counters.write_samples,
        spike_reasons=reasons,
        limitations=limitations,
        meta={
            "exit_code": exit_code if isinstance(exit_code, int) else None,
            "timed_out": timed_out,
            "duration_seconds": duration,
            "targets": _clean_targets(meta.get("targets")),
        },
        synthetic=bundle.get("synthetic") is True,
        truncated=truncated,
    )
