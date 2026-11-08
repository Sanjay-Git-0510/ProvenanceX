"""Sandbox supervisor. Runs as PID 1 inside the disposable container, and nowhere else.

It selects a fixed set of targets from the read-only /artifact mount, runs each under
`strace -f`, samples cgroup usage, and writes one provenancex-trace-v1 bundle to its own
stdout. Target output is redirected to files in /tmp. That does not isolate the bundle:
targets run as the same uid and can write to this process's stdout through /proc/1/fd or
alter /trace, so the host must treat the bundle as untrusted.

Targets (nothing from the artifact can add to this list):
  software  setup_py   python /artifact/setup.py install --root /tmp/px-root ...
  model     pickle     stdlib pickle.load of a file, or of a *.pkl member of a ZIP
            auto_map   importlib.import_module of a module named by a config auto_map

This file uses the standard library only, because the image has nothing else.
"""

import argparse
import importlib
import json
import os
import pickle
import re
import signal
import stat
import subprocess
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

TRACE_FORMAT = "provenancex-trace-v1"
ARTIFACT = Path("/artifact")
TRACE_DIR = Path("/trace")
WORK_DIR = Path("/tmp")  # noqa: S108 - the container's size-limited tmpfs
CGROUP = Path("/sys/fs/cgroup")
SELF = "/opt/px/supervisor.py"

MAX_PICKLE_TARGETS = 8
MAX_AUTO_MAP_TARGETS = 8
MAX_PICKLE_BYTES = 64 * 1024 * 1024
MAX_WALK_FILES = 20000
MAX_CONFIG_BYTES = 1024 * 1024
# Bundles stay under the host's SANDBOX_MAX_TRACE_MB even after JSON escaping.
MAX_TRACE_BYTES = 8 * 1024 * 1024
MAX_TRACE_LINES = 150_000
MAX_SAMPLES = 2000
SAMPLE_SECONDS = 0.25
STRACE_STRING_BYTES = "256"

PICKLE_SUFFIXES = frozenset({".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt"})
AUTO_MAP_CONFIGS = ("config.json", "tokenizer_config.json")
_MODULE_RE = re.compile(r"^[A-Za-z_]\w{0,99}(?:\.[A-Za-z_]\w{0,99}){0,8}$")
TARGET_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": str(WORK_DIR),
    "PYTHONDONTWRITEBYTECODE": "1",
}


@dataclass(frozen=True)
class Target:
    kind: str  # setup_py | pickle | auto_map
    path: str  # relative to the artifact root
    member: str | None = None  # a *.pkl member inside a ZIP, or the module for auto_map


def _regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _pickle_targets(root: Path) -> list[Target]:
    targets: list[Target] = []
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            seen += 1
            if seen > MAX_WALK_FILES or len(targets) >= MAX_PICKLE_TARGETS:
                return targets
            path = Path(dirpath) / name
            is_pickle_name = path.suffix.lower() in PICKLE_SUFFIXES
            if not is_pickle_name or not _regular_file(path):
                continue
            rel = path.relative_to(root).as_posix()
            try:
                if path.stat().st_size > MAX_PICKLE_BYTES:
                    continue
                with path.open("rb") as fh:
                    head = fh.read(2)
                if head.startswith(b"PK"):
                    with zipfile.ZipFile(path) as zf:
                        members = sorted(n for n in zf.namelist() if n.endswith(".pkl"))
                    for member in members:
                        if len(targets) < MAX_PICKLE_TARGETS:
                            targets.append(Target("pickle", rel, member))
                elif head[:1] == b"\x80" or path.suffix.lower() in (".pkl", ".pickle"):
                    targets.append(Target("pickle", rel))
            except (OSError, zipfile.BadZipFile, ValueError, RuntimeError, EOFError):
                continue
    return targets


def _auto_map_targets(root: Path) -> list[Target]:
    modules: dict[str, str] = {}
    for config in AUTO_MAP_CONFIGS:
        path = root / config
        if not _regular_file(path) or path.stat().st_size > MAX_CONFIG_BYTES:
            continue
        try:
            data = json.loads(path.read_bytes())
        except (ValueError, RecursionError):
            continue
        auto_map = data.get("auto_map") if isinstance(data, dict) else None
        if not isinstance(auto_map, dict):
            continue
        for value in auto_map.values():
            for ref in value if isinstance(value, list) else [value]:
                if not isinstance(ref, str) or "--" in ref or "." not in ref:
                    continue
                module = ref.rsplit(".", 1)[0]
                if not _MODULE_RE.match(module):
                    continue
                rel = module.replace(".", "/") + ".py"
                if _regular_file(root / rel):
                    modules[module] = rel
    ordered = sorted(modules.items())[:MAX_AUTO_MAP_TARGETS]
    return [Target("auto_map", rel, module) for module, rel in ordered]


def select_targets(root: Path, kind: str) -> list[Target]:
    if kind == "software":
        return [Target("setup_py", "setup.py")] if _regular_file(root / "setup.py") else []
    if kind == "model":
        return _pickle_targets(root) + _auto_map_targets(root)
    raise ValueError(f"unknown kind: {kind}")


def target_command(target: Target, root: Path = ARTIFACT) -> list[str]:
    python = sys.executable
    if target.kind == "setup_py":
        return [
            python,
            "-B",
            str(root / target.path),
            "install",
            "--root",
            str(WORK_DIR / "px-root"),
            "--record",
            str(WORK_DIR / "px-record"),
        ]
    if target.kind == "pickle":
        command = [python, "-B", SELF, "--run-pickle", str(root / target.path)]
        return command + (["--member", target.member] if target.member else [])
    if target.kind == "auto_map":
        return [python, "-B", SELF, "--run-module", target.member or ""]
    raise ValueError(f"unknown target: {target.kind}")


# ---------------------------------------------------------------------- inside a target
def run_pickle(path: str, member: str | None) -> None:
    """Deliberately unsafe: this is the behavior being observed, inside the sandbox only."""
    if member:
        with zipfile.ZipFile(path) as zf, zf.open(member) as fh:
            pickle.load(fh)  # noqa: S301
    else:
        with open(path, "rb") as fh:
            pickle.load(fh)  # noqa: S301


def run_module(module: str) -> None:
    sys.path.insert(0, str(ARTIFACT))
    importlib.import_module(module)


# ---------------------------------------------------------------------- resources
def _read_int(path: Path) -> int | None:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def read_limits(cgroup: Path = CGROUP) -> dict[str, float | None]:
    """The limits actually in force, from the cgroup."""
    cpus: float | None = None
    try:
        quota, period = (cgroup / "cpu.max").read_text().split()
        if quota != "max":
            cpus = int(quota) / int(period)
    except (OSError, ValueError):
        pass
    return {
        "memory_bytes": _read_int(cgroup / "memory.max"),
        "pids": _read_int(cgroup / "pids.max"),
        "cpus": cpus,
    }


def read_oom_kills(cgroup: Path = CGROUP) -> int | None:
    """How many processes the kernel OOM killer has killed in this container."""
    try:
        for line in (cgroup / "memory.events").read_text().splitlines():
            if line.startswith("oom_kill "):
                return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return None


def read_sample(started: float, cgroup: Path = CGROUP) -> dict[str, float] | None:
    memory = _read_int(cgroup / "memory.current")
    pids = _read_int(cgroup / "pids.current")
    usage = None
    try:
        for line in (cgroup / "cpu.stat").read_text().splitlines():
            if line.startswith("usage_usec "):
                usage = int(line.split()[1])
    except (OSError, ValueError):
        pass
    if memory is None or pids is None or usage is None:
        return None
    return {
        "t": round(time.monotonic() - started, 3),
        "memory_bytes": memory,
        "pids": pids,
        "cpu_usec": usage,
    }


# ---------------------------------------------------------------------- running targets
def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    proc.wait()


def run_target(
    target: Target,
    index: int,
    deadline: float,
    started: float,
    samples: list[dict[str, float]],
) -> tuple[int | None, bool]:
    """Run one target under strace. Returns (exit code, timed out)."""
    trace = TRACE_DIR / f"strace.{index}"
    command = [
        "strace",
        "-f",
        "-ttt",
        "-s",
        STRACE_STRING_BYTES,
        "-o",
        str(trace),
        "--",
        *target_command(target),
    ]
    with (WORK_DIR / f"target.{index}.out").open("wb") as out:
        proc = subprocess.Popen(  # noqa: S603 - fixed argv inside the sandbox
            command,
            cwd=WORK_DIR,
            env=TARGET_ENV,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    while True:
        code = proc.poll()
        if len(samples) < MAX_SAMPLES and (sample := read_sample(started)) is not None:
            samples.append(sample)
        if code is not None:
            return code, False
        if time.monotonic() > deadline:
            _kill_group(proc)
            return None, True
        time.sleep(SAMPLE_SECONDS)


def read_traces(paths: list[Path]) -> tuple[list[str], bool]:
    """All recorded strace lines, within the byte and line budgets."""
    lines: list[str] = []
    total = 0
    for path in paths:
        try:
            with path.open("rb") as fh:
                for raw in fh:
                    total += len(raw)
                    if total > MAX_TRACE_BYTES or len(lines) >= MAX_TRACE_LINES:
                        return lines, True
                    lines.append(raw.decode("utf-8", "replace").rstrip("\n"))
        except OSError:
            continue
    return lines, False


def build_bundle(
    results: list[dict],
    timed_out: bool,
    duration: float,
    limits: dict,
    lines: list[str],
    truncated: bool,
    samples: list[dict],
    oom_kills: int | None = None,
) -> dict:
    failing = next((r["exit_code"] for r in results if r["exit_code"]), 0)
    return {
        "format": TRACE_FORMAT,
        "meta": {
            "exit_code": None if timed_out else failing,
            "timed_out": timed_out,
            "duration_seconds": round(duration, 3),
            "targets": results,
            "limits": limits,
            "trace_truncated": truncated,
            "oom_kill_count": oom_kills,
        },
        "strace_lines": lines,
        "resource_samples": samples,
    }


def supervise(kind: str, timeout: float) -> dict:
    started = time.monotonic()
    deadline = started + timeout
    targets = select_targets(ARTIFACT, kind)
    samples: list[dict[str, float]] = []
    results: list[dict] = []
    paths: list[Path] = []
    timed_out = False
    for index, target in enumerate(targets):
        entry = {"kind": target.kind, "path": target.path, "member": target.member}
        if timed_out:
            results.append({**entry, "exit_code": None, "ran": False})
            continue
        paths.append(TRACE_DIR / f"strace.{index}")
        code, timed_out = run_target(target, index, deadline, started, samples)
        results.append({**entry, "exit_code": code, "ran": True})
    lines, truncated = read_traces(paths)
    return build_bundle(
        results,
        timed_out,
        time.monotonic() - started,
        read_limits(),
        lines,
        truncated,
        samples,
        read_oom_kills(),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", choices=("software", "model"))
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--run-pickle")
    parser.add_argument("--member")
    parser.add_argument("--run-module")
    args = parser.parse_args()
    if args.run_pickle:
        run_pickle(args.run_pickle, args.member)
        return 0
    if args.run_module:
        run_module(args.run_module)
        return 0
    if not args.kind or not args.timeout:
        parser.error("--kind and --timeout are required")
    data = json.dumps(supervise(args.kind, args.timeout)).encode()
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
