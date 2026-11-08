# ruff: noqa: S108 - fixed container paths, used as test data
"""Target selection and bundle building in the sandbox supervisor. Nothing here runs a target."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from tests.conftest import build_zip, symlink_info
from tests.model_helpers import reduce_pickle, torch_zip_bytes, write

SUPERVISOR = Path(__file__).resolve().parents[3] / "docker" / "sandbox" / "supervisor.py"


@pytest.fixture(scope="module")
def sup():
    spec = importlib.util.spec_from_file_location("px_supervisor", SUPERVISOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules["px_supervisor"] = module
    spec.loader.exec_module(module)
    yield module
    del sys.modules["px_supervisor"]


PICKLE = reduce_pickle(print, ("x",))


def test_software_runs_only_a_root_setup_py(sup, tmp_path):
    write(tmp_path / "setup.py", "x=1")
    write(tmp_path / "sub/setup.py", "x=1")
    write(tmp_path / "model.pkl", PICKLE)
    assert sup.select_targets(tmp_path, "software") == [sup.Target("setup_py", "setup.py")]


def test_software_without_setup_py_runs_nothing(sup, tmp_path):
    write(tmp_path / "pyproject.toml", "")
    assert sup.select_targets(tmp_path, "software") == []


def test_setup_py_symlink_is_not_a_target(sup, tmp_path):
    (tmp_path / "setup.py").symlink_to("/etc/passwd")
    assert sup.select_targets(tmp_path, "software") == []


def test_model_ignores_setup_py(sup, tmp_path):
    write(tmp_path / "setup.py", "x=1")
    assert sup.select_targets(tmp_path, "model") == []


def test_raw_pickle_targets(sup, tmp_path):
    write(tmp_path / "a.pkl", PICKLE)
    write(tmp_path / "b.bin", PICKLE)
    write(tmp_path / "c.txt", PICKLE)
    write(tmp_path / "d.safetensors", b"\x80")
    assert {t.path for t in sup.select_targets(tmp_path, "model")} == {"a.pkl", "b.bin"}


def test_bin_file_without_pickle_header_is_skipped(sup, tmp_path):
    write(tmp_path / "w.bin", b"not a pickle")
    assert sup.select_targets(tmp_path, "model") == []


def test_zip_members_become_targets(sup, tmp_path):
    write(tmp_path / "m.pt", torch_zip_bytes(PICKLE))
    [target] = sup.select_targets(tmp_path, "model")
    assert (target.kind, target.path, target.member) == ("pickle", "m.pt", "archive/data.pkl")


def test_corrupt_zip_is_skipped(sup, tmp_path):
    write(tmp_path / "m.pt", b"PK\x03\x04broken")
    assert sup.select_targets(tmp_path, "model") == []


def test_pickle_targets_are_capped(sup, tmp_path):
    for i in range(sup.MAX_PICKLE_TARGETS + 5):
        write(tmp_path / f"{i}.pkl", PICKLE)
    assert len(sup.select_targets(tmp_path, "model")) == sup.MAX_PICKLE_TARGETS


def test_oversized_pickle_is_skipped(sup, tmp_path, monkeypatch):
    monkeypatch.setattr(sup, "MAX_PICKLE_BYTES", 4)
    write(tmp_path / "a.pkl", PICKLE)
    assert sup.select_targets(tmp_path, "model") == []


def test_symlinked_pickle_is_not_followed(sup, tmp_path):
    target = write(tmp_path / "outside" / "real.bin", PICKLE)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.pkl").symlink_to(target)
    assert sup.select_targets(repo, "model") == []


def auto_map(tmp_path, value):
    write(tmp_path / "config.json", json.dumps({"auto_map": value}))


def test_auto_map_targets(sup, tmp_path):
    auto_map(tmp_path, {"AutoModel": "modeling_x.Model", "AutoConfig": "pkg.conf.Config"})
    write(tmp_path / "modeling_x.py", "")
    write(tmp_path / "pkg/conf.py", "")
    targets = sup.select_targets(tmp_path, "model")
    assert [(t.kind, t.path, t.member) for t in targets] == [
        ("auto_map", "modeling_x.py", "modeling_x"),
        ("auto_map", "pkg/conf.py", "pkg.conf"),
    ]


def test_auto_map_list_values(sup, tmp_path):
    auto_map(tmp_path, {"AutoTokenizer": ["tok.T", None]})
    write(tmp_path / "tok.py", "")
    assert len(sup.select_targets(tmp_path, "model")) == 1


@pytest.mark.parametrize(
    "value",
    [
        "other/repo--modeling.Model",
        "../evil.Model",
        "os.system",
        "a b.Model",
        "NoDot",
        7,
    ],
)
def test_bad_auto_map_values_are_skipped(sup, tmp_path, value):
    auto_map(tmp_path, {"AutoModel": value})
    assert sup.select_targets(tmp_path, "model") == []


def test_auto_map_missing_file_is_skipped(sup, tmp_path):
    auto_map(tmp_path, {"AutoModel": "modeling_x.Model"})
    assert sup.select_targets(tmp_path, "model") == []


@pytest.mark.parametrize("content", ["{not json", "[1]", '{"auto_map": 3}'])
def test_malformed_config_is_skipped(sup, tmp_path, content):
    write(tmp_path / "config.json", content)
    assert sup.select_targets(tmp_path, "model") == []


def test_unknown_kind_is_rejected(sup, tmp_path):
    with pytest.raises(ValueError, match="unknown kind"):
        sup.select_targets(tmp_path, "evil")


def test_commands_are_fixed(sup):
    root = Path("/artifact")
    setup = sup.target_command(sup.Target("setup_py", "setup.py"), root)
    assert setup[1:4] == ["-B", "/artifact/setup.py", "install"] and "/tmp/px-root" in setup
    pick = sup.target_command(sup.Target("pickle", "a.pt", "archive/data.pkl"), root)
    assert pick[2:] == [sup.SELF, "--run-pickle", "/artifact/a.pt", "--member", "archive/data.pkl"]
    mod = sup.target_command(sup.Target("auto_map", "m.py", "m"), root)
    assert mod[2:] == [sup.SELF, "--run-module", "m"]


def test_read_limits_from_cgroup(sup, tmp_path):
    write(tmp_path / "memory.max", "1024\n")
    write(tmp_path / "pids.max", "64\n")
    write(tmp_path / "cpu.max", "50000 100000\n")
    assert sup.read_limits(tmp_path) == {"memory_bytes": 1024, "pids": 64, "cpus": 0.5}


def test_read_limits_unlimited_or_missing(sup, tmp_path):
    write(tmp_path / "memory.max", "max\n")
    write(tmp_path / "cpu.max", "max 100000\n")
    assert sup.read_limits(tmp_path) == {"memory_bytes": None, "pids": None, "cpus": None}


def test_read_sample(sup, tmp_path):
    write(tmp_path / "memory.current", "10\n")
    write(tmp_path / "pids.current", "2\n")
    write(tmp_path / "cpu.stat", "usage_usec 99\nuser_usec 1\n")
    sample = sup.read_sample(0.0, tmp_path)
    assert sample["memory_bytes"] == 10 and sample["pids"] == 2 and sample["cpu_usec"] == 99


def test_read_sample_without_cgroup_is_none(sup, tmp_path):
    assert sup.read_sample(0.0, tmp_path) is None


def test_read_oom_kills(sup, tmp_path):
    write(tmp_path / "memory.events", "low 0\noom 2\noom_kill 3\n")
    assert sup.read_oom_kills(tmp_path) == 3


def test_read_oom_kills_unavailable_is_none_not_zero(sup, tmp_path):
    assert sup.read_oom_kills(tmp_path) is None


def test_read_traces_budget(sup, tmp_path, monkeypatch):
    path = write(tmp_path / "t", "a\nb\nc\n")
    assert sup.read_traces([path]) == (["a", "b", "c"], False)
    monkeypatch.setattr(sup, "MAX_TRACE_LINES", 2)
    assert sup.read_traces([path]) == (["a", "b"], True)
    monkeypatch.setattr(sup, "MAX_TRACE_LINES", 100)
    monkeypatch.setattr(sup, "MAX_TRACE_BYTES", 3)
    assert sup.read_traces([path])[1] is True


def test_read_traces_missing_file_and_bad_bytes(sup, tmp_path):
    path = write(tmp_path / "t", b"\xff\xfe\n")
    lines, truncated = sup.read_traces([tmp_path / "missing", path])
    assert len(lines) == 1 and truncated is False


def test_bundle_matches_the_parser(sup):
    from app.scanners.sandbox.telemetry import SpikeThresholds, TraceLimits, parse_trace_bundle

    results = [
        {"kind": "setup_py", "path": "setup.py", "member": None, "exit_code": 3, "ran": True}
    ]
    bundle = sup.build_bundle(
        results,
        False,
        1.0,
        {"memory_bytes": 10, "pids": 2, "cpus": 1.0},
        ["getpid() = 1"],
        False,
        [],
    )
    assert bundle["meta"]["exit_code"] == 3
    parsed = parse_trace_bundle(
        json.dumps(bundle).encode(), TraceLimits(10**6, 10), SpikeThresholds(0.9, 0.9, 0.9, 3)
    )
    assert parsed.features["syscall_count"] == 1 and parsed.meta["targets"][0]["ran"] is True


def test_timed_out_bundle_has_no_exit_code(sup):
    assert sup.build_bundle([], True, 1.0, {}, [], False, [])["meta"]["exit_code"] is None


def test_zip_helper_entries_with_symlink_do_not_crash(sup, tmp_path):
    write(tmp_path / "m.pt", build_zip([(symlink_info("archive/data.pkl"), b"x")]))
    assert len(sup.select_targets(tmp_path, "model")) == 1  # the container handles the rest
