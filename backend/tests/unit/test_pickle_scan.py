import collections
import os
import subprocess

import pytest

from app.scanners.model.pickle_scan import classify_global, scan_pickle_file
from tests.model_helpers import (
    global_pickle,
    memo_stack_global,
    obfuscated_stack_global,
    reduce_pickle,
    stack_global_pickle,
    torch_zip_bytes,
    write,
)

LIMITS = {"max_bytes": 10 * 1024 * 1024, "max_opcodes": 100_000}


def scan(tmp_path, data: bytes, serialization="pickle", name="m.pkl"):
    return scan_pickle_file(write(tmp_path / name, data), serialization, **LIMITS)


@pytest.mark.parametrize(
    ("module", "name", "expected"),
    [
        ("collections", "OrderedDict", "safe"),
        ("torch._utils", "_rebuild_tensor_v2", "safe"),
        ("torch", "FloatStorage", "safe"),
        ("os", "system", "dangerous"),
        ("posix", "system", "dangerous"),
        ("subprocess", "Popen", "dangerous"),
        ("builtins", "eval", "dangerous"),
        ("__builtin__", "exec", "dangerous"),
        ("builtins", "__import__", "dangerous"),
        ("urllib.request", "urlopen", "dangerous"),
        ("operator", "attrgetter", "dangerous"),
        ("mypkg.models", "Net", "unknown"),
        ("builtins", "print", "unknown"),
    ],
)
def test_classify(module, name, expected):
    assert classify_global(module, name) == expected


@pytest.mark.parametrize("protocol", [0, 1, 2, 3, 4, 5])
def test_reduce_to_os_system_all_protocols(tmp_path, protocol):
    r = scan(tmp_path, reduce_pickle(os.system, ("echo hi",), protocol))
    assert r.status == "ok"
    assert any(g.endswith(".system") for g in r.dangerous)
    assert r.call_opcodes >= 1


def test_benign_pickle_is_clean(tmp_path):
    import pickle

    data = pickle.dumps(collections.OrderedDict(a=[1, 2, {"b": (3, 4)}]), protocol=4)
    r = scan(tmp_path, data)
    assert r.status == "ok" and r.dangerous == [] and r.unknown == []
    assert r.globals == {"collections.OrderedDict": "safe"} and r.protocol == 4


def test_raw_global_and_stack_global(tmp_path):
    assert scan(tmp_path, global_pickle("os", "system"), name="a.pkl").dangerous == ["os.system"]
    r = scan(tmp_path, stack_global_pickle("builtins", "exec"), name="b.pkl")
    assert r.dangerous == ["builtins.exec"]


def test_obfuscated_stack_global_resolves_real_target(tmp_path):
    r = scan(tmp_path, obfuscated_stack_global("os", "system"))
    assert r.dangerous == ["os.system"]
    assert "collections.OrderedDict" not in r.globals


def test_memo_stack_global_resolves(tmp_path):
    r = scan(tmp_path, memo_stack_global("subprocess", "call"))
    assert r.dangerous == ["subprocess.call"]


def test_unresolvable_stack_global_counted(tmp_path):
    # STACK_GLOBAL operands are not strings (two empty tuples).
    r = scan(tmp_path, b"\x80\x04)\x29\x93)R.")
    assert r.unresolved_stack_globals == 1 and r.globals == {}


def test_unknown_global(tmp_path):
    r = scan(tmp_path, reduce_pickle(subprocess.list2cmdline, ([],)))
    assert r.dangerous == ["subprocess.list2cmdline"]
    r = scan(tmp_path, global_pickle("mypkg.layers", "Custom"), name="c.pkl")
    assert r.unknown == ["mypkg.layers.Custom"] and r.dangerous == []


def test_garbage_is_parse_error(tmp_path):
    r = scan(tmp_path, b"this is not a pickle at all")
    assert r.status == "parse_error" and r.error


def test_stack_underflow_is_parse_error(tmp_path):
    assert scan(tmp_path, b"\x80\x04R.").status == "parse_error"


def test_opcode_budget(tmp_path):
    data = b"\x80\x04" + b"N0" * 1000 + b"N."
    r = scan_pickle_file(write(tmp_path / "m.pkl", data), "pickle", max_bytes=10**6, max_opcodes=50)
    assert r.status == "truncated"


def test_size_limit_not_scanned(tmp_path):
    path = write(tmp_path / "m.pkl", global_pickle("os", "system"))
    r = scan_pickle_file(path, "pickle", max_bytes=4, max_opcodes=100)
    assert r.status == "too_large" and r.globals == {}


def test_legacy_multi_pickle_with_trailing_bytes(tmp_path):
    import pickle

    data = pickle.dumps(0x1950A86A20F9469CFC6C, 2) + pickle.dumps({"protocol": 1000}, 2)
    data += global_pickle("os", "system") + b"\x00\xffRAW TENSOR BYTES"
    r = scan(tmp_path, data, name="legacy.pt")
    assert r.pickles == 3 and r.dangerous == ["os.system"] and r.status == "ok"


def test_pytorch_zip_member_scanned(tmp_path):
    payload = reduce_pickle(os.system, ("id",))
    r = scan(tmp_path, torch_zip_bytes(payload), "pytorch_zip", "pytorch_model.bin")
    assert r.members == ["archive/data.pkl"]
    assert any(g.endswith(".system") for g in r.dangerous)


def test_pytorch_zip_without_pickle_members(tmp_path):
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", "x")
    r = scan(tmp_path, buf.getvalue(), "pytorch_zip", "m.pt")
    assert r.status == "not_scanned"


def test_to_dict_shape(tmp_path):
    d = scan(tmp_path, global_pickle("os", "system")).to_dict()
    assert d["dangerous_globals"] == ["os.system"] and d["status"] == "ok"
