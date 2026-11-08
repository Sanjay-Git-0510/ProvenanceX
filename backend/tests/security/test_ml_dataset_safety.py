"""Dataset generation only parses fixtures: nothing runs, loads or reaches the network."""

import ast
import os
import pickle
import socket
import subprocess
from pathlib import Path

import pytest

from app.ml.dataset.generator import generate_records
from app.ml.dataset.tampering import INERT_FLAGGED_PICKLE
from app.ml.dataset.templates import SEEDS_DIR

ML_DIR = Path(__file__).resolve().parents[2] / "app" / "ml"
BANNED_IMPORTS = {
    "subprocess",
    "importlib",
    "runpy",
    "pickle",
    "cPickle",
    "dill",
    "cloudpickle",
    "joblib",
    "torch",
    "socket",
    "httpx",
    "requests",
    "urllib",
    "docker",
}
BANNED_CALLS = {"eval", "exec", "compile", "__import__"}


def _sources():
    return [p for p in ML_DIR.rglob("*.py") if "__pycache__" not in p.parts]


@pytest.mark.parametrize("path", _sources(), ids=lambda p: p.relative_to(ML_DIR).as_posix())
def test_ml_code_has_no_execution_or_network_primitives(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not {a.name.split(".")[0] for a in node.names} & BANNED_IMPORTS
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in BANNED_IMPORTS
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in BANNED_CALLS


def test_generation_never_executes_loads_or_connects(monkeypatch):
    def forbid(*_args, **_kwargs):
        raise AssertionError("dataset generation attempted a forbidden operation")

    monkeypatch.setattr(subprocess, "Popen", forbid)
    monkeypatch.setattr(os, "system", forbid)
    monkeypatch.setattr(pickle, "load", forbid)
    monkeypatch.setattr(pickle, "loads", forbid)
    monkeypatch.setattr(pickle, "Unpickler", forbid)
    monkeypatch.setattr(socket.socket, "connect", forbid)
    monkeypatch.setattr(socket, "create_connection", forbid)
    assert generate_records(12, 3)


def test_inert_flagged_pickle_only_invokes_true():
    assert b"'true'" in INERT_FLAGGED_PICKLE
    assert len(INERT_FLAGGED_PICKLE) < 40


@pytest.mark.parametrize("path", sorted(SEEDS_DIR.iterdir()), ids=lambda p: p.name)
def test_seeds_are_text_and_state_they_are_inert_fixtures(path):
    text = path.read_text(encoding="utf-8")
    assert "Synthetic fixture" in text
    assert "Parsed only, never run" in text
    assert path.suffix == ".txt"


def test_suspicious_seed_targets_only_a_reserved_address():
    text = (SEEDS_DIR / "inert_suspicious.py.txt").read_text(encoding="utf-8")
    assert '"192.0.2.1"' in text
    assert "http" not in text


def test_seed_functions_are_never_called_at_module_level():
    source = (SEEDS_DIR / "inert_suspicious.py.txt").read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert not [n for n in tree.body if isinstance(n, ast.Expr | ast.Assign) and _is_call(n)]


def _is_call(node) -> bool:
    return isinstance(getattr(node, "value", None), ast.Call)
