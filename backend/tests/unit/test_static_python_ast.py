"""Python rules. Every sample is a source string that is parsed and never executed."""

import pytest

from app.scanners.static import rules
from app.scanners.static.python_ast import analyze_python


def symbols(src: str) -> set[str]:
    result = analyze_python(src)
    assert result.parse_error is None
    return {h.symbol for h in result.hits}


def ids(src: str) -> set[str]:
    return {h.rule.id for h in analyze_python(src).hits}


@pytest.mark.parametrize(
    ("src", "rule"),
    [
        ("import subprocess", rules.IMPORT_PROCESS),
        ("import ctypes", rules.IMPORT_NATIVE),
        ("import socket", rules.IMPORT_NETWORK),
        ("import urllib.request", rules.IMPORT_NETWORK),
        ("from urllib import request", rules.IMPORT_NETWORK),
        ("from http.client import HTTPConnection", rules.IMPORT_NETWORK),
        ("import pickle", rules.IMPORT_DESERIALIZE),
        ("import marshal as m", rules.IMPORT_DESERIALIZE),
        ("import runpy", rules.IMPORT_DYNAMIC),
    ],
)
def test_dangerous_imports(src, rule):
    [hit] = analyze_python(src).hits
    assert hit.rule == rule and hit.rule.kind == rules.KIND_IMPORT and hit.line == 1


@pytest.mark.parametrize(
    "src",
    [
        "import os",
        "import json, re, sys",
        "from pathlib import Path",
        "import urllib.parse",
        "from .subprocess import helper",
        "from . import pickle",
    ],
)
def test_ordinary_imports_are_not_flagged(src):
    assert analyze_python(src).hits == []


@pytest.mark.parametrize(
    ("src", "symbol"),
    [
        ("import os\nos.system('x')", "os.system"),
        ("import os as o\no.system('x')", "os.system"),
        ("from os import system\nsystem('x')", "os.system"),
        ("from os import system as s\ns('x')", "os.system"),
        ("import os\nrun = os.system\nrun('x')", "os.system"),
        ("__import__('os').system('x')", "os.system"),
        ("import importlib\nimportlib.import_module('os').system('x')", "os.system"),
        ("import os\ngetattr(os, 'system')('x')", "os.system"),
        ("import builtins\nbuiltins.eval('1')", "eval"),
        ("import builtins\ngetattr(builtins, 'exec')('1')", "exec"),
        ("e = eval\ne('1')", "eval"),
        ("import subprocess as sp\nsp.Popen(['x'])", "subprocess.Popen"),
        ("from subprocess import check_output\ncheck_output(['x'])", "subprocess.check_output"),
        ("import ctypes\nctypes.CDLL('x')", "ctypes.CDLL"),
        ("import requests\nrequests.post('u')", "requests.post"),
        ("import socket\nsocket.socket()", "socket.socket"),
        ("import pickle\npickle.loads(b'')", "pickle.loads"),
        ("import torch\ntorch.load('m')", "torch.load"),
    ],
)
def test_api_calls_resolve_through_aliases(src, symbol):
    assert symbol in symbols(src)


@pytest.mark.parametrize(
    "src",
    [
        "model.eval()",
        "self.exec()",
        "import re\nre.compile('x')",
        "obj.system('x')",
        "session.get('u')",
        "def f(o, n):\n    return getattr(o, n)",
        "getattr(obj, 'name')",
        "getattr(obj, 'x', None)",
    ],
)
def test_lookalike_calls_are_not_flagged(src):
    assert analyze_python(src).hits == []


@pytest.mark.parametrize(
    "src",
    [
        "import os\ndef f(n):\n    return getattr(os, n)",
        "import os\ngetattr(os, 'sys' + 'tem')",
        "getattr(obj, 'a' + 'b')",
        "getattr(obj, f'{x}y')",
        "getattr(obj, decode(z))",
    ],
)
def test_dynamic_attribute_access_is_flagged(src):
    assert rules.API_OBFUSCATION.id in ids(src)


@pytest.mark.parametrize(
    "src",
    [
        "import base64\nexec(base64.b64decode('eA=='))",
        "import zlib\neval(zlib.decompress(b''))",
        "import base64\nexec(base64.b64decode('eA==').decode())",
        "import base64\ndata = base64.b64decode('eA==')\nexec(data)",
        "from base64 import b64decode as d\nexec(d('eA=='))",
        "exec(bytes.fromhex('41'))",
    ],
)
def test_exec_of_decoded_data_is_high(src):
    hits = [h for h in analyze_python(src).hits if h.rule == rules.API_EXEC_DECODED]
    assert hits and hits[0].rule.severity == "HIGH"


def test_plain_exec_is_medium_not_decoded():
    assert ids("exec('x')") == {rules.API_EVAL.id}


def test_dynamic_import():
    assert ids("__import__(name)") == {rules.API_DYNAMIC_IMPORT.id}
    assert ids("__import__('json')") == set()
    assert ids("__import__('socket')") == {rules.IMPORT_NETWORK.id}


def test_cell_index_is_recorded():
    assert analyze_python("exec('x')", cell=4).hits[0].cell == 4


@pytest.mark.parametrize("src", ["def (:", "\x00", "if True\n  x"])
def test_invalid_source_is_a_parse_error(src):
    result = analyze_python(src)
    assert result.parse_error and result.hits == []
