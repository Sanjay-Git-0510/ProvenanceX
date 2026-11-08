"""Static analysis against hostile inputs. Samples are strings: parsed, never executed."""

import ast
import json
import sys
import time
from pathlib import Path

import pytest

import app as app_package
from app.scanners.static.analyzer import StaticLimits, analyze_artifact
from app.scanners.static.archive_anomaly import inspect_nested_zip
from app.scanners.static.install_hooks import scan_package_json
from app.scanners.static.python_ast import analyze_python
from app.scanners.static.text_scan import scan_text
from tests.conftest import build_zip
from tests.model_helpers import write

LIMITS = StaticLimits(
    max_files=100,
    max_file_bytes=1024 * 1024,
    max_total_bytes=8 * 1024 * 1024,
    max_findings=100,
    max_compression_ratio=100,
    ratio_warn_fraction=0.8,
)
STATIC_DIR = Path(app_package.__file__).parent / "scanners" / "static"


def analyze(tmp_path, files):
    src = tmp_path / "src"
    src.mkdir()
    for rel, data in files.items():
        write(src / rel, data)
    return analyze_artifact(src, LIMITS)


# ------------------------------------------------------------------ nothing is executed
def test_analyzed_python_is_never_executed_or_imported(tmp_path):
    canary = tmp_path / "CANARY"
    payload = f"import os\nos.mkdir({str(canary)!r})\nos.system('true')\n"
    result = analyze(
        tmp_path,
        {
            "evil_mod.py": payload,
            "setup.py": payload,
            "n.ipynb": json.dumps({"cells": [{"cell_type": "code", "source": payload}]}),
        },
    )
    assert result.features["suspicious_api_count"] == 3
    assert not canary.exists()
    assert "evil_mod" not in sys.modules


@pytest.mark.parametrize("path", sorted(STATIC_DIR.glob("*.py")), ids=lambda p: p.name)
def test_analyzer_source_has_no_execution_primitives(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    banned_modules = {"subprocess", "importlib", "pickle", "runpy"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not {a.name.split(".")[0] for a in node.names} & banned_modules
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in banned_modules
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in ("eval", "exec", "compile", "__import__")


# ------------------------------------------------------------------ malformed source
@pytest.mark.parametrize(
    "source",
    [
        b"",
        b"\x00\x00\x00",
        b"\xff\xfe\xfa",
        b"# -*- coding: no-such-codec -*-\nx = 1\n",
        b"x = '" + b"a" * 10_000,
        b"(" * 50_000,
        b"[" * 50_000 + b"]" * 50_000,
        b"-" * 50_000 + b"1",
        b"x" + b".a" * 50_000,
        b"def f():\n" + b" " * 100_000 + b"pass\n",
    ],
)
def test_malformed_or_extreme_python_never_raises(source):
    analyze_python(source)  # the contract: returns a result, whatever the input


def test_long_attribute_chain_within_parser_limits_is_resolved():
    source = "import os\n" + "x = os" + ".a" * 500 + "\n"
    assert analyze_python(source).parse_error is None


def test_hostile_names_are_bounded_in_text_symbols():
    hit = scan_text("curl " + "A" * 3000 + " | sh", "shell")
    assert all(len(h.symbol) <= 120 for h in hit)


# ------------------------------------------------------------------ regex performance
@pytest.mark.parametrize(
    ("text", "language"),
    [
        ("curl " + "a " * 200_000, "shell"),
        ("curl " * 50_000, "shell"),
        ("nc " + "-" * 200_000, "shell"),
        ("base64 -d " + "|" * 200_000, "shell"),
        ("require(" + " " * 200_000, "javascript"),
        ("eval" + " " * 200_000 + "(", "javascript"),
        ("-e " + "A" * 200_000, "powershell"),
        ("certutil " * 50_000, "batch"),
    ],
)
def test_pathological_lines_stay_fast(text, language):
    begin = time.monotonic()
    scan_text(text, language)
    assert time.monotonic() - begin < 2


def test_many_pathological_lines_stay_fast():
    begin = time.monotonic()
    scan_text(("curl " + "a" * 4000 + "\n") * 2000, "shell")
    assert time.monotonic() - begin < 10


# ------------------------------------------------------------------ other formats
@pytest.mark.parametrize(
    "raw",
    [b"[" * 200_000, b'{"scripts":' * 50_000, b"\x00" * 100],
)
def test_hostile_package_json_never_raises(raw):
    assert scan_package_json(raw) == []


def test_deeply_nested_notebook_is_a_parse_error(tmp_path):
    result = analyze(tmp_path, {"n.ipynb": b"[" * 200_000})
    assert result.features["parse_errors"] == 1


@pytest.mark.parametrize("name", ["notes.py", "a.sh", "a.js", "a.ps1", "a.bat"])
def test_binary_content_with_code_extension(tmp_path, name):
    result = analyze(tmp_path, {name: bytes(range(256)) * 100})
    assert result.features["files_analyzed"] == 1


# ------------------------------------------------------------------ nested archives
def test_nested_bomb_is_flagged_without_inflating(tmp_path, monkeypatch):
    import zipfile

    def no_inflate(*_a, **_k):
        raise AssertionError("a nested archive must never be decompressed")

    path = write(tmp_path / "bomb.zip", build_zip([("x.bin", b"\x00" * 2_000_000)]))
    monkeypatch.setattr(zipfile.ZipFile, "open", no_inflate)
    hits = inspect_nested_zip(path, 100)
    assert any("compression ratio" in h.symbol for h in hits)


def test_nested_entry_name_cannot_write_outside(tmp_path):
    result = analyze(tmp_path, {"inner.zip": build_zip([("../../../escaped", "x")])})
    assert result.features["archive_anomaly"] == 2
    assert [p for p in tmp_path.rglob("escaped")] == []


def test_huge_filename_is_bounded(tmp_path):
    name = "a" * 200 + ".bin"
    result = analyze(tmp_path, {name: b"\x7fELF...."})
    assert all(len(s) <= 180 for f in result.findings for s in f.symbols)


def test_symbols_are_safe_to_store_in_postgres(tmp_path):
    """PostgreSQL JSON and text reject NUL and lone surrogates; SQLite would not notice."""
    pkg = json.dumps({"scripts": {"install": "a\x00b\ud800c"}})
    result = analyze(
        tmp_path,
        {
            "package.json": pkg,
            "a.sh": "curl \x00x | sh\n",
            "inner.zip": build_zip([("../a\tb", "x")]),
        },
    )
    symbols = [s for f in result.findings for s in f.symbols]
    assert len(symbols) >= 3
    assert all("\x00" not in s and s.encode("utf-8") for s in symbols)
    assert all(s.isprintable() for s in symbols)


# ------------------------------------------------------------------ evidence honesty
def test_budget_never_reports_skipped_code_as_clean(tmp_path):
    src = tmp_path / "src"
    write(src / "evil.py", "import socket\n" * 1000)
    limits = StaticLimits(10, 16, 1024, 10, 100, 0.8)
    result = analyze_artifact(src, limits)
    assert result.features["dangerous_import_count"] == 0
    assert result.not_analyzed_count == 1  # 0 is only "clean" when this is also 0
