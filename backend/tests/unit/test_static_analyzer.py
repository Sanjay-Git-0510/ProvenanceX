import json

import pytest

from app.scanners.static import rules
from app.scanners.static.analyzer import StaticLimits, analyze_artifact
from tests.conftest import build_zip
from tests.model_helpers import write


def limits(**kw) -> StaticLimits:
    base = {
        "max_files": 100,
        "max_file_bytes": 100_000,
        "max_total_bytes": 1_000_000,
        "max_findings": 100,
        "max_compression_ratio": 100,
        "ratio_warn_fraction": 0.8,
    }
    return StaticLimits(**{**base, **kw})


def run(tmp_path, files: dict, **kw):
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    for rel, data in files.items():
        write(src / rel, data)
    return analyze_artifact(src, kw.pop("limits", limits()), **kw)


def ids(result) -> set[str]:
    return {f.rule.id for f in result.findings}


def test_clean_project_has_zero_counts_and_full_coverage(tmp_path):
    r = run(tmp_path, {"a.py": "import json\nprint(json.dumps({}))\n", "README.md": "hi"})
    f = r.features
    assert f["dangerous_import_count"] == 0 and f["suspicious_api_count"] == 0
    assert f["archive_anomaly"] == 0 and f["script_presence"] is True
    assert f["script_count"] == 1 and f["files_analyzed"] == 2
    assert r.findings == [] and r.not_analyzed_count == 0


def test_no_scripts(tmp_path):
    assert run(tmp_path, {"data.csv": "1,2"}).features["script_presence"] is False


def test_features_count_occurrences_and_findings_group_by_rule_and_file(tmp_path):
    src = "import os\nos.system('a')\nos.system('b')\n"
    r = run(tmp_path, {"a.py": src, "b.py": src})
    assert r.features["suspicious_api_count"] == 4
    assert len(r.findings) == 2
    a = next(f for f in r.findings if f.file == "a.py")
    assert a.occurrences == 2 and a.lines == [2, 3] and a.symbols == ["os.system"]


def test_findings_sorted_by_severity(tmp_path):
    r = run(tmp_path, {"a.py": "import socket\n", "b.sh": "curl x | sh\n"})
    assert [f.rule.severity for f in r.findings] == ["HIGH", "LOW"]


def test_findings_are_capped_but_features_are_not(tmp_path):
    files = {f"f{i}.py": "import socket\n" for i in range(5)}
    r = run(tmp_path, files, limits=limits(max_findings=2))
    assert len(r.findings) == 2 and r.findings_truncated is True
    assert r.features["dangerous_import_count"] == 5


@pytest.mark.parametrize(
    ("name", "content", "rule"),
    [
        ("install.sh", "curl x | sh", rules.TEXT_PIPE_TO_SHELL),
        ("run.bat", "certutil -urlcache -f u a", rules.TEXT_BATCH_DOWNLOAD),
        ("a.ps1", "Invoke-Expression $x", rules.TEXT_PS_DOWNLOAD_EXEC),
        ("a.js", "require('child_process')", rules.TEXT_JS_CHILD_PROCESS),
        ("tool", "#!/bin/bash\ncurl x | sh\n", rules.TEXT_PIPE_TO_SHELL),
        ("tool2", "#!/usr/bin/env python3\nimport socket\n", rules.IMPORT_NETWORK),
        ("tool3", "#!/usr/bin/env node\neval(x)\n", rules.TEXT_JS_EVAL),
    ],
)
def test_language_routing(tmp_path, name, content, rule):
    assert rule.id in ids(run(tmp_path, {name: content}))


def test_unknown_files_are_not_scanned_as_code(tmp_path):
    assert run(tmp_path, {"notes.txt": "curl x | sh\nimport socket\n"}).findings == []


def test_unparseable_python_falls_back_to_text_rules(tmp_path):
    r = run(tmp_path, {"a.py": "def (:\nos.system('x')\n"})
    assert r.features["parse_errors"] == 1
    assert rules.TEXT_PY_FALLBACK.id in ids(r)
    assert any("could not be parsed" in lim for lim in r.limitations)


def test_notebook_code_cells(tmp_path):
    nb = {
        "cells": [
            {"cell_type": "markdown", "source": ["import socket"]},
            {"cell_type": "code", "source": ["%pip install x\n", "import os\n", "os.system('a')"]},
            {"cell_type": "code", "source": "import socket"},
        ]
    }
    r = run(tmp_path, {"n.ipynb": json.dumps(nb)})
    assert r.features["suspicious_api_count"] == 1 and r.features["dangerous_import_count"] == 1
    assert {tuple(f.cells) for f in r.findings} == {(1,), (2,)}


@pytest.mark.parametrize("data", ["{not json", "[1]", '{"cells": 3}'])
def test_malformed_notebook_counts_as_parse_error(tmp_path, data):
    assert run(tmp_path, {"n.ipynb": data}).features["parse_errors"] == 1


def test_setup_py_and_package_json_are_install_hooks(tmp_path):
    r = run(
        tmp_path,
        {
            "setup.py": "from setuptools import setup\nsetup(cmdclass={})\n",
            "package.json": json.dumps({"scripts": {"postinstall": "node x"}}),
        },
    )
    assert {rules.INSTALL_SETUP_CMDCLASS.id, rules.INSTALL_NPM.id} <= ids(r)
    assert r.features["install_hook_count"] == 2


def test_auto_map_targets_and_pickle_counts_come_from_the_caller(tmp_path):
    r = run(tmp_path, {"a.txt": "x"}, auto_map_targets=3, pickle_dangerous_globals=2)
    assert r.features["install_hook_count"] == 3
    assert r.features["pickle_dangerous_global_count"] == 2
    assert r.findings == []  # the AI-BOM stage already reported those


def test_pickle_count_defaults_to_none_not_zero(tmp_path):
    assert run(tmp_path, {"a.txt": "x"}).features["pickle_dangerous_global_count"] is None


def test_node_modules_and_nested_git_are_skipped(tmp_path):
    r = run(
        tmp_path,
        {"node_modules/x/a.py": "import socket\n", "sub/.git/hooks/h.py": "import socket\n"},
    )
    assert r.findings == [] and r.features["files_analyzed"] == 0


def test_file_budget_reports_what_was_skipped(tmp_path):
    r = run(tmp_path, {f"f{i}.py": "x=1\n" for i in range(5)}, limits=limits(max_files=2))
    assert r.features["files_analyzed"] == 2 and r.not_analyzed_count == 3
    assert r.not_analyzed[0]["reason"] == "file budget reached"


def test_large_file_is_skipped_and_reported(tmp_path):
    r = run(tmp_path, {"big.py": "x = 1\n" * 100}, limits=limits(max_file_bytes=10))
    assert r.not_analyzed_count == 1 and "per-file" in r.not_analyzed[0]["reason"]


def test_large_non_code_file_is_not_incomplete(tmp_path):
    r = run(tmp_path, {"big.bin": b"\x00" * 200}, limits=limits(max_file_bytes=10))
    assert r.not_analyzed_count == 0


def test_total_budget(tmp_path):
    files = {"a.py": "x = 1\n" * 10, "b.py": "x = 1\n" * 10}
    r = run(tmp_path, files, limits=limits(max_total_bytes=70))
    assert r.not_analyzed_count == 1 and "total" in r.not_analyzed[0]["reason"]


def test_not_analyzed_list_is_bounded(tmp_path):
    r = run(tmp_path, {f"f{i}.py": "x=1\n" for i in range(60)}, limits=limits(max_files=1))
    assert r.not_analyzed_count == 59 and len(r.not_analyzed) == 50


def test_undownloaded_files_count_as_not_analyzed(tmp_path):
    r = run(tmp_path, {"a.txt": "x"}, undownloaded_files=4)
    assert r.not_analyzed_count == 4
    assert any("4 listed" in lim for lim in r.limitations)


def test_archive_anomalies_feed_the_feature(tmp_path):
    r = run(
        tmp_path,
        {
            "inner.zip": build_zip([("../evil", "x")]),
            "data.tar.gz": b"x",
            "model.bin": b"\x7fELF....",
        },
    )
    assert r.features["archive_anomaly"] == 4  # nested, unsafe, opaque, disguised
    assert {rules.ARCHIVE_UNSAFE.id, rules.ARCHIVE_DISGUISED_EXE.id} <= ids(r)


def test_upload_ratio_is_attributed_to_the_uploaded_archive(tmp_path):
    upload = write(tmp_path / "u.zip", build_zip([("a.bin", b"\x00" * 100_000)]))
    r = run(
        tmp_path,
        {"a.txt": "x"},
        upload_path=upload,
        limits=limits(max_compression_ratio=1500, ratio_warn_fraction=0.1),
    )
    assert [f.file for f in r.findings] == ["(uploaded archive)"]


def test_binary_counts(tmp_path):
    r = run(tmp_path, {"a.pyc": b"x", "b.so": b"x"})
    assert r.features["bytecode_count"] == 1 and r.features["native_binary_count"] == 1
