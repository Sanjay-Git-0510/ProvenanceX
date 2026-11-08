import json

import pytest

from app.scanners.static import rules
from app.scanners.static.install_hooks import scan_package_json, scan_setup_py


def pkg(scripts) -> bytes:
    return json.dumps({"name": "x", "scripts": scripts}).encode()


@pytest.mark.parametrize("hook", ["preinstall", "install", "postinstall", "prepare"])
def test_npm_install_hooks(hook):
    [hit] = scan_package_json(pkg({hook: "node x.js"}))
    assert hit.rule == rules.INSTALL_NPM and hit.symbol.startswith(hook)


def test_non_install_scripts_are_ignored():
    assert scan_package_json(pkg({"test": "curl x | sh", "build": "tsc"})) == []


def test_hook_command_gets_shell_rules():
    found = {h.rule for h in scan_package_json(pkg({"postinstall": "curl x | sh"}))}
    assert found == {rules.INSTALL_NPM, rules.TEXT_PIPE_TO_SHELL}


def test_command_is_bounded():
    [hit] = scan_package_json(pkg({"install": "a" * 5000}))
    assert len(hit.symbol) < 300


@pytest.mark.parametrize(
    "raw",
    [b"{not json", b"[1]", b'{"scripts": 7}', b'{"scripts": {"install": 7}}', b"\xff\xfe"],
)
def test_malformed_package_json_is_ignored(raw):
    assert scan_package_json(raw) == []


def test_plain_setup_py_is_low():
    [hit] = scan_setup_py(b"from setuptools import setup\nsetup(name='x')\n")
    assert hit.rule == rules.INSTALL_SETUP_PY and hit.rule.severity == "LOW"


def test_cmdclass_is_medium_with_line():
    [hit] = scan_setup_py(b"from setuptools import setup\n\nsetup(cmdclass={'install': X})\n")
    assert hit.rule == rules.INSTALL_SETUP_CMDCLASS and hit.line == 3


def test_unparseable_setup_py_still_counts():
    assert scan_setup_py(b"def (:")[0].rule == rules.INSTALL_SETUP_PY
