"""Install-time code execution hooks: npm lifecycle scripts and setup.py. Parse only."""

import ast
import json

from app.scanners.static.python_ast import Hit, parse_python
from app.scanners.static.rules import INSTALL_NPM, INSTALL_SETUP_CMDCLASS, INSTALL_SETUP_PY
from app.scanners.static.text_scan import scan_text

NPM_INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")
MAX_COMMAND_CHARS = 256


def scan_package_json(raw: bytes) -> list[Hit]:
    """Lifecycle scripts, plus the shell rules applied to their commands."""
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return []
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return []
    hits: list[Hit] = []
    for hook in NPM_INSTALL_HOOKS:
        command = scripts.get(hook)
        if isinstance(command, str):
            hits.append(Hit(INSTALL_NPM, f"{hook}: {command[:MAX_COMMAND_CHARS]}"))
            hits.extend(scan_text(command, "shell"))
    return hits


def scan_setup_py(source: bytes) -> list[Hit]:
    """setup.py always runs on install. Overriding `cmdclass` is a stronger signal."""
    tree, _ = parse_python(source)
    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and any(k.arg == "cmdclass" for k in node.keywords):
                return [Hit(INSTALL_SETUP_CMDCLASS, "setup(cmdclass=...)", node.lineno)]
    return [Hit(INSTALL_SETUP_PY, "setup.py")]
