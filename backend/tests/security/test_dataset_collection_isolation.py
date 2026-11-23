"""The network-using dataset collectors are tooling only: no service code may import them."""

import ast
from pathlib import Path

APP = Path(__file__).resolve().parents[2] / "app"


def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_no_service_code_imports_dataset_collection():
    offenders = [
        str(p.relative_to(APP))
        for p in APP.rglob("*.py")
        if "dataset_collection" not in p.parts
        and any(n.startswith("app.dataset_collection") for n in _imports(p))
    ]
    assert offenders == []
