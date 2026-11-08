"""Python source analysis using `ast`. The source is parsed, never compiled or imported.

Names are resolved through a file-wide alias table (scopes are not modeled), which
follows `import os as o`, `from os import system as s`, `run = os.system`,
`__import__("os")` and `importlib.import_module("os")`.

getattr() is only flagged when it can hide something. `getattr(obj, name)` is everywhere
in ordinary code, so a variable name is flagged only on a sensitive module, and a
computed name (concatenation, f-string, call) is flagged on anything.
`getattr(os, "system")` resolves to os.system.
"""

import ast
import warnings
from dataclasses import dataclass

from app.scanners.static.rules import (
    API_DYNAMIC_IMPORT,
    API_EVAL,
    API_EXEC_DECODED,
    API_OBFUSCATION,
    API_RULES,
    DECODER_CALLS,
    SENSITIVE_ROOTS,
    Rule,
    import_rule,
)

_BUILTIN_PREFIXES = ("builtins.", "__builtin__.", "__builtins__.")
_DYNAMIC_IMPORTERS = frozenset({"__import__", "importlib.import_module"})
_BUILTIN_CALLABLES = frozenset({"eval", "exec", "compile", "__import__", "getattr"})
_COMPUTED_NAME_NODES = (ast.BinOp, ast.JoinedStr, ast.Call)


@dataclass(frozen=True)
class Hit:
    rule: Rule
    symbol: str
    line: int | None = None
    cell: int | None = None  # notebook cell index


@dataclass
class PythonResult:
    hits: list[Hit]
    parse_error: str | None = None


def _literal_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _strip_builtins(name: str) -> str:
    for prefix in _BUILTIN_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


class _Resolver:
    def __init__(self, tree: ast.AST) -> None:
        self.aliases: dict[str, str] = {}
        self.decoded_names: set[str] = set()
        nodes = list(ast.walk(tree))
        for node in nodes:
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.aliases[a.asname] = a.name
                    else:
                        root = a.name.split(".")[0]
                        self.aliases[root] = root
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                for a in node.names:
                    self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"
        for node in nodes:
            if not (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                continue
            target = node.targets[0].id
            value = self.resolve(node.value)
            if value is not None and self._tracked(value):
                self.aliases[target] = value
            if self.contains_decoder(node.value):
                self.decoded_names.add(target)

    @staticmethod
    def _tracked(name: str) -> bool:
        return (
            name in API_RULES
            or name in DECODER_CALLS
            or name in _BUILTIN_CALLABLES
            or name in SENSITIVE_ROOTS
            or import_rule(name) is not None
        )

    def resolve(self, node: ast.AST) -> str | None:
        """Dotted name of an expression, through aliases. Iterative: chains can be long."""
        parts: list[str] = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            root = self.aliases.get(current.id, current.id)
        elif isinstance(current, ast.Call):
            func = self.resolve(current.func)
            if func not in _DYNAMIC_IMPORTERS or not current.args:
                return None
            literal = _literal_str(current.args[0])
            if literal is None:
                return None
            root = literal
        else:
            return None
        parts.append(root)
        return _strip_builtins(".".join(reversed(parts)))

    def contains_decoder(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and self.resolve(child.func) in DECODER_CALLS:
                return True
            if isinstance(child, ast.Name) and child.id in self.decoded_names:
                return True
        return False


def _check_getattr(res: _Resolver, call: ast.Call, line: int | None) -> Hit | None:
    if len(call.args) < 2:
        return None
    target = res.resolve(call.args[0])
    literal = _literal_str(call.args[1])
    if literal is not None:
        if target is None:
            return None
        qualified = _strip_builtins(f"{target}.{literal}")
        rule = API_RULES.get(qualified)
        return Hit(rule, qualified, line) if rule else None
    computed = isinstance(call.args[1], _COMPUTED_NAME_NODES)
    sensitive = target is not None and target.split(".")[0] in SENSITIVE_ROOTS
    if computed or sensitive:
        return Hit(API_OBFUSCATION, f"getattr({target or '<expr>'}, <dynamic>)", line)
    return None


def _check_call(res: _Resolver, call: ast.Call) -> Hit | None:
    name = res.resolve(call.func)
    if name is None:
        return None
    line = getattr(call, "lineno", None)
    if name in _DYNAMIC_IMPORTERS:
        literal = _literal_str(call.args[0]) if call.args else None
        if literal is None:
            return Hit(API_DYNAMIC_IMPORT, name, line)
        rule = import_rule(literal)
        return Hit(rule, literal, line) if rule else None
    if name == "getattr":
        return _check_getattr(res, call, line)
    if name in ("eval", "exec"):
        if any(res.contains_decoder(arg) for arg in call.args):
            return Hit(API_EXEC_DECODED, name, line)
        return Hit(API_EVAL, name, line)
    rule = API_RULES.get(name)
    return Hit(rule, name, line) if rule else None


def _check_imports(node: ast.Import | ast.ImportFrom) -> list[Hit]:
    hits: list[Hit] = []
    if isinstance(node, ast.Import):
        for a in node.names:
            if rule := import_rule(a.name):
                hits.append(Hit(rule, a.name, node.lineno))
    elif node.level == 0 and node.module:
        rule = import_rule(node.module)
        if rule:
            hits.append(Hit(rule, node.module, node.lineno))
        else:
            for a in node.names:
                full = f"{node.module}.{a.name}"
                if rule := import_rule(full):
                    hits.append(Hit(rule, full, node.lineno))
    return hits


def parse_python(source: bytes | str) -> tuple[ast.AST | None, str | None]:
    """Parse untrusted source. Returns (tree, None) or (None, reason)."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # artifact-controlled text must not reach the logs
            return ast.parse(source, filename="<artifact>"), None
    except SyntaxError:
        return None, "syntax error"
    except (ValueError, RecursionError, MemoryError) as exc:
        return None, exc.__class__.__name__


def analyze_tree(tree: ast.AST, cell: int | None = None) -> list[Hit]:
    res = _Resolver(tree)
    hits: list[Hit] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import | ast.ImportFrom):
            hits.extend(_check_imports(node))
        elif isinstance(node, ast.Call) and (hit := _check_call(res, node)):
            hits.append(hit)
    if cell is None:
        return hits
    return [Hit(h.rule, h.symbol, h.line, cell) for h in hits]


def analyze_python(source: bytes | str, cell: int | None = None) -> PythonResult:
    tree, error = parse_python(source)
    if tree is None:
        return PythonResult([], error)
    return PythonResult(analyze_tree(tree, cell))


__all__ = ["API_EVAL", "Hit", "PythonResult", "analyze_python", "analyze_tree", "parse_python"]
