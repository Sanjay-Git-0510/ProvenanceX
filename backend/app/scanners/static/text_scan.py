"""Line-based rules for shell, batch, PowerShell, JavaScript and unparseable Python.

Patterns use bounded repeats and each line is truncated first, so hostile input cannot
cause catastrophic regex backtracking.
"""

import re

from app.scanners.static.python_ast import Hit
from app.scanners.static.rules import (
    TEXT_BATCH_DOWNLOAD,
    TEXT_JS_CHILD_PROCESS,
    TEXT_JS_EVAL,
    TEXT_PIPE_TO_SHELL,
    TEXT_PS_DOWNLOAD_EXEC,
    TEXT_PS_ENCODED,
    TEXT_PY_FALLBACK,
    TEXT_REVERSE_SHELL,
    Rule,
)

MAX_LINE_CHARS = 4096
MAX_HITS_PER_FILE = 200

_SHELL_NAMES = r"(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
_SHELL_RULES: list[tuple[re.Pattern[str], Rule]] = [
    (
        re.compile(rf"\b(?:curl|wget)\b[^\n|]{{0,1000}}\|\s{{0,8}}{_SHELL_NAMES}"),
        TEXT_PIPE_TO_SHELL,
    ),
    (
        re.compile(rf"\bbase64\s+(?:-d|--decode)\b[^\n|]{{0,1000}}\|\s{{0,8}}{_SHELL_NAMES}"),
        TEXT_PIPE_TO_SHELL,
    ),
    (re.compile(r"/dev/(?:tcp|udp)/"), TEXT_REVERSE_SHELL),
    (re.compile(r"\bbash\s+-i\b[^\n]{0,200}>&"), TEXT_REVERSE_SHELL),
    (re.compile(r"\bnc(?:at)?\b[^\n]{0,200}\s-[a-z]{0,8}e\b"), TEXT_REVERSE_SHELL),
]
_JS_RULES: list[tuple[re.Pattern[str], Rule]] = [
    (
        re.compile(r"""(?:require\s{0,8}\(\s{0,8}|from\s{1,8})['"](?:node:)?child_process['"]"""),
        TEXT_JS_CHILD_PROCESS,
    ),
    (re.compile(r"(?<![\w.$])eval\s{0,8}\("), TEXT_JS_EVAL),
    (re.compile(r"\bnew\s{1,8}Function\s{0,8}\("), TEXT_JS_EVAL),
]
_PS_FLAGS = re.IGNORECASE
_PS_RULES: list[tuple[re.Pattern[str], Rule]] = [
    (
        re.compile(r"\s-e(?:nc|ncodedcommand)?\s{1,8}[A-Za-z0-9+/=]{16,}", _PS_FLAGS),
        TEXT_PS_ENCODED,
    ),
    (re.compile(r"\bInvoke-Expression\b|\biex\s{1,8}[(\"'$]", _PS_FLAGS), TEXT_PS_DOWNLOAD_EXEC),
    (re.compile(r"\bDownloadString\b|\bDownloadFile\b", _PS_FLAGS), TEXT_PS_DOWNLOAD_EXEC),
]
_BATCH_RULES: list[tuple[re.Pattern[str], Rule]] = [
    (re.compile(r"\bcertutil\b[^\n]{0,200}-urlcache\b", _PS_FLAGS), TEXT_BATCH_DOWNLOAD),
    (re.compile(r"\bbitsadmin\b[^\n]{0,200}/transfer\b", _PS_FLAGS), TEXT_BATCH_DOWNLOAD),
    (re.compile(r"\bpowershell\b[^\n]{0,200}\s-e(?:nc\w*)?\s", _PS_FLAGS), TEXT_PS_ENCODED),
]
_PY_FALLBACK_RULES: list[tuple[re.Pattern[str], Rule]] = [
    (
        re.compile(
            r"\bos\.(?:system|popen)\s{0,8}\(|\bsubprocess\.\w+\s{0,8}\("
            r"|(?<![\w.])(?:eval|exec)\s{0,8}\(|\b__import__\s{0,8}\("
        ),
        TEXT_PY_FALLBACK,
    ),
]
RULES_BY_LANGUAGE: dict[str, list[tuple[re.Pattern[str], Rule]]] = {
    "shell": _SHELL_RULES,
    "javascript": _JS_RULES,
    "powershell": _PS_RULES + _SHELL_RULES[:1],
    "batch": _BATCH_RULES,
    "python_unparsed": _PY_FALLBACK_RULES + _SHELL_RULES,
}


def scan_text(text: str, language: str) -> list[Hit]:
    """Apply the rules for `language`. Symbols are bounded excerpts of the matched text."""
    rules = RULES_BY_LANGUAGE[language]
    hits: list[Hit] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw[:MAX_LINE_CHARS]
        for pattern, rule in rules:
            if match := pattern.search(line):
                hits.append(Hit(rule, match.group(0)[:120], number))
                if len(hits) >= MAX_HITS_PER_FILE:
                    return hits
    return hits
