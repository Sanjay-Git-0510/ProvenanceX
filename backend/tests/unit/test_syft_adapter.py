"""SyftProvider tests using a fake `syft` executable (no real Syft needed)."""

import json
import os
import stat
from pathlib import Path

import pytest

from app.core.errors import AppError, ErrorCode
from app.scanners.sbom.syft import SyftProvider

MINIMAL_SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}


def _fake_syft(tmp_path: Path, body: str) -> Path:
    """Write an executable shell script that stands in for syft.

    It handles `version -o json` and otherwise runs `body`, where $OUT is the path from
    the `-o cyclonedx-json=<path>` argument.
    """
    script = tmp_path / "bin" / "syft"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "version" ]; then echo \'{"version": "9.9.9-fake"}\'; exit 0; fi\n'
        'OUT=""\n'
        'for a in "$@"; do case "$a" in cyclonedx-json=*) OUT="${a#cyclonedx-json=}";; esac; done\n'
        'env > "$(dirname "$OUT")/env.txt"\n'
        'pwd > "$(dirname "$OUT")/cwd.txt"\n'
        'printf "%s\\n" "$@" > "$(dirname "$OUT")/argv.txt"\n'
        f"{body}\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


@pytest.fixture
def dirs(tmp_path):
    work = tmp_path / "ws"
    src = work / "src"
    src.mkdir(parents=True)
    (src / "requirements.txt").write_text("flask==3.0.3\n")
    return src, work


def _provider(script, timeout=10, max_bytes=10**6):
    return SyftProvider(str(script), timeout, max_bytes)


def test_success_reads_output_and_version(tmp_path, dirs, monkeypatch):
    src, work = dirs
    payload = json.dumps(MINIMAL_SBOM)
    script = _fake_syft(tmp_path, f"echo '{payload}' > \"$OUT\"")
    monkeypatch.setenv("NVD_API_KEY", "secret-should-not-leak")
    monkeypatch.setenv("DATABASE_URL", "postgresql://secret")
    result = _provider(script).generate(src, work)
    assert json.loads(result.raw) == MINIMAL_SBOM
    assert result.source == "syft"
    assert result.tool_version == "9.9.9-fake"
    assert not (work / "sbom.syft.cdx.json").exists()  # temp output removed

    argv = (work / "argv.txt").read_text().splitlines()
    assert argv[0] == "scan" and argv[1] == f"dir:{src.resolve()}"
    assert "--exclude" in argv and "./.git/**" in argv
    assert not any(a.startswith("--enrich") for a in argv)
    # cwd is the trusted workspace, never the untrusted source dir
    assert Path((work / "cwd.txt").read_text().strip()).resolve() == work.resolve()
    env = (work / "env.txt").read_text()
    assert "SYFT_CHECK_FOR_APP_UPDATE=false" in env
    assert "secret-should-not-leak" not in env
    assert "DATABASE_URL" not in env


def test_missing_binary_is_unavailable(dirs):
    src, work = dirs
    with pytest.raises(AppError) as exc:
        SyftProvider("definitely-not-a-real-syft-binary", 5, 1000).generate(src, work)
    assert exc.value.code == ErrorCode.SBOM_TOOL_UNAVAILABLE


def test_nonzero_exit_is_failed_with_stderr_tail(tmp_path, dirs):
    src, work = dirs
    script = _fake_syft(tmp_path, 'echo "boom: cataloger crashed" >&2; exit 3')
    with pytest.raises(AppError) as exc:
        _provider(script).generate(src, work)
    assert exc.value.code == ErrorCode.SBOM_FAILED
    assert exc.value.details["returncode"] == 3
    assert "cataloger crashed" in exc.value.details["stderr_tail"]


def test_timeout(tmp_path, dirs):
    src, work = dirs
    script = _fake_syft(tmp_path, "sleep 5")
    with pytest.raises(AppError) as exc:
        _provider(script, timeout=1).generate(src, work)
    assert exc.value.code == ErrorCode.SBOM_TIMEOUT


def test_oversize_output_rejected_and_removed(tmp_path, dirs):
    src, work = dirs
    script = _fake_syft(tmp_path, 'head -c 5000 /dev/zero > "$OUT"')
    with pytest.raises(AppError) as exc:
        _provider(script, max_bytes=1000).generate(src, work)
    assert exc.value.code == ErrorCode.SBOM_TOO_LARGE
    assert not (work / "sbom.syft.cdx.json").exists()


def test_no_output_file(tmp_path, dirs):
    src, work = dirs
    script = _fake_syft(tmp_path, "exit 0")
    with pytest.raises(AppError) as exc:
        _provider(script).generate(src, work)
    assert exc.value.code == ErrorCode.SBOM_FAILED


def test_work_dir_inside_source_refused(tmp_path, dirs):
    src, _ = dirs
    script = _fake_syft(tmp_path, "exit 0")
    with pytest.raises(AppError) as exc:
        _provider(script).generate(src, src / "sub")
    assert exc.value.code == ErrorCode.WORKSPACE_ERROR


def test_version_failure_returns_none(tmp_path):
    script = tmp_path / "syft"
    script.write_text("#!/bin/sh\nexit 1\n")
    script.chmod(0o755)
    assert SyftProvider(str(script), 5, 1000).version() is None
    assert os.access(script, os.X_OK)
