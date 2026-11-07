"""Security tests: hostile archives, SSRF, option injection and resource limits.

Every malicious archive is generated in memory at test time. None is committed.
"""

import io
import stat
import sys
import time
import warnings
import zipfile

import pytest

from app.core.errors import AppError, ErrorCode
from app.scanners.git_fetch import git_env, run_limited_command
from app.security import url_validation
from app.security.archive import ArchiveLimits, safe_extract_zip
from tests.conftest import build_zip, special_info, symlink_info

LIMITS = ArchiveLimits(max_total_bytes=4 * 1024 * 1024, max_files=50, max_compression_ratio=100)


def _extract(tmp_path, data):
    archive = tmp_path / "evil.zip"
    archive.write_bytes(data)
    dest = tmp_path / "jail" / "out"
    dest.mkdir(parents=True)
    return safe_extract_zip(archive, dest, LIMITS)


def _assert_nothing_escaped(tmp_path):
    allowed = {tmp_path / "evil.zip", tmp_path / "jail", tmp_path / "jail" / "out"}
    for p in tmp_path.rglob("*"):
        assert p in allowed or (tmp_path / "jail" / "out") in p.parents, f"escaped: {p}"


@pytest.mark.parametrize(
    ("entries", "reason"),
    [
        ([("../evil.txt", "x")], "path traversal"),
        ([("a/../../evil.txt", "x")], "path traversal"),
        ([("ok.txt", "x"), ("../../../../tmp/evil.txt", "x")], "path traversal"),
        ([("/etc/evil.txt", "x")], "absolute path"),
        ([("C:/evil.txt", "x")], "absolute path"),
        ([("C:\\evil.txt", "x")], "backslash in entry name"),
        ([("..\\..\\evil.txt", "x")], "backslash in entry name"),
        ([(symlink_info("link"), "/etc/passwd")], "symlink entry"),
        ([(symlink_info("dir/link"), "../../..")], "symlink entry"),
        ([(special_info("fifo", stat.S_IFIFO), "")], "special file entry"),
        ([(special_info("dev", stat.S_IFCHR), "")], "special file entry"),
    ],
)
def test_hostile_entry_names_and_types(tmp_path, entries, reason):
    with pytest.raises(AppError) as exc:
        _extract(tmp_path, build_zip(entries))
    assert exc.value.code == ErrorCode.UNSAFE_ARCHIVE
    assert exc.value.details["reason"] == reason
    _assert_nothing_escaped(tmp_path)


def test_validation_happens_before_any_write(tmp_path):
    data = build_zip([("good.txt", "fine"), ("../evil.txt", "x")])
    with pytest.raises(AppError):
        _extract(tmp_path, data)
    assert list((tmp_path / "jail" / "out").iterdir()) == []


def _set_encrypted_flag(data: bytes) -> bytes:
    """Set the 'encrypted' general-purpose bit in the local and central headers.

    zipfile clears flag_bits when writing, so the bit has to be patched into the raw bytes.
    """
    buf = bytearray(data)
    local = buf.index(b"PK\x03\x04")
    central = buf.index(b"PK\x01\x02")
    buf[local + 6] |= 0x1
    buf[central + 8] |= 0x1
    return bytes(buf)


def test_encrypted_entry(tmp_path):
    data = _set_encrypted_flag(build_zip([("secret.txt", "x")], compression=zipfile.ZIP_STORED))
    assert zipfile.ZipFile(io.BytesIO(data)).infolist()[0].flag_bits & 0x1
    with pytest.raises(AppError) as exc:
        _extract(tmp_path, data)
    assert exc.value.details["reason"] == "encrypted entry"


def test_duplicate_entries(tmp_path):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # zipfile warns on duplicate names
        data = build_zip([("a.txt", "first"), ("a.txt", "second")])
    with pytest.raises(AppError) as exc:
        _extract(tmp_path, data)
    assert exc.value.details["reason"] == "duplicate entry name"


def test_duplicate_after_normalization(tmp_path):
    data = build_zip([("a/b.txt", "1"), ("a/./b.txt", "2")])
    with pytest.raises(AppError) as exc:
        _extract(tmp_path, data)
    assert exc.value.details["reason"] == "duplicate entry name"


def test_decompression_bomb_ratio(tmp_path):
    data = build_zip([("zeros.bin", b"\0" * (3 * 1024 * 1024))])
    assert len(data) < 30_000  # highly compressible
    with pytest.raises(AppError) as exc:
        _extract(tmp_path, data)
    assert exc.value.code == ErrorCode.UNSAFE_ARCHIVE
    assert "decompression bomb" in exc.value.details["reason"]
    assert list((tmp_path / "jail" / "out").iterdir()) == []


def test_many_small_entries_over_file_limit(tmp_path):
    data = build_zip([(f"f{i}", "") for i in range(51)])
    with pytest.raises(AppError) as exc:
        _extract(tmp_path, data)
    assert exc.value.code == ErrorCode.TOO_MANY_FILES


# ---------------------------------------------------------------- SSRF via the API
@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1"])
def test_api_rejects_host_resolving_to_internal_ip(
    scan_client, session_factory, test_settings, monkeypatch, ip
):
    monkeypatch.setattr(url_validation, "resolve_host", lambda host: [ip])
    resp = scan_client.post("/api/v1/scans/software", data={"source_url": "https://github.com/a/b"})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "private_address"
    from app.db.models import Scan

    with session_factory() as s:
        assert s.query(Scan).count() == 0
    assert not test_settings.workspace_root.exists() or not any(
        test_settings.workspace_root.iterdir()
    )


@pytest.mark.parametrize(
    "revision", ["--upload-pack=touch /tmp/pwned", "-o", "main;id", "$(id)", "a..b"]
)
def test_api_rejects_option_injection_in_revision(scan_client, revision):
    resp = scan_client.post(
        "/api/v1/scans/software",
        data={"source_url": "https://github.com/a/b", "revision": revision},
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_revision"


# ---------------------------------------------------------------- process limits
def test_command_killed_on_timeout(tmp_path):
    start = time.monotonic()
    with pytest.raises(AppError) as exc:
        run_limited_command(
            ["sleep", "30"],
            env=git_env(tmp_path),
            watch_dir=tmp_path,
            deadline=time.monotonic() + 0.5,
            max_bytes=10**9,
            poll_interval=0.1,
        )
    assert exc.value.code == ErrorCode.CLONE_TIMEOUT
    assert time.monotonic() - start < 5


def test_command_killed_when_output_exceeds_size(tmp_path):
    script = (
        "import sys, time, pathlib;"
        "pathlib.Path(sys.argv[1], 'big.bin').write_bytes(b'x' * 2_000_000);"
        "time.sleep(30)"
    )
    start = time.monotonic()
    with pytest.raises(AppError) as exc:
        run_limited_command(
            [sys.executable, "-c", script, str(tmp_path)],
            env=git_env(tmp_path),
            watch_dir=tmp_path,
            deadline=time.monotonic() + 20,
            max_bytes=1_000_000,
            poll_interval=0.1,
        )
    assert exc.value.code == ErrorCode.ARTIFACT_TOO_LARGE
    assert time.monotonic() - start < 10
