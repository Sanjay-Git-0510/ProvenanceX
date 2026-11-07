"""Functional tests for safe ZIP extraction. Hostile inputs are in tests/security."""

import zipfile

import pytest

from app.core.errors import AppError, ErrorCode
from app.security.archive import ArchiveLimits, normalize_member_name, safe_extract_zip
from tests.conftest import build_zip

LIMITS = ArchiveLimits(max_total_bytes=1024 * 1024, max_files=20, max_compression_ratio=100)


def _extract(tmp_path, data, limits=LIMITS):
    archive = tmp_path / "in.zip"
    archive.write_bytes(data)
    dest = tmp_path / "out"
    dest.mkdir()
    return safe_extract_zip(archive, dest, limits), dest


def test_extracts_files_and_dirs(tmp_path):
    data = build_zip([("pkg/", ""), ("pkg/a.py", "print('a')"), ("README.md", "# hi")])
    result, dest = _extract(tmp_path, data)
    assert (dest / "pkg" / "a.py").read_text() == "print('a')"
    assert (dest / "README.md").read_text() == "# hi"
    assert (result.file_count, result.dir_count) == (2, 1)
    assert result.total_bytes == len("print('a')") + len("# hi")


def test_stored_entries(tmp_path):
    data = build_zip([("a.txt", "abc")], compression=zipfile.ZIP_STORED)
    result, dest = _extract(tmp_path, data)
    assert (dest / "a.txt").read_text() == "abc"


def test_empty_archive(tmp_path):
    result, dest = _extract(tmp_path, build_zip([]))
    assert result.file_count == 0
    assert list(dest.iterdir()) == []


@pytest.mark.parametrize(
    ("name", "expected"),
    [("a.txt", "a.txt"), ("./a/./b.txt", "a/b.txt"), ("a//b", "a/b"), ("dir/", "dir")],
)
def test_normalize_member_name(name, expected):
    assert normalize_member_name(name) == expected


def test_not_a_zip(tmp_path):
    with pytest.raises(AppError) as exc:
        _extract(tmp_path, b"this is not a zip file")
    assert exc.value.code == ErrorCode.INVALID_ARCHIVE


def test_truncated_zip(tmp_path):
    data = build_zip([("a.txt", "x" * 5000)])
    with pytest.raises(AppError) as exc:
        _extract(tmp_path, data[: len(data) // 2])
    assert exc.value.code == ErrorCode.INVALID_ARCHIVE


def test_file_dir_conflict_is_invalid(tmp_path):
    data = build_zip([("a", "file"), ("a/b", "nested")])
    with pytest.raises(AppError) as exc:
        _extract(tmp_path, data)
    assert exc.value.code == ErrorCode.INVALID_ARCHIVE


def test_too_many_entries(tmp_path):
    data = build_zip([(f"f{i}.txt", "x") for i in range(21)])
    with pytest.raises(AppError) as exc:
        _extract(tmp_path, data)
    assert exc.value.code == ErrorCode.TOO_MANY_FILES


def test_total_size_limit(tmp_path):
    limits = ArchiveLimits(max_total_bytes=1000, max_files=20, max_compression_ratio=1000)
    data = build_zip([("a.bin", bytes(range(256)) * 4), ("b.bin", bytes(range(256)) * 4)])
    with pytest.raises(AppError) as exc:
        _extract(tmp_path, data, limits)
    assert exc.value.code == ErrorCode.ARTIFACT_TOO_LARGE
    assert exc.value.status_code == 413
