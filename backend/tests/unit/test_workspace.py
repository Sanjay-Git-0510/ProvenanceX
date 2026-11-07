import io
import stat
import uuid

import pytest

from app.core.errors import AppError, ErrorCode
from app.pipeline.workspace import (
    Workspace,
    create_workspace,
    directory_size,
    open_workspace,
    remove_workspace,
    resolve_within,
    write_stream_limited,
)


def test_create_workspace_layout_and_permissions(tmp_path):
    scan_id = uuid.uuid4()
    ws = create_workspace(tmp_path / "base", scan_id)
    assert ws.root == (tmp_path / "base").resolve() / str(scan_id)
    for d in (ws.root, ws.input_dir, ws.src_dir):
        assert d.is_dir()
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
    assert ws.upload_path == ws.input_dir / "upload.zip"


def test_create_workspace_twice_fails(tmp_path):
    scan_id = uuid.uuid4()
    create_workspace(tmp_path, scan_id)
    with pytest.raises(AppError) as exc:
        create_workspace(tmp_path, scan_id)
    assert exc.value.code == ErrorCode.WORKSPACE_ERROR


def test_open_missing_workspace(tmp_path):
    with pytest.raises(AppError) as exc:
        open_workspace(tmp_path, uuid.uuid4())
    assert exc.value.code == ErrorCode.WORKSPACE_ERROR


def test_open_workspace_rejects_symlink(tmp_path):
    scan_id = uuid.uuid4()
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / str(scan_id)).symlink_to(tmp_path / "elsewhere")
    with pytest.raises(AppError):
        open_workspace(tmp_path, scan_id)


def test_remove_workspace(tmp_path):
    ws = create_workspace(tmp_path, uuid.uuid4())
    (ws.src_dir / "f.txt").write_text("x")
    remove_workspace(ws, tmp_path)
    assert not ws.root.exists()
    remove_workspace(ws, tmp_path)  # idempotent


def test_remove_workspace_refuses_paths_outside_base(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("x")
    remove_workspace(Workspace(outside), tmp_path / "base")
    assert (outside / "keep.txt").exists()


def test_resolve_within(tmp_path):
    assert resolve_within(tmp_path, "a", "b") == tmp_path.resolve() / "a" / "b"
    for parts in (("..", "x"), ("/etc/passwd",), ("a", "../../x")):
        with pytest.raises(AppError) as exc:
            resolve_within(tmp_path, *parts)
        assert exc.value.code == ErrorCode.UNSAFE_CONTENT


def test_directory_size_does_not_follow_symlinks(tmp_path):
    (tmp_path / "a.bin").write_bytes(b"x" * 100)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.bin").write_bytes(b"y" * 50)
    big = tmp_path.parent / f"big-{uuid.uuid4()}.bin"
    big.write_bytes(b"z" * 10_000)
    (tmp_path / "link").symlink_to(big)
    size = directory_size(tmp_path)
    assert 150 <= size < 10_000


def test_write_stream_limited(tmp_path):
    dest = tmp_path / "out.bin"
    assert write_stream_limited(io.BytesIO(b"a" * 1000), dest, 1000) == 1000
    assert dest.read_bytes() == b"a" * 1000


def test_write_stream_limited_rejects_oversize(tmp_path):
    with pytest.raises(AppError) as exc:
        write_stream_limited(io.BytesIO(b"a" * 1001), tmp_path / "out.bin", 1000)
    assert exc.value.code == ErrorCode.ARTIFACT_TOO_LARGE
    assert exc.value.status_code == 413


def test_write_stream_limited_never_overwrites(tmp_path):
    dest = tmp_path / "out.bin"
    dest.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        write_stream_limited(io.BytesIO(b"new"), dest, 1000)
