import hashlib
import os

import pytest

from app.core.errors import AppError, ErrorCode
from app.core.hashing import TREE_DIGEST_VERSION, sha256_bytes, sha256_file, tree_digest


def test_sha256_known_vectors():
    assert sha256_bytes(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256_bytes(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_sha256_file_streams_multiple_chunks(tmp_path):
    data = os.urandom(3 * 1024 * 1024 + 17)
    path = tmp_path / "blob.bin"
    path.write_bytes(data)
    assert sha256_file(path) == hashlib.sha256(data).hexdigest()


def _write(root, files):
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)


def test_tree_digest_documented_format(tmp_path):
    _write(tmp_path, {"b.txt": b"B", "a/x.txt": b"X"})
    expected = hashlib.sha256(f"{TREE_DIGEST_VERSION}\n".encode())
    for rel, content in sorted({"a/x.txt": b"X", "b.txt": b"B"}.items()):
        expected.update(rel.encode() + b"\0" + hashlib.sha256(content).hexdigest().encode() + b"\n")
    result = tree_digest(tmp_path)
    assert result.sha256 == expected.hexdigest()
    assert (result.file_count, result.total_bytes) == (2, 2)


def test_tree_digest_independent_of_creation_order_and_empty_dirs(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    files = {"x/1.txt": b"one", "y/2.txt": b"two", "3.txt": b"three"}
    _write(a, files)
    _write(b, dict(reversed(list(files.items()))))
    (b / "empty_dir").mkdir()
    assert tree_digest(a).sha256 == tree_digest(b).sha256


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: (r / "f.txt").write_bytes(b"changed"),
        lambda r: (r / "f.txt").rename(r / "g.txt"),
        lambda r: (r / "new.txt").write_bytes(b""),
    ],
    ids=["content", "rename", "added-empty-file"],
)
def test_tree_digest_detects_changes(tmp_path, mutation):
    (tmp_path / "f.txt").write_bytes(b"original")
    before = tree_digest(tmp_path).sha256
    mutation(tmp_path)
    assert tree_digest(tmp_path).sha256 != before


def test_tree_digest_excludes_top_level_git_only(tmp_path):
    (tmp_path / "f.txt").write_bytes(b"x")
    baseline = tree_digest(tmp_path).sha256
    _write(tmp_path, {".git/HEAD": b"ref: refs/heads/main"})
    assert tree_digest(tmp_path).sha256 == baseline
    _write(tmp_path, {"sub/.git/HEAD": b"nested"})
    assert tree_digest(tmp_path).sha256 != baseline


@pytest.mark.parametrize("kind", ["file", "dir"])
def test_tree_digest_rejects_symlinks(tmp_path, kind):
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "f.txt").write_bytes(b"x")
    target = tmp_path / "real" / ("f.txt" if kind == "file" else "")
    os.symlink(target, tmp_path / "link")
    with pytest.raises(AppError) as exc:
        tree_digest(tmp_path)
    assert exc.value.code == ErrorCode.UNSAFE_CONTENT


def test_tree_digest_rejects_fifo(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(AppError) as exc:
        tree_digest(tmp_path)
    assert exc.value.code == ErrorCode.UNSAFE_CONTENT


def test_tree_digest_max_files(tmp_path):
    for i in range(4):
        (tmp_path / f"{i}.txt").write_bytes(b"x")
    assert tree_digest(tmp_path, max_files=4).file_count == 4
    with pytest.raises(AppError) as exc:
        tree_digest(tmp_path, max_files=3)
    assert exc.value.code == ErrorCode.TOO_MANY_FILES
