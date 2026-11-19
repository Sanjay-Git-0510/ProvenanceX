"""SHA-256 helpers, including a deterministic digest over a directory tree.

Tree digest format (``provenancex-tree-v1``):

    sha256( b"provenancex-tree-v1\\n"
            + for each regular file, sorted by the bytes of its relative POSIX path:
                  <relpath bytes> b"\\0" <file sha256 hex> b"\\n" )

- File contents and relative paths are covered. Permissions, timestamps and empty
  directories are not, so the same content gives the same digest whether it came from
  a git clone or a ZIP upload.
- A top-level ``.git`` directory is excluded.
- The format is unambiguous: paths cannot contain NUL, and the hash has a fixed length.
- Symlinks and special files are rejected rather than followed.

Files are opened with O_NOFOLLOW and checked with fstat on the open descriptor, and a file
listed by the tree walk must still be the same inode when it is opened (audit finding M5). A path
swapped for a symlink, FIFO or another file between listing and reading is therefore refused as
unsafe content, never followed.
"""

import errno
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from app.core.errors import AppError, ErrorCode

CHUNK_SIZE = 1024 * 1024
TREE_DIGEST_VERSION = "provenancex-tree-v1"
DEFAULT_EXCLUDED_TOP_LEVEL = frozenset({".git"})


@dataclass(frozen=True)
class TreeDigest:
    sha256: str
    file_count: int
    total_bytes: int


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unsafe(message: str, rel: str) -> AppError:
    return AppError(ErrorCode.UNSAFE_CONTENT, message, 400, {"path": rel})


_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)  # a FIFO swapped in must not block the open
    | getattr(os, "O_CLOEXEC", 0)
)


def open_regular(path: Path, expect: os.stat_result | None = None) -> tuple[int, os.stat_result]:
    """Open `path` without following a symlink; return (fd, fstat) of a regular file only.

    With `expect` (an earlier lstat), the opened file must be that same inode. Raises
    unsafe_content otherwise; other OSErrors (missing, permission) propagate unchanged.
    """
    try:
        fd = os.open(path, _OPEN_FLAGS)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise _unsafe("Symlinks are not allowed", path.name) from exc
        raise
    info = os.fstat(fd)
    same = expect is None or (info.st_dev, info.st_ino) == (expect.st_dev, expect.st_ino)
    if not stat.S_ISREG(info.st_mode) or not same:
        os.close(fd)
        raise _unsafe("The file was replaced or is not a regular file", path.name)
    return fd, info


def sha256_file(path: Path, expect: os.stat_result | None = None) -> str:
    """Stream a regular file through SHA-256 without loading it into memory (see open_regular)."""
    fd, _ = open_regular(path, expect)
    digest = hashlib.sha256()
    with os.fdopen(fd, "rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def list_tree_files(
    root: Path,
    *,
    excluded_top_level: frozenset[str] = DEFAULT_EXCLUDED_TOP_LEVEL,
    max_files: int | None = None,
) -> list[tuple[bytes, Path]]:
    """Return (relative path bytes, absolute path) for every regular file, sorted."""
    return [
        (rel, path)
        for rel, path, _ in _walk(root, excluded_top_level=excluded_top_level, max_files=max_files)
    ]


def _walk(
    root: Path,
    *,
    excluded_top_level: frozenset[str],
    max_files: int | None,
) -> list[tuple[bytes, Path, os.stat_result]]:
    entries: list[tuple[bytes, Path, os.stat_result]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        kept: list[str] = []
        for name in dirnames:
            path = current / name
            if path.is_symlink():
                raise _unsafe("Symlinks are not allowed", path.relative_to(root).as_posix())
            if current == root and name in excluded_top_level:
                continue
            kept.append(name)
        dirnames[:] = kept

        for name in filenames:
            path = current / name
            rel = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise _unsafe("Symlinks are not allowed", rel)
            if not stat.S_ISREG(info.st_mode):
                raise _unsafe("Special files are not allowed", rel)
            entries.append((os.fsencode(rel), path, info))
            if max_files is not None and len(entries) > max_files:
                raise AppError(
                    ErrorCode.TOO_MANY_FILES,
                    "Artifact contains too many files",
                    413,
                    {"max_files": max_files},
                )
    entries.sort(key=lambda entry: entry[0])
    return entries


def tree_digest(
    root: Path,
    *,
    excluded_top_level: frozenset[str] = DEFAULT_EXCLUDED_TOP_LEVEL,
    max_files: int | None = None,
    max_bytes: int | None = None,
) -> TreeDigest:
    """Compute the provenancex-tree-v1 digest of `root` (see module docstring).

    `max_bytes` caps the total size listed (artifact_too_large), checked before any file is read.
    """
    digest = hashlib.sha256(f"{TREE_DIGEST_VERSION}\n".encode())
    files = _walk(root, excluded_top_level=excluded_top_level, max_files=max_files)
    listed = sum(info.st_size for _, _, info in files)
    if max_bytes is not None and listed > max_bytes:
        raise AppError(
            ErrorCode.ARTIFACT_TOO_LARGE,
            "Artifact exceeds the size limit",
            413,
            {"max_bytes": max_bytes},
        )
    total = 0
    for rel, path, info in files:
        fd, opened = open_regular(path, info)
        file_digest = hashlib.sha256()
        with os.fdopen(fd, "rb") as fh:
            while chunk := fh.read(CHUNK_SIZE):
                file_digest.update(chunk)
        digest.update(rel + b"\0" + file_digest.hexdigest().encode("ascii") + b"\n")
        total += opened.st_size
    return TreeDigest(sha256=digest.hexdigest(), file_count=len(files), total_bytes=total)
