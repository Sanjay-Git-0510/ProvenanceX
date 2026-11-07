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
"""

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


def sha256_file(path: Path) -> str:
    """Stream a file through SHA-256 without loading it into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _unsafe(message: str, rel: str) -> AppError:
    return AppError(ErrorCode.UNSAFE_CONTENT, message, 400, {"path": rel})


def list_tree_files(
    root: Path,
    *,
    excluded_top_level: frozenset[str] = DEFAULT_EXCLUDED_TOP_LEVEL,
    max_files: int | None = None,
) -> list[tuple[bytes, Path]]:
    """Return (relative path bytes, absolute path) for every regular file, sorted."""
    entries: list[tuple[bytes, Path]] = []
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
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise _unsafe("Symlinks are not allowed", rel)
            if not stat.S_ISREG(mode):
                raise _unsafe("Special files are not allowed", rel)
            entries.append((os.fsencode(rel), path))
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
) -> TreeDigest:
    """Compute the provenancex-tree-v1 digest of `root` (see module docstring)."""
    digest = hashlib.sha256(f"{TREE_DIGEST_VERSION}\n".encode())
    total = 0
    files = list_tree_files(root, excluded_top_level=excluded_top_level, max_files=max_files)
    for rel, path in files:
        digest.update(rel + b"\0" + sha256_file(path).encode("ascii") + b"\n")
        total += path.stat().st_size
    return TreeDigest(sha256=digest.hexdigest(), file_count=len(files), total_bytes=total)
