"""Per-scan disposable workspaces under WORKSPACE_ROOT.

Layout: <WORKSPACE_ROOT>/<scan_id>/{input,src}, with every directory mode 0700.
- input/  holds the raw upload (upload.zip). It is never extracted in place.
- src/    holds the extracted or cloned artifact content that is analyzed.

The scan id is a UUID, so the workspace path cannot be steered by user input.
Workspaces are removed on failure and kept on success, because later phases need the
source.
"""

import logging
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from uuid import UUID

from app.core.errors import AppError, ErrorCode

logger = logging.getLogger(__name__)

CHUNK_SIZE = 1024 * 1024
MB = 1024 * 1024
UPLOAD_FILENAME = "upload.zip"


@dataclass(frozen=True)
class Workspace:
    root: Path

    @property
    def input_dir(self) -> Path:
        return self.root / "input"

    @property
    def src_dir(self) -> Path:
        return self.root / "src"

    @property
    def upload_path(self) -> Path:
        return self.input_dir / UPLOAD_FILENAME


def _workspace_root(base: Path, scan_id: UUID) -> Path:
    return base.resolve() / str(UUID(str(scan_id)))


def create_workspace(base: Path, scan_id: UUID) -> Workspace:
    """Create a fresh workspace. Fails if one already exists for this scan id."""
    base.mkdir(parents=True, exist_ok=True)
    root = _workspace_root(base, scan_id)
    try:
        root.mkdir(mode=0o700)
        (root / "input").mkdir(mode=0o700)
        (root / "src").mkdir(mode=0o700)
    except OSError as exc:
        logger.error("Could not create workspace %s: %s", root, exc)
        raise AppError(ErrorCode.WORKSPACE_ERROR, "Could not create scan workspace", 500) from exc
    return Workspace(root)


def open_workspace(base: Path, scan_id: UUID) -> Workspace:
    root = _workspace_root(base, scan_id)
    if root.is_symlink() or not root.is_dir():
        raise AppError(ErrorCode.WORKSPACE_ERROR, "Scan workspace is missing", 500)
    return Workspace(root)


def remove_workspace(workspace: Workspace, base: Path) -> None:
    """Delete a workspace. Refuses to delete anything that is not a direct child of base."""
    root = workspace.root
    if root.is_symlink() or root.parent != base.resolve():
        logger.error("Refusing to remove unexpected workspace path %s", root)
        return
    try:
        shutil.rmtree(root)
    except FileNotFoundError:
        return
    except OSError:
        logger.exception("Failed to remove workspace %s", root)


def resolve_within(base: Path, *parts: str) -> Path:
    """Join `parts` onto base and raise if the result escapes base."""
    base_resolved = base.resolve()
    target = base_resolved.joinpath(*parts).resolve()
    if not target.is_relative_to(base_resolved):
        raise AppError(ErrorCode.UNSAFE_CONTENT, "Path escapes the workspace", 400)
    return target


def directory_size(path: Path) -> int:
    """Total size of the files under path. Symlinks are not followed."""
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path, followlinks=False):
        for name in filenames:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except FileNotFoundError:
                # Files can disappear while git is writing (temporary packs). Skip them.
                continue
    return total


def write_stream_limited(stream: BinaryIO, dest: Path, max_bytes: int) -> int:
    """Copy a stream to a new file at dest, raising artifact_too_large past max_bytes."""
    written = 0
    with dest.open("xb") as out:
        while chunk := stream.read(CHUNK_SIZE):
            written += len(chunk)
            if written > max_bytes:
                raise AppError(
                    ErrorCode.ARTIFACT_TOO_LARGE,
                    f"Upload exceeds the {max_bytes // MB} MB limit",
                    413,
                    {"max_bytes": max_bytes},
                )
            out.write(chunk)
    return written
