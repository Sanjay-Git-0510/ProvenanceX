"""Safe ZIP extraction for untrusted uploads.

All entries are validated before anything is written:
- no absolute paths, drive letters, backslashes, NUL bytes or '..' components;
- no symlinks or special files (unix mode bits), no encrypted entries;
- no duplicate entry names;
- entry count <= max_files, total declared size <= max_total_bytes;
- per-entry compression ratio <= max_compression_ratio (decompression-bomb guard).

During extraction, bytes are counted as they are actually decompressed, so a lying header
cannot bypass the size limits. Files are opened with 'xb' and are never overwritten.
On any error the caller removes the whole workspace.
"""

import re
import stat
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

from app.core.errors import AppError, ErrorCode

CHUNK_SIZE = 1024 * 1024
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_ZIP_FLAG_ENCRYPTED = 0x1
_ZIP_SYSTEM_UNIX = 3


@dataclass(frozen=True)
class ArchiveLimits:
    max_total_bytes: int
    max_files: int
    max_compression_ratio: float


@dataclass(frozen=True)
class ExtractionResult:
    file_count: int
    dir_count: int
    total_bytes: int


def _unsafe(reason: str, entry: str | None = None) -> AppError:
    return AppError(
        ErrorCode.UNSAFE_ARCHIVE,
        f"Unsafe archive: {reason}",
        400,
        {"reason": reason, "entry": entry},
    )


def _too_large(limit: int) -> AppError:
    return AppError(
        ErrorCode.ARTIFACT_TOO_LARGE,
        "Archive content exceeds the size limit",
        413,
        {"max_bytes": limit},
    )


def normalize_member_name(name: str) -> str:
    """Return a safe relative POSIX path for a ZIP entry name, or raise unsafe_archive."""
    if not name:
        raise _unsafe("empty entry name")
    if "\x00" in name:
        raise _unsafe("NUL byte in entry name", name)
    if "\\" in name:
        raise _unsafe("backslash in entry name", name)
    if name.startswith("/") or _DRIVE_RE.match(name):
        raise _unsafe("absolute path", name)
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise _unsafe("path traversal", name)
    if not parts:
        raise _unsafe("empty entry name", name)
    return "/".join(parts)


def _check_entry_type(info: zipfile.ZipInfo) -> None:
    if info.flag_bits & _ZIP_FLAG_ENCRYPTED:
        raise _unsafe("encrypted entry", info.filename)
    if info.create_system == _ZIP_SYSTEM_UNIX:
        mode = (info.external_attr >> 16) & 0xFFFF
        fmt = stat.S_IFMT(mode)
        if fmt == stat.S_IFLNK:
            raise _unsafe("symlink entry", info.filename)
        if fmt not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise _unsafe("special file entry", info.filename)


def safe_extract_zip(zip_path: Path, dest: Path, limits: ArchiveLimits) -> ExtractionResult:
    """Validate then extract `zip_path` into the existing directory `dest`."""
    dest_root = dest.resolve()
    archive_size = zip_path.stat().st_size
    try:
        with zipfile.ZipFile(zip_path) as zf:
            infos = zf.infolist()
            if len(infos) > limits.max_files:
                raise AppError(
                    ErrorCode.TOO_MANY_FILES,
                    "Archive contains too many entries",
                    413,
                    {"max_files": limits.max_files, "entries": len(infos)},
                )

            # Pass 1: validate every entry before writing anything.
            plan: list[tuple[zipfile.ZipInfo, Path, bool]] = []
            seen: set[str] = set()
            declared_total = 0
            for info in infos:
                rel = normalize_member_name(info.filename)
                _check_entry_type(info)
                if rel in seen:
                    raise _unsafe("duplicate entry name", info.filename)
                seen.add(rel)
                target = (dest_root / rel).resolve()
                if target == dest_root or not target.is_relative_to(dest_root):
                    raise _unsafe("entry escapes destination", info.filename)
                is_dir = info.is_dir()
                if not is_dir:
                    declared_total += info.file_size
                    if info.file_size > 0 and (
                        info.compress_size == 0
                        or info.file_size / info.compress_size > limits.max_compression_ratio
                    ):
                        raise _unsafe(
                            "compression ratio exceeds limit (possible decompression bomb)",
                            info.filename,
                        )
                plan.append((info, target, is_dir))

            if declared_total > limits.max_total_bytes:
                raise _too_large(limits.max_total_bytes)

            # Pass 2: extract, counting real decompressed bytes.
            files = dirs = written_total = 0
            for info, target, is_dir in plan:
                if is_dir:
                    target.mkdir(parents=True, exist_ok=True)
                    dirs += 1
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                entry_written = 0
                with zf.open(info) as src, target.open("xb") as out:
                    while chunk := src.read(CHUNK_SIZE):
                        entry_written += len(chunk)
                        written_total += len(chunk)
                        if entry_written > info.file_size:
                            raise _unsafe("entry larger than declared size", info.filename)
                        if written_total > limits.max_total_bytes:
                            raise _too_large(limits.max_total_bytes)
                        out.write(chunk)
                files += 1

            if archive_size > 0 and written_total / archive_size > limits.max_compression_ratio:
                raise _unsafe("overall compression ratio exceeds limit")
    except AppError:
        raise
    except (
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        NotImplementedError,
        RuntimeError,
        EOFError,
        zlib.error,
        OSError,
        ValueError,
    ) as exc:
        raise AppError(
            ErrorCode.INVALID_ARCHIVE,
            "Archive could not be read or extracted",
            400,
            {"reason": exc.__class__.__name__},
        ) from exc

    return ExtractionResult(file_count=files, dir_count=dirs, total_bytes=written_total)
