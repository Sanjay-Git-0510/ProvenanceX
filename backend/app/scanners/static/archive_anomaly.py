"""Archive and file-identity anomalies.

Hostile top-level uploads are refused at ingestion (app/security/archive.py). This module
reports what can legitimately get past that: archives nested in the artifact, disguised
executables and double extensions. Nested ZIPs are only listed through their central
directory. They are never extracted or decompressed.
"""

import re
import stat
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.core.errors import AppError
from app.scanners.model.custom_code import NATIVE_EXTENSIONS
from app.scanners.static.python_ast import Hit
from app.scanners.static.rules import (
    ARCHIVE_CORRUPT,
    ARCHIVE_DISGUISED_EXE,
    ARCHIVE_DOUBLE_EXT,
    ARCHIVE_NEAR_LIMIT,
    ARCHIVE_NESTED,
    ARCHIVE_UNSAFE,
)
from app.security.archive import normalize_member_name

ZIP_FAMILY = frozenset({".zip", ".whl", ".jar", ".war", ".egg", ".nupkg"})
OPAQUE_ARCHIVES = (".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".7z", ".rar")
MAX_NESTED_ENTRIES = 20000
MAX_REPORTED = 20
HEAD_BYTES = 4096

_BINARY_EXTENSIONS = NATIVE_EXTENSIONS | {".o", ".a", ".node", ".com", ".sys", ".msi", ".elf"}
_VERSIONED_SO_RE = re.compile(r"\.so(?:\.\d+)+$")
_MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
_EXECUTABLE_SUFFIXES = frozenset(
    {".exe", ".scr", ".bat", ".cmd", ".com", ".ps1", ".vbs", ".sh", ".msi", ".pif"}
)
_DECOY_SUFFIXES = frozenset(
    {
        ".bin",
        ".pt",
        ".pth",
        ".ckpt",
        ".safetensors",
        ".onnx",
        ".pkl",
        ".json",
        ".txt",
        ".csv",
        ".pdf",
        ".doc",
        ".docx",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
    }
)


@dataclass
class ZipInspection:
    hits: list[Hit] = field(default_factory=list)


def executable_format(head: bytes) -> str | None:
    """ELF, PE or Mach-O from magic bytes. PE needs its header too: "MZ" alone is plain text."""
    if head.startswith(b"\x7fELF"):
        return "ELF"
    if head.startswith(_MACHO_MAGICS):
        return "Mach-O"
    if head.startswith(b"MZ") and len(head) >= 64:
        (offset,) = struct.unpack_from("<I", head, 0x3C)
        if offset + 4 <= len(head) and head[offset : offset + 4] == b"PE\0\0":
            return "PE"
    return None


def _is_binary_name(name: str, suffix: str) -> bool:
    """A binary extension, or a versioned shared library such as libz.so.1.2."""
    return suffix in _BINARY_EXTENSIONS or _VERSIONED_SO_RE.search(name.lower()) is not None


def check_identity(rel: str, head: bytes) -> list[Hit]:
    hits: list[Hit] = []
    path = PurePosixPath(rel)
    suffixes = [s.lower() for s in path.suffixes]
    kind = executable_format(head)
    if kind and suffixes and not _is_binary_name(path.name, suffixes[-1]):
        hits.append(Hit(ARCHIVE_DISGUISED_EXE, f"{kind} content in {path.name[:120]}"))
    if len(suffixes) >= 2 and suffixes[-1] in _EXECUTABLE_SUFFIXES:
        if suffixes[-2] in _DECOY_SUFFIXES:
            hits.append(Hit(ARCHIVE_DOUBLE_EXT, path.name[:120]))
    return hits


def is_zip_family(rel: str) -> bool:
    return PurePosixPath(rel).suffix.lower() in ZIP_FAMILY


def is_opaque_archive(rel: str) -> bool:
    return rel.lower().endswith(OPAQUE_ARCHIVES)


def _entry_problem(info: zipfile.ZipInfo, max_ratio: float) -> str | None:
    try:
        normalize_member_name(info.filename)
    except AppError as exc:
        return str((exc.details or {}).get("reason", "unsafe name"))
    if info.create_system == 3:
        fmt = stat.S_IFMT((info.external_attr >> 16) & 0xFFFF)
        if fmt == stat.S_IFLNK:
            return "symlink entry"
        if fmt not in (0, stat.S_IFREG, stat.S_IFDIR):
            return "special file entry"
    if not info.is_dir() and info.file_size > 0:
        if info.compress_size == 0 or info.file_size / info.compress_size > max_ratio:
            return "compression ratio exceeds limit"
    return None


def inspect_nested_zip(path: Path, max_ratio: float) -> list[Hit]:
    """Read only the central directory of a nested ZIP-family file."""
    hits = [Hit(ARCHIVE_NESTED, path.suffix.lower())]
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, OSError, ValueError, EOFError):
        return [Hit(ARCHIVE_CORRUPT, path.suffix.lower())]
    except (RuntimeError, NotImplementedError):
        return [Hit(ARCHIVE_CORRUPT, path.suffix.lower())]
    if len(infos) > MAX_NESTED_ENTRIES:
        hits.append(Hit(ARCHIVE_UNSAFE, f"too many entries ({len(infos)})"))
    problems: dict[str, str] = {}
    for info in infos[:MAX_NESTED_ENTRIES]:
        problem = _entry_problem(info, max_ratio)
        if problem and len(problems) < MAX_REPORTED:
            problems[info.filename[:120]] = problem
        elif problem:
            break
    hits.extend(Hit(ARCHIVE_UNSAFE, f"{name}: {why}") for name, why in problems.items())
    return hits


def inspect_upload_ratio(path: Path, max_ratio: float, warn_fraction: float) -> list[Hit]:
    """Entries that passed the ingestion bomb guard but came close to its limit."""
    threshold = max_ratio * warn_fraction
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError, EOFError):
        return []
    hits: list[Hit] = []
    for info in infos:
        if info.is_dir() or info.file_size == 0 or info.compress_size == 0:
            continue
        ratio = info.file_size / info.compress_size
        if ratio >= threshold:
            hits.append(Hit(ARCHIVE_NEAR_LIMIT, f"{info.filename[:120]} ({ratio:.0f}:1)"))
            if len(hits) >= MAX_REPORTED:
                break
    return hits
