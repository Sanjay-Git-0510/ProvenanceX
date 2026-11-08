"""File inventory of a model artifact: category, size, hash and serialization per file.

Local files are hashed (SHA-256) and their serialization is detected from magic bytes.
Files that were listed by Hugging Face but not downloaded (over the size cap) are
included with their HF-reported size and LFS SHA-256, marked downloaded=False. Their
serialization comes from the extension only and is labeled unverified.
"""

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from app.core.hashing import list_tree_files, sha256_file
from app.scanners.model.config_parse import is_config_path
from app.scanners.model.serialization import (
    detect_serialization,
    is_weight_file,
    serialization_from_name,
)

TOKENIZER_NAMES = frozenset(
    {
        "tokenizer.json",
        "vocab.json",
        "vocab.txt",
        "merges.txt",
        "special_tokens_map.json",
        "added_tokens.json",
        "tokenizer.model",
        "spiece.model",
        "sentencepiece.bpe.model",
    }
)
CODE_EXTENSIONS = frozenset(
    {".py", ".pyw", ".sh", ".bash", ".bat", ".cmd", ".ps1", ".ipynb", ".pyc", ".pyo"}
)
NATIVE_EXTENSIONS = frozenset({".so", ".dll", ".dylib", ".exe", ".pyd"})
DATA_EXTENSIONS = frozenset({".csv", ".tsv", ".parquet", ".arrow", ".jsonl", ".avro", ".orc"})
MODEL_SERIALIZATIONS = frozenset(
    {
        "safetensors",
        "pickle",
        "pytorch_zip",
        "numpy",
        "numpy_zip",
        "onnx",
        "gguf",
        "hdf5",
        "keras_zip",
        "tflite",
        "msgpack",
    }
)
# Extension -> the serialization a file with that extension is expected to have.
_EXPECTED = {".safetensors": "safetensors", ".gguf": "gguf", ".npy": "numpy", ".h5": "hdf5"}


@dataclass
class InventoryFile:
    path: str
    size: int
    category: str  # weights | config | tokenizer | card | code | native | data | other
    downloaded: bool
    sha256: str | None
    serialization: str | None
    serialization_verified: bool
    remote_sha256: str | None = None  # HF-reported LFS SHA-256
    hash_verified: bool | None = None  # local hash matched the HF-reported hash
    skip_reason: str | None = None
    format_mismatch: str | None = None
    analysis: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "category": self.category,
            "downloaded": self.downloaded,
            "sha256": self.sha256,
            "serialization": self.serialization,
            "serialization_verified": self.serialization_verified,
            "remote_sha256": self.remote_sha256,
            "hash_verified": self.hash_verified,
            "skip_reason": self.skip_reason,
            "format_mismatch": self.format_mismatch,
            "analysis": self.analysis,
        }


@dataclass(frozen=True)
class RemoteOnlyFile:
    """A file listed by the source but not present locally."""

    path: str
    size: int
    remote_sha256: str | None
    skip_reason: str


def categorize(rel: str, serialization: str | None) -> str:
    name = PurePosixPath(rel).name
    suffix = PurePosixPath(rel).suffix.lower()
    if rel.lower() == "readme.md":
        return "card"
    if is_config_path(rel):
        return "config"
    if name in TOKENIZER_NAMES:
        return "tokenizer"
    if suffix in CODE_EXTENSIONS:
        return "code"
    if suffix in NATIVE_EXTENSIONS:
        return "native"
    if is_weight_file(rel) or (serialization in MODEL_SERIALIZATIONS):
        return "weights"
    if suffix in DATA_EXTENSIONS:
        return "data"
    return "other"


def build_inventory(
    src_dir: Path,
    *,
    max_files: int,
    remote_only: list[RemoteOnlyFile] | None = None,
    remote_hashes: dict[str, str | None] | None = None,
) -> list[InventoryFile]:
    """Inventory local files under `src_dir` plus listed-but-not-downloaded files."""
    remote_hashes = remote_hashes or {}
    files: list[InventoryFile] = []
    for rel_bytes, path in list_tree_files(src_dir, max_files=max_files):
        rel = rel_bytes.decode("utf-8", errors="replace")
        serialization = detect_serialization(path)
        expected = _EXPECTED.get(PurePosixPath(rel).suffix.lower())
        mismatch = None
        if expected and serialization != expected:
            mismatch = f"extension suggests {expected} but content is {serialization}"
        elif serialization in ("pickle", "pytorch_zip") and PurePosixPath(rel).suffix.lower() in (
            ".json",
            ".txt",
            ".md",
            ".yaml",
            ".yml",
        ):
            mismatch = f"text extension but content is {serialization}"
        sha = sha256_file(path)
        remote = remote_hashes.get(rel)
        files.append(
            InventoryFile(
                path=rel,
                size=path.stat().st_size,
                category=categorize(rel, serialization),
                downloaded=True,
                sha256=sha,
                serialization=serialization if serialization != "unknown" else None,
                serialization_verified=True,
                remote_sha256=remote,
                hash_verified=(sha == remote) if remote else None,
                format_mismatch=mismatch,
            )
        )
    for rf in remote_only or []:
        guessed = serialization_from_name(rf.path)
        files.append(
            InventoryFile(
                path=rf.path,
                size=rf.size,
                category=categorize(rf.path, None),
                downloaded=False,
                sha256=None,
                serialization=guessed if guessed != "unknown" else None,
                serialization_verified=False,
                remote_sha256=rf.remote_sha256,
                hash_verified=None,
                skip_reason=rf.skip_reason,
            )
        )
    files.sort(key=lambda f: f.path)
    return files
