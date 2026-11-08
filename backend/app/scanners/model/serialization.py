"""Model-file serialization detection from magic bytes plus the file extension.

Only the first bytes of a file are read. Detection never imports a framework or loads
the file. Types:
  safetensors, pickle, pytorch_zip (a ZIP holding *.pkl pickles, i.e. torch.save),
  numpy, numpy_zip, onnx, gguf, hdf5, keras_zip, tflite, msgpack, zip, unknown.
`pickle` and `pytorch_zip` are formats whose loaders can execute code.
"""

import struct
import zipfile
from pathlib import Path

HEAD_BYTES = 64
MAX_ZIP_MEMBERS_LISTED = 10000

PICKLE_EXTENSIONS = frozenset({".pkl", ".pickle", ".joblib", ".dill"})
TORCH_EXTENSIONS = frozenset({".pt", ".pth", ".bin", ".ckpt", ".pkl", ".mar"})
WEIGHT_EXTENSIONS = frozenset(
    {
        ".safetensors",
        ".bin",
        ".pt",
        ".pth",
        ".ckpt",
        ".pkl",
        ".pickle",
        ".joblib",
        ".dill",
        ".onnx",
        ".gguf",
        ".ggml",
        ".h5",
        ".hdf5",
        ".keras",
        ".tflite",
        ".msgpack",
        ".npy",
        ".npz",
        ".pb",
        ".mlmodel",
        ".mar",
    }
)
# Formats whose standard loaders can run arbitrary code during deserialization.
CODE_EXECUTING_FORMATS = frozenset({"pickle", "pytorch_zip"})


def _is_safetensors(head: bytes, size: int) -> bool:
    if len(head) < 10:
        return False
    (header_len,) = struct.unpack("<Q", head[:8])
    return 2 <= header_len <= size - 8 and head[8:9] == b"{"


def _is_pickle_head(head: bytes) -> bool:
    # Protocol 2+ starts with PROTO (0x80) and a protocol number 2..5.
    return len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5


def _zip_kind(path: Path) -> str:
    try:
        with zipfile.ZipFile(path) as zf:
            names = [i.filename for i in zf.infolist()[:MAX_ZIP_MEMBERS_LISTED]]
    except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError):
        return "unknown"
    if any(n.endswith(".pkl") for n in names):
        return "pytorch_zip"
    if names and all(n.endswith(".npy") for n in names if not n.endswith("/")):
        return "numpy_zip"
    if any(n == "config.json" for n in names) and any(n.endswith(".h5") for n in names):
        return "keras_zip"
    return "zip"


def detect_serialization(path: Path) -> str:
    """Return the serialization type of a regular file (see module docstring)."""
    suffix = path.suffix.lower()
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            head = fh.read(HEAD_BYTES)
    except OSError:
        return "unknown"

    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return _zip_kind(path)
    if head.startswith(b"GGUF"):
        return "gguf"
    if head.startswith(b"\x89HDF\r\n\x1a\n"):
        return "hdf5"
    if head.startswith(b"\x93NUMPY"):
        return "numpy"
    if len(head) >= 8 and head[4:8] == b"TFL3":
        return "tflite"
    if _is_safetensors(head, size):
        return "safetensors"
    if _is_pickle_head(head):
        return "pickle"
    if suffix in PICKLE_EXTENSIONS:
        # Protocol 0/1 pickles have no PROTO header; treat the extension as a claim.
        return "pickle"
    if suffix == ".onnx":
        return "onnx"  # protobuf has no magic; identified by extension only
    if suffix == ".msgpack":
        return "msgpack"
    return "unknown"


def is_weight_file(path: str) -> bool:
    return Path(path).suffix.lower() in WEIGHT_EXTENSIONS


def serialization_from_name(path: str) -> str:
    """Best-effort type for a file that was NOT downloaded (extension only, unverified)."""
    suffix = Path(path).suffix.lower()
    mapping = {
        ".safetensors": "safetensors",
        ".gguf": "gguf",
        ".onnx": "onnx",
        ".h5": "hdf5",
        ".hdf5": "hdf5",
        ".keras": "keras_zip",
        ".tflite": "tflite",
        ".msgpack": "msgpack",
        ".npy": "numpy",
        ".npz": "numpy_zip",
    }
    if suffix in mapping:
        return mapping[suffix]
    if suffix in PICKLE_EXTENSIONS or suffix in TORCH_EXTENSIONS:
        return "pickle_or_pytorch"
    return "unknown"
