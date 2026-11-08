"""Parse and validate a safetensors header without loading any tensor data.

Format: an 8-byte little-endian header length N, then N bytes of JSON mapping tensor
names to {dtype, shape, data_offsets: [begin, end]} (offsets relative to the data area),
plus an optional "__metadata__" dict of strings. Only the header is read.
"""

import json
import math
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_HEADER_BYTES = 16 * 1024 * 1024
MAX_TENSORS = 100_000
MAX_METADATA_ITEMS = 50
DTYPE_SIZES = {
    "BOOL": 1,
    "U8": 1,
    "I8": 1,
    "F8_E5M2": 1,
    "F8_E4M3": 1,
    "I16": 2,
    "U16": 2,
    "F16": 2,
    "BF16": 2,
    "I32": 4,
    "U32": 4,
    "F32": 4,
    "F64": 8,
    "I64": 8,
    "U64": 8,
}


@dataclass
class SafetensorsInfo:
    valid: bool
    tensor_count: int = 0
    parameter_count: int = 0
    dtypes: dict[str, int] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)
    header_bytes: int = 0
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "tensor_count": self.tensor_count,
            "parameter_count": self.parameter_count,
            "dtypes": self.dtypes,
            "metadata": self.metadata,
            "header_bytes": self.header_bytes,
            "issues": self.issues,
        }


def _fail(info: SafetensorsInfo, issue: str) -> SafetensorsInfo:
    info.valid = False
    info.issues.append(issue)
    return info


def parse_safetensors_header(path: Path) -> SafetensorsInfo:
    info = SafetensorsInfo(valid=True)
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            prefix = fh.read(8)
            if len(prefix) < 8:
                return _fail(info, "file shorter than the 8-byte header length")
            (header_len,) = struct.unpack("<Q", prefix)
            info.header_bytes = header_len
            if header_len > MAX_HEADER_BYTES:
                return _fail(info, f"header length {header_len} exceeds {MAX_HEADER_BYTES}")
            if header_len > size - 8:
                return _fail(info, "header length exceeds the file size")
            raw = fh.read(header_len)
    except OSError as exc:
        return _fail(info, f"could not read file: {exc.__class__.__name__}")

    try:
        header = json.loads(raw)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return _fail(info, "header is not valid JSON")
    if not isinstance(header, dict):
        return _fail(info, "header is not a JSON object")
    if len(header) > MAX_TENSORS:
        return _fail(info, "too many tensors in header")

    data_len = size - 8 - header_len
    meta = header.pop("__metadata__", None)
    if meta is not None:
        if not isinstance(meta, dict):
            info.issues.append("__metadata__ is not an object")
        else:
            for key, value in list(meta.items())[:MAX_METADATA_ITEMS]:
                if isinstance(key, str) and isinstance(value, str):
                    info.metadata[key[:128]] = value[:512]
                else:
                    info.issues.append("__metadata__ has a non-string entry")
                    break

    spans: list[tuple[int, int]] = []
    for name, entry in header.items():
        if not isinstance(entry, dict):
            return _fail(info, f"tensor entry is not an object: {str(name)[:80]}")
        dtype, shape, offsets = entry.get("dtype"), entry.get("shape"), entry.get("data_offsets")
        if dtype not in DTYPE_SIZES:
            return _fail(info, f"unknown dtype {str(dtype)[:16]!r} for {str(name)[:80]}")
        if not isinstance(shape, list) or not all(
            isinstance(d, int) and not isinstance(d, bool) and d >= 0 for d in shape
        ):
            return _fail(info, f"invalid shape for {str(name)[:80]}")
        if (
            not isinstance(offsets, list)
            or len(offsets) != 2
            or not all(isinstance(o, int) and not isinstance(o, bool) for o in offsets)
        ):
            return _fail(info, f"invalid data_offsets for {str(name)[:80]}")
        begin, end = offsets
        if not 0 <= begin <= end <= data_len:
            return _fail(info, f"data_offsets out of bounds for {str(name)[:80]}")
        elements = math.prod(shape)
        if elements * DTYPE_SIZES[dtype] != end - begin:
            return _fail(info, f"byte size does not match shape/dtype for {str(name)[:80]}")
        spans.append((begin, end))
        info.tensor_count += 1
        info.parameter_count += elements
        info.dtypes[dtype] = info.dtypes.get(dtype, 0) + 1

    spans.sort()
    cursor = 0
    for begin, end in spans:
        if begin < cursor:
            return _fail(info, "tensor byte ranges overlap")
        if begin > cursor:
            info.issues.append("gap between tensor byte ranges")
        cursor = end
    if cursor < data_len:
        info.issues.append(f"{data_len - cursor} trailing byte(s) not covered by any tensor")
    return info
