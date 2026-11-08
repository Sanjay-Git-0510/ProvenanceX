"""Builders for model-file test inputs. Everything is generated in memory by the tests.

Hostile pickles are built as raw opcode bytes (or with pickle.dumps on a local class).
They are written to tmp_path and only ever *parsed* by the scanner, never loaded.
"""

import io
import json
import pickle
import struct
import zipfile
from pathlib import Path


def safetensors_bytes(tensors: dict | None = None, metadata: dict | None = None) -> bytes:
    """A valid safetensors file. `tensors`: name -> (dtype, shape)."""
    sizes = {"F32": 4, "F16": 2, "I64": 8, "U8": 1}
    tensors = tensors or {"w": ("F32", [2, 2])}
    header: dict = {}
    offset = 0
    for name, (dtype, shape) in tensors.items():
        n = sizes[dtype]
        for d in shape:
            n *= d
        header[name] = {"dtype": dtype, "shape": shape, "data_offsets": [offset, offset + n]}
        offset += n
    if metadata is not None:
        header["__metadata__"] = metadata
    raw = json.dumps(header).encode()
    return struct.pack("<Q", len(raw)) + raw + bytes(offset)


def raw_safetensors(header: object, data: bytes = b"", declared_len: int | None = None) -> bytes:
    raw = json.dumps(header).encode() if not isinstance(header, bytes) else header
    length = len(raw) if declared_len is None else declared_len
    return struct.pack("<Q", length) + raw + data


class _Reduce:
    """Pickles to `callable(*args)` without ever being called here."""

    def __init__(self, func, args):
        self.func, self.args = func, args

    def __reduce__(self):
        return (self.func, self.args)


def reduce_pickle(func, args=(), protocol: int = 4) -> bytes:
    return pickle.dumps(_Reduce(func, args), protocol=protocol)


def global_pickle(module: str, name: str) -> bytes:
    """Protocol-0 style GLOBAL + REDUCE, built from raw opcodes."""
    return b"c" + module.encode() + b"\n" + name.encode() + b"\n(S'x'\ntR."


def stack_global_pickle(module: str, name: str) -> bytes:
    """Protocol 4 STACK_GLOBAL + REDUCE, built from raw opcodes."""

    def s(v: str) -> bytes:
        b = v.encode()
        return b"\x8c" + bytes([len(b)]) + b

    return b"\x80\x04" + s(module) + s(name) + b"\x93" + s("x") + b"\x85R."


def obfuscated_stack_global(module: str, name: str) -> bytes:
    """Pushes the real target, then decoy strings that are POPped before STACK_GLOBAL."""

    def s(v: str) -> bytes:
        b = v.encode()
        return b"\x8c" + bytes([len(b)]) + b

    return (
        b"\x80\x04"
        + s(module)
        + s(name)
        + s("collections")
        + s("OrderedDict")
        + b"00"  # POP POP
        + b"\x93"
        + s("x")
        + b"\x85R."
    )


def memo_stack_global(module: str, name: str) -> bytes:
    """Operands stored in the memo, popped, then fetched back with BINGET."""

    def s(v: str) -> bytes:
        b = v.encode()
        return b"\x8c" + bytes([len(b)]) + b

    return (
        b"\x80\x04"
        + s(module)
        + b"\x94"
        + s(name)
        + b"\x94"
        + b"00"
        + b"h\x00h\x01\x93"
        + (s("x") + b"\x85R.")
    )


def torch_zip_bytes(pickle_payload: bytes, *, name: str = "archive/data.pkl") -> bytes:
    """A torch.save-style ZIP: <name> pickle plus a fake tensor storage member."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr(name, pickle_payload)
        zf.writestr("archive/data/0", bytes(16))
        zf.writestr("archive/version", "3\n")
    return buf.getvalue()


def write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_bytes(data)
    return path
