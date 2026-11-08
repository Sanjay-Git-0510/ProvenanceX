"""Static pickle inspection by opcode parsing (pickletools.genops). No pickle is loaded.

A pickle can import any callable (GLOBAL / STACK_GLOBAL / INST) and call it (REDUCE /
OBJ / NEWOBJ / BUILD), so loading an untrusted pickle is arbitrary code execution. This
module only walks the opcode stream and reports which globals the pickle would import:

  safe       on a small allowlist of reconstruction helpers used by torch/numpy/etc.
  dangerous  on a denylist (os, subprocess, builtins.eval/exec, socket, runpy, ...)
  unknown    everything else (custom classes and so on). Not proof of anything, but a
             loader would import and possibly call them.

STACK_GLOBAL takes its module and name from the stack. The scanner simulates the stack
shape from each opcode's documented stack effect, tracking string values (also through
the memo), so the operands resolve correctly. If they cannot be resolved, the import is
counted as `unresolved`, which is itself suspicious (a common obfuscation).

PyTorch zip checkpoints (torch.save) hold their pickles as `*.pkl` archive members. The
members are read through zipfile (never extracted) under size and ratio limits.
Legacy torch files hold several pickles back to back followed by raw tensor bytes:
parsing continues pickle after pickle until the data stops looking like one.
"""

import io
import pickletools
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from struct import error as struct_error
from typing import IO, Any

MAX_PICKLES_PER_STREAM = 8
MAX_REPORTED_GLOBALS = 200
MAX_ZIP_MEMBERS = 10000
MAX_ZIP_RATIO = 200.0

_STRING_OPS = frozenset(
    {
        "STRING",
        "BINSTRING",
        "SHORT_BINSTRING",
        "UNICODE",
        "BINUNICODE",
        "SHORT_BINUNICODE",
        "BINUNICODE8",
    }
)
_PUT_OPS = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})
_GET_OPS = frozenset({"GET", "BINGET", "LONG_BINGET"})
_CALL_OPS = frozenset({"REDUCE", "OBJ", "NEWOBJ", "NEWOBJ_EX", "INST", "BUILD"})

SAFE_GLOBALS = frozenset(
    {
        ("collections", "OrderedDict"),
        ("collections", "defaultdict"),
        ("torch._utils", "_rebuild_tensor"),
        ("torch._utils", "_rebuild_tensor_v2"),
        ("torch._utils", "_rebuild_tensor_v3"),
        ("torch._utils", "_rebuild_parameter"),
        ("torch._utils", "_rebuild_parameter_with_state"),
        ("torch._utils", "_rebuild_qtensor"),
        ("torch._utils", "_rebuild_sparse_tensor"),
        ("torch._tensor", "_rebuild_from_type_v2"),
        ("torch", "Size"),
        ("torch", "device"),
        ("torch", "dtype"),
        ("torch", "bfloat16"),
        ("torch", "float16"),
        ("torch", "float32"),
        ("torch", "float64"),
        ("torch", "int8"),
        ("torch", "int16"),
        ("torch", "int32"),
        ("torch", "int64"),
        ("torch", "uint8"),
        ("torch", "bool"),
        ("torch.nn.parameter", "Parameter"),
        ("numpy", "dtype"),
        ("numpy", "ndarray"),
        ("numpy.core.multiarray", "_reconstruct"),
        ("numpy.core.multiarray", "scalar"),
        ("numpy._core.multiarray", "_reconstruct"),
        ("numpy._core.multiarray", "scalar"),
        ("_codecs", "encode"),
        ("builtins", "set"),
        ("builtins", "frozenset"),
        ("builtins", "dict"),
        ("builtins", "list"),
        ("builtins", "tuple"),
        ("builtins", "bytearray"),
        ("builtins", "complex"),
        ("builtins", "slice"),
        ("builtins", "range"),
    }
)
# torch.FloatStorage, torch.HalfStorage, ... are storage type markers.
_SAFE_NAME_SUFFIXES = {"torch": ("Storage",)}

DANGEROUS_MODULES = frozenset(
    {
        "os",
        "posix",
        "nt",
        "subprocess",
        "sys",
        "socket",
        "shutil",
        "runpy",
        "pty",
        "webbrowser",
        "importlib",
        "ctypes",
        "multiprocessing",
        "code",
        "codeop",
        "commands",
        "pdb",
        "bdb",
        "timeit",
        "requests",
        "urllib",
        "urllib2",
        "http",
        "httplib",
        "ftplib",
        "telnetlib",
        "smtplib",
        "pickle",
        "_pickle",
        "cPickle",
        "dill",
        "marshal",
        "types",
        "platform",
        "signal",
        "asyncio",
        "threading",
        "_thread",
        "pip",
        "setuptools",
        "torch.hub",
        "torch.ops",
        "torch.jit",
    }
)
DANGEROUS_BUILTINS = frozenset(
    {
        "eval",
        "exec",
        "execfile",
        "compile",
        "open",
        "file",
        "getattr",
        "setattr",
        "delattr",
        "__import__",
        "globals",
        "locals",
        "vars",
        "breakpoint",
        "input",
        "apply",
        "help",
        "memoryview",
    }
)
_BUILTIN_MODULES = frozenset({"builtins", "__builtin__", "__builtins__"})
DANGEROUS_PAIRS = frozenset(
    {
        ("operator", "attrgetter"),
        ("operator", "methodcaller"),
        ("operator", "itemgetter"),
        ("functools", "reduce"),
        ("numpy", "load"),
        ("numpy.lib.npyio", "load"),
        ("torch", "load"),
        ("torch.serialization", "load"),
        ("joblib", "load"),
    }
)


def classify_global(module: str, name: str) -> str:
    """Return safe | dangerous | unknown for an imported `module.name`."""
    if (module, name) in SAFE_GLOBALS:
        return "safe"
    if any(name.endswith(s) for s in _SAFE_NAME_SUFFIXES.get(module, ())):
        return "safe"
    if module in _BUILTIN_MODULES:
        return "dangerous" if name in DANGEROUS_BUILTINS or name.startswith("_") else "unknown"
    root = module.split(".", 1)[0]
    if module in DANGEROUS_MODULES or root in DANGEROUS_MODULES:
        return "dangerous"
    if (module, name) in DANGEROUS_PAIRS:
        return "dangerous"
    return "unknown"


@dataclass
class PickleScan:
    """Result for one file (or one *.pkl member of a zip)."""

    status: str = "ok"  # ok | parse_error | truncated | too_large | not_scanned
    pickles: int = 0
    opcode_count: int = 0
    protocol: int | None = None
    globals: dict[str, str] = field(default_factory=dict)  # "module.name" -> class
    unresolved_stack_globals: int = 0
    call_opcodes: int = 0
    members: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def dangerous(self) -> list[str]:
        return sorted(g for g, c in self.globals.items() if c == "dangerous")

    @property
    def unknown(self) -> list[str]:
        return sorted(g for g, c in self.globals.items() if c == "unknown")

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "pickles": self.pickles,
            "opcode_count": self.opcode_count,
            "protocol": self.protocol,
            "globals": dict(sorted(self.globals.items())),
            "dangerous_globals": self.dangerous,
            "unknown_globals": self.unknown,
            "unresolved_stack_globals": self.unresolved_stack_globals,
            "call_opcodes": self.call_opcodes,
            "members": self.members,
            "error": self.error,
        }


class _OpcodeBudgetExceeded(Exception):
    pass


def _record_global(result: PickleScan, module: str, name: str) -> None:
    key = f"{module}.{name}"[:256]
    if key not in result.globals and len(result.globals) >= MAX_REPORTED_GLOBALS:
        return
    result.globals[key] = classify_global(module, name)


_MARK = object()  # stack sentinel for pickletools.markobject


def _pop_to_mark(stack: list[Any]) -> None:
    for i in range(len(stack) - 1, -1, -1):
        if stack[i] is _MARK:
            del stack[i:]
            return
    raise ValueError("MARK expected on the pickle stack")


def _pop(stack: list[Any], count: int) -> None:
    if count > len(stack):
        raise ValueError("pickle stack underflow")
    if count:
        del stack[-count:]


def _scan_one_pickle(stream: IO[bytes], result: PickleScan, max_opcodes: int) -> None:
    """Walk one pickle (up to STOP), simulating the stack shape. Never executes anything.

    Only string values are tracked; every other stack item is None. That is enough to
    resolve STACK_GLOBAL operands, including through the memo (PUT/GET/MEMOIZE) and DUP.
    Raises ValueError (or a genops error) on malformed data.
    """
    stack: list[Any] = []
    memo: dict[int, Any] = {}
    for opcode, arg, _pos in pickletools.genops(stream):
        result.opcode_count += 1
        if result.opcode_count > max_opcodes:
            raise _OpcodeBudgetExceeded
        name = opcode.name
        top = stack[-1] if stack else None

        if name == "PROTO" and result.protocol is None:
            result.protocol = int(arg)
        elif name in ("GLOBAL", "INST"):
            module, _, attr = str(arg).partition(" ")
            _record_global(result, module, attr)
        elif name == "STACK_GLOBAL":
            module = stack[-2] if len(stack) >= 2 else None
            attr = stack[-1] if stack else None
            if isinstance(module, str) and isinstance(attr, str):
                _record_global(result, module, attr)
            else:
                result.unresolved_stack_globals += 1
        elif name in _PUT_OPS:
            if not stack:
                raise ValueError("PUT on an empty stack")
            memo[int(arg)] = top
        elif name == "MEMOIZE":
            if not stack:
                raise ValueError("MEMOIZE on an empty stack")
            memo[len(memo)] = top
        if name in _CALL_OPS:
            result.call_opcodes += 1

        # Apply the opcode's stack effect.
        before = opcode.stack_before
        if pickletools.markobject in before:
            _pop_to_mark(stack)
            _pop(stack, before.index(pickletools.markobject))
        else:
            _pop(stack, len(before))
        if name in _STRING_OPS:
            stack.append(arg.decode("latin-1") if isinstance(arg, bytes) else str(arg))
        elif name in _GET_OPS:
            if int(arg) not in memo:
                raise ValueError("memo key missing")
            stack.append(memo[int(arg)])
        elif name == "MEMOIZE":
            stack.append(top)
        elif name == "DUP":
            stack.extend([top, top])
        else:
            for item in opcode.stack_after:
                stack.append(_MARK if item is pickletools.markobject else None)


def scan_pickle_stream(stream: IO[bytes], result: PickleScan, max_opcodes: int) -> None:
    """Scan consecutive pickles in a stream until EOF or non-pickle data."""
    for index in range(MAX_PICKLES_PER_STREAM):
        start = stream.tell() if stream.seekable() else None
        head = stream.read(1)
        if not head:
            return
        if start is not None:
            stream.seek(start)
        else:  # pragma: no cover - all our streams are seekable
            stream = io.BufferedReader(io.BytesIO(head + stream.read()))  # type: ignore[arg-type]
        try:
            _scan_one_pickle(stream, result, max_opcodes)
            result.pickles += 1
        except _OpcodeBudgetExceeded:
            result.status = "truncated"
            result.error = f"opcode budget of {max_opcodes} exceeded"
            return
        except (ValueError, EOFError, KeyError, IndexError, UnicodeDecodeError, struct_error):
            if index == 0:
                result.status = "parse_error"
                result.error = "data is not a valid pickle stream"
            # Later failures: trailing raw data (legacy torch tensor bytes). Stop quietly.
            return


class _LimitedReader(io.RawIOBase):
    """Wraps a zip member stream and fails once more than `limit` bytes are read."""

    def __init__(self, raw: IO[bytes], limit: int) -> None:
        self._raw = raw
        self._limit = limit
        self._read = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        data = self._raw.read(len(buffer))
        self._read += len(data)
        if self._read > self._limit:
            raise ValueError("zip member exceeds its size limit")
        buffer[: len(data)] = data
        return len(data)


def _iter_zip_pickles(
    zf: zipfile.ZipFile, max_bytes: int
) -> Iterator[tuple[zipfile.ZipInfo, str | None]]:
    infos = zf.infolist()
    if len(infos) > MAX_ZIP_MEMBERS:
        raise ValueError("too many zip members")
    for info in infos:
        if not info.filename.endswith(".pkl") or info.is_dir():
            continue
        if info.flag_bits & 0x1:
            yield info, "encrypted member"
        elif info.file_size > max_bytes:
            yield info, "member exceeds the pickle size limit"
        elif info.file_size > 0 and (
            info.compress_size == 0 or info.file_size / info.compress_size > MAX_ZIP_RATIO
        ):
            yield info, "member compression ratio exceeds the limit"
        else:
            yield info, None


def scan_pickle_file(
    path: Path, serialization: str, *, max_bytes: int, max_opcodes: int
) -> PickleScan:
    """Scan a raw pickle or the *.pkl members of a PyTorch zip. Never raises on bad input."""
    result = PickleScan()
    try:
        size = path.stat().st_size
        if serialization == "pytorch_zip":
            with zipfile.ZipFile(path) as zf:
                for info, problem in _iter_zip_pickles(zf, max_bytes):
                    result.members.append(info.filename[:256])
                    if problem:
                        result.status = "too_large" if "limit" in problem else "parse_error"
                        result.error = problem
                        continue
                    with zf.open(info) as member:
                        reader = io.BufferedReader(_LimitedReader(member, info.file_size))
                        # BufferedReader over a non-seekable member: buffer fully (bounded).
                        data = io.BytesIO(reader.read())
                    scan_pickle_stream(data, result, max_opcodes)
                    if result.status in ("parse_error", "truncated"):
                        return result
                if not result.members:
                    result.status = "not_scanned"
                    result.error = "no *.pkl members found"
            return result

        if size > max_bytes:
            result.status = "too_large"
            result.error = f"file exceeds the pickle scan limit of {max_bytes} bytes"
            return result
        with path.open("rb") as fh:
            scan_pickle_stream(fh, result, max_opcodes)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, NotImplementedError) as exc:
        result.status = "parse_error"
        result.error = f"archive could not be read: {exc.__class__.__name__}"
    except (OSError, ValueError, EOFError, RuntimeError) as exc:
        result.status = "parse_error"
        result.error = f"could not be parsed: {exc.__class__.__name__}"
    return result
