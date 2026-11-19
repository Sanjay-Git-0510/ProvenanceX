"""Framed stdout protocol between sandbox containers and the scan-runner (audit finding M3).

Before this, a worker printed one JSON document that carried the whole SBOM as a string, and the
runner decoded up to 96 MB of it with `json.loads`. The audit measured about 1.16 GB of runner
memory growth for 48 MB of output. Now the output is a short sequence of length-prefixed frames:

    MAGIC  ("PXF1\\n")
    'E' <u64 big-endian length> <JSON envelope>        exactly once, first, <= envelope cap
    'S' <u64 big-endian length> <raw SBOM bytes>       at most once, after E, <= SBOM cap
    'Z' <u64 = 0>                                      exactly once, last; nothing may follow

The runner decodes incrementally (`FrameDecoder`): a frame whose declared length is over its cap
is refused from its 9-byte header, before any of its body is read; the SBOM body is streamed to
a file and never held in memory; truncated, duplicated, reordered, unknown or trailing data is
refused. Only the small envelope is ever parsed as JSON, and only after a structural budget check
(`check_json_budget`) bounds how many Python objects it can expand into.

This module imports only the standard library, so the worker images can use it unchanged.
"""

import hashlib
import re
import struct
from collections.abc import Callable
from typing import BinaryIO

MAGIC = b"PXF1\n"
TAG_ENVELOPE = b"E"
TAG_SBOM = b"S"
TAG_END = b"Z"
_HEADER = struct.Struct(">cQ")
HEADER_SIZE = _HEADER.size  # 9
_COPY_CHUNK = 1024 * 1024


class FrameError(ValueError):
    """The framed output is malformed. The message is safe to record (no untrusted bytes)."""


# --------------------------------------------------------------------------- writing (worker)
def write_frames(out: BinaryIO, envelope: bytes, sbom: BinaryIO | None = None) -> None:
    """Write MAGIC, E, optional S (streamed from a file object) and Z to `out`."""
    out.write(MAGIC)
    out.write(_HEADER.pack(TAG_ENVELOPE, len(envelope)))
    out.write(envelope)
    if sbom is not None:
        sbom.seek(0, 2)
        size = sbom.tell()
        sbom.seek(0)
        out.write(_HEADER.pack(TAG_SBOM, size))
        remaining = size
        while remaining:
            chunk = sbom.read(min(_COPY_CHUNK, remaining))
            if not chunk:
                raise FrameError("SBOM file shrank while it was written")
            out.write(chunk)
            remaining -= len(chunk)
    out.write(_HEADER.pack(TAG_END, 0))
    out.flush()


# --------------------------------------------------------------------------- reading (runner)
class FrameDecoder:
    """Incremental decoder. Feed stdout chunks with `feed`, then call `finish` at EOF.

    `open_sbom()` is called once, when an S frame header is accepted, and must return a writable
    binary file; the decoder writes the SBOM body to it and records its size and SHA-256.
    """

    def __init__(
        self,
        *,
        max_envelope: int,
        max_sbom: int,
        open_sbom: Callable[[], BinaryIO] | None = None,
    ) -> None:
        self.max_envelope = max_envelope
        self.max_sbom = max_sbom
        self._open_sbom = open_sbom
        self._buf = bytearray()
        self._state = "magic"  # magic | header | body | done
        self._tag: bytes = b""
        self._remaining = 0
        self._seen: list[bytes] = []
        self._envelope = bytearray()
        self._sbom_file: BinaryIO | None = None
        self._sbom_hash = hashlib.sha256()
        self.sbom_size: int | None = None
        self.sbom_sha256: str | None = None
        self.total = 0

    # -- state machine
    def feed(self, chunk: bytes) -> None:
        self.total += len(chunk)
        if self._state == "done":
            if chunk:
                raise FrameError("unexpected data after the end frame")
            return
        self._buf += chunk
        while self._step():
            pass

    def _step(self) -> bool:
        if self._state == "magic":
            if len(self._buf) < len(MAGIC):
                if not MAGIC.startswith(bytes(self._buf)):
                    raise FrameError("output does not start with the frame marker")
                return False
            if bytes(self._buf[: len(MAGIC)]) != MAGIC:
                raise FrameError("output does not start with the frame marker")
            del self._buf[: len(MAGIC)]
            self._state = "header"
            return True
        if self._state == "header":
            if len(self._buf) < HEADER_SIZE:
                return False
            tag, length = _HEADER.unpack(bytes(self._buf[:HEADER_SIZE]))
            del self._buf[:HEADER_SIZE]
            self._accept_header(tag, length)
            return True
        if self._state == "body":
            if not self._buf:
                return False
            take = min(len(self._buf), self._remaining)
            part = bytes(self._buf[:take])
            del self._buf[:take]
            self._consume_body(part)
            self._remaining -= take
            if self._remaining == 0:
                self._end_body()
            return True
        # done
        if self._buf:
            raise FrameError("unexpected data after the end frame")
        return False

    def _accept_header(self, tag: bytes, length: int) -> None:
        if tag not in (TAG_ENVELOPE, TAG_SBOM, TAG_END):
            raise FrameError("unknown frame type")
        if tag in self._seen:
            raise FrameError("duplicate frame")
        if not self._seen and tag != TAG_ENVELOPE:
            raise FrameError("the envelope frame must come first")
        self._seen.append(tag)
        if tag == TAG_END:
            if length != 0:
                raise FrameError("the end frame must be empty")
            self._state = "done"
            if self._buf:
                raise FrameError("unexpected data after the end frame")
            return
        cap = self.max_envelope if tag == TAG_ENVELOPE else self.max_sbom
        if length > cap:
            what = "envelope" if tag == TAG_ENVELOPE else "SBOM"
            raise FrameError(f"{what} frame exceeds its size limit ({length} > {cap} bytes)")
        if tag == TAG_SBOM:
            if self._open_sbom is None:
                raise FrameError("an SBOM frame is not expected for this run")
            self._sbom_file = self._open_sbom()
        self._tag = tag
        self._remaining = length
        self._state = "body"
        if length == 0:
            self._end_body()

    def _consume_body(self, part: bytes) -> None:
        if self._tag == TAG_ENVELOPE:
            self._envelope += part
        else:
            assert self._sbom_file is not None  # noqa: S101 - set in _accept_header
            self._sbom_file.write(part)
            self._sbom_hash.update(part)

    def _end_body(self) -> None:
        if self._tag == TAG_SBOM:
            assert self._sbom_file is not None  # noqa: S101
            self._sbom_file.flush()
            self.sbom_size = self._sbom_file.tell()
            self.sbom_sha256 = self._sbom_hash.hexdigest()
        self._state = "header"

    def finish(self) -> bytes:
        """Call at EOF. Returns the envelope bytes; raises FrameError if incomplete."""
        if self._state != "done":
            raise FrameError("output is truncated (no end frame)")
        return bytes(self._envelope)

    @property
    def has_sbom(self) -> bool:
        return TAG_SBOM in self._seen


def decode_frames(raw: bytes, *, max_envelope: int, max_sbom: int = 0) -> bytes:
    """Decode a complete in-memory output that carries no SBOM frame. Returns the envelope."""
    decoder = FrameDecoder(max_envelope=max_envelope, max_sbom=max_sbom)
    decoder.feed(raw)
    return decoder.finish()


# --------------------------------------------------------------------------- JSON budget
_JSON_STRING = re.compile(rb'"(?:[^"\\]|\\.)*"', re.DOTALL)
_BRACKETS = bytes.maketrans(b"", b"")
_KEEP = b"[]{}"
_DELETE = bytes(b for b in range(256) if b not in _KEEP)


def check_json_budget(raw: bytes, *, max_containers: int, max_items: int, max_depth: int) -> None:
    """Bound what `json.loads(raw)` can allocate, without parsing it.

    Strings are blanked out first (so brackets and commas inside them do not count), then the
    containers (`{`, `[`), the separators (`,`, an upper bound on extra elements) and the nesting
    depth are counted. A small document with millions of `{}` would otherwise expand about 20x
    in memory. Raises FrameError when a budget is exceeded. Linear time, constant extra memory
    apart from the blanked copy.
    """
    blank = _JSON_STRING.sub(b'""', raw)
    containers = blank.count(b"{") + blank.count(b"[")
    if containers > max_containers:
        raise FrameError(f"JSON has too many objects or arrays ({containers} > {max_containers})")
    items = blank.count(b",") + containers
    if items > max_items:
        raise FrameError(f"JSON has too many elements ({items} > {max_items})")
    depth = deepest = 0
    for byte in blank.translate(_BRACKETS, _DELETE):
        if byte in (0x5B, 0x7B):  # [ {
            depth += 1
            if depth > deepest:
                deepest = depth
                if deepest > max_depth:
                    raise FrameError(f"JSON is nested too deeply (> {max_depth})")
        else:
            depth -= 1
