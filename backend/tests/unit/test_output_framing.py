"""Framed sandbox output (audit finding M3): malformed, truncated, oversized or unexpected output
is refused without buffering it, and the JSON envelope's memory expansion is bounded."""

import io
import json
import struct
import tracemalloc

import pytest

from app.analysis.base import parse_worker_output
from app.analysis.framing import (
    MAGIC,
    FrameDecoder,
    FrameError,
    check_json_budget,
    decode_frames,
    write_frames,
)
from app.core.errors import AppError

MB = 1024 * 1024
ENVELOPE = b'{"a": 1}'


def _frame(tag: bytes, body: bytes, length: int | None = None) -> bytes:
    return struct.pack(">cQ", tag, len(body) if length is None else length) + body


def _framed(envelope=ENVELOPE, sbom: bytes | None = None) -> bytes:
    buf = io.BytesIO()
    write_frames(buf, envelope, io.BytesIO(sbom) if sbom is not None else None)
    return buf.getvalue()


class _Sink(io.BytesIO):
    opened = 0


def _decoder(max_envelope=1 * MB, max_sbom=1 * MB, sink: _Sink | None = None) -> FrameDecoder:
    def opener():
        assert sink is not None, "no SBOM frame expected"
        sink.opened += 1
        return sink

    return FrameDecoder(
        max_envelope=max_envelope, max_sbom=max_sbom, open_sbom=opener if sink else None
    )


def test_round_trip_without_sbom():
    assert decode_frames(_framed(), max_envelope=MB) == ENVELOPE


def test_round_trip_with_sbom_streamed_to_the_sink_byte_by_byte():
    sbom = b'{"bomFormat": "CycloneDX"}' * 1000
    sink = _Sink()
    decoder = _decoder(sink=sink)
    for byte in _framed(sbom=sbom):
        decoder.feed(bytes([byte]))
    assert decoder.finish() == ENVELOPE
    assert sink.getvalue() == sbom
    assert decoder.has_sbom and decoder.sbom_size == len(sbom)
    import hashlib

    assert decoder.sbom_sha256 == hashlib.sha256(sbom).hexdigest()


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"", "truncated"),
        (b'{"json": true}', "frame marker"),
        (b"PXF2\n" + _frame(b"E", ENVELOPE) + _frame(b"Z", b""), "frame marker"),
        (MAGIC + _frame(b"E", ENVELOPE), "truncated"),  # no end frame
        (MAGIC + _frame(b"E", ENVELOPE)[:-3], "truncated"),  # body cut short
        (MAGIC + _frame(b"E", ENVELOPE) + _frame(b"Z", b"")[:5], "truncated"),
        (MAGIC + _frame(b"X", b"x") + _frame(b"Z", b""), "unknown frame"),
        (MAGIC + _frame(b"S", b"x") + _frame(b"E", ENVELOPE) + _frame(b"Z", b""), "first"),
        (
            MAGIC + _frame(b"E", ENVELOPE) + _frame(b"E", ENVELOPE) + _frame(b"Z", b""),
            "duplicate",
        ),
        (MAGIC + _frame(b"E", ENVELOPE) + _frame(b"Z", b"", length=3) + b"abc", "empty"),
        (MAGIC + _frame(b"E", ENVELOPE) + _frame(b"Z", b"") + b"trailing", "after the end"),
        (MAGIC + _frame(b"E", ENVELOPE) + _frame(b"S", b"x") + _frame(b"Z", b""), "not expected"),
    ],
)
def test_malformed_output_is_refused(raw, reason):
    decoder = _decoder()
    with pytest.raises(FrameError) as info:
        decoder.feed(raw)
        decoder.finish()
    assert reason in str(info.value)


def test_oversized_envelope_is_refused_from_its_header_without_reading_the_body():
    decoder = _decoder(max_envelope=1 * MB)
    with pytest.raises(FrameError, match="envelope frame exceeds"):
        decoder.feed(MAGIC + struct.pack(">cQ", b"E", 64 * MB))
    assert len(decoder._envelope) == 0  # noqa: SLF001 - nothing buffered


def test_oversized_sbom_is_refused_before_the_sink_is_opened():
    sink = _Sink()
    decoder = _decoder(max_sbom=1 * MB, sink=sink)
    with pytest.raises(FrameError, match="SBOM frame exceeds"):
        decoder.feed(MAGIC + _frame(b"E", ENVELOPE) + struct.pack(">cQ", b"S", 2 * MB))
    assert sink.opened == 0


def test_a_huge_declared_length_never_allocates():
    tracemalloc.start()
    try:
        decoder = _decoder(max_envelope=16 * MB)
        with pytest.raises(FrameError):
            decoder.feed(MAGIC + struct.pack(">cQ", b"E", 2**63))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 1 * MB


# --------------------------------------------------------------------------- JSON budget
def test_budget_counts_containers_but_not_brackets_inside_strings():
    check_json_budget(
        json.dumps({"s": "[[[[{{{{" * 1000}).encode(),
        max_containers=1,
        max_items=10,
        max_depth=2,
    )
    with pytest.raises(FrameError, match="too many objects"):
        check_json_budget(b"[" + b"{}," * 10 + b"{}]", max_containers=5, max_items=100, max_depth=5)


def test_budget_counts_items_and_depth():
    with pytest.raises(FrameError, match="too many elements"):
        check_json_budget(b"[" + b"1," * 100 + b"1]", max_containers=5, max_items=50, max_depth=5)
    with pytest.raises(FrameError, match="nested too deeply"):
        check_json_budget(b"[" * 70 + b"]" * 70, max_containers=100, max_items=100, max_depth=64)


def test_escaped_quotes_do_not_confuse_the_string_blanking():
    raw = json.dumps({"k": 'a\\"[{' * 50, "list": [1, 2]}).encode()
    check_json_budget(raw, max_containers=2, max_items=10, max_depth=2)


def test_hostile_envelope_is_refused_before_json_loads_with_bounded_memory():
    """12 MB of `{}` would expand ~20x in json.loads; the budget refuses it first."""
    hostile = b'{"format":"x","mode":"analyze","items":[' + b"{}," * (4 * MB) + b"{}]}"
    tracemalloc.start()
    try:
        with pytest.raises(AppError) as info:
            parse_worker_output(hostile, 16 * MB, "analyze")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert info.value.code == "analyzer_output_invalid"
    assert "too many" in info.value.details["reason"]
    # The blanked copy of the input is the only large allocation (~1x the input).
    assert peak < 3 * len(hostile), peak


def test_large_but_legitimate_envelope_parses_with_bounded_amplification():
    """A 20,000-file tree listing (the MAX_ARTIFACT_FILES default) stays far below the cap."""
    paths = [f"src/package_{i:05d}/module_{i:05d}.py" for i in range(20_000)]
    doc = {
        "format": "provenancex-analyzer-result-v1",
        "mode": "analyze",
        "status": "ok",
        "isolation_mode": "container",
        "isolation": {"non_root": True},
        "analysis": {
            "tree": {"sha256": "a" * 64, "file_count": 20_000, "total_bytes": 1},
            "file_paths": paths,
        },
    }
    raw = json.dumps(doc).encode()
    tracemalloc.start()
    try:
        result = parse_worker_output(raw, 12 * MB, "analyze")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(result.analysis.file_paths) == 20_000
    assert len(raw) < 2 * MB
    assert peak < 20 * MB, peak
