from app.scanners.model.safetensors_header import parse_safetensors_header
from tests.model_helpers import raw_safetensors, safetensors_bytes, write


def test_valid_header(tmp_path):
    path = write(
        tmp_path / "m.safetensors",
        safetensors_bytes({"a": ("F32", [2, 3]), "b": ("F16", [4])}, metadata={"format": "pt"}),
    )
    info = parse_safetensors_header(path)
    assert info.valid and info.issues == []
    assert info.tensor_count == 2 and info.parameter_count == 10
    assert info.dtypes == {"F32": 1, "F16": 1} and info.metadata == {"format": "pt"}


def test_header_length_beyond_file(tmp_path):
    path = write(tmp_path / "m.safetensors", raw_safetensors({}, declared_len=999))
    info = parse_safetensors_header(path)
    assert not info.valid and "exceeds the file size" in info.issues[0]


def test_oversized_header_rejected_without_reading(tmp_path):
    path = write(tmp_path / "m.safetensors", (2**40).to_bytes(8, "little") + b"{")
    info = parse_safetensors_header(path)
    assert not info.valid and "exceeds" in info.issues[0]


def test_invalid_json_and_non_object(tmp_path):
    assert not parse_safetensors_header(write(tmp_path / "a", raw_safetensors(b"{nope"))).valid
    assert not parse_safetensors_header(write(tmp_path / "b", raw_safetensors([1, 2]))).valid


def test_out_of_bounds_offsets(tmp_path):
    header = {"w": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}}
    info = parse_safetensors_header(write(tmp_path / "m", raw_safetensors(header, bytes(4))))
    assert not info.valid and "out of bounds" in info.issues[0]


def test_size_shape_mismatch_and_bad_dtype(tmp_path):
    header = {"w": {"dtype": "F32", "shape": [3], "data_offsets": [0, 8]}}
    info = parse_safetensors_header(write(tmp_path / "a", raw_safetensors(header, bytes(8))))
    assert not info.valid and "does not match" in info.issues[0]
    header = {"w": {"dtype": "EVIL", "shape": [2], "data_offsets": [0, 8]}}
    info = parse_safetensors_header(write(tmp_path / "b", raw_safetensors(header, bytes(8))))
    assert not info.valid and "unknown dtype" in info.issues[0]


def test_overlap_rejected_and_trailing_bytes_reported(tmp_path):
    header = {
        "a": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]},
        "b": {"dtype": "F32", "shape": [2], "data_offsets": [4, 12]},
    }
    info = parse_safetensors_header(write(tmp_path / "a", raw_safetensors(header, bytes(12))))
    assert not info.valid and "overlap" in info.issues[0]
    header = {"a": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}}
    info = parse_safetensors_header(write(tmp_path / "b", raw_safetensors(header, bytes(20))))
    assert info.valid and "trailing" in info.issues[0]


def test_truncated_file(tmp_path):
    info = parse_safetensors_header(write(tmp_path / "m", b"\x01\x02"))
    assert not info.valid
