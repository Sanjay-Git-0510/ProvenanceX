import zipfile

import pytest

from app.scanners.model.serialization import (
    detect_serialization,
    is_weight_file,
    serialization_from_name,
)
from tests.model_helpers import safetensors_bytes, torch_zip_bytes, write


@pytest.mark.parametrize(
    ("name", "data", "expected"),
    [
        ("m.safetensors", safetensors_bytes(), "safetensors"),
        ("m.bin", b"\x80\x02}q\x00.", "pickle"),
        ("m.pkl", b"(dp0\n.", "pickle"),  # protocol 0: claimed by extension
        ("m.gguf", b"GGUF\x03\x00\x00\x00" + bytes(16), "gguf"),
        ("m.h5", b"\x89HDF\r\n\x1a\n" + bytes(8), "hdf5"),
        ("m.npy", b"\x93NUMPY\x01\x00", "numpy"),
        ("m.tflite", b"\x1c\x00\x00\x00TFL3" + bytes(8), "tflite"),
        ("m.onnx", b"\x08\x07\x12\x04test", "onnx"),
        ("m.msgpack", b"\x81\xa1a\x01", "msgpack"),
        ("notes.txt", b"hello", "unknown"),
    ],
)
def test_magic_detection(tmp_path, name, data, expected):
    assert detect_serialization(write(tmp_path / name, data)) == expected


def test_pytorch_zip_detected(tmp_path):
    path = write(tmp_path / "pytorch_model.bin", torch_zip_bytes(b"\x80\x02}q\x00."))
    assert detect_serialization(path) == "pytorch_zip"


def test_plain_and_numpy_zip(tmp_path):
    plain = tmp_path / "a.zip"
    with zipfile.ZipFile(plain, "w") as zf:
        zf.writestr("x.txt", "hi")
    assert detect_serialization(plain) == "zip"
    npz = tmp_path / "a.npz"
    with zipfile.ZipFile(npz, "w") as zf:
        zf.writestr("arr.npy", b"\x93NUMPY")
    assert detect_serialization(npz) == "numpy_zip"


def test_corrupt_zip_is_unknown(tmp_path):
    assert detect_serialization(write(tmp_path / "x.pt", b"PK\x03\x04garbage")) == "unknown"


def test_safetensors_with_bad_length_is_not_safetensors(tmp_path):
    data = (10**9).to_bytes(8, "little") + b"{}"
    assert detect_serialization(write(tmp_path / "m.safetensors", data)) == "unknown"


def test_name_helpers():
    assert is_weight_file("a/b/model.safetensors") and not is_weight_file("README.md")
    assert serialization_from_name("pytorch_model-00001-of-00002.bin") == "pickle_or_pytorch"
    assert serialization_from_name("model.gguf") == "gguf"
    assert serialization_from_name("x.txt") == "unknown"
