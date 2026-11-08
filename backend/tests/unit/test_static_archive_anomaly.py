import struct

import pytest

from app.scanners.static import archive_anomaly as aa
from app.scanners.static import rules
from tests.conftest import build_zip, symlink_info
from tests.model_helpers import write

RATIO = 100


def pe_head() -> bytes:
    head = bytearray(b"MZ" + bytes(126))
    struct.pack_into("<I", head, 0x3C, 0x40)
    head[0x40:0x44] = b"PE\0\0"
    return bytes(head)


@pytest.mark.parametrize(
    ("head", "kind"),
    [
        (b"\x7fELF\x02\x01", "ELF"),
        (b"\xcf\xfa\xed\xfe....", "Mach-O"),
        (b"\xfe\xed\xfa\xce....", "Mach-O"),
        (pe_head(), "PE"),
        (b"MZ this is a text file that happens to start with those letters" + b" " * 40, None),
        (b"MZ", None),
        (b"plain", None),
        (b"", None),
    ],
)
def test_executable_format(head, kind):
    assert aa.executable_format(head) == kind


@pytest.mark.parametrize("name", ["model.bin", "weights.pt", "notes.txt", "a/b/config.json"])
def test_disguised_executable(name):
    [hit] = aa.check_identity(name, b"\x7fELF....")
    assert hit.rule == rules.ARCHIVE_DISGUISED_EXE and hit.rule.severity == "HIGH"


@pytest.mark.parametrize("name", ["lib.so", "a.dll", "a.exe", "tool", "lib.so.1", "libz.so.1.2.13"])
def test_native_names_or_no_extension_are_not_disguised(name):
    assert aa.check_identity(name, b"\x7fELF....") == []


@pytest.mark.parametrize("name", ["model.bin.exe", "invoice.pdf.scr", "readme.txt.bat"])
def test_double_extension(name):
    assert [h.rule for h in aa.check_identity(name, b"x")] == [rules.ARCHIVE_DOUBLE_EXT]


@pytest.mark.parametrize("name", ["a.b.exe", "archive.tar.gz", "my.script.sh", "setup.exe"])
def test_ordinary_dotted_names(name):
    assert aa.check_identity(name, b"x") == []


@pytest.mark.parametrize(
    ("rel", "zip_family", "opaque"),
    [
        ("a.zip", True, False),
        ("a.whl", True, False),
        ("a.tar.gz", False, True),
        ("a.TGZ", False, True),
        ("a.7z", False, True),
        ("a.txt", False, False),
    ],
)
def test_archive_classification(rel, zip_family, opaque):
    assert aa.is_zip_family(rel) is zip_family and aa.is_opaque_archive(rel) is opaque


def test_clean_nested_zip_is_reported_as_nested_only(tmp_path):
    path = write(tmp_path / "n.zip", build_zip([("a.txt", "hello")]))
    assert [h.rule for h in aa.inspect_nested_zip(path, RATIO)] == [rules.ARCHIVE_NESTED]


@pytest.mark.parametrize(
    ("entries", "reason"),
    [
        ([("../evil", "x")], "path traversal"),
        ([("/abs", "x")], "absolute path"),
        ([(symlink_info("link"), "/etc/passwd")], "symlink entry"),
        ([("bomb.bin", b"\x00" * 1_000_000)], "compression ratio"),
    ],
)
def test_unsafe_nested_entries(tmp_path, entries, reason):
    path = write(tmp_path / "n.zip", build_zip(entries))
    unsafe = [h for h in aa.inspect_nested_zip(path, RATIO) if h.rule == rules.ARCHIVE_UNSAFE]
    assert unsafe and reason in unsafe[0].symbol


def test_nested_zip_is_never_extracted(tmp_path):
    path = write(tmp_path / "n.zip", build_zip([("../evil", "x"), ("ok.txt", "y")]))
    before = set(tmp_path.rglob("*"))
    aa.inspect_nested_zip(path, RATIO)
    assert set(tmp_path.rglob("*")) == before


def test_too_many_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(aa, "MAX_NESTED_ENTRIES", 2)
    path = write(tmp_path / "n.zip", build_zip([(f"f{i}", "x") for i in range(4)]))
    assert any("too many" in h.symbol for h in aa.inspect_nested_zip(path, RATIO))


def test_reported_problems_are_capped(tmp_path):
    entries = [(f"../e{i}", "x") for i in range(aa.MAX_REPORTED + 10)]
    path = write(tmp_path / "n.zip", build_zip(entries))
    assert len(aa.inspect_nested_zip(path, RATIO)) == aa.MAX_REPORTED + 1


@pytest.mark.parametrize("data", [b"", b"not a zip", b"PK\x03\x04broken"])
def test_corrupt_nested_zip(tmp_path, data):
    path = write(tmp_path / "n.zip", data)
    assert [h.rule for h in aa.inspect_nested_zip(path, RATIO)] == [rules.ARCHIVE_CORRUPT]


def test_upload_ratio_near_limit(tmp_path):
    path = write(tmp_path / "u.zip", build_zip([("a.bin", b"\x00" * 100_000)]))
    [hit] = aa.inspect_upload_ratio(path, 1500, 0.1)
    assert hit.rule == rules.ARCHIVE_NEAR_LIMIT and "a.bin" in hit.symbol


def test_upload_ratio_below_threshold(tmp_path):
    path = write(tmp_path / "u.zip", build_zip([("a.txt", "abc")]))
    assert aa.inspect_upload_ratio(path, 100, 0.8) == []


def test_upload_ratio_on_unreadable_file(tmp_path):
    assert aa.inspect_upload_ratio(write(tmp_path / "u.zip", b"x"), 100, 0.8) == []
