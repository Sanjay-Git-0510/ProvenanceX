"""Security tests for AI/ML inputs: hostile pickles, archives, headers, cards and URLs.

Hostile inputs are generated in memory (tests/model_helpers.py) and only parsed. Their
payloads are harmless canaries: if anything ever deserialized one, it would create a
marker directory inside tmp_path, and the tests would fail.
"""

import ast
import io
import os
import pickle
import struct
import subprocess
import sys
import types
import zipfile
from pathlib import Path

import pytest

import app as app_package
from app.core.config import Settings
from app.core.errors import AppError, ErrorCode
from app.scanners.model import pickle_scan as pickle_scan_module
from app.scanners.model.aibom import ModelContext, analyze_model
from app.scanners.model.model_card import parse_model_card
from app.scanners.model.pickle_scan import scan_pickle_file
from app.scanners.model.safetensors_header import parse_safetensors_header
from app.security.url_validation import validate_hf_repo_url
from tests.conftest import build_zip, symlink_info
from tests.model_helpers import (
    global_pickle,
    memo_stack_global,
    obfuscated_stack_global,
    raw_safetensors,
    reduce_pickle,
    stack_global_pickle,
    torch_zip_bytes,
    write,
)

URL = "/api/v1/scans/model"
LIMITS = {"max_bytes": 1024 * 1024, "max_opcodes": 100_000}
APP_DIR = Path(app_package.__file__).parent


def scan(tmp_path, data, serialization="pickle", name="m.pkl", **kw):
    return scan_pickle_file(write(tmp_path / name, data), serialization, **{**LIMITS, **kw})


def _forbid(*_a, **_k):
    raise AssertionError("artifact deserialization must never happen")


@pytest.fixture
def no_deserialization(monkeypatch):
    """Every loader that could run artifact code raises if it is touched."""
    monkeypatch.setattr(pickle, "load", _forbid)
    monkeypatch.setattr(pickle, "loads", _forbid)
    monkeypatch.setattr(pickle, "Unpickler", _forbid)
    monkeypatch.setattr(os, "system", _forbid)
    monkeypatch.setattr(subprocess, "Popen", _forbid)
    fake_torch = types.ModuleType("torch")
    fake_torch.load = _forbid
    monkeypatch.setitem(sys.modules, "torch", fake_torch)
    fake_joblib = types.ModuleType("joblib")
    fake_joblib.load = _forbid
    monkeypatch.setitem(sys.modules, "joblib", fake_joblib)


def ctx() -> ModelContext:
    return ModelContext(name="x", artifact_type="model", source="upload", source_url=None)


# ------------------------------------------------------------------ hostile pickles
@pytest.mark.parametrize(
    ("builder", "module", "name"),
    [
        (global_pickle, "os", "system"),
        (global_pickle, "builtins", "eval"),
        (global_pickle, "subprocess", "Popen"),
        (stack_global_pickle, "builtins", "exec"),
        (stack_global_pickle, "posix", "system"),
        (obfuscated_stack_global, "os", "system"),
        (obfuscated_stack_global, "builtins", "__import__"),
        (memo_stack_global, "subprocess", "check_output"),
        (memo_stack_global, "socket", "socket"),
    ],
)
def test_hostile_opcodes_are_flagged(tmp_path, builder, module, name, no_deserialization):
    result = scan(tmp_path, builder(module, name))
    assert result.status == "ok"
    assert result.dangerous == [f"{module}.{name}"]


def test_decoy_safe_import_does_not_hide_the_real_target(tmp_path):
    result = scan(tmp_path, obfuscated_stack_global("os", "system"))
    assert "os.system" in result.dangerous and "collections.OrderedDict" not in result.globals


def test_dangerous_pickle_hidden_after_a_benign_stream(tmp_path):
    data = pickle.dumps({"ok": 1}, 2) + global_pickle("os", "system")
    assert scan(tmp_path, data).dangerous == ["os.system"]


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x80",
        b"\x80\x04",
        b"\xff" * 64,
        b"\x80\x04\x95\xff\xff\xff\xff\xff\xff\xff\xff",  # FRAME with an absurd length
        b"\x80\x04R.",  # stack underflow
        b"\x80\x04\x93.",  # STACK_GLOBAL with an empty stack
        b"(" * 10_000,  # unbalanced marks
        b"c\n\n.",  # GLOBAL with empty names
    ],
)
def test_malformed_pickles_never_crash(tmp_path, data, no_deserialization):
    assert scan(tmp_path, data).status in ("parse_error", "ok", "truncated")


def test_opcode_flood_is_truncated(tmp_path):
    result = scan(tmp_path, b"\x80\x04" + b"N0" * 5000 + b"N.", max_opcodes=100)
    assert result.status == "truncated"


# ------------------------------------------------------------------ PyTorch ZIP containers
def _zip(entries, compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compression) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def test_zip_bomb_member_is_refused_without_inflating(tmp_path, monkeypatch):
    bomb = _zip([("archive/data.pkl", b"\x00" * (512 * 1024))])

    def no_inflate(*_a, **_k):
        raise AssertionError("bomb member must not be opened")

    monkeypatch.setattr(zipfile.ZipFile, "open", no_inflate)
    result = scan(tmp_path, bomb, "pytorch_zip", "pytorch_model.bin")
    assert result.status == "too_large" and "ratio" in result.error


def test_member_over_the_size_limit_is_refused(tmp_path):
    data = torch_zip_bytes(b"N" * 2048 + b".")
    result = scan(tmp_path, data, "pytorch_zip", "m.pt", max_bytes=1024)
    assert result.status == "too_large" and "size limit" in result.error


def test_too_many_members_is_a_parse_error(tmp_path, monkeypatch):
    monkeypatch.setattr(pickle_scan_module, "MAX_ZIP_MEMBERS", 3)
    data = _zip([(f"archive/{i}.pkl", b"N.") for i in range(5)])
    assert scan(tmp_path, data, "pytorch_zip", "m.pt").status == "parse_error"


def test_encrypted_member_is_reported(tmp_path):
    raw = bytearray(_zip([("archive/data.pkl", b"N.")], zipfile.ZIP_STORED))
    # Set the "encrypted" flag bit in the local header and the central directory.
    for sig, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        at = raw.find(sig) + offset
        raw[at : at + 2] = struct.pack("<H", struct.unpack("<H", raw[at : at + 2])[0] | 1)
    result = scan(tmp_path, bytes(raw), "pytorch_zip", "m.pt")
    assert result.status == "parse_error" and result.error == "encrypted member"


def test_corrupt_zip_is_a_parse_error(tmp_path):
    assert scan(tmp_path, b"PK\x03\x04broken", "pytorch_zip", "m.pt").status == "parse_error"


def test_traversal_member_name_is_read_but_never_extracted(tmp_path):
    data = _zip([("../../escaped.pkl", global_pickle("os", "system"))])
    before = set(tmp_path.rglob("*"))
    result = scan(tmp_path, data, "pytorch_zip", "m.pt")
    assert result.dangerous == ["os.system"]
    assert set(tmp_path.rglob("*")) - before == {tmp_path / "m.pt"}


# ------------------------------------------------------------------ nothing is ever loaded
@pytest.mark.parametrize("wrap", [False, True])
def test_analysis_never_deserializes_or_runs_payloads(tmp_path, monkeypatch, wrap):
    canary = tmp_path / "CANARY"
    payload = reduce_pickle(os.mkdir, (str(canary),))
    root = tmp_path / "src"
    if wrap:
        write(root / "pytorch_model.bin", torch_zip_bytes(payload))
    else:
        write(root / "model.pkl", payload)
    monkeypatch.setattr(pickle, "load", _forbid)
    monkeypatch.setattr(pickle, "loads", _forbid)
    monkeypatch.setattr(pickle, "Unpickler", _forbid)
    analysis = analyze_model(root, ctx(), Settings(_env_file=None))
    weights = [f for f in analysis.inventory if f.analysis.get("pickle")]
    assert weights and any(
        g.endswith(".mkdir") for g in weights[0].analysis["pickle"]["dangerous_globals"]
    )
    assert not canary.exists()


def test_custom_code_is_detected_but_never_imported(tmp_path):
    canary = tmp_path / "CANARY"
    root = tmp_path / "src"
    write(root / "modeling_x.py", f"open({str(canary)!r}, 'w').close()\n")
    write(
        root / "config.json",
        '{"model_type": "x", "auto_map": {"AutoModel": "modeling_x.Model"}}',
    )
    analysis = analyze_model(root, ctx(), Settings(_env_file=None))
    assert analysis.custom_code.present and analysis.custom_code.remote_code_required
    assert not canary.exists()
    assert "modeling_x" not in sys.modules


def _app_sources():
    return [p for p in APP_DIR.rglob("*.py") if "__pycache__" not in p.parts]


FORBIDDEN_MODULES = {"pickle", "cPickle", "dill", "cloudpickle", "joblib", "torch", "safetensors"}


@pytest.mark.parametrize("path", _app_sources(), ids=lambda p: p.relative_to(APP_DIR).as_posix())
def test_application_code_has_no_unsafe_loader(path):
    """Static guard (CLAUDE.md boundary 2): artifact-loading libraries are never imported."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not {a.name.split(".")[0] for a in node.names} & FORBIDDEN_MODULES
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in FORBIDDEN_MODULES
        elif isinstance(node, ast.keyword):
            is_true = isinstance(node.value, ast.Constant) and node.value.value is True
            assert not (node.arg == "trust_remote_code" and is_true)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "yaml"
            and node.func.attr == "load"
        ):
            loader = next((k.value for k in node.keywords if k.arg == "Loader"), None)
            assert isinstance(loader, ast.Attribute) and loader.attr == "SafeLoader"


# ------------------------------------------------------------------ safetensors headers
@pytest.mark.parametrize(
    ("data", "issue"),
    [
        (struct.pack("<Q", 2**63) + b"{}", "exceeds"),
        (struct.pack("<Q", 2**64 - 1), "exceeds"),
        (struct.pack("<Q", 64 * 1024 * 1024) + b"{}", "exceeds"),
        (struct.pack("<Q", 100) + b"{}", "exceeds the file size"),
        (b"\x01\x02", "shorter"),
        (b"", "shorter"),
        (raw_safetensors(b"{not json"), "not valid JSON"),
        (raw_safetensors(b"[" * 200_000), "not valid JSON"),
        (raw_safetensors([1, 2]), "not a JSON object"),
        (raw_safetensors({"t": "not-an-object"}), "not an object"),
    ],
)
def test_hostile_safetensors_header(tmp_path, data, issue):
    info = parse_safetensors_header(write(tmp_path / "m.safetensors", data))
    assert info.valid is False and any(issue in i for i in info.issues), info.issues


@pytest.mark.parametrize(
    "entry",
    [
        {"dtype": "F32", "shape": [2], "data_offsets": [0, 8000]},  # beyond the file
        {"dtype": "F32", "shape": [2], "data_offsets": [8, 0]},  # reversed
        {"dtype": "F32", "shape": [2], "data_offsets": [-8, 0]},  # negative
        {"dtype": "F32", "shape": [2], "data_offsets": [0, 4]},  # disagrees with the shape
        {"dtype": "F32", "shape": [2**40, 2**40], "data_offsets": [0, 8]},  # size overflow
        {"dtype": "EVIL", "shape": [2], "data_offsets": [0, 8]},
        {"dtype": "F32", "shape": "nope", "data_offsets": [0, 8]},
    ],
)
def test_hostile_tensor_entries_never_pass_as_clean(tmp_path, entry):
    data = raw_safetensors({"t": entry}, bytes(8))
    info = parse_safetensors_header(write(tmp_path / "m.safetensors", data))
    assert info.issues, entry


# ------------------------------------------------------------------ model cards (YAML)
def card(front: str) -> bytes:
    return f"---\n{front}\n---\n\n# Card\n".encode()


def test_yaml_alias_bomb_is_rejected():
    bomb = "a: &a [x, x]\nb: &b [*a, *a]\nc: &c [*b, *b]\nd: [*c, *c]"
    parsed = parse_model_card(card(bomb), max_bytes=1024 * 1024)
    assert parsed.metadata == {} and any("anchors" in i for i in parsed.issues)


@pytest.mark.parametrize(
    "tag",
    [
        "!!python/object/apply:os.mkdir [CANARY]",
        "!!python/object/new:os.system [id]",
        "!!python/name:os.system",
        "!!python/module:os",
    ],
)
def test_yaml_python_tags_are_not_constructed(tmp_path, monkeypatch, tag):
    monkeypatch.chdir(tmp_path)
    parsed = parse_model_card(card(f"license: {tag}"), max_bytes=1024 * 1024)
    assert parsed.metadata == {} and parsed.issues
    assert not (tmp_path / "CANARY").exists()


def test_deeply_nested_yaml_does_not_crash():
    parsed = parse_model_card(card("a: " + "[" * 20_000), max_bytes=1024 * 1024)
    assert parsed.metadata == {} and parsed.issues


def test_oversized_front_matter_is_rejected():
    parsed = parse_model_card(card("a: " + "x" * 70_000), max_bytes=1024 * 1024)
    assert any("64 KB" in i for i in parsed.issues)


def test_too_many_yaml_events_is_rejected():
    flood = "a: [" + ",".join(["1"] * 25_000) + "]"
    parsed = parse_model_card(card(flood[:64_000].rsplit(",", 1)[0] + "]"), max_bytes=10**6)
    assert any("too many" in i for i in parsed.issues)


def test_oversized_readme_is_truncated():
    parsed = parse_model_card(b"# Card\n" + b"x" * 5000, max_bytes=1000)
    assert any("exceeds" in i for i in parsed.issues)


@pytest.mark.parametrize("raw", [b"\xff\xfe\x00", b"---\n\x00\n---\n", b"---\nunterminated"])
def test_binary_or_malformed_cards_do_not_crash(raw):
    assert parse_model_card(raw, max_bytes=1000).present is True


def test_card_field_types_are_enforced():
    parsed = parse_model_card(
        card("license: {a: 1}\nbase_model: 7\ndatasets: [1, {x: y}]\ntags: [ok]"),
        max_bytes=10_000,
    )
    assert parsed.metadata == {"tags": ["ok"]}


# ------------------------------------------------------------------ Hugging Face URLs
BAD_URLS = [
    "http://huggingface.co/org/repo",
    "ftp://huggingface.co/org/repo",
    "file:///etc/passwd",
    "https://huggingface.co.evil.example/org/repo",
    "https://evil.example/huggingface.co/org/repo",
    "https://github.com/org/repo",
    "https://www.huggingface.co/org/repo",
    "https://hf.co/org/repo",
    "https://user:pw@huggingface.co/org/repo",
    "https://huggingface.co@evil.example/org/repo",
    "https://huggingface.co:8443/org/repo",
    "https://127.0.0.1/org/repo",
    "https://[::1]/org/repo",
    "https://169.254.169.254/latest/meta-data",
    "https://huggingface.co/org/repo?x=1",
    "https://huggingface.co/org/repo#frag",
    "https://huggingface.co/org/repo/tree/main",
    "https://huggingface.co/org/repo/resolve/main/x.bin",
    "https://huggingface.co/org/repo/blob/main/x.bin",
    "https://huggingface.co/spaces/org/app",
    "https://huggingface.co/api/models/org",
    "https://huggingface.co/settings/tokens",
    "https://huggingface.co/datasets/only-one",
    "https://huggingface.co/",
    "https://huggingface.co",
    "https://huggingface.co/org/../../etc",
    "https://huggingface.co/org/%2e%2e",
    "https://huggingface.co/org/repo.git",
    "https://huggingface.co/-org/repo",
    "https://huggingface.co/org\\repo",
    "https://huggingface.co/org/re po",
    "https://huggingfacе.co/org/repo",  # Cyrillic "е"
    "https://huggingface.co/org/" + "x" * 3000,
    "",
    "   ",
]


@pytest.mark.parametrize("url", BAD_URLS)
def test_hostile_hf_urls_are_refused(url):
    with pytest.raises(AppError) as exc:
        validate_hf_repo_url(url, check_dns=False)
    assert exc.value.code in (ErrorCode.INVALID_URL, ErrorCode.URL_NOT_ALLOWED)


@pytest.mark.parametrize("value", [None, 7, ["https://huggingface.co/a/b"]])
def test_non_string_urls_are_refused(value):
    with pytest.raises(AppError):
        validate_hf_repo_url(value, check_dns=False)


@pytest.mark.parametrize(
    ("url", "repo_type", "repo_id"),
    [
        ("https://huggingface.co/org/repo", "model", "org/repo"),
        ("https://huggingface.co/org/repo/", "model", "org/repo"),
        ("https://huggingface.co/gpt2", "model", "gpt2"),
        ("https://huggingface.co/datasets/org/data", "dataset", "org/data"),
    ],
)
def test_valid_hf_urls_are_canonicalized(url, repo_type, repo_id):
    repo = validate_hf_repo_url(url, check_dns=False)
    assert (repo.repo_type, repo.repo_id) == (repo_type, repo_id)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fe80::1"])
def test_hf_host_resolving_to_private_address_is_refused(monkeypatch, ip):
    monkeypatch.setattr("app.security.url_validation.resolve_host", lambda h: [ip])
    with pytest.raises(AppError) as exc:
        validate_hf_repo_url("https://huggingface.co/org/repo")
    assert exc.value.code == ErrorCode.PRIVATE_ADDRESS


def test_api_rejects_private_dns_with_a_structured_error(scan_client, monkeypatch):
    monkeypatch.setattr("app.security.url_validation.resolve_host", lambda h: ["127.0.0.1"])
    resp = scan_client.post(URL, data={"source_url": "https://huggingface.co/org/repo"})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "private_address"


@pytest.mark.parametrize(
    "url",
    [
        "http://huggingface.co/org/repo",
        "https://evil.example/org/repo",
        "https://huggingface.co/org/repo/tree/main",
    ],
)
def test_api_rejects_bad_urls_before_creating_a_scan(scan_client, test_settings, url):
    resp = scan_client.post(URL, data={"source_url": url})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] in ("invalid_url", "url_not_allowed")
    root = test_settings.workspace_root
    assert not root.exists() or not list(root.iterdir())


# ------------------------------------------------------------------ uploads end to end
def _upload(client, data: bytes, name: str = "m.zip"):
    resp = client.post(URL, files={"file": (name, data, "application/zip")})
    assert resp.status_code == 202, resp.text
    return client.get(f"/api/v1/scans/{resp.json()['scan_id']}").json()


@pytest.mark.parametrize(
    ("entries", "reason"),
    [
        ([("../evil.safetensors", b"x")], "path traversal"),
        ([("/etc/evil", b"x")], "absolute path"),
        ([(symlink_info("model.bin"), "/etc/passwd")], "symlink entry"),
    ],
)
def test_hostile_model_zip_fails_safely(scan_client, entries, reason):
    body = _upload(scan_client, build_zip(entries))
    assert body["status"] == "failed"
    assert body["error"]["code"] == "unsafe_archive"
    assert body["error"]["details"]["reason"] == reason
    assert (body.get("stages") or {}) == {}


def test_decompression_bomb_upload_fails_safely(scan_client):
    body = _upload(scan_client, build_zip([("weights.bin", b"\x00" * (1024 * 1024))]))
    assert body["status"] == "failed" and body["error"]["code"] == "unsafe_archive"


def test_malicious_pickle_upload_is_reported_not_executed(scan_client, tmp_path):
    canary = tmp_path / "CANARY"
    payload = torch_zip_bytes(reduce_pickle(os.mkdir, (str(canary),)))
    body = _upload(scan_client, build_zip([("pytorch_model.bin", payload)]))
    assert body["status"] == "completed", body
    assert not canary.exists()
    scan_id = body["scan_id"]
    static = scan_client.get(
        f"/api/v1/scans/{scan_id}/findings", params={"category": "static"}
    ).json()["items"]
    dangerous = [f for f in static if f["identifier"] == "PX-PICKLE-DANGEROUS-IMPORT"]
    assert len(dangerous) == 1
    finding = dangerous[0]
    assert finding["severity"] == "HIGH" and finding["kind"] == "unsafe_deserialization"
    assert finding["source"] == "provenancex"
    # A suspicious signal, not a known vulnerability: no CVSS may be attached.
    assert finding["cvss"] is None or finding["cvss"].get("score") is None
    vulns = scan_client.get(
        f"/api/v1/scans/{scan_id}/findings", params={"category": "vulnerability"}
    ).json()
    assert vulns["total"] == 0


def test_garbage_weights_do_not_fail_the_scan(scan_client):
    body = _upload(
        scan_client,
        build_zip(
            [
                ("not_really.safetensors", struct.pack("<Q", 2**63) + b"{}"),
                (
                    "bad_offsets.safetensors",
                    raw_safetensors(
                        {"t": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8000]}}, bytes(8)
                    ),
                ),
                ("model.pkl", b"\xff" * 32),
                ("config.json", "{not json"),
                ("README.md", b"---\n\xff\n---\n"),
            ]
        ),
    )
    assert body["status"] == "completed", body
    assert body["stages"]["aibom"]["status"] == "completed"
    ids = {
        f["identifier"]
        for f in scan_client.get(f"/api/v1/scans/{body['scan_id']}/findings").json()["items"]
    }
    assert {"PX-SAFETENSORS-MALFORMED", "PX-MODEL-FORMAT-MISMATCH"} <= ids


def test_error_message_does_not_leak_internal_paths(scan_client, test_settings):
    body = _upload(scan_client, build_zip([("../evil", b"x")]))
    assert str(test_settings.workspace_root) not in str(body["error"])
