"""Real Hugging Face provider, driven by an in-memory fake Hub (httpx.MockTransport)."""

import hashlib
import json
import stat

import httpx
import pytest

from app.core.errors import AppError, ErrorCode
from app.scanners.hf.base import HfFetchLimits
from app.scanners.hf.client import (
    MAX_PATH_DEPTH,
    MAX_REDIRECTS,
    HuggingFaceProvider,
    safe_repo_path,
)
from app.security.url_validation import HfRepo

SHA = "a" * 40
REPO = HfRepo("model", "org/repo")
LIMITS = HfFetchLimits(max_total_bytes=1000, max_file_bytes=100, max_files=20, timeout_seconds=60)
RESOLVE = f"/org/repo/resolve/{SHA}/"


def regular(path, data: bytes) -> dict:
    oid = hashlib.sha1(f"blob {len(data)}\0".encode() + data, usedforsecurity=False).hexdigest()
    return {"type": "file", "path": path, "size": len(data), "oid": oid}


def lfs(path, data: bytes) -> dict:
    return {
        "type": "file",
        "path": path,
        "size": len(data),
        "oid": "b" * 40,
        "lfs": {"oid": hashlib.sha256(data).hexdigest(), "size": len(data)},
    }


class Hub:
    """Serves API + file routes and records every request it receives."""

    def __init__(self, tree, files=None, info=None):
        self.tree = tree
        self.files = files or {}  # url path -> bytes | httpx.Response
        self.info = {"sha": SHA, "id": "org/repo", "author": "org", **(info or {})}
        self.requests: list[httpx.Request] = []

    @property
    def hosts(self) -> set[str]:
        return {r.url.host for r in self.requests}

    @property
    def paths(self) -> list[str]:
        return [r.url.path for r in self.requests]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path in self.files:
            value = self.files[path]
            return (
                value if isinstance(value, httpx.Response) else httpx.Response(200, content=value)
            )
        if "/tree/" in path:
            return httpx.Response(200, json=self.tree)
        if path.startswith(("/api/models/", "/api/datasets/")):
            return httpx.Response(200, json=self.info)
        return httpx.Response(404)


def provider(handler, **kw) -> HuggingFaceProvider:
    args = {
        "timeout_seconds": 5,
        "max_retries": 1,
        "max_api_bytes": 1024 * 1024,
        "user_agent": "provenancex-tests",
        "transport": httpx.MockTransport(handler),
        "check_dns": False,
        "sleep": lambda _s: None,
    }
    return HuggingFaceProvider(**{**args, **kw})


def fetch(tmp_path, hub, limits=LIMITS, revision=None, repo=REPO, **kw):
    dest = tmp_path / "jail" / "src"
    dest.mkdir(parents=True)
    return provider(hub, **kw).fetch(repo, revision, dest, limits)


def only(result):
    assert len(result.files) == 1
    return result.files[0]


def assert_jailed(tmp_path):
    """Nothing may be written outside the destination directory."""
    jail = tmp_path / "jail"
    for p in tmp_path.rglob("*"):
        assert p == jail or jail in p.parents, f"escaped: {p}"


# ------------------------------------------------------------------ happy paths
def test_downloads_and_verifies_regular_and_lfs_files(tmp_path):
    cfg, weights = b'{"a": 1}', b"weights" * 3
    hub = Hub(
        [regular("config.json", cfg), lfs("sub/m.safetensors", weights)],
        {RESOLVE + "config.json": cfg, RESOLVE + "sub/m.safetensors": weights},
        {"library_name": "peft", "tags": ["x"], "cardData": {"license": "mit"}},
    )
    result = fetch(tmp_path, hub)
    assert result.source == "huggingface" and result.commit_sha == SHA
    assert result.meta["library_name"] == "peft" and result.card_data == {"license": "mit"}
    assert all(f.downloaded and f.status == "downloaded" and f.hash_verified for f in result.files)
    target = tmp_path / "jail/src/sub/m.safetensors"
    assert target.read_bytes() == weights
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    by_path = {f.path: f for f in result.files}
    assert by_path["sub/m.safetensors"].local_sha256 == hashlib.sha256(weights).hexdigest()
    assert result.counts()["downloaded"] == 2 and result.warnings == []


def test_never_sends_credentials(tmp_path):
    hub = Hub([regular("a", b"x")], {RESOLVE + "a": b"x"})
    fetch(tmp_path, hub)
    assert hub.requests and all("authorization" not in r.headers for r in hub.requests)
    assert hub.hosts == {"huggingface.co"}


def test_revision_is_url_encoded_and_files_use_the_resolved_commit(tmp_path):
    hub = Hub([regular("a", b"x")], {RESOLVE + "a": b"x"})
    fetch(tmp_path, hub, revision="refs/pr/1")
    assert b"/revision/refs%2Fpr%2F1" in hub.requests[0].url.raw_path
    assert RESOLVE + "a" in hub.paths  # the commit sha, never the movable ref


def test_dataset_repos_use_dataset_routes(tmp_path):
    path = f"/datasets/org/data/resolve/{SHA}/a.csv"
    hub = Hub([regular("a.csv", b"1,2")], {path: b"1,2"})
    result = fetch(tmp_path, hub, repo=HfRepo("dataset", "org/data"))
    assert only(result).downloaded
    assert hub.paths[0] == "/api/datasets/org/data"


# ------------------------------------------------------------------ redirects
@pytest.mark.parametrize(
    "location",
    [
        "https://cdn-lfs.huggingface.co/x?Signature=abc",
        "https://cas-bridge.xethub.hf.co/x?sig=1",
        "https://us.aws.cdn.hf.co/x",
    ],
)
def test_allowlisted_redirect_is_followed(tmp_path, location):
    data = b"weights"
    hub = Hub(
        [lfs("m.bin", data)],
        {RESOLVE + "m.bin": httpx.Response(302, headers={"location": location}), "/x": data},
    )
    assert only(fetch(tmp_path, hub)).hash_verified is True


def test_relative_redirect_stays_on_the_hub(tmp_path):
    data = b"weights"
    hub = Hub(
        [lfs("m.bin", data)],
        {RESOLVE + "m.bin": httpx.Response(307, headers={"location": "/moved"}), "/moved": data},
    )
    assert only(fetch(tmp_path, hub)).downloaded
    assert hub.hosts == {"huggingface.co"}


@pytest.mark.parametrize(
    "location",
    [
        "http://cdn-lfs.huggingface.co/x",
        "https://evil.example/x",
        "https://huggingface.co.evil.example/x",
        "https://evilhf.co/x",
        "https://127.0.0.1/x",
        "https://169.254.169.254/latest/meta-data/",
        "https://[::1]/x",
        "https://user:pw@cdn-lfs.huggingface.co/x",
        "https://cdn-lfs.huggingface.co:8443/x",
        "file:///etc/passwd",
        "ftp://cdn-lfs.huggingface.co/x",
        # The *.hf.co wildcard must not widen any of the rules above.
        "https://hf.co.evil.com/x",
        "https://us.aws.cdn.hf.co.evil.com/x",
        "http://us.aws.cdn.hf.co/x",
        "https://user:pw@us.aws.cdn.hf.co/x",
        "https://us.aws.cdn.hf.co:8443/x",
    ],
)
def test_disallowed_redirect_is_refused_and_never_contacted(tmp_path, location):
    data = b"weights"
    hub = Hub(
        [lfs("m.bin", data)],
        {RESOLVE + "m.bin": httpx.Response(302, headers={"location": location})},
    )
    f = only(fetch(tmp_path, hub))
    assert f.status == "rejected" and "redirect refused" in f.reason and not f.downloaded
    assert hub.hosts == {"huggingface.co"}
    assert not (tmp_path / "jail/src/m.bin").exists()


def test_redirect_host_resolving_to_private_ip_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr("app.security.url_validation.resolve_host", lambda h: ["10.0.0.5"])
    hub = Hub(
        [lfs("m.bin", b"w")],
        {
            RESOLVE + "m.bin": httpx.Response(
                302, headers={"location": "https://cdn-lfs.huggingface.co/x"}
            )
        },
    )
    f = only(fetch(tmp_path, hub, check_dns=True))
    assert f.status == "rejected"
    assert "/x" not in hub.paths


@pytest.mark.parametrize(
    "addresses",
    [
        ["127.0.0.1"],  # loopback
        ["10.0.0.5"],  # private
        ["192.168.1.1"],  # private
        ["169.254.169.254"],  # link-local (cloud metadata)
        ["100.64.0.1"],  # shared address space (CGNAT)
        ["0.0.0.0"],  # noqa: S104 - unspecified address, used as fake DNS data
        ["::1"],  # IPv6 loopback
        ["fe80::1"],  # IPv6 link-local
        ["fc00::1"],  # IPv6 unique local
        ["::ffff:10.0.0.5"],  # IPv4-mapped private
        ["140.82.112.3", "10.0.0.5"],  # one public address does not excuse a private one
    ],
)
def test_wildcard_host_resolving_to_non_public_ip_is_refused(tmp_path, monkeypatch, addresses):
    monkeypatch.setattr("app.security.url_validation.resolve_host", lambda h: addresses)
    hub = Hub(
        [lfs("m.bin", b"w")],
        {
            RESOLVE + "m.bin": httpx.Response(
                302, headers={"location": "https://us.aws.cdn.hf.co/x"}
            )
        },
    )
    f = only(fetch(tmp_path, hub, check_dns=True))
    assert f.status == "rejected" and "redirect refused" in f.reason and not f.downloaded
    assert hub.hosts == {"huggingface.co"}


def test_redirect_loop_stops_at_the_hop_limit(tmp_path):
    hub = Hub(
        [lfs("m.bin", b"w")],
        {RESOLVE + "m.bin": httpx.Response(302, headers={"location": RESOLVE + "m.bin"})},
    )
    f = only(fetch(tmp_path, hub))
    assert f.status == "rejected" and f.reason == "too many redirects"
    assert hub.paths.count(RESOLVE + "m.bin") == MAX_REDIRECTS + 1


def test_redirect_without_location_fails(tmp_path):
    hub = Hub([lfs("m.bin", b"w")], {RESOLVE + "m.bin": httpx.Response(302)})
    assert only(fetch(tmp_path, hub)).status == "failed"


# ------------------------------------------------------------------ caps
def test_lfs_file_over_per_file_cap_is_listed_but_never_requested(tmp_path):
    big = b"x" * 101
    hub = Hub([lfs("big.bin", big)])
    f = only(fetch(tmp_path, hub))
    assert (f.status, f.downloaded, f.hash_verified) == ("skipped", False, None)
    assert f.lfs_sha256 == hashlib.sha256(big).hexdigest()  # reported by the Hub, unverified
    assert RESOLVE + "big.bin" not in hub.paths


def test_total_budget_downloads_smallest_files_first(tmp_path):
    small, large = b"s" * 10, b"l" * 95
    limits = HfFetchLimits(
        max_total_bytes=100, max_file_bytes=100, max_files=20, timeout_seconds=60
    )
    hub = Hub(
        [lfs("large.bin", large), lfs("small.bin", small)],
        {RESOLVE + "small.bin": small, RESOLVE + "large.bin": large},
    )
    by_path = {f.path: f for f in fetch(tmp_path, hub, limits).files}
    assert by_path["small.bin"].downloaded
    assert by_path["large.bin"].status == "skipped"
    assert "budget" in by_path["large.bin"].reason


@pytest.mark.parametrize(
    ("served", "reason"),
    [(b"longer than listed!", "larger"), (b"sho", "differs")],
)
def test_content_size_not_matching_the_listing_is_discarded(tmp_path, served, reason):
    entry = regular("a.txt", b"listed")
    hub = Hub([entry], {RESOLVE + "a.txt": served})
    f = only(fetch(tmp_path, hub))
    assert f.status == "integrity_mismatch" and reason in f.reason and f.hash_verified is False
    assert not (tmp_path / "jail/src/a.txt").exists()


def test_lfs_hash_mismatch_is_discarded(tmp_path):
    hub = Hub([lfs("m.bin", b"genuine")], {RESOLVE + "m.bin": b"tamperd"})
    f = only(fetch(tmp_path, hub))
    assert f.status == "integrity_mismatch" and "SHA-256" in f.reason and not f.downloaded
    assert not (tmp_path / "jail/src/m.bin").exists()


def test_git_blob_mismatch_is_discarded(tmp_path):
    hub = Hub([regular("a.json", b"genuine")], {RESOLVE + "a.json": b"tamperd"})
    f = only(fetch(tmp_path, hub))
    assert f.status == "integrity_mismatch" and "git blob" in f.reason
    assert not (tmp_path / "jail/src/a.json").exists()


def test_download_time_budget_skips_remaining_files(tmp_path):
    ticks = iter([0.0, *[1000.0] * 50])
    hub = Hub([regular("a", b"x")], {RESOLVE + "a": b"x"})
    f = only(fetch(tmp_path, hub, clock=lambda: next(ticks)))
    assert f.status == "skipped" and "time budget" in f.reason


def test_download_http_error_and_timeout_are_recorded_not_raised(tmp_path):
    def handler(request):
        if request.url.path.endswith("/timeout.bin"):
            raise httpx.ReadTimeout("slow", request=request)
        return hub(request)

    hub = Hub(
        [regular("a", b"x"), regular("timeout.bin", b"y")],
        {RESOLVE + "a": httpx.Response(500)},
    )
    dest = tmp_path / "src"
    dest.mkdir()
    result = provider(handler).fetch(REPO, None, dest, LIMITS)
    assert [f.status for f in result.files] == ["failed", "failed"]
    assert result.warnings == ["2 file(s) failed to download"]


def test_too_many_files_is_a_structured_error(tmp_path):
    hub = Hub([regular(f"f{i}", b"x") for i in range(21)])
    with pytest.raises(AppError) as exc:
        fetch(tmp_path, hub)
    assert exc.value.code == ErrorCode.TOO_MANY_FILES and exc.value.status_code == 413


# ------------------------------------------------------------------ hostile listings
@pytest.mark.parametrize(
    "path",
    [
        "../evil",
        "a/../../evil",
        "a/../b",
        "/etc/passwd",
        "C:/evil",
        "a\\b",
        "..\\evil",
        "a\x00b",
        "a\nb",
        "./a",
        "a//b",
        "",
        "x" * 513,
        "/".join(["d"] * (MAX_PATH_DEPTH + 1)),
        None,
        7,
    ],
)
def test_unsafe_listing_paths_are_refused(tmp_path, path):
    assert safe_repo_path(path) is None
    entry = {"type": "file", "path": path, "size": 1, "oid": "c" * 40}
    hub = Hub([entry])
    f = only(fetch(tmp_path, hub))
    assert f.status == "rejected" and f.reason == "unsafe path in repository listing"
    assert not any("/resolve/" in p for p in hub.paths)
    assert_jailed(tmp_path)


@pytest.mark.parametrize("path", ["config.json", "sub/dir/a.bin", "name with space.txt"])
def test_safe_paths_accepted(path):
    assert safe_repo_path(path) == path


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        ({"type": "file", "path": "a", "size": -1, "oid": "c" * 40}, "invalid size"),
        ({"type": "file", "path": "a", "size": "1", "oid": "c" * 40}, "invalid size"),
        ({"type": "file", "path": "a", "size": 1, "oid": "nope"}, "git object id"),
        (
            {"type": "file", "path": "a", "size": 1, "oid": "c" * 40, "lfs": {"oid": "short"}},
            "LFS entry",
        ),
    ],
)
def test_bad_listing_metadata_is_refused(tmp_path, entry, reason):
    hub = Hub([entry])
    f = only(fetch(tmp_path, hub))
    assert f.status == "rejected" and reason in f.reason


def test_duplicate_listing_path_downloaded_once(tmp_path):
    entry = regular("a", b"x")
    hub = Hub([entry, dict(entry)], {RESOLVE + "a": b"x"})
    statuses = sorted(f.status for f in fetch(tmp_path, hub).files)
    assert statuses == ["downloaded", "rejected"]


def test_tree_directories_are_ignored(tmp_path):
    hub = Hub([{"type": "directory", "path": "sub"}, regular("a", b"x")], {RESOLVE + "a": b"x"})
    assert only(fetch(tmp_path, hub)).path == "a"


# ------------------------------------------------------------------ pagination
def test_tree_pagination_is_followed(tmp_path):
    tree_path = f"/api/models/org/repo/tree/{SHA}"
    link = f'<https://huggingface.co{tree_path}?cursor=2>; rel="next"'

    def handler(request):
        if request.url.path == tree_path:
            hub.requests.append(request)
            if request.url.params.get("cursor") == "2":
                return httpx.Response(200, json=[regular("b", b"y")])
            return httpx.Response(200, json=[regular("a", b"x")], headers={"link": link})
        return hub(request)

    hub = Hub([], {RESOLVE + "a": b"x", RESOLVE + "b": b"y"})
    dest = tmp_path / "src"
    dest.mkdir()
    result = provider(handler).fetch(REPO, None, dest, LIMITS)
    assert sorted(f.path for f in result.files) == ["a", "b"]


@pytest.mark.parametrize(
    "target",
    ["https://evil.example/api/models/org/repo/tree/x", "https://huggingface.co/api/whoami"],
)
def test_tree_pagination_link_cannot_leave_the_listing(tmp_path, target):
    def handler(request):
        if "/tree/" in request.url.path:
            hub.requests.append(request)
            return httpx.Response(200, json=[], headers={"link": f'<{target}>; rel="next"'})
        return hub(request)

    hub = Hub([])
    dest = tmp_path / "src"
    dest.mkdir()
    with pytest.raises(AppError) as exc:
        provider(handler).fetch(REPO, None, dest, LIMITS)
    assert exc.value.code == ErrorCode.HF_ERROR
    assert hub.hosts == {"huggingface.co"}


# ------------------------------------------------------------------ API errors
@pytest.mark.parametrize(
    "info",
    [
        {"gated": "auto"},
        {"gated": "manual"},
        {"gated": True},
        {"private": True},
        {"disabled": True},
    ],
)
def test_gated_private_disabled_are_denied_and_nothing_downloads(tmp_path, info):
    hub = Hub([regular("a", b"x")], {RESOLVE + "a": b"x"}, info)
    with pytest.raises(AppError) as exc:
        fetch(tmp_path, hub)
    assert exc.value.code == ErrorCode.HF_ACCESS_DENIED and exc.value.status_code == 403
    assert not any("/resolve/" in p for p in hub.paths)


@pytest.mark.parametrize(
    ("status", "code", "http"),
    [
        (401, ErrorCode.HF_ACCESS_DENIED, 403),
        (403, ErrorCode.HF_ACCESS_DENIED, 403),
        (404, ErrorCode.HF_NOT_FOUND, 404),
        (302, ErrorCode.HF_ERROR, 502),
        (418, ErrorCode.HF_ERROR, 502),
    ],
)
def test_api_status_mapping(tmp_path, status, code, http):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status)

    with pytest.raises(AppError) as exc:
        provider(handler).fetch(REPO, None, tmp_path, LIMITS)
    assert exc.value.code == code and exc.value.status_code == http
    assert len(calls) == 1  # definitive answers are not retried


@pytest.mark.parametrize(
    "response",
    [
        lambda r: httpx.Response(503),
        lambda r: httpx.Response(429),
    ],
)
def test_transient_status_retries_then_unavailable(tmp_path, response):
    calls, sleeps = [], []

    def handler(request):
        calls.append(request)
        return response(request)

    with pytest.raises(AppError) as exc:
        provider(handler, sleep=sleeps.append).fetch(REPO, None, tmp_path, LIMITS)
    assert exc.value.code == ErrorCode.HF_UNAVAILABLE and exc.value.status_code == 503
    assert len(calls) == 2 and len(sleeps) == 1


@pytest.mark.parametrize("error", [httpx.ConnectTimeout, httpx.ConnectError])
def test_network_failure_is_unavailable(tmp_path, error):
    def handler(request):
        raise error("down", request=request)

    with pytest.raises(AppError) as exc:
        provider(handler).fetch(REPO, None, tmp_path, LIMITS)
    assert exc.value.code == ErrorCode.HF_UNAVAILABLE


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, content=b"{not json"),
        httpx.Response(200, json=["not", "an", "object"]),
        httpx.Response(200, json={"sha": "not-a-commit"}),
        httpx.Response(200, json={}),
    ],
)
def test_malformed_api_bodies_are_structured_errors(tmp_path, response):
    with pytest.raises(AppError) as exc:
        provider(lambda r: response).fetch(REPO, None, tmp_path, LIMITS)
    assert exc.value.code == ErrorCode.HF_ERROR


def test_tree_that_is_not_a_list_is_a_structured_error(tmp_path):
    hub = Hub({"oops": True})
    with pytest.raises(AppError) as exc:
        fetch(tmp_path, hub)
    assert exc.value.code == ErrorCode.HF_ERROR


def test_oversized_api_response_is_refused(tmp_path):
    body = json.dumps({"sha": SHA, "padding": "x" * 5000}).encode()
    with pytest.raises(AppError) as exc:
        provider(lambda r: httpx.Response(200, content=body), max_api_bytes=1000).fetch(
            REPO, None, tmp_path, LIMITS
        )
    assert exc.value.code == ErrorCode.HF_ERROR and "size limit" in exc.value.message


def test_meta_fields_are_bounded_and_type_checked(tmp_path):
    hub = Hub(
        [],
        info={
            "author": "a" * 1000,
            "library_name": {"not": "a string"},
            "tags": ["t" * 100, 3] + ["x"] * 100,
            "downloads": "many",
        },
    )
    meta = fetch(tmp_path, hub).meta
    assert len(meta["author"]) == 256 and meta["library_name"] is None
    assert len(meta["tags"]) <= 50 and len(meta["tags"][0]) == 64
    assert meta["downloads"] is None
