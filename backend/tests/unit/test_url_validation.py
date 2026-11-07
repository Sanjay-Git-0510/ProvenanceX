import socket

import pytest

from app.core.errors import AppError, ErrorCode
from app.security import url_validation
from app.security.url_validation import (
    ensure_public_host,
    validate_github_repo_url,
    validate_source_url,
)


@pytest.mark.parametrize(
    ("url", "owner", "repo"),
    [
        ("https://github.com/psf/requests", "psf", "requests"),
        ("https://github.com/psf/requests.git", "psf", "requests"),
        ("https://github.com/psf/requests/", "psf", "requests"),
        ("  https://GitHub.com/psf/requests  ", "psf", "requests"),
        ("https://github.com/my-org/.github", "my-org", ".github"),
    ],
)
def test_valid_github_urls(public_dns, url, owner, repo):
    result = validate_github_repo_url(url)
    assert (result.owner, result.repo) == (owner, repo)
    assert result.canonical_url == f"https://github.com/{owner}/{repo}"
    assert result.clone_url == f"https://github.com/{owner}/{repo}.git"


def test_huggingface_allowed_by_generic_validator(public_dns):
    assert validate_source_url("https://huggingface.co/org/model").host == "huggingface.co"


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("http://github.com/a/b", ErrorCode.URL_NOT_ALLOWED),
        ("ftp://github.com/a/b", ErrorCode.URL_NOT_ALLOWED),
        ("file:///etc/passwd", ErrorCode.URL_NOT_ALLOWED),
        ("ssh://git@github.com/a/b", ErrorCode.URL_NOT_ALLOWED),
        ("git@github.com:a/b.git", ErrorCode.URL_NOT_ALLOWED),
        ("github.com/a/b", ErrorCode.URL_NOT_ALLOWED),
        ("https://gitlab.com/a/b", ErrorCode.URL_NOT_ALLOWED),
        ("https://github.com.evil.com/a/b", ErrorCode.URL_NOT_ALLOWED),
        ("https://api.github.com/a/b", ErrorCode.URL_NOT_ALLOWED),
        ("https://github.com./a/b", ErrorCode.URL_NOT_ALLOWED),
        ("https://huggingface.co/a/b", ErrorCode.URL_NOT_ALLOWED),
        ("https://140.82.112.3/a/b", ErrorCode.URL_NOT_ALLOWED),
        ("https://[::1]/a/b", ErrorCode.URL_NOT_ALLOWED),
        ("https://xn--gthub-zsa.com/a/b", ErrorCode.URL_NOT_ALLOWED),
        ("https://evil.com@github.com/a/b", ErrorCode.INVALID_URL),
        ("https://github.com@evil.com/a/b", ErrorCode.INVALID_URL),
        ("https://user:pass@github.com/a/b", ErrorCode.INVALID_URL),
        ("https://github.com:443/a/b", ErrorCode.INVALID_URL),
        ("https://github.com:8443/a/b", ErrorCode.INVALID_URL),
        ("https://github.com:/a/b", ErrorCode.INVALID_URL),
        ("https://github.com:99999/a/b", ErrorCode.INVALID_URL),
        ("https://github.com/a/b?x=1", ErrorCode.INVALID_URL),
        ("https://github.com/a/b#readme", ErrorCode.INVALID_URL),
        ("https://github.com/a/b?", ErrorCode.INVALID_URL),
        ("https://github.com", ErrorCode.INVALID_URL),
        ("https://github.com/a", ErrorCode.INVALID_URL),
        ("https://github.com/a/b/c", ErrorCode.INVALID_URL),
        ("https://github.com/a/b/tree/main", ErrorCode.INVALID_URL),
        ("https://github.com/../b", ErrorCode.INVALID_URL),
        ("https://github.com/a/..", ErrorCode.INVALID_URL),
        ("https://github.com/a/%2e%2e", ErrorCode.INVALID_URL),
        ("https://github.com/-a/b", ErrorCode.INVALID_URL),
        ("https://gíthub.com/a/b", ErrorCode.INVALID_URL),
        ("https://github.com/a\n/b", ErrorCode.INVALID_URL),
        ("https://github.com/a /b", ErrorCode.INVALID_URL),
        ("https://github.com\\@evil.com/a/b", ErrorCode.INVALID_URL),
        ("", ErrorCode.INVALID_URL),
        ("   ", ErrorCode.INVALID_URL),
        ("https://github.com/a/" + "b" * 3000, ErrorCode.INVALID_URL),
    ],
)
def test_rejected_github_urls(public_dns, url, code):
    with pytest.raises(AppError) as exc:
        validate_github_repo_url(url)
    assert exc.value.code == code
    assert exc.value.status_code == 400


def test_non_string_rejected(public_dns):
    with pytest.raises(AppError) as exc:
        validate_github_repo_url(None)
    assert exc.value.code == ErrorCode.INVALID_URL


@pytest.mark.parametrize(
    "addresses",
    [
        ["10.0.0.5"],
        ["172.16.0.1"],
        ["192.168.1.10"],
        ["127.0.0.1"],
        ["169.254.169.254"],
        ["100.64.0.1"],
        ["0.0.0.0"],  # noqa: S104 - test data
        ["224.0.0.1"],
        ["::1"],
        ["fe80::1%eth0"],
        ["fc00::1"],
        ["::ffff:10.0.0.1"],
        ["140.82.112.3", "10.0.0.1"],
    ],
)
def test_non_public_resolution_rejected(monkeypatch, addresses):
    monkeypatch.setattr(url_validation, "resolve_host", lambda host: addresses)
    with pytest.raises(AppError) as exc:
        validate_github_repo_url("https://github.com/a/b")
    assert exc.value.code == ErrorCode.PRIVATE_ADDRESS


def test_dns_failure(monkeypatch):
    def boom(host):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(url_validation, "resolve_host", boom)
    with pytest.raises(AppError) as exc:
        ensure_public_host("github.com")
    assert exc.value.code == ErrorCode.DNS_RESOLUTION_FAILED


def test_dns_empty_result(monkeypatch):
    monkeypatch.setattr(url_validation, "resolve_host", lambda host: [])
    with pytest.raises(AppError) as exc:
        ensure_public_host("github.com")
    assert exc.value.code == ErrorCode.DNS_RESOLUTION_FAILED


def test_check_dns_false_skips_resolution(monkeypatch):
    def must_not_resolve(host):
        raise AssertionError("resolver called")

    monkeypatch.setattr(url_validation, "resolve_host", must_not_resolve)
    assert validate_github_repo_url("https://github.com/a/b", check_dns=False).repo == "b"


def test_path_validated_before_dns(monkeypatch):
    calls = []
    monkeypatch.setattr(url_validation, "resolve_host", lambda host: calls.append(host) or [])
    with pytest.raises(AppError):
        validate_github_repo_url("https://github.com/only-owner")
    assert calls == []
