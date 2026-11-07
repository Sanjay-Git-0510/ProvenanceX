import pytest

from app.core.errors import AppError, ErrorCode
from app.security.revision import is_commit_sha, validate_revision


@pytest.mark.parametrize(
    "rev",
    ["main", "v1.2.3", "feature/x-y", "release_1.0", "1.0+build", "a" * 40, "A1" * 20],
)
def test_valid_revisions(rev):
    assert validate_revision(rev) == rev


@pytest.mark.parametrize("rev", [None, "", "   "])
def test_empty_revision_is_none(rev):
    assert validate_revision(rev) is None


def test_revision_is_stripped():
    assert validate_revision("  main ") == "main"


@pytest.mark.parametrize(
    "rev",
    [
        "-upload-pack=touch /tmp/x",
        "--output=/tmp/x",
        "-c",
        "a..b",
        "a b",
        "a;b",
        "$(id)",
        "`id`",
        "a//b",
        "a/",
        "a.",
        "x.lock",
        "a/.hidden",
        "HEAD~1",
        "HEAD^",
        "@{1}",
        "a:b",
        "a\nb",
        "ref\\x",
        "x" * 201,
    ],
)
def test_invalid_revisions(rev):
    with pytest.raises(AppError) as exc:
        validate_revision(rev)
    assert exc.value.code == ErrorCode.INVALID_REVISION


@pytest.mark.parametrize(
    ("rev", "expected"),
    [
        ("a" * 40, True),
        ("ABCDEF0123" * 4, True),
        ("0" * 64, True),
        ("deadbeef", False),
        ("a" * 39, False),
        ("g" * 40, False),
        ("main", False),
    ],
)
def test_is_commit_sha(rev, expected):
    assert is_commit_sha(rev) is expected
