"""Validation of user-supplied git revisions (branch, tag or full commit SHA).

The pattern is deliberately stricter than git's ref rules. In particular a revision can
never start with '-', so it cannot be parsed as a git command-line option.
"""

import re

from app.core.errors import AppError, ErrorCode

MAX_REVISION_LENGTH = 200

_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+-]{0,199}$")
_COMMIT_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$", re.IGNORECASE)


def validate_revision(value: str | None) -> str | None:
    """Return the cleaned revision, None when empty, or raise invalid_revision."""
    if value is None:
        return None
    rev = value.strip()
    if not rev:
        return None
    if (
        not _REVISION_RE.match(rev)
        or ".." in rev
        or "//" in rev
        or "/." in rev
        or rev.endswith(("/", ".", ".lock"))
    ):
        raise AppError(
            ErrorCode.INVALID_REVISION,
            "Invalid revision: use a branch name, tag or full commit SHA",
            400,
        )
    return rev


def is_commit_sha(rev: str) -> bool:
    """True for a full SHA-1 (40 hex) or SHA-256 (64 hex) object id.

    Shorter hex strings are treated as branch/tag names, because remote fetch by
    abbreviated SHA is not supported.
    """
    return bool(_COMMIT_SHA_RE.match(rev))
