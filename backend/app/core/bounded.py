"""Bounds for free-form values that arrive from a sandbox (audit finding L5).

An error's `details` is copied into the scan's error record and returned by the API, so a
compromised worker must not be able to make it large, deep or non-JSON. Standard library only:
the analyzer and fetcher images import this.
"""

import json
from typing import Annotated, Any

from pydantic import AfterValidator

MAX_DETAILS_BYTES = 4096
MAX_DETAILS_DEPTH = 6


def _depth(value: Any, level: int = 0) -> int:
    if level > MAX_DETAILS_DEPTH:
        return level
    if isinstance(value, dict):
        return max((_depth(v, level + 1) for v in value.values()), default=level + 1)
    if isinstance(value, list):
        return max((_depth(v, level + 1) for v in value), default=level + 1)
    return level


def bounded_details(value: Any) -> Any:
    """Accept None or a small JSON value (at most 4 KiB serialized, nesting depth 6)."""
    if value is None:
        return None
    try:
        encoded = json.dumps(value, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ValueError("details must be plain JSON") from exc
    if len(encoded.encode()) > MAX_DETAILS_BYTES:
        raise ValueError("details are too large")
    if _depth(value) > MAX_DETAILS_DEPTH:
        raise ValueError("details are nested too deeply")
    return value


def clamp_details(value: Any) -> Any:
    """Worker side: send details only if they fit the bound, otherwise a marker (never fail)."""
    try:
        return bounded_details(value)
    except ValueError:
        return {"details_omitted": "too large or not plain JSON"}


BoundedDetails = Annotated[Any, AfterValidator(bounded_details)]


def printable_excerpt(raw: bytes, limit: int = 300) -> str:
    """A log-safe excerpt of untrusted output: control characters and non-ASCII escaped, so it
    can neither forge log lines nor carry terminal escapes, and capped at `limit` characters."""
    text = raw[: limit * 4].decode("utf-8", "replace")
    safe = text.encode("ascii", "backslashreplace").decode("ascii")
    safe = "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in safe)
    return safe[:limit]
