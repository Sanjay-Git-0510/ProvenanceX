"""Shared pieces for the metadata adapters: an allowlisted JSON client, criteria and helpers.

The client reuses JsonHttpClient (timeouts, bounded retries, a response-size cap, no redirects)
and adds a fixed host allowlist and an https-only check. It fetches JSON metadata only, never
an artifact. A GitHub token, if given, is sent to api.github.com and nowhere else.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from packaging.version import InvalidVersion, Version

from app.scanners.vulns.http import JsonHttpClient

GITHUB_API = "api.github.com"
ALLOWED_HOSTS = frozenset({GITHUB_API, "api.osv.dev", "services.nvd.nist.gov", "huggingface.co"})
USER_AGENT = "provenancex-dataset-collector/1"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class SourceError(Exception):
    """A source could not be read. The collector records it and moves on."""


@dataclass(frozen=True)
class Criteria:
    """Benign criteria and collection limits. Research parameters, recorded in the metadata."""

    min_repo_age_days: int = 365
    min_release_age_days: int = 180
    min_hf_age_days: int = 180
    max_hf_storage_mb: int = 600

    def as_dict(self) -> dict[str, int]:
        return dict(self.__dict__)


@dataclass
class CollectionContext:
    client: "MetadataClient"
    today: date
    criteria: Criteria = field(default_factory=Criteria)
    errors: list[dict[str, str]] = field(default_factory=list)

    def record_error(self, source: str, identifier: str, exc: Exception) -> None:
        self.errors.append({"source": source, "identifier": identifier, "error": str(exc)[:300]})


class MetadataClient:
    """GET JSON from an allowlisted https host. Raises SourceError on any failure."""

    def __init__(
        self,
        *,
        github_token: str | None = None,
        timeout_seconds: float = 20.0,
        max_retries: int = 2,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        kwargs: dict[str, Any] = {} if sleep is None else {"sleep": sleep}
        self._http = JsonHttpClient(
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            max_response_bytes=MAX_RESPONSE_BYTES,
            user_agent=USER_AGENT,
            transport=transport,
            **kwargs,
        )
        self._github_token = github_token or None
        self.request_count = 0

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "MetadataClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _check(self, url: str) -> str:
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS or parts.port:
            raise SourceError(f"Host not allowed: {parts.scheme}://{parts.hostname}")
        if parts.username or parts.password:
            raise SourceError("Credentials in URL are not allowed")
        return parts.hostname

    def _headers(self, host: str) -> dict[str, str] | None:
        if host == GITHUB_API:
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            if self._github_token:
                headers["Authorization"] = f"Bearer {self._github_token}"
            return headers
        return None

    def get(self, url: str, params: dict[str, str] | None = None) -> Any:
        host = self._check(url)
        self.request_count += 1
        try:
            return self._http.get_json(url, params=params, headers=self._headers(host))
        except Exception as exc:  # HttpError and anything unexpected become a SourceError
            raise SourceError(f"GET {host}{urlsplit(url).path} failed: {exc}") from exc

    def post(self, url: str, payload: Any) -> Any:
        host = self._check(url)
        self.request_count += 1
        try:
            return self._http.post_json(url, payload)
        except Exception as exc:
            raise SourceError(f"POST {host}{urlsplit(url).path} failed: {exc}") from exc


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def age_days(value: object, today: date) -> int | None:
    parsed = parse_time(value)
    return None if parsed is None else (today - parsed.date()).days


def parse_version(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


_CONSTRAINT_RE = re.compile(r"^\s*(<=|>=|<|>|=)\s*(\S+)\s*$")


def in_range(version: Version, range_text: str) -> bool | None:
    """Evaluate a GHSA `vulnerable_version_range` such as '>= 1.0, < 1.4.2'.

    Returns None when the range cannot be parsed, so the caller can skip it instead of guessing.
    """
    parts = [p for p in range_text.split(",") if p.strip()]
    if not parts:
        return None
    for part in parts:
        match = _CONSTRAINT_RE.match(part)
        bound = parse_version(match.group(2)) if match else None
        if match is None or bound is None:
            return None
        op = match.group(1)
        ok = {
            "<": version < bound,
            "<=": version <= bound,
            ">": version > bound,
            ">=": version >= bound,
            "=": version == bound,
        }[op]
        if not ok:
            return False
    return True


_TAG_PREFIX_RE = re.compile(r"^(?:v|release-|rel-|version-)", re.IGNORECASE)


def version_from_tag(tag: str, package: str | None = None) -> Version | None:
    """The version a tag names: '1.2.3', 'v1.2.3', '<package>-1.2.3' or '<package>@1.2.3'."""
    text = tag.strip()
    if package:
        for sep in ("@", "-", "_", "/"):
            prefix = f"{package}{sep}"
            if text.lower().startswith(prefix.lower()):
                text = text[len(prefix) :]
                break
    text = _TAG_PREFIX_RE.sub("", text)
    if not text[:1].isdigit():
        return None
    return parse_version(text)


OSV_ECOSYSTEMS = {"pip": "PyPI", "npm": "npm"}
