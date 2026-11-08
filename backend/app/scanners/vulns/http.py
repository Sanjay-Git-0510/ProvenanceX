"""Small JSON-over-HTTPS client for vulnerability sources.

It adds the following to httpx:
- connect/read timeouts
- bounded retries with exponential backoff on timeouts, transport errors, 429 and 5xx
  (Retry-After is honored, capped)
- a response-size cap, enforced while streaming, so a hostile or broken endpoint cannot
  exhaust memory
- no redirects, so a configured API host cannot bounce requests elsewhere
- a generic User-Agent, with no personal contact details

Failures raise HttpError with a `kind`, so callers can turn them into structured
stage errors.
"""

import json
import logging
import time
from collections.abc import Callable
from typing import Any

import httpx

logger = logging.getLogger(__name__)

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
MAX_RETRY_AFTER_SECONDS = 10.0


class HttpError(Exception):
    def __init__(self, kind: str, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.kind = kind  # timeout | network | status | too_large | invalid_json
        self.status = status


class JsonHttpClient:
    def __init__(
        self,
        *,
        timeout_seconds: float,
        max_retries: int,
        max_response_bytes: int,
        user_agent: str,
        transport: httpx.BaseTransport | None = None,
        backoff_seconds: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.max_retries = max_retries
        self.max_response_bytes = max_response_bytes
        self.backoff_seconds = backoff_seconds
        self.sleep = sleep
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            headers={"User-Agent": user_agent, "Accept": "application/json"},
            transport=transport,
        )

    def __enter__(self) -> "JsonHttpClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def get_json(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        return self._request("GET", url, params=params, headers=headers)

    def post_json(self, url: str, payload: Any) -> Any:
        return self._request("POST", url, json_body=payload)

    def _delay(self, attempt: int, retry_after: str | None) -> float:
        if retry_after:
            try:
                return min(float(retry_after), MAX_RETRY_AFTER_SECONDS)
            except ValueError:
                pass
        return self.backoff_seconds * (2**attempt)

    def _read_limited(self, response: httpx.Response) -> bytes:
        declared = response.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self.max_response_bytes:
            raise HttpError("too_large", "Response exceeds the size limit", response.status_code)
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > self.max_response_bytes:
                raise HttpError(
                    "too_large", "Response exceeds the size limit", response.status_code
                )
            chunks.append(chunk)
        return b"".join(chunks)

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
    ) -> Any:
        last_error: HttpError | None = None
        for attempt in range(self.max_retries + 1):
            retry_after: str | None = None
            try:
                with self._client.stream(
                    method, url, params=params, headers=headers, json=json_body
                ) as response:
                    status = response.status_code
                    if status in RETRY_STATUSES:
                        retry_after = response.headers.get("retry-after")
                        last_error = HttpError("status", f"HTTP {status}", status)
                    elif status >= 300:  # redirects are not followed
                        raise HttpError("status", f"HTTP {status}", status)
                    else:
                        body = self._read_limited(response)
                        try:
                            return json.loads(body)
                        except (ValueError, RecursionError) as exc:
                            raise HttpError("invalid_json", "Response is not valid JSON") from exc
            except httpx.TimeoutException:
                last_error = HttpError("timeout", "Request timed out")
            except httpx.TransportError as exc:
                last_error = HttpError("network", f"Network error: {exc.__class__.__name__}")

            if attempt < self.max_retries:
                delay = self._delay(attempt, retry_after)
                logger.info(
                    "Retrying %s %s after %s (attempt %d), sleeping %.1fs",
                    method,
                    url,
                    last_error.kind if last_error else "?",
                    attempt + 1,
                    delay,
                )
                self.sleep(delay)
        assert last_error is not None  # noqa: S101 - loop always sets it before falling out
        raise last_error
