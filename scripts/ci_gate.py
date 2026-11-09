#!/usr/bin/env python3
"""ProvenanceX CI gate: submit a scan, wait for it, read the real decision, exit with the result.

Exit codes:
  0  the policy lets the pipeline continue
  1  BLOCK (or REVIEW with --fail-on-review)
  2  no trustworthy pass is possible: the scan failed or timed out, there is no recognized
     decision, ALLOW or REVIEW came with no risk score, or the evidence contains mock data
     without --allow-mock

Standard library only, so a CI runner needs nothing installed. Text from the API goes into CI
logs and the job summary, so only validated identifiers and escaped server notices are written.
"""

from __future__ import annotations

import argparse
import io
import json
import math
import os
import re
import stat
import sys
import time
import uuid
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, parse, request

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INCONCLUSIVE = 2

DEFAULT_API_URL = "http://127.0.0.1:8000/api/v1"
DEFAULT_TIMEOUT_SECONDS = 900
DEFAULT_POLL_SECONDS = 5
DEFAULT_MAX_UPLOAD_MB = 100
REQUEST_TIMEOUT_SECONDS = 60
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_NOTICE_CHARS = 300

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_TERMINAL_STATUSES = frozenset({"completed", "failed"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_UPLOAD_NAME = re.compile(r"^[A-Za-z0-9_.@-]{1,255}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")
_MARKDOWN = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~&:@])")
_DECISIONS = frozenset({"ALLOW", "REVIEW", "BLOCK"})
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


class GateError(Exception):
    """A failure with a fixed code and message, safe to print in CI logs."""

    def __init__(self, code: str, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status

    @property
    def retryable(self) -> bool:
        return self.status is None or self.status == 429 or self.status >= 500


@dataclass(frozen=True)
class Verdict:
    exit_code: int
    label: str
    reason: str


def identifier(value: Any) -> str | None:
    """A value from a fixed API vocabulary, or None if it does not look like one."""
    return value if isinstance(value, str) and _IDENTIFIER.fullmatch(value) else None


def escape_markdown(value: Any) -> str:
    """Plain text for the job summary. Breaks links, mentions, tables and HTML."""
    if not isinstance(value, str):
        return ""
    text = _CONTROL.sub(" ", value).strip()[:MAX_NOTICE_CHARS]
    return _MARKDOWN.sub(r"\\\1", text)


def safe_log(message: str) -> None:
    """Print one line that cannot start or contain a GitHub workflow command."""
    print(_CONTROL.sub(" ", message).replace("::", ": :"), flush=True)


def _valid_score(value: Any) -> bool:
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0 <= value <= 1
    )


def evaluate(
    scan_status: Any,
    risk: Any,
    *,
    fail_on_review: bool = False,
    allow_mock: bool = False,
) -> Verdict:
    """Apply the gate policy. Anything not positively understood is inconclusive, never a pass."""
    if scan_status != "completed":
        status = identifier(scan_status) or "unrecognized"
        return Verdict(EXIT_INCONCLUSIVE, "INCONCLUSIVE", f"The scan did not complete ({status})")
    if not isinstance(risk, dict) or risk.get("scan_status") != "completed":
        return Verdict(
            EXIT_INCONCLUSIVE, "INCONCLUSIVE", "The risk result is not for a finished scan"
        )

    decision = risk.get("decision")
    if decision is None:
        return Verdict(EXIT_INCONCLUSIVE, "INCONCLUSIVE", "The scan has no decision")
    if decision not in _DECISIONS:
        return Verdict(EXIT_INCONCLUSIVE, "INCONCLUSIVE", "The decision was not recognized")

    # Anything other than an explicit false counts as mock, so a missing flag cannot pass.
    if risk.get("contains_mock_evidence") is not False and not allow_mock:
        return Verdict(
            EXIT_INCONCLUSIVE,
            "INCONCLUSIVE",
            f"The {decision} decision used mock evidence, and --allow-mock was not set",
        )
    if decision == "BLOCK":
        return Verdict(EXIT_FAIL, "FAIL", "The decision is BLOCK")
    if risk.get("status") != "computed" or not _valid_score(risk.get("risk_score")):
        return Verdict(EXIT_INCONCLUSIVE, "INCONCLUSIVE", f"{decision} has no risk score")
    if decision == "ALLOW":
        return Verdict(EXIT_PASS, "PASS", "The decision is ALLOW")
    if fail_on_review:
        return Verdict(EXIT_FAIL, "FAIL", "The decision is REVIEW and --fail-on-review is set")
    return Verdict(EXIT_PASS, "PASS", "The decision is REVIEW, which passes by default")


def validate_api_url(url: str) -> str:
    """https anywhere, or http on loopback only. Credentials in the URL are refused."""
    try:
        parts = parse.urlsplit(url)
        host = parts.hostname
        has_credentials = parts.username is not None or parts.password is not None
    except ValueError as exc:
        raise GateError("invalid_api_url", "The API URL is malformed") from exc
    if not host or has_credentials or parts.query or parts.fragment:
        raise GateError("invalid_api_url", "The API URL must be a plain URL with no credentials")
    if parts.scheme != "https" and not (parts.scheme == "http" and host in _LOOPBACK_HOSTS):
        raise GateError("invalid_api_url", "The API URL must use https, or http on loopback")
    return url.rstrip("/")


def zip_directory(root: Path, max_bytes: int) -> bytes:
    """Zip a directory into memory. Symlinks and special files stop the gate."""
    if root.is_symlink() or not root.is_dir():
        raise GateError("invalid_path", "The scan path must be a real directory")

    buffer = io.BytesIO()
    total = 0
    count = 0
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(name for name in dirs if name != ".git")
            base = Path(current)
            if any((base / name).is_symlink() for name in dirs):
                raise GateError("unsafe_path", "The scan path contains a symlink")
            for name in sorted(files):
                path = base / name
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    raise GateError("unsafe_path", "The scan path contains a link or special file")
                total += info.st_size
                if total > max_bytes:
                    raise GateError("too_large", "The scan path exceeds the upload limit")
                entry = zipfile.ZipInfo(path.relative_to(root).as_posix(), _ZIP_EPOCH)
                entry.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(entry, path.read_bytes())
                count += 1
    if count == 0:
        raise GateError("empty_path", "The scan path has no files")
    data = buffer.getvalue()
    if len(data) > max_bytes:
        raise GateError("too_large", "The scan archive exceeds the upload limit")
    return data


def _multipart(name: str, payload: bytes) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    body = (
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="name"\r\n\r\n{name}\r\n'
            f"--{boundary}\r\nContent-Disposition: form-data; "
            'name="file"; filename="artifact.zip"\r\nContent-Type: application/zip\r\n\r\n'
        ).encode()
        + payload
        + f"\r\n--{boundary}--\r\n".encode()
    )
    return body, f"multipart/form-data; boundary={boundary}"


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class ApiClient:
    """Minimal JSON client. It sends no credentials and does not follow redirects."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url
        self._opener = request.build_opener(request.ProxyHandler({}), _NoRedirect())

    def _call(self, req: request.Request) -> Any:
        try:
            # The scheme was checked by validate_api_url, and only fixed paths are appended.
            with self._opener.open(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except error.HTTPError as exc:
            raise GateError("api_error", f"The API returned HTTP {exc.code}", exc.code) from exc
        except (error.URLError, TimeoutError, OSError) as exc:
            raise GateError("api_unreachable", "The API could not be reached") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise GateError("invalid_response", "The API response was too large", 400)
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise GateError("invalid_response", "The API response was not JSON", 400) from exc

    def get(self, path: str) -> Any:
        url = f"{self.base_url}{path}"
        return self._call(request.Request(url, headers={"Accept": "application/json"}))  # noqa: S310

    def submit(self, kind: str, name: str, payload: bytes) -> str:
        body, content_type = _multipart(name, payload)
        req = request.Request(  # noqa: S310
            f"{self.base_url}/scans/{kind}",
            data=body,
            method="POST",
            headers={"Accept": "application/json", "Content-Type": content_type},
        )
        created = self._call(req)
        scan_id = created.get("scan_id") if isinstance(created, dict) else None
        try:
            return str(uuid.UUID(scan_id))
        except (TypeError, ValueError, AttributeError) as exc:
            raise GateError("invalid_response", "The API returned no scan ID", 400) from exc


def wait_for_scan(
    client: ApiClient,
    scan_id: str,
    timeout: float,
    poll: float,
    *,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> str:
    """Poll until the scan ends. Temporary API errors are retried until the deadline."""
    deadline = clock() + timeout
    while True:
        try:
            scan = client.get(f"/scans/{scan_id}")
        except GateError as exc:
            if not exc.retryable:
                raise
        else:
            status = scan.get("status") if isinstance(scan, dict) else None
            if status in _TERMINAL_STATUSES:
                return status
        if clock() >= deadline:
            raise GateError("scan_timeout", "The scan did not finish before the timeout")
        sleep(poll)


def _names(values: Any) -> str:
    if not isinstance(values, list):
        return "Not reported"
    names = [identifier(value) or "unrecognized" for value in values]
    return ", ".join(escape_markdown(name) for name in names) or "None"


def _number(value: Any, missing: str) -> str:
    return f"{value:.3f}" if _valid_score(value) else missing


def _ml_line(risk: dict[str, Any]) -> str:
    ml = risk.get("ml") if isinstance(risk.get("ml"), dict) else {}
    status = identifier(ml.get("status"))
    if status == "available":
        return "available"
    return "ML model unavailable (rule-based score)"


def _mock_line(risk: dict[str, Any]) -> str:
    flag = risk.get("contains_mock_evidence")
    if flag is False:
        return "None"
    if flag is True:
        return "**MOCK EVIDENCE PRESENT** (source=mock)"
    return "Not reported, treated as mock"


def _risk_rows(risk: dict[str, Any]) -> list[str]:
    decision = risk.get("decision")
    confidence_label = identifier(risk.get("confidence_label"))
    confidence = _number(risk.get("confidence"), "Not computed")
    if confidence_label:
        confidence = f"{confidence} ({escape_markdown(confidence_label)})"
    rules = risk.get("hard_rules") if isinstance(risk.get("hard_rules"), dict) else {}
    fired = rules.get("fired") if isinstance(rules.get("fired"), list) else []
    fired_ids = [item.get("rule_id") for item in fired if isinstance(item, dict)]
    training = risk.get("training_data") if isinstance(risk.get("training_data"), dict) else {}
    reason = risk.get("reason") if isinstance(risk.get("reason"), dict) else {}
    rows = [
        ("Decision", escape_markdown(decision) if decision in _DECISIONS else "None"),
        ("ProvenanceX risk score", _number(risk.get("risk_score"), "Not computed")),
        ("Confidence", confidence),
        ("Not-evaluated layers", _names(risk.get("not_evaluated_layers"))),
        ("Partial layers", _names(risk.get("partial_layers"))),
        ("Hard rules fired", _names(fired_ids)),
        ("Mock evidence", _mock_line(risk)),
        ("ML status", _ml_line(risk)),
        ("Training data", escape_markdown(training.get("notice")) or "Not reported"),
    ]
    if identifier(reason.get("code")):
        rows.append(("Reason code", escape_markdown(reason["code"])))
    return [f"| {name} | {value} |" for name, value in rows]


def render_summary(scan_id: str | None, verdict: Verdict, risk: Any) -> str:
    """The job summary. Not-evaluated layers mean missing evidence, not a clean result."""
    lines = [
        "## ProvenanceX gate",
        "",
        f"**{verdict.label}** (exit {verdict.exit_code}): {escape_markdown(verdict.reason)}",
        "",
    ]
    if scan_id:
        lines += [f"Scan ID: `{scan_id}`", ""]
    if isinstance(risk, dict):
        lines += ["| Field | Value |", "| --- | --- |", *_risk_rows(risk), ""]
    lines.append(
        "A not-evaluated layer is missing evidence, not a clean result. Decisions come from "
        "hand-set research parameters."
    )
    return "\n".join(lines) + "\n"


def _write_summary(text: str, summary_path: str | None) -> None:
    if not summary_path:
        safe_log(text)
        return
    try:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(text)
    except OSError as exc:
        safe_log(f"Could not write the job summary ({type(exc).__name__})")


def run_gate(
    args: argparse.Namespace, client: ApiClient | None = None
) -> tuple[str | None, Verdict, Any]:
    """Run the scan and return its ID, verdict and risk result. Raises GateError on failure."""
    root = Path(args.path)
    name = args.name or root.resolve().name
    if not _UPLOAD_NAME.fullmatch(name):
        name = "artifact"
    client = client or ApiClient(validate_api_url(args.api_url))
    payload = zip_directory(root, args.max_upload_mb * 1024 * 1024)
    scan_id = client.submit(args.kind, name, payload)
    safe_log(f"Submitted scan {scan_id}")
    try:
        status = wait_for_scan(client, scan_id, args.timeout, args.poll)
        risk = client.get(f"/scans/{scan_id}/risk")
    except GateError as exc:
        return scan_id, Verdict(EXIT_INCONCLUSIVE, "INCONCLUSIVE", exc.message), None
    verdict = evaluate(status, risk, fail_on_review=args.fail_on_review, allow_mock=args.allow_mock)
    return scan_id, verdict, risk


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ProvenanceX CI gate")
    parser.add_argument("path", help="directory to scan")
    parser.add_argument("--kind", choices=("software", "model"), default="software")
    parser.add_argument("--name", help="artifact name (default: the directory name)")
    parser.add_argument("--api-url", default=os.environ.get("PROVENANCEX_API_URL", DEFAULT_API_URL))
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--poll", type=float, default=DEFAULT_POLL_SECONDS)
    parser.add_argument("--max-upload-mb", type=int, default=DEFAULT_MAX_UPLOAD_MB)
    parser.add_argument("--fail-on-review", action="store_true", help="exit 1 on REVIEW")
    parser.add_argument(
        "--allow-mock", action="store_true", help="let a decision that used mock evidence count"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    scan_id = None
    risk = None
    try:
        scan_id, verdict, risk = run_gate(args)
    except GateError as exc:
        verdict = Verdict(EXIT_INCONCLUSIVE, "INCONCLUSIVE", exc.message)
    except Exception as exc:  # noqa: BLE001 - any crash must end as "no pass", with its type logged
        safe_log(f"Unexpected error: {type(exc).__name__}")
        verdict = Verdict(EXIT_INCONCLUSIVE, "INCONCLUSIVE", "The gate failed unexpectedly")

    _write_summary(render_summary(scan_id, verdict, risk), os.environ.get("GITHUB_STEP_SUMMARY"))
    safe_log(f"ProvenanceX gate: {verdict.label} (exit {verdict.exit_code}): {verdict.reason}")
    if verdict.exit_code != EXIT_PASS and os.environ.get("GITHUB_ACTIONS") == "true":
        message = verdict.reason.replace("%", "%25").replace("::", ": :")
        print(f"::error title=ProvenanceX gate::{_CONTROL.sub(' ', message)}", flush=True)
    return verdict.exit_code


if __name__ == "__main__":
    sys.exit(main())
