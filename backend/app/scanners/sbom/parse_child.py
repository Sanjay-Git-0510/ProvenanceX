"""Parse an untrusted CycloneDX SBOM in a memory-limited child process (audit finding M3).

The raw SBOM (up to MAX_SBOM_MB) arrives as its own frame and is spooled to a file. Decoding it
with `json.loads` and validating it with pydantic can take many times its size in memory, which
the audit measured in the scan-runner. So the runner never parses it itself:

    python -I -c <bootstrap> <app root> <sbom file> <max bytes> <max components> <memory MB>

The child sets RLIMIT_AS (address space) before reading anything, parses with the existing
`parse_cyclonedx` (size and component caps, strict schema), and prints a compact, normalized
result. A hostile SBOM can at most exhaust the child's own limit: the child dies with a
MemoryError or is killed, and the runner records sbom_parse_error. The parent validates the
child's output against strict pydantic models before rebuilding `ParsedSbom`.

`-I` (isolated mode) ignores PYTHON* variables, the user site directory and the current
directory, and the child gets a minimal environment.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictInt, ValidationError

from app.core.bounded import printable_excerpt
from app.core.errors import AppError, ErrorCode
from app.scanners.sbom.cyclonedx import ParsedComponent, ParsedSbom

_BOOTSTRAP = (
    "import sys; sys.path.insert(0, sys.argv[1]); "
    "from app.scanners.sbom.parse_child import child_main; sys.exit(child_main(sys.argv[2:]))"
)
APP_ROOT = Path(__file__).resolve().parents[3]  # the directory that contains `app/`
MB = 1024 * 1024
EXIT_OK = 0
EXIT_REPORTED = 3  # a structured AppError was printed
EXIT_MEMORY = 4


# --------------------------------------------------------------------------- child
def child_main(argv: list[str]) -> int:
    import resource

    path, max_bytes, max_components, memory_mb = argv[0], int(argv[1]), int(argv[2]), int(argv[3])
    limit = memory_mb * MB
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    out = sys.stdout
    try:
        from app.scanners.sbom.cyclonedx import parse_cyclonedx

        with open(path, "rb") as fh:  # noqa: PTH123
            size = os.fstat(fh.fileno()).st_size
            if size > max_bytes:
                raise AppError(
                    ErrorCode.SBOM_TOO_LARGE,
                    "SBOM exceeds the size limit",
                    413,
                    {"size_bytes": size, "max_bytes": max_bytes},
                )
            raw = fh.read(max_bytes + 1)
        parsed = parse_cyclonedx(raw, max_bytes=max_bytes, max_components=max_components)
        del raw
        payload = {
            "ok": {
                "spec_version": parsed.spec_version,
                "root_ref": parsed.root_ref,
                "root_name": parsed.root_name,
                "tools": parsed.tools,
                "components": [
                    [
                        c.bom_ref,
                        c.name,
                        c.version,
                        c.component_type,
                        c.purl,
                        c.ecosystem,
                        list(c.licenses),
                        c.cpe,
                        c.found_by,
                        list(c.locations),
                    ]
                    for c in parsed.components
                ],
                "edges": [list(e) for e in parsed.edges],
                "stats": parsed.stats,
            }
        }
        out.write(json.dumps(payload, separators=(",", ":")))
        return EXIT_OK
    except MemoryError:
        return EXIT_MEMORY
    except AppError as exc:
        out.write(
            json.dumps(
                {
                    "error": {
                        "code": str(exc.code),
                        "message": exc.message[:500],
                        "details": exc.details,
                    }
                },
                default=str,
            )
        )
        return EXIT_REPORTED


# --------------------------------------------------------------------------- parent
class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _Error(_Strict):
    code: str = Field(max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    message: str = Field(max_length=500)
    details: Any = None


_Opt = str | None


class _Parsed(_Strict):
    spec_version: str = Field(max_length=16)
    root_ref: _Opt = Field(default=None, max_length=2048)
    root_name: _Opt = Field(default=None, max_length=1024)
    tools: list[str] = Field(max_length=1000)
    components: list[tuple[str, str, _Opt, str, _Opt, _Opt, list[str], _Opt, _Opt, list[str]]]
    edges: list[tuple[str, str]]
    stats: dict[str, StrictInt]


class _Envelope(_Strict):
    ok: _Parsed | None = None
    error: _Error | None = None


def _error(message: str, details: Any = None) -> AppError:
    return AppError(ErrorCode.SBOM_PARSE_ERROR, message, 422, details)


def parse_sbom_isolated(
    path: Path,
    *,
    max_bytes: int,
    max_components: int,
    memory_mb: int,
    timeout_seconds: float,
) -> ParsedSbom:
    """Parse the SBOM file at `path` in a child process. Raises AppError (sbom_* codes)."""
    argv = [
        sys.executable,
        "-I",
        "-c",
        _BOOTSTRAP,
        str(APP_ROOT),
        str(path),
        str(max_bytes),
        str(max_components),
        str(memory_mb),
    ]
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise _error("SBOM parsing timed out", {"timeout_seconds": timeout_seconds}) from exc
    if done.returncode == EXIT_MEMORY or (done.returncode < 0 and not done.stdout):
        raise _error("SBOM parsing exceeded its memory limit", {"memory_mb": memory_mb})
    if done.returncode not in (EXIT_OK, EXIT_REPORTED):
        tail = printable_excerpt(done.stderr[-300:])
        raise _error("SBOM parser failed", {"exit_code": done.returncode, "stderr": tail})
    # The child's output is bounded by the component cap; refuse anything implausibly large.
    if len(done.stdout) > max(max_bytes * 2, 4 * MB):
        raise _error("SBOM parser output is too large")
    try:
        envelope = _Envelope.model_validate_json(done.stdout)
    except ValidationError as exc:
        raise _error("SBOM parser output failed validation") from exc
    if envelope.error is not None:
        known = {str(c) for c in ErrorCode}
        code = envelope.error.code if envelope.error.code in known else ErrorCode.SBOM_PARSE_ERROR
        raise AppError(code, envelope.error.message, 422, envelope.error.details)
    parsed = envelope.ok
    if parsed is None or len(parsed.components) > max_components:
        raise _error("SBOM parser output failed validation")
    return ParsedSbom(
        spec_version=parsed.spec_version,
        root_ref=parsed.root_ref,
        root_name=parsed.root_name,
        tools=list(parsed.tools),
        components=[
            ParsedComponent(
                bom_ref=c[0],
                name=c[1],
                version=c[2],
                component_type=c[3],
                purl=c[4],
                ecosystem=c[5],
                licenses=tuple(c[6]),
                cpe=c[7],
                found_by=c[8],
                locations=tuple(c[9]),
            )
            for c in parsed.components
        ],
        edges=[(a, b) for a, b in parsed.edges],
        stats=dict(parsed.stats),
    )
