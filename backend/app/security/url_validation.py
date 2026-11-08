"""Validation of remote source URLs (SSRF defenses).

Rules (CLAUDE.md security boundary 3):
- https only, exact host allowlist (github.com, huggingface.co), no subdomains;
- no credentials, explicit ports, IP-literal hosts, query strings or fragments;
- ASCII only (blocks IDN homographs), no whitespace/control chars/backslashes;
- the host must resolve, and every resolved address must be public.

The DNS check narrows but cannot fully close DNS-rebinding windows (git resolves the
host again). The strict hostname allowlist is the primary control; the IP check is
defense in depth.
"""

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.core.errors import AppError, ErrorCode

ALLOWED_HOSTS = frozenset({"github.com", "huggingface.co"})
GITHUB_HOSTS = frozenset({"github.com"})
MAX_URL_LENGTH = 2048

_GH_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_GH_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


@dataclass(frozen=True)
class SourceUrl:
    host: str
    path: str


@dataclass(frozen=True)
class GitHubRepo:
    owner: str
    repo: str

    @property
    def canonical_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}"

    @property
    def clone_url(self) -> str:
        return f"{self.canonical_url}.git"


def resolve_host(host: str) -> list[str]:
    """Return the IP addresses a host resolves to. Tests monkeypatch this."""
    infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    return sorted({str(info[4][0]) for info in infos})


def _invalid(message: str) -> AppError:
    return AppError(ErrorCode.INVALID_URL, message, 400)


def _not_allowed(message: str, details: object = None) -> AppError:
    return AppError(ErrorCode.URL_NOT_ALLOWED, message, 400, details)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def ensure_public_host(host: str) -> list[str]:
    """Resolve `host` and reject it if any address is not globally routable."""
    try:
        addresses = resolve_host(host)
    except (OSError, UnicodeError) as exc:  # socket.gaierror is an OSError
        raise AppError(
            ErrorCode.DNS_RESOLUTION_FAILED, f"Could not resolve host {host}", 400
        ) from exc
    if not addresses:
        raise AppError(ErrorCode.DNS_RESOLUTION_FAILED, f"Could not resolve host {host}", 400)

    for raw in addresses:
        ip = ipaddress.ip_address(raw.split("%", 1)[0])  # drop IPv6 zone id
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        # is_global is False for private, loopback, link-local, reserved, shared (CGNAT),
        # unspecified and documentation ranges.
        if not ip.is_global or ip.is_multicast:
            raise AppError(
                ErrorCode.PRIVATE_ADDRESS,
                "Host resolves to a non-public address",
                400,
                {"host": host},
            )
    return addresses


def validate_source_url(
    raw: object, *, allowed_hosts: frozenset[str] = ALLOWED_HOSTS, check_dns: bool = True
) -> SourceUrl:
    """Validate a remote source URL against the scheme/host/shape rules above."""
    if not isinstance(raw, str) or not raw.strip():
        raise _invalid("A source URL is required")
    url = raw.strip()
    if len(url) > MAX_URL_LENGTH:
        raise _invalid("URL is too long")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise _invalid("URL contains whitespace or control characters")
    if "\\" in url:
        raise _invalid("URL contains a backslash")
    if not url.isascii():
        raise _invalid("URL must be ASCII")

    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise _invalid("URL could not be parsed") from exc

    if parts.scheme != "https":
        raise _not_allowed("Only https:// URLs are accepted")
    if "@" in parts.netloc:
        raise _invalid("Credentials in URLs are not allowed")
    try:
        port = parts.port
    except ValueError as exc:
        raise _invalid("URL has an invalid port") from exc
    if port is not None or parts.netloc.endswith(":"):
        raise _invalid("Explicit ports are not allowed")

    host = parts.hostname or ""
    if not host:
        raise _invalid("URL has no host")
    if _is_ip_literal(host):
        raise _not_allowed("IP address hosts are not allowed")
    if host not in allowed_hosts:
        raise _not_allowed(f"Host is not allowed: {host}", {"allowed_hosts": sorted(allowed_hosts)})
    if parts.query or parts.fragment or url.endswith(("?", "#")):
        raise _invalid("Query strings and fragments are not allowed")

    if check_dns:
        ensure_public_host(host)
    return SourceUrl(host=host, path=parts.path)


def validate_github_repo_url(raw: object, *, check_dns: bool = True) -> GitHubRepo:
    """Validate `https://github.com/<owner>/<repo>[.git][/]` and return its parts."""
    src = validate_source_url(raw, allowed_hosts=GITHUB_HOSTS, check_dns=False)

    path = src.path[:-1] if src.path.endswith("/") else src.path
    segments = path.split("/")[1:] if path.startswith("/") else []
    if len(segments) != 2:
        raise _invalid("Expected a repository URL: https://github.com/<owner>/<repo>")
    owner, repo = segments
    if repo.endswith(".git"):
        repo = repo[: -len(".git")]
    if not _GH_OWNER_RE.match(owner) or not _GH_REPO_RE.match(repo) or repo in {".", ".."}:
        raise _invalid("Invalid GitHub owner or repository name")

    if check_dns:
        ensure_public_host(src.host)
    return GitHubRepo(owner=owner, repo=repo)


# --------------------------------------------------------------------------- Hugging Face
HF_HOST = "huggingface.co"
HF_HOSTS = frozenset({HF_HOST})
# Download redirects may only go to Hugging Face's own hosts. LFS/Xet content is served
# from HF-owned CDN hosts under hf.co (e.g. us.aws.cdn.hf.co) or the legacy
# cdn-lfs*.huggingface.co hosts. This list is fixed in code, not configurable.
HF_REDIRECT_EXACT_HOSTS = frozenset(
    {
        HF_HOST,
        "cdn-lfs.huggingface.co",
        "cdn-lfs-us-1.huggingface.co",
        "cdn-lfs-eu-1.huggingface.co",
        "cas-bridge.xethub.hf.co",
    }
)
HF_REDIRECT_HOST_SUFFIXES = (".hf.co",)

# First path segments that are HF site routes, not repository owners or legacy repo ids.
_HF_RESERVED = frozenset(
    {
        "api",
        "spaces",
        "models",
        "docs",
        "settings",
        "organizations",
        "new",
        "join",
        "login",
        "logout",
        "blog",
        "papers",
        "collections",
        "pricing",
        "tasks",
        "search",
        "posts",
        "learn",
        "enterprise",
        "chat",
        "resolve",
        "tree",
        "blob",
    }
)
_HF_SEGMENT_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,94}[A-Za-z0-9])?$")


@dataclass(frozen=True)
class HfRepo:
    """A Hugging Face repository reference. repo_id is `owner/name` (or a legacy `name`)."""

    repo_type: str  # "model" | "dataset"
    repo_id: str

    @property
    def canonical_url(self) -> str:
        prefix = "datasets/" if self.repo_type == "dataset" else ""
        return f"https://{HF_HOST}/{prefix}{self.repo_id}"


def _valid_hf_segment(segment: str) -> bool:
    return (
        bool(_HF_SEGMENT_RE.match(segment))
        and ".." not in segment
        and "--" not in segment
        and not segment.endswith(".git")
    )


def validate_hf_repo_url(raw: object, *, check_dns: bool = True) -> HfRepo:
    """Validate `https://huggingface.co/[datasets/]<owner>/<name>` (or a legacy `/<name>`).

    Only bare repository URLs are accepted (no /tree/, /blob/ or /resolve/ paths); the
    revision is a separate, validated field. Spaces are not supported.
    """
    src = validate_source_url(raw, allowed_hosts=HF_HOSTS, check_dns=False)
    path = src.path[:-1] if src.path.endswith("/") else src.path
    segments = path.split("/")[1:] if path.startswith("/") else []
    repo_type = "model"
    if segments and segments[0] == "datasets":
        repo_type = "dataset"
        segments = segments[1:]
    if not segments or len(segments) > 2:
        raise _invalid("Expected a repository URL: https://huggingface.co/<owner>/<name>")
    if segments[0].lower() in _HF_RESERVED:
        raise _invalid("This Hugging Face URL is not a model or dataset repository")
    if repo_type == "dataset" and len(segments) != 2:
        raise _invalid("Expected a dataset URL: https://huggingface.co/datasets/<owner>/<name>")
    if not all(_valid_hf_segment(s) for s in segments):
        raise _invalid("Invalid Hugging Face owner or repository name")

    if check_dns:
        ensure_public_host(src.host)
    return HfRepo(repo_type=repo_type, repo_id="/".join(segments))


def is_allowed_hf_redirect_host(host: str) -> bool:
    host = host.lower()
    return host in HF_REDIRECT_EXACT_HOSTS or (
        host.endswith(HF_REDIRECT_HOST_SUFFIXES) and host.count(".") <= 5
    )


def validate_hf_redirect_url(url: str, *, check_dns: bool = True) -> str:
    """Validate one redirect hop of a Hugging Face file download.

    Rules: https only, no credentials, no explicit port, no IP literal, host on the
    fixed HF allowlist, and (with check_dns) every resolved address public. Query strings
    are allowed, because CDN URLs are signed. Returns the host.
    """
    if len(url) > 8192 or not url.isascii() or any(ord(ch) < 33 or ord(ch) == 127 for ch in url):
        raise _not_allowed("Redirect URL is malformed")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise _not_allowed("Redirect URL is malformed") from exc
    if parts.scheme != "https":
        raise _not_allowed("Redirect to a non-https URL")
    if "@" in parts.netloc or port is not None or parts.netloc.endswith(":"):
        raise _not_allowed("Redirect URL has credentials or a port")
    host = (parts.hostname or "").lower()
    if not host or _is_ip_literal(host):
        raise _not_allowed("Redirect to an IP address or empty host")
    if not is_allowed_hf_redirect_host(host):
        raise _not_allowed("Redirect host is not allowed", {"host": host})
    if check_dns:
        ensure_public_host(host)
    return host
