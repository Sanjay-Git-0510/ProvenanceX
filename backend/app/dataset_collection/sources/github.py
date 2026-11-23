"""GitHub REST adapter: repository facts, publisher verification, releases, tags and signatures."""

import re
from dataclasses import dataclass
from typing import Any

from app.dataset_collection.sources.base import MetadataClient, SourceError

API = "https://api.github.com"
MAX_TAG_PAGES = 3
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


@dataclass(frozen=True)
class RepoInfo:
    owner: str
    name: str
    owner_type: str | None
    created_at: str | None
    archived: bool
    fork: bool
    license: str | None  # SPDX id
    raw: dict[str, Any]


def _check(owner: str, repo: str) -> None:
    if not (_NAME_RE.match(owner) and _NAME_RE.match(repo)) or ".." in owner + repo:
        raise SourceError(f"Invalid GitHub repository name: {owner}/{repo}")


def parse_repo_url(url: str) -> tuple[str, str] | None:
    """(owner, repo) from a https://github.com/<owner>/<repo> URL, or None."""
    match = re.match(r"^https://github\.com/([^/\s]+)/([^/\s#?]+?)(?:\.git)?/?$", url or "")
    if not match:
        return None
    owner, repo = match.group(1), match.group(2)
    if not (_NAME_RE.match(owner) and _NAME_RE.match(repo)):
        return None
    return owner, repo


def repo_info(client: MetadataClient, owner: str, repo: str) -> RepoInfo:
    _check(owner, repo)
    data = client.get(f"{API}/repos/{owner}/{repo}")
    if not isinstance(data, dict):
        raise SourceError("GitHub returned an unexpected repository response")
    lic = data.get("license") if isinstance(data.get("license"), dict) else {}
    spdx = lic.get("spdx_id") if isinstance(lic.get("spdx_id"), str) else None
    owner_data = data.get("owner") if isinstance(data.get("owner"), dict) else {}
    raw = {
        k: data.get(k) for k in ("full_name", "created_at", "archived", "fork", "default_branch")
    }
    raw["owner_type"] = owner_data.get("type")
    raw["license"] = spdx
    return RepoInfo(
        owner=str(owner_data.get("login") or owner),
        name=str(data.get("name") or repo),
        owner_type=owner_data.get("type"),
        created_at=data.get("created_at"),
        archived=bool(data.get("archived")),
        fork=bool(data.get("fork")),
        license=spdx,
        raw=raw,
    )


def org_verified(client: MetadataClient, org: str) -> bool:
    """True when GitHub shows the organization as verified (domain-verified publisher)."""
    if not _NAME_RE.match(org):
        raise SourceError(f"Invalid organization name: {org}")
    data = client.get(f"{API}/orgs/{org}")
    return isinstance(data, dict) and data.get("is_verified") is True


def releases(client: MetadataClient, owner: str, repo: str) -> list[dict[str, Any]]:
    """Published, non-draft, non-prerelease releases, newest first (one page).

    Asks for 30; when release notes make that page exceed the size cap, retries with 10.
    """
    _check(owner, repo)
    url = f"{API}/repos/{owner}/{repo}/releases"
    try:
        data = client.get(url, params={"per_page": "30"})
    except SourceError as exc:
        if "size limit" not in str(exc):
            raise
        data = client.get(url, params={"per_page": "10"})
    if not isinstance(data, list):
        raise SourceError("GitHub returned an unexpected releases response")
    return [
        {"tag_name": r.get("tag_name"), "published_at": r.get("published_at")}
        for r in data
        if isinstance(r, dict)
        and not r.get("draft")
        and not r.get("prerelease")
        and isinstance(r.get("tag_name"), str)
    ]


def tags(client: MetadataClient, owner: str, repo: str) -> list[tuple[str, str]]:
    """(tag name, commit sha) pairs, up to MAX_TAG_PAGES pages of 100."""
    _check(owner, repo)
    out: list[tuple[str, str]] = []
    for page in range(1, MAX_TAG_PAGES + 1):
        data = client.get(
            f"{API}/repos/{owner}/{repo}/tags", params={"per_page": "100", "page": str(page)}
        )
        if not isinstance(data, list):
            raise SourceError("GitHub returned an unexpected tags response")
        for tag in data:
            commit = tag.get("commit") if isinstance(tag, dict) else None
            sha = commit.get("sha") if isinstance(commit, dict) else None
            if isinstance(tag.get("name"), str) and isinstance(sha, str) and len(sha) == 40:
                out.append((tag["name"], sha))
        if len(data) < 100:
            break
    return out


@dataclass(frozen=True)
class CommitFacts:
    sha: str
    date: str | None
    signature_verified: bool
    signature_reason: str | None


def commit_facts(client: MetadataClient, owner: str, repo: str, sha: str) -> CommitFacts:
    """Commit date and GitHub's signature verification for one commit."""
    _check(owner, repo)
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise SourceError("Invalid commit sha")
    data = client.get(f"{API}/repos/{owner}/{repo}/commits/{sha}")
    commit = data.get("commit") if isinstance(data, dict) else None
    if not isinstance(commit, dict):
        raise SourceError("GitHub returned an unexpected commit response")
    verification = (
        commit.get("verification") if isinstance(commit.get("verification"), dict) else {}
    )
    committer = commit.get("committer") if isinstance(commit.get("committer"), dict) else {}
    return CommitFacts(
        sha=sha,
        date=committer.get("date"),
        signature_verified=verification.get("verified") is True,
        signature_reason=verification.get("reason"),
    )
