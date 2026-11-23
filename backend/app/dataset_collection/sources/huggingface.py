"""Hugging Face Hub metadata adapter (JSON API only; no file is downloaded).

Lists repositories by author, reads one repository's metadata (including the Hub's own security
scan status), and checks whether an organization is verified.
"""

import re
from dataclasses import dataclass
from typing import Any

from app.dataset_collection.sources.base import MetadataClient, SourceError

API = "https://huggingface.co/api"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}/[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")


@dataclass(frozen=True)
class HfRepoMeta:
    repo_id: str
    kind: str  # model | dataset
    sha: str | None
    created_at: str | None
    gated: bool
    private: bool
    disabled: bool
    license: str | None
    tags: tuple[str, ...]
    used_storage: int | None
    scans_done: bool | None
    files_with_issues: tuple[tuple[str, str], ...]  # (path, level) as the Hub reports them
    raw: dict[str, Any]

    def issue_paths(self, *levels: str) -> list[str]:
        return [path for path, level in self.files_with_issues if level in levels]

    @property
    def author(self) -> str:
        return self.repo_id.split("/", 1)[0]

    @property
    def is_adapter(self) -> bool:
        return "peft" in self.tags or any(t.startswith("base_model:adapter:") for t in self.tags)

    @property
    def base_models(self) -> tuple[str, ...]:
        """Declared base models (the plain `base_model:<id>` tags)."""
        out = []
        for tag in self.tags:
            rest = tag.removeprefix("base_model:")
            if rest != tag and _ID_RE.match(rest):
                out.append(rest)
        return tuple(sorted(set(out)))


def valid_repo_id(repo_id: object) -> bool:
    return isinstance(repo_id, str) and bool(_ID_RE.match(repo_id)) and ".." not in repo_id


def _license(tags: tuple[str, ...], card: Any) -> str | None:
    for tag in tags:
        if tag.startswith("license:"):
            return tag.removeprefix("license:")[:64]
    if isinstance(card, dict) and isinstance(card.get("license"), str):
        return card["license"][:64]
    return None


def parse_repo(doc: Any, kind: str) -> HfRepoMeta | None:
    if not isinstance(doc, dict) or not valid_repo_id(doc.get("id")):
        return None
    tags = tuple(t for t in doc.get("tags") or [] if isinstance(t, str))
    security = doc.get("securityRepoStatus")
    scans_done = security.get("scansDone") if isinstance(security, dict) else None
    issues = security.get("filesWithIssues") if isinstance(security, dict) else None
    issue_paths = tuple(
        (str(i.get("path"))[:200], str(i.get("level") or "unspecified")[:32])
        if isinstance(i, dict)
        else (str(i)[:200], "unspecified")
        for i in (issues or [])
    )
    storage = doc.get("usedStorage")
    meta = HfRepoMeta(
        repo_id=doc["id"],
        kind=kind,
        sha=doc.get("sha") if isinstance(doc.get("sha"), str) else None,
        created_at=doc.get("createdAt"),
        gated=bool(doc.get("gated")),
        private=bool(doc.get("private")),
        disabled=bool(doc.get("disabled")),
        license=_license(tags, doc.get("cardData")),
        tags=tags,
        used_storage=storage if isinstance(storage, int) else None,
        scans_done=scans_done if isinstance(scans_done, bool) else None,
        files_with_issues=issue_paths,
        raw={},
    )
    raw = {
        "id": meta.repo_id,
        "kind": kind,
        "sha": meta.sha,
        "createdAt": meta.created_at,
        "gated": meta.gated,
        "private": meta.private,
        "disabled": meta.disabled,
        "license": meta.license,
        "tags": sorted(tags),
        "usedStorage": meta.used_storage,
        "scansDone": meta.scans_done,
        "filesWithIssues": [list(i) for i in issue_paths],
    }
    return HfRepoMeta(**{**meta.__dict__, "raw": raw})


def list_repos(
    client: MetadataClient,
    kind: str,
    *,
    author: str | None = None,
    filter_tag: str | None = None,
    limit: int = 20,
) -> list[str]:
    """Repository ids, sorted by downloads, for an author and/or tag filter."""
    if author is not None and not _NAME_RE.match(author):
        raise SourceError(f"Invalid author: {author}")
    params = {"sort": "downloads", "direction": "-1", "limit": str(limit)}
    if author:
        params["author"] = author
    if filter_tag:
        params["filter"] = filter_tag
    data = client.get(f"{API}/{kind}s", params=params)
    if not isinstance(data, list):
        raise SourceError("Hugging Face returned an unexpected listing")
    return [d["id"] for d in data if isinstance(d, dict) and valid_repo_id(d.get("id"))]


def repo_meta(client: MetadataClient, kind: str, repo_id: str) -> HfRepoMeta:
    if not valid_repo_id(repo_id):
        raise SourceError(f"Invalid repository id: {repo_id}")
    data = client.get(f"{API}/{kind}s/{repo_id}", params={"securityStatus": "true"})
    meta = parse_repo(data, kind)
    if meta is None:
        raise SourceError(f"Hugging Face returned unexpected metadata for {repo_id}")
    return meta


def org_verified(client: MetadataClient, org: str) -> bool | None:
    """True or False for an organization; None when the name is a user, not an organization."""
    if not _NAME_RE.match(org):
        raise SourceError(f"Invalid organization name: {org}")
    try:
        data = client.get(f"{API}/organizations/{org}/overview")
    except SourceError as exc:
        if "HTTP 404" in str(exc):
            return None
        raise
    return isinstance(data, dict) and data.get("isVerified") is True
