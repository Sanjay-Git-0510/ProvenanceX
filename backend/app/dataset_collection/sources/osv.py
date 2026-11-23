"""OSV adapter (https://api.osv.dev): which advisories affect one package version."""

from dataclasses import dataclass

from app.dataset_collection.sources.base import OSV_ECOSYSTEMS, MetadataClient, SourceError

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
MAX_PAGES = 5


@dataclass(frozen=True)
class OsvResult:
    ids: tuple[str, ...]  # advisory ids plus their aliases
    complete: bool  # False when paging stopped early


def query_version(client: MetadataClient, ecosystem: str, name: str, version: str) -> OsvResult:
    """Advisories OSV lists for `name@version`. Raises SourceError for unknown ecosystems."""
    osv_ecosystem = OSV_ECOSYSTEMS.get(ecosystem)
    if osv_ecosystem is None:
        raise SourceError(f"Ecosystem not supported by the OSV adapter: {ecosystem}")
    payload: dict[str, object] = {
        "package": {"name": name, "ecosystem": osv_ecosystem},
        "version": version,
    }
    ids: set[str] = set()
    for _ in range(MAX_PAGES):
        data = client.post(OSV_QUERY_URL, payload)
        if not isinstance(data, dict):
            raise SourceError("OSV returned an unexpected response")
        for vuln in data.get("vulns") or []:
            if isinstance(vuln, dict) and isinstance(vuln.get("id"), str):
                ids.add(vuln["id"])
                ids.update(a for a in vuln.get("aliases") or [] if isinstance(a, str))
        token = data.get("next_page_token")
        if not token:
            return OsvResult(tuple(sorted(ids)), True)
        payload["page_token"] = str(token)
    return OsvResult(tuple(sorted(ids)), False)
