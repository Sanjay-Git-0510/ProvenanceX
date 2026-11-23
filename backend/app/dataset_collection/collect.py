"""Collect labeled real-world manifest records from public metadata.

Each function turns one candidate into one ManifestRecord, applying the label rules in
manifest.py. A source failure for one candidate is recorded in `ctx.errors` and skipped; it is
never turned into a label.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from app.dataset_collection.sources import ghsa, github, huggingface, osv
from app.dataset_collection.sources.base import (
    OSV_ECOSYSTEMS,
    CollectionContext,
    SourceError,
    age_days,
    in_range,
    version_from_tag,
)
from app.dataset_collection.sources.nvd import NvdLookup
from app.ml.realworld.dedup import hf_family, package_family, software_family
from app.ml.realworld.manifest import (
    DATASET_VERSION,
    NOASSERTION,
    GroundTruth,
    ManifestRecord,
    RealLabel,
    canonical_sha256,
    record_id_for,
)

logger = logging.getLogger(__name__)
T = TypeVar("T")


# --- seeds ---------------------------------------------------------------------------------


class SoftwareSeed(BaseModel):
    """A candidate repository. Seeds are identifiers only; labels come from the collectors."""

    model_config = ConfigDict(extra="forbid")
    repo: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    ecosystem: str
    package: str = Field(min_length=1, max_length=214)


class HfSeeds(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model_authors: list[str] = []
    dataset_authors: list[str] = []
    lora_authors: list[str] = []
    per_author_limit: int = Field(default=8, ge=1, le=100)
    global_lora_limit: int = Field(default=20, ge=0, le=200)


class GhsaSeeds(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ecosystems: list[str] = ["pip", "npm"]
    max_windows: int = Field(default=6, ge=1, le=60)
    max_vulnerable_per_ecosystem: int = Field(default=60, ge=0, le=1000)
    max_malware_per_ecosystem: int = Field(default=150, ge=0, le=5000)


class Seeds(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int
    software: list[SoftwareSeed] = []
    huggingface: HfSeeds = HfSeeds()
    ghsa: GhsaSeeds = GhsaSeeds()
    nvd_max_lookups: int = Field(default=20, ge=0, le=500)


# --- shared record builder -----------------------------------------------------------------


@dataclass
class Draft:
    data_source: str
    source_url: str
    identifier: str
    artifact_type: str
    label: RealLabel
    truth: GroundTruth
    justification: str
    license: str | None
    family_id: str
    preprocessing: list[str]
    source_record: Any
    revision: str | None = None
    scan_url: str | None = None
    scan_eligible: bool = False
    evidence: dict[str, Any] | None = None


def build(ctx: CollectionContext, draft: Draft) -> ManifestRecord:
    return ManifestRecord(
        data_source=draft.data_source,
        source_url=draft.source_url,
        collection_date=ctx.today,
        artifact_identifier=draft.identifier,
        artifact_type=draft.artifact_type,  # type: ignore[arg-type]
        label=draft.label,
        label_justification=draft.justification,
        license=draft.license or NOASSERTION,
        dataset_version=DATASET_VERSION,
        preprocessing=draft.preprocessing,
        record_id=record_id_for(draft.artifact_type, draft.identifier, draft.revision),
        family_id=draft.family_id,
        ground_truth_status=draft.truth,
        revision=draft.revision,
        scan_url=draft.scan_url,
        scan_eligible=draft.scan_eligible,
        sha256_status="pending_scan" if draft.scan_eligible else "not_collected",
        source_record_sha256=canonical_sha256(draft.source_record),
        evidence=draft.evidence or {},
    )


# --- software: seeds -----------------------------------------------------------------------


def _vulnerable_ids(
    ctx: CollectionContext, ecosystem: str, package: str, version_text: str
) -> tuple[list[str], list[str], bool]:
    """(GHSA ids whose range covers the version, OSV ids, OSV complete)."""
    version = version_from_tag(version_text)
    ghsa_hits = []
    if version is not None:
        for adv in ghsa.advisories_affecting(ctx.client, ecosystem, package):
            for pkg in adv.affected:
                if pkg.name.lower() == package.lower() and pkg.vulnerable_range:
                    if in_range(version, pkg.vulnerable_range):
                        ghsa_hits.append(adv.ghsa_id)
    result = osv.query_version(ctx.client, ecosystem, package, version_text)
    return sorted(set(ghsa_hits)), list(result.ids), result.complete


def label_software_seed(ctx: CollectionContext, seed: SoftwareSeed) -> ManifestRecord:
    owner, repo = seed.repo.split("/", 1)
    info = github.repo_info(ctx.client, owner, repo)
    identifier = f"github.com/{owner}/{repo}"
    url = f"https://github.com/{owner}/{repo}"
    family = software_family(owner, repo)
    steps = ["seed:identifier-only", "release:latest-older-than-min-age", "osv+ghsa:version-check"]
    min_rel = ctx.criteria.min_release_age_days
    old_releases = [
        r
        for r in github.releases(ctx.client, owner, repo)
        if (age_days(r["published_at"], ctx.today) or -1) >= min_rel
    ]
    source: dict[str, Any] = {"seed": seed.model_dump(), "repo": info.raw}

    def unknown(reason: str, revision: str | None = None, **extra: Any) -> ManifestRecord:
        return build(
            ctx,
            Draft(
                "github",
                url,
                identifier,
                "software",
                RealLabel.UNKNOWN,
                GroundTruth.NONE,
                f"Unknown: {reason}. Missing evidence is not treated as benign.",
                info.license,
                family,
                steps,
                {**source, **extra},
                revision=revision,
                evidence={"failed_criteria": reason},
            ),
        )

    if not old_releases:
        return unknown(f"no stable GitHub release older than {min_rel} days")
    release = old_releases[0]
    tag = release["tag_name"]
    sha = dict(github.tags(ctx.client, owner, repo)).get(tag)
    if sha is None:
        return unknown(f"release tag {tag!r} not found in the first tag pages")
    version = version_from_tag(tag, seed.package)
    if version is None:
        return unknown(f"tag {tag!r} does not name a parsable version", sha)
    commit = github.commit_facts(ctx.client, owner, repo, sha)
    ghsa_ids, osv_ids, osv_complete = _vulnerable_ids(
        ctx, seed.ecosystem, seed.package, str(version)
    )
    verified = info.owner_type == "Organization" and github.org_verified(ctx.client, info.owner)
    repo_age = age_days(info.created_at, ctx.today)
    release_age = age_days(release["published_at"], ctx.today)
    source.update(
        release=release,
        sha=sha,
        version=str(version),
        ghsa_ids=ghsa_ids,
        osv_ids=osv_ids,
        org_verified=verified,
        signature_verified=commit.signature_verified,
    )
    evidence = {
        "tag": tag,
        "version": str(version),
        "commit_date": commit.date,
        "org_verified": verified,
        "signature_verified": commit.signature_verified,
        "signature_reason": commit.signature_reason,
        "repo_age_days": repo_age,
        "release_age_days": release_age,
        "ghsa_ids": ghsa_ids,
        "osv_ids": osv_ids,
        "package": f"{seed.ecosystem}:{seed.package}",
    }
    if ghsa_ids or osv_ids:
        named = ", ".join((ghsa_ids or osv_ids)[:5])
        return build(
            ctx,
            Draft(
                "ghsa" if ghsa_ids else "osv",
                url,
                identifier,
                "software",
                RealLabel.KNOWN_VULNERABLE,
                GroundTruth.ESTABLISHED,
                f"{seed.package} {version} (tag {tag}) is in the affected range of {named}.",
                info.license,
                family,
                steps,
                source,
                revision=sha,
                scan_url=url,
                scan_eligible=True,
                evidence=evidence,
            ),
        )
    failed = []
    if not (verified or commit.signature_verified):
        failed.append("no verified publisher and release commit not signature-verified")
    if repo_age is None or repo_age < ctx.criteria.min_repo_age_days:
        failed.append(f"repository younger than {ctx.criteria.min_repo_age_days} days")
    if info.archived or info.fork:
        failed.append("archived or fork")
    if not osv_complete:
        failed.append("OSV result incomplete")
    if failed:
        return unknown("; ".join(failed), sha, **evidence)
    proof = "verified organization" if verified else "signature-verified release commit"
    return build(
        ctx,
        Draft(
            "github",
            url,
            identifier,
            "software",
            RealLabel.BENIGN,
            GroundTruth.CRITERIA_BASED,
            f"Benign by criteria: no GHSA/OSV advisory for {seed.package} {version}; {proof}; "
            f"repository {repo_age} days old; release {release_age} days old.",
            info.license,
            family,
            steps,
            source,
            revision=sha,
            scan_url=url,
            scan_eligible=True,
            evidence=evidence,
        ),
    )


# --- software: GHSA reviewed advisories ----------------------------------------------------


def _pick_vulnerable_tag(
    tags: list[tuple[str, str]], package: str, pkg: ghsa.AffectedPackage
) -> tuple[str, str, str] | None:
    """The highest tag whose version is inside the vulnerable range: (tag, sha, version)."""
    best = None
    for tag, sha in tags:
        version = version_from_tag(tag, package)
        if version is None or version.is_prerelease or not pkg.vulnerable_range:
            continue
        if in_range(version, pkg.vulnerable_range) and (best is None or version > best[0]):
            best = (version, tag, sha)
    return None if best is None else (best[1], best[2], str(best[0]))


def label_ghsa_vulnerable(
    ctx: CollectionContext, adv: ghsa.Advisory, nvd: NvdLookup | None
) -> ManifestRecord | None:
    """A known-vulnerable repository revision from one reviewed advisory, or None."""
    parsed = github.parse_repo_url(adv.source_code_location or "")
    if parsed is None:
        return None
    owner, repo = parsed
    candidates = [p for p in adv.affected if p.ecosystem in OSV_ECOSYSTEMS and p.vulnerable_range]
    if not candidates:
        return None
    pkg = candidates[0]
    pick = _pick_vulnerable_tag(github.tags(ctx.client, owner, repo), pkg.name, pkg)
    if pick is None:
        return None
    tag, sha, version = pick
    info = github.repo_info(ctx.client, owner, repo)
    osv_ids = list(osv.query_version(ctx.client, pkg.ecosystem, pkg.name, version).ids)
    nvd_status = None
    if nvd is not None and adv.cve_id:
        try:
            status = nvd.status(adv.cve_id)
            nvd_status = None if status is None else status.__dict__
        except SourceError as exc:
            ctx.record_error("nvd", adv.cve_id, exc)
    url = f"https://github.com/{owner}/{repo}"
    corroborated = adv.ghsa_id in osv_ids or bool(adv.cve_id and adv.cve_id in osv_ids)
    return build(
        ctx,
        Draft(
            "ghsa",
            adv.html_url,
            f"github.com/{owner}/{repo}",
            "software",
            RealLabel.KNOWN_VULNERABLE,
            GroundTruth.ESTABLISHED,
            f"Reviewed advisory {adv.ghsa_id} lists {pkg.ecosystem}:{pkg.name} "
            f"'{pkg.vulnerable_range}'; tag {tag} names version {version} inside that range."
            + (" OSV lists the same advisory for that version." if corroborated else ""),
            info.license,
            software_family(owner, repo),
            [
                "ghsa:reviewed-30d-windows",
                "range:packaging.Version",
                "tag:highest-in-range",
                "osv:corroboration",
                "nvd:status-capped",
            ],
            {"advisory": adv.raw, "tag": tag, "sha": sha, "repo": info.raw},
            revision=sha,
            scan_url=url,
            scan_eligible=True,
            evidence={
                "ghsa_id": adv.ghsa_id,
                "cve_id": adv.cve_id,
                "cvss_v3": adv.cvss_v3,
                "package": f"{pkg.ecosystem}:{pkg.name}",
                "tag": tag,
                "version": version,
                "first_patched": pkg.first_patched,
                "osv_corroborated": corroborated,
                "nvd": nvd_status,
                "label_scope": "the package's own code; its dependencies may show no advisory",
            },
        ),
    )


# --- registry malware (metadata only) ------------------------------------------------------


def label_ghsa_malware(ctx: CollectionContext, adv: ghsa.Advisory) -> list[ManifestRecord]:
    """One metadata-only record per malicious package named by a malware advisory."""
    out = []
    for name in sorted({(p.ecosystem, p.name) for p in adv.affected}):
        ecosystem, package = name
        versions = sorted({p.vulnerable_range or "" for p in adv.affected if p.name == package})
        out.append(
            build(
                ctx,
                Draft(
                    "ghsa",
                    adv.html_url,
                    f"{ecosystem}:{package}",
                    "package",
                    RealLabel.CONFIRMED_MALICIOUS,
                    GroundTruth.ESTABLISHED,
                    f"GitHub malware advisory {adv.ghsa_id} names {ecosystem}:{package}. "
                    "Metadata only: nothing was downloaded or scanned.",
                    None,
                    package_family(ecosystem, package),
                    ["ghsa:malware-30d-windows", "metadata-only"],
                    {"advisory": adv.raw, "package": package},
                    evidence={"ghsa_id": adv.ghsa_id, "versions": versions[:20]},
                ),
            )
        )
    return out


# --- Hugging Face --------------------------------------------------------------------------


class HfVerifiedCache:
    def __init__(self, ctx: CollectionContext) -> None:
        self.ctx = ctx
        self._cache: dict[str, bool | None] = {}

    def get(self, author: str) -> bool | None:
        if author not in self._cache:
            self._cache[author] = huggingface.org_verified(self.ctx.client, author)
        return self._cache[author]


def label_hf(
    ctx: CollectionContext, kind: str, repo_id: str, verified: HfVerifiedCache
) -> ManifestRecord:
    meta = huggingface.repo_meta(ctx.client, kind, repo_id)
    artifact_type = "dataset" if kind == "dataset" else ("lora" if meta.is_adapter else "model")
    url = f"https://huggingface.co/{'datasets/' if kind == 'dataset' else ''}{meta.repo_id}"
    org = verified.get(meta.author)
    age = age_days(meta.created_at, ctx.today)
    family = hf_family(kind, meta.repo_id, meta.base_models)
    steps = ["hf:list-by-author-or-tag", "hf:securityStatus", "hf:org-verified", "criteria:benign"]
    max_bytes = ctx.criteria.max_hf_storage_mb * 1024 * 1024
    fits = meta.used_storage is not None and meta.used_storage <= max_bytes
    evidence = {
        "org_verified": org,
        "age_days": age,
        "gated": meta.gated,
        "scans_done": meta.scans_done,
        "files_with_issues": [list(i) for i in meta.files_with_issues],
        "used_storage": meta.used_storage,
        "base_models": list(meta.base_models),
        "fits_scan_budget": fits,
        "advisory_source": "none exists for Hub repositories; the Hub security scan is used",
    }
    source = {"repo": meta.raw, "org_verified": org}
    unsafe = meta.issue_paths("unsafe")
    if unsafe:
        return build(
            ctx,
            Draft(
                "huggingface",
                url,
                meta.repo_id,
                artifact_type,
                RealLabel.SUSPICIOUS,
                GroundTruth.THIRD_PARTY_FLAG,
                f"The Hub security scan marks {len(unsafe)} file(s) unsafe. "
                "A scanner flag, not a confirmed finding; never scanned here.",
                meta.license,
                family,
                steps,
                source,
                revision=meta.sha,
                evidence=evidence,
            ),
        )
    failed = []
    if org is not True:
        failed.append("publisher is not a verified organization")
    if age is None or age < ctx.criteria.min_hf_age_days:
        failed.append(f"younger than {ctx.criteria.min_hf_age_days} days")
    if meta.gated or meta.private or meta.disabled:
        failed.append("gated, private or disabled")
    if meta.scans_done is not True:
        failed.append("Hub security scan not completed")
    if meta.files_with_issues:
        # 'caution' (e.g. unusual pickle imports) and 'error' (the scan failed on a file) are
        # not confirmed findings, but they are not a clean scan either.
        levels = sorted({level for _, level in meta.files_with_issues})
        failed.append(f"Hub security scan reports file issues ({', '.join(levels)})")
    if meta.sha is None:
        failed.append("no pinned revision")
    if failed:
        return build(
            ctx,
            Draft(
                "huggingface",
                url,
                meta.repo_id,
                artifact_type,
                RealLabel.UNKNOWN,
                GroundTruth.NONE,
                f"Unknown: {'; '.join(failed)}. Missing evidence is not treated as benign.",
                meta.license,
                family,
                steps,
                source,
                revision=meta.sha,
                evidence={**evidence, "failed_criteria": "; ".join(failed)},
            ),
        )
    return build(
        ctx,
        Draft(
            "huggingface",
            url,
            meta.repo_id,
            artifact_type,
            RealLabel.BENIGN,
            GroundTruth.CRITERIA_BASED,
            f"Benign by criteria: verified organization {meta.author}; {age} days old; Hub "
            "security scan done with no flagged files; revision pinned.",
            meta.license,
            family,
            steps,
            source,
            revision=meta.sha,
            scan_url=url,
            scan_eligible=fits,
            evidence=evidence,
        ),
    )


# --- orchestration -------------------------------------------------------------------------


def _safe(
    ctx: CollectionContext, source: str, identifier: str, fn: Callable[..., T], *args: Any
) -> T | None:
    """Run one source call; a SourceError is recorded and skipped, never turned into a label."""
    try:
        return fn(*args)
    except SourceError as exc:
        logger.warning("%s %s skipped: %s", source, identifier, exc)
        ctx.record_error(source, identifier, exc)
        return None


def _advisories(
    ctx: CollectionContext, advisory_type: str, ecosystem: str, windows: int
) -> list[ghsa.Advisory]:
    def fetch() -> list[ghsa.Advisory]:
        return list(
            ghsa.iter_advisories(
                ctx.client,
                advisory_type=advisory_type,
                ecosystem=ecosystem,
                end=ctx.today,
                max_windows=windows,
            )
        )

    return _safe(ctx, "ghsa", f"{advisory_type}/{ecosystem}", fetch) or []


def collect(ctx: CollectionContext, seeds: Seeds) -> list[ManifestRecord]:
    records: list[ManifestRecord] = []
    nvd = NvdLookup(ctx.client, seeds.nvd_max_lookups) if seeds.nvd_max_lookups else None

    for seed in seeds.software:
        rec = _safe(ctx, "github", seed.repo, label_software_seed, ctx, seed)
        if rec is not None:
            records.append(rec)

    for ecosystem in seeds.ghsa.ecosystems:
        taken, seen_repos = 0, set()
        target = seeds.ghsa.max_vulnerable_per_ecosystem
        advisories = _advisories(ctx, "reviewed", ecosystem, seeds.ghsa.max_windows)
        for adv in advisories:
            if taken >= target:
                break
            repo = (adv.source_code_location or "").lower().rstrip("/")
            if not repo or repo in seen_repos:
                continue
            seen_repos.add(repo)
            rec = _safe(ctx, "ghsa", adv.ghsa_id, label_ghsa_vulnerable, ctx, adv, nvd)
            if rec is not None:
                records.append(rec)
                taken += 1

        malware = _advisories(ctx, "malware", ecosystem, seeds.ghsa.max_windows)
        mal_records = [r for adv in malware for r in label_ghsa_malware(ctx, adv)]
        records.extend(mal_records[: seeds.ghsa.max_malware_per_ecosystem])

    hf = seeds.huggingface
    verified = HfVerifiedCache(ctx)
    jobs: list[tuple[str, str]] = []
    for kind, authors, tag in (
        ("model", hf.model_authors, None),
        ("dataset", hf.dataset_authors, None),
        ("model", hf.lora_authors, "peft"),
    ):
        for author in authors:
            ids = _safe(
                ctx,
                "huggingface",
                f"{kind}s/{author}",
                lambda k=kind, a=author, t=tag: huggingface.list_repos(
                    ctx.client, k, author=a, filter_tag=t, limit=hf.per_author_limit
                ),
            )
            jobs.extend((kind, i) for i in ids or [])
    if hf.global_lora_limit:
        ids = _safe(
            ctx,
            "huggingface",
            "models?filter=peft",
            lambda: huggingface.list_repos(
                ctx.client, "model", filter_tag="peft", limit=hf.global_lora_limit
            ),
        )
        jobs.extend(("model", i) for i in ids or [])
    for kind, repo_id in dict.fromkeys(jobs):
        rec = _safe(ctx, "huggingface", repo_id, label_hf, ctx, kind, repo_id, verified)
        if rec is not None:
            records.append(rec)
    return records
