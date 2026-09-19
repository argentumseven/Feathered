"""RPM repository loading and evidence-mirror orchestration.

The loader owns metadata acquisition semantics but receives transport,
verification, and evidence operations as explicit services.  That keeps this
module independent from the legacy ``core`` façade while preserving its
runtime-injection seams.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set, Tuple

import rpm_metadata
from core_models import ArtifactVerification, Package, RepoDataRef, RepoTrust
from evidence_model import REL_REBUILD_PEER
from execution_reporter import Reporter
from package_contracts import PackageArtifact
from repository_config import RepoSpec


@dataclass(frozen=True)
class RepositoryLoaderServices:
    url_join: Callable[..., str]
    fetch_bytes: Callable[..., bytes]
    verification_strategy: Callable[[RepoSpec], str]
    verify_openpgp: Callable[..., None]
    repo_trust: Callable[[RepoSpec], RepoTrust]
    repo_relative_url: Callable[..., str]
    hash_bytes: Callable[[bytes, str], str]
    decompress_metadata: Callable[..., bytes]
    parse_primary: Callable[[bytes, RepoSpec, Set[str], Reporter], List[Package]]
    package_has_selected_digest: Callable[[PackageArtifact], bool]
    artifact_verification: Callable[[PackageArtifact], ArtifactVerification]
    mirrors_are_distinct: Callable[[str, str], Tuple[bool, str]]
    redact_url: Callable[[str], str]
    evidence_repo_for_url: Callable[[RepoSpec, str], RepoSpec]
    evidence_relationship: Callable[[RepoSpec, str], str]
    evidence_authority_relationship: Callable[[RepoSpec, str], str]
    apply_mirror_evidence: Callable[..., Dict[str, int]]


def repo_trust(repo: RepoSpec) -> RepoTrust:
    """Return the verification record for a repository, creating it on first use."""
    record = getattr(repo, "trust", None)
    if record is None or record.repo != repo.name:
        record = RepoTrust(repo=repo.name)
        setattr(repo, "trust", record)
    return record


def get_repo_data(
    repo: RepoSpec,
    reporter: Reporter,
    services: RepositoryLoaderServices,
    retries: int = 3,
) -> Dict[str, RepoDataRef]:
    return rpm_metadata.get_repo_data(
        repo,
        reporter,
        retries=retries,
        url_join_fn=services.url_join,
        fetch_bytes_fn=services.fetch_bytes,
        verification_strategy_fn=services.verification_strategy,
        verify_openpgp_fn=services.verify_openpgp,
        repo_trust_fn=services.repo_trust,
        repo_relative_url_fn=services.repo_relative_url,
    )


def diagnose_missing_repository(
    repo_url: str,
    reporter: Reporter,
    services: RepositoryLoaderServices,
    retries: int = 1,
) -> str:
    """Explain why a repository root has no metadata by examining its listing."""
    root = repo_url.rstrip("/") + "/"
    try:
        raw = services.fetch_bytes(root, reporter, retries=retries).decode(
            "utf-8", "replace"
        )
    except Exception as exc:
        return (
            f"The directory itself could not be listed either ({exc}). The path is most "
            "likely wrong, or the mirror does not serve this release."
        )

    hrefs = re.findall(r'href=[\'\"]([^\'\"]+)[\'\"]', raw, re.IGNORECASE)
    entries = []
    for href in hrefs:
        name = href.strip("/").split("/")[-1]
        if not name or name.startswith(("?", "#")) or name in {"..", "."}:
            continue
        if name not in entries:
            entries.append(name)

    if not entries:
        return (
            "The directory exists but appears to be empty. This usually means the release "
            "has not been published to this mirror."
        )

    substantive = [
        entry
        for entry in entries
        if not entry.lower().startswith(("readme", "index", "changelog"))
    ]
    if not substantive:
        return (
            f"The directory exists but contains only {', '.join(entries)} - no repository "
            "content. This release is almost certainly not published yet, or has been "
            "retired and moved to a vault mirror. Try the major-version stream directory "
            "instead of the exact point release."
        )

    likely = [
        entry
        for entry in substantive
        if any(
            keyword in entry.lower()
            for keyword in (
                "baseos",
                "appstream",
                "os",
                "release",
                "updates",
                "extras",
                "crb",
                "powertools",
                "main",
                "everything",
            )
        )
    ]
    listing = ", ".join(substantive[:12]) + (" …" if len(substantive) > 12 else "")
    if likely:
        return (
            f"No repodata/ here, but the directory contains: {listing}. The repository root is "
            f"probably one level down - try appending one of: {', '.join(likely[:5])}."
        )
    return (
        f"No repodata/ here. The directory contains: {listing}. Check that this is the "
        "repository root (the folder that directly contains repodata/)."
    )


def load_repository_once(
    repo: RepoSpec,
    arches: Set[str],
    reporter: Reporter,
    services: RepositoryLoaderServices,
    retries: int = 3,
) -> List[Package]:
    reporter.log(f"Loading repository: {repo.name}")
    refs = get_repo_data(repo, reporter, services, retries=retries)
    primary = refs.get("primary")
    if primary is None:
        raise RuntimeError(f"{repo.name}: repomd.xml contains no primary metadata")
    reporter.log(f"{repo.name}: primary -> {primary.url}")
    compressed = services.fetch_bytes(
        primary.url,
        reporter,
        retries=retries,
        repo=repo,
    )
    skip_provenance = services.verification_strategy(repo) == "skip-provenance"
    if skip_provenance:
        reporter.warn(
            f"{repo.name}: primary metadata checksum verification skipped by operator policy."
        )
    elif primary.checksum:
        actual = services.hash_bytes(compressed, primary.checksum_type)
        if actual.lower() != primary.checksum.lower():
            raise RuntimeError(f"{repo.name}: primary metadata checksum mismatch")
        services.repo_trust(repo).metadata_digest_verified = True
    elif repo.allow_unverified_index:
        reporter.warn(
            f"{repo.name}: repomd.xml publishes no digest for primary metadata; "
            "accepted because 'allow unverified indexes' is enabled for this repository."
        )
    else:
        raise RuntimeError(
            f"{repo.name}: repomd.xml publishes no checksum for the primary metadata, so the "
            "package digests cannot be trusted. Use a complete mirror, or enable 'Allow unverified "
            "indexes' for this repository in Advanced… if you accept that risk."
        )
    xml = services.decompress_metadata(compressed, primary.url)
    if primary.open_checksum and not skip_provenance:
        actual_open = services.hash_bytes(xml, primary.open_checksum_type)
        if actual_open.lower() != primary.open_checksum.lower():
            raise RuntimeError(f"{repo.name}: decompressed metadata checksum mismatch")

    from module_policy import load_supplemental

    load_supplemental(repo, refs, reporter, retries)
    return services.parse_primary(xml, repo, arches, reporter)


def load_repository(
    repo: RepoSpec,
    arches: Set[str],
    reporter: Reporter,
    services: RepositoryLoaderServices,
    retries: int = 3,
    *,
    load_once_fn=None,
) -> List[Package]:
    """Load RPM acquisition metadata and optional independent evidence metadata."""
    if load_once_fn is None:
        load_once_fn = lambda source, family_arches, out, attempts=3: load_repository_once(
            source, family_arches, out, services, retries=attempts)
    packages = load_once_fn(repo, arches, reporter, retries)
    strategy = services.verification_strategy(repo)
    if strategy in {"checksum-required", "checksum-available", "skip-provenance"}:
        return packages
    if strategy in {"evidence-fallback", "legacy-fallback"} and all(
        services.package_has_selected_digest(pkg) for pkg in packages
    ):
        for pkg in packages:
            services.artifact_verification(pkg).evidence_status = "not-needed"
        reporter.log(
            f"{repo.name}: configured checksum strength is available from acquisition metadata; "
            "evidence fallback not needed"
        )
        return packages
    if not repo.evidence_urls:
        if strategy in {
            "evidence-fallback",
            "full-corroboration",
            "legacy-evidence-required",
            "legacy-fallback",
            "legacy-corroborate",
        }:
            for pkg in packages:
                services.artifact_verification(pkg).evidence_status = "unavailable"
        return packages

    usable = False
    last_error = ""
    for evidence_url in repo.evidence_urls:
        distinct, reason = services.mirrors_are_distinct(repo.normalized_url, evidence_url)
        if not distinct:
            reporter.warn(
                f"{repo.name}: evidence source {services.redact_url(evidence_url)} ignored "
                f"({reason}); a source bond requires a distinct mirror hostname"
            )
            last_error = reason
            continue
        evidence_repo = services.evidence_repo_for_url(repo, evidence_url)
        relationship = services.evidence_relationship(repo, evidence_url)
        try:
            evidence_packages = load_once_fn(evidence_repo, arches, reporter, 1)
            stats = services.apply_mirror_evidence(
                packages,
                evidence_packages,
                evidence_repo,
                reporter,
                relationship=relationship,
                authority=services.evidence_authority_relationship(repo, evidence_url),
            )
            kind = (
                "independent rebuild peer"
                if relationship == REL_REBUILD_PEER
                else "evidence mirror"
            )
            reporter.log(
                f"Source bond {repo.name}: {kind} {services.redact_url(evidence_url)} matched "
                f"{stats['matched']:,} package identities ({stats['digest']:,} with strong digest, "
                f"{stats['metadata']:,} metadata-only; {stats['missing']:,} not yet present; "
                f"{stats.get('conflict', 0):,} metadata conflict(s) deferred to selected-artifact verification)"
            )
            usable = True
            break
        except RuntimeError as exc:
            if (
                ("Mirror bond" in str(exc) or "Peer evidence" in str(exc))
                and "disagreement" in str(exc)
            ):
                raise
            last_error = str(exc)
            reporter.warn(
                f"{repo.name}: evidence mirror {services.redact_url(evidence_url)} "
                f"unavailable/inconclusive: {exc}"
            )

    if not usable:
        for pkg in packages:
            record = services.artifact_verification(pkg)
            if record.evidence_status in {"not-configured", "unavailable"}:
                record.evidence_status = "artifact-pending"
            if not record.evidence_source and repo.evidence_urls:
                record.evidence_source = services.redact_url(repo.evidence_urls[0])
        if repo.evidence_urls:
            reporter.warn(
                f"{repo.name}: evidence endpoint is not a recognizable RPM repository"
                + (f" ({last_error})" if last_error else "")
                + "; Feathered will try the exact package artifact during verification"
            )
    return packages


def probe_repository(
    repo: RepoSpec,
    reporter: Optional[Reporter],
    services: RepositoryLoaderServices,
    retries: int = 2,
) -> Tuple[bool, str]:
    rep = reporter or Reporter()
    if not repo.url.strip():
        return False, "No URL/path configured"
    try:
        refs = get_repo_data(repo, rep, services, retries=retries)
        primary = refs.get("primary")
        if primary is None:
            return False, "No primary metadata"
        return True, primary.url
    except Exception as exc:
        detail = str(exc)
        if "404" in detail or "Not Found" in detail:
            detail += "\n\n" + diagnose_missing_repository(repo.url, rep, services)
        return False, detail
