"""Headless Review-page projections from explicit, immutable application snapshots.

This service formats the *requested* build contract and preflight summary. It
neither reads GUI widgets nor performs dependency resolution or verification;
the GUI adapter captures current inputs and owns all rendering.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from acquisition_model import AcquisitionCapability, AcquisitionIntent


ReviewRow = tuple[str, str, str, str]


@dataclass(frozen=True)
class ReviewMirrorSource:
    name: str
    safe_url: str  # The GUI must redact credentials before constructing this.


@dataclass(frozen=True)
class ReviewRequestedPackage:
    identity: str
    repository_name: str


@dataclass(frozen=True)
class ReviewWorkload:
    label: str
    custom: bool = False
    contextual_packages: bool = False


@dataclass(frozen=True)
class ReviewRepository:
    tier: str
    has_url: bool
    has_archive_key: bool
    verification_strategy: str
    verification_label: str
    has_evidence: bool
    vendor_id: str = ""
    mirror_selected: bool = False


@dataclass(frozen=True)
class ReviewSummaryInput:
    intent: AcquisitionIntent
    capability: AcquisitionCapability
    reason: str
    distribution: str
    release: str
    architecture: str
    repositories: tuple[ReviewRepository, ...]
    selected_package_count: int
    workload_label: str
    package_version: str
    vendor_signature_profiles: Mapping[str, Mapping[str, str]]
    signing_key_configured: bool
    baseline_configured: bool
    mode: str
    requires_distribution_sources: bool
    output_path: str
    mirror_output_paths: tuple[str, ...] = ()
    platform_note: str = ""


@dataclass(frozen=True)
class ReviewSummary:
    labels: Mapping[str, str]
    source_warning: bool
    output_warning: bool


class ReviewProjectionService:
    """Derive Review content without depending on the composed application."""

    @staticmethod
    def requested_roots(
        *, intent: AcquisitionIntent,
        mirrors: Sequence[ReviewMirrorSource] = (),
        exact_packages: Sequence[ReviewRequestedPackage] = (),
        requests: Sequence[Sequence[object]] = (),
        workload: ReviewWorkload | None = None,
    ) -> list[ReviewRow]:
        if intent is AcquisitionIntent.REPOSITORY_MIRROR:
            return [(source.name, "selected", source.safe_url,
                     "repository selected for mirroring") for source in mirrors]
        if intent is AcquisitionIntent.PACKAGES:
            return [(pkg.identity, "requested", pkg.repository_name,
                     "explicit package selection") for pkg in exact_packages]
        if workload is None:
            return []
        reason = ("VKS node OS package addition" if workload.contextual_packages else
                  "custom package request" if workload.custom else
                  f"requested by {workload.label}")
        rows: list[ReviewRow] = []
        for request in requests:
            name = str(request[0])
            version = request[1] if len(request) > 1 else None
            package = f"{name} {version}" if version else name
            rows.append((package, "requested", "enabled repositories", reason))
        return rows

    @staticmethod
    def summary(data: ReviewSummaryInput) -> ReviewSummary:
        repositories = data.repositories
        base = [repo for repo in repositories if repo.has_url and repo.tier == "base"]
        signed = sum(repo.has_archive_key for repo in repositories)
        if data.intent is AcquisitionIntent.REPOSITORY_MIRROR:
            chosen = sum(repo.mirror_selected for repo in repositories)
            selection = f"Mirror {chosen} repository/repositories"
        elif data.intent is AcquisitionIntent.PACKAGES:
            selection = (f"{data.selected_package_count} exact package(s)"
                         if data.selected_package_count else "no packages chosen")
        else:
            selection = f"{data.workload_label} · {data.package_version}"

        verification = f"{signed}/{len(repositories)} sources with archive keys"
        strategies = {repo.verification_strategy for repo in repositories}
        if len(strategies) == 1:
            # Labels are captured by the GUI at the same time as strategies.
            strategy = next(iter(strategies))
            label = next(repo.verification_label for repo in repositories
                         if repo.verification_strategy == strategy)
            verification += f" | {label}"
        else:
            verification += " | mixed verification strategies"
        evidence = sum(repo.has_evidence for repo in repositories)
        if evidence:
            verification += f" | {evidence} evidence source(s) configured"
        vendor_ids = {repo.vendor_id for repo in repositories if repo.vendor_id}
        configured = sum(bool(str(data.vendor_signature_profiles.get(v, {}).get("keyring", "")).strip())
                         for v in vendor_ids)
        required = sum(data.vendor_signature_profiles.get(v, {}).get("policy") == "require"
                       for v in vendor_ids)
        if configured:
            verification += f" | {configured} vendor keyring profile(s)"
        if required:
            verification += f" | signatures required for {required} vendor(s)"
        if data.signing_key_configured:
            verification += " · bundle signed"

        if data.capability is AcquisitionCapability.PACKAGE_ONLY:
            transfer = "Package-only artifacts; dependency completeness not derived"
            sources_text = (f"{len(repositories)} root source(s) participating · " +
                            (data.reason or "dependency closure not requested"))
            selection_text = f"{selection} · package-only acquisition"
        elif data.capability is AcquisitionCapability.REPOSITORY_MIRROR:
            transfer = "Repository mirror; package-root dependency closure does not apply"
            sources_text = f"{len(repositories)} repository/repositories selected for mirroring"
            selection_text = selection
        elif data.capability is AcquisitionCapability.BLOCKED:
            transfer = "Blocked until the acquisition/source requirements are satisfied"
            sources_text = data.reason or "Source requirements incomplete"
            selection_text = selection
        else:
            transfer = "Differential against a baseline" if data.baseline_configured else "Full transaction bundle"
            sources_text = (f"{len(repositories)} enabled, {len(base)} distribution/base source(s)" +
                            ("  |  add a base source" if not base and data.requires_distribution_sources else ""))
            selection_text = f"{selection} · {data.mode}"

        bundle_path = ("\n".join(data.mirror_output_paths) if data.mirror_output_paths else "-") \
            if data.capability is AcquisitionCapability.REPOSITORY_MIRROR else (data.output_path or "-")
        platform_note = f"\nPlatform note: {data.platform_note}" if data.platform_note else ""
        labels = {
            "Linux Distribution": f"{data.distribution} {data.release} ({data.architecture})" + platform_note,
            "Sources": sources_text,
            "Selection": selection_text,
            "Verification": verification,
            "Bundle path": bundle_path,
            "Output": transfer,
        }
        return ReviewSummary(
            labels=labels,
            source_warning=(data.capability is AcquisitionCapability.PACKAGE_ONLY or
                            not base and data.requires_distribution_sources),
            output_warning=(data.capability is AcquisitionCapability.PACKAGE_ONLY or data.baseline_configured),
        )
