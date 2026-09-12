"""Checked metadata orchestration and cache access, independent of Tk/backends.

The host owns cache lifetime and metadata signatures. Scoped coverage loads
never consume or publish the shared cache. Backend parsing and source-plan
validation remain supplied capabilities, with their existing error semantics.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Generic, Protocol, Sequence, TypeVar


class MetadataSource(Protocol):
    @property
    def name(self) -> str: ...
    @property
    def url(self) -> str: ...
    @property
    def enabled(self) -> bool: ...
    @property
    def optional(self) -> bool: ...
    @property
    def priority(self) -> int: ...
    @property
    def source_identity(self) -> str: ...


class MetadataReporter(Protocol):
    def log(self, message: str, /) -> None: ...
    def warn(self, message: str, /) -> None: ...
    def progress(self, label: str, value: float, /) -> None: ...
    def check_cancel(self) -> None: ...


RepositoryT = TypeVar("RepositoryT", bound=MetadataSource)
PackageT = TypeVar("PackageT")


class MetadataCacheHost(Protocol[PackageT]):
    loaded_signature: object
    loaded_packages: list[PackageT]


def lookup_metadata_cache(host: MetadataCacheHost[PackageT], signature: object) -> list[PackageT] | None:
    """Keep list identity and the historical retry of an empty successful load."""
    if signature == host.loaded_signature and host.loaded_packages:
        return host.loaded_packages
    return None


def store_metadata_cache(host: MetadataCacheHost[PackageT], signature: object,
                         packages: list[PackageT]) -> None:
    host.loaded_signature = signature
    host.loaded_packages = packages


@dataclass(frozen=True)
class MetadataLoadContext(Generic[RepositoryT, PackageT]):
    """Lazy capabilities retain partial-host and scoped-load compatibility.

    signature_tier reads the stored source tier used by the existing cache key;
    source_tier classifies the source for the distribution fallback policy.
    These are intentionally distinct operations on the host.
    """

    build_scope: Callable[[], Sequence[RepositoryT]]
    signature: Callable[[], object]
    signature_tier: Callable[[RepositoryT], str]
    selected_arch: Callable[[], str]
    mirror_mode: Callable[[], bool]
    load_repository: Callable[[RepositoryT, set[str], MetadataReporter], Sequence[PackageT]]
    validate_successful: Callable[[Sequence[RepositoryT], Sequence[RepositoryT]], None]
    active_source_method: Callable[[], str]
    source_tier: Callable[[RepositoryT], str]
    lookup_cache: Callable[[object], list[PackageT] | None]
    store_cache: Callable[[object, list[PackageT]], None]
    cancelled_error: type[Exception]


def load_metadata(context: MetadataLoadContext[RepositoryT, PackageT],
                  reporter: MetadataReporter,
                  repositories: Sequence[RepositoryT] | None = None,
                  enforce_distribution_plan: bool = True) -> list[PackageT]:
    scoped = repositories is not None
    source_rows = list(repositories) if repositories is not None else context.build_scope()
    signature = (context.signature(), tuple(
        (r.source_identity, r.priority, context.signature_tier(r)) for r in source_rows))
    if not scoped:
        cached = context.lookup_cache(signature)
        if cached is not None:
            reporter.log("Using cached repository metadata.")
            return cached
    if scoped and context.mirror_mode():
        enabled = [r for r in source_rows if r.url.strip()]
    else:
        enabled = [r for r in source_rows if r.enabled and r.url.strip()]
    if not enabled:
        raise RuntimeError("No enabled repositories are configured")
    arches = {context.selected_arch(), "noarch"}
    all_packages: list[PackageT] = []
    successful: list[RepositoryT] = []
    for i, repo in enumerate(enabled, 1):
        reporter.progress(f"Metadata {i}/{len(enabled)}: {repo.name}",
                          0.05 + (i - 1) / max(1, len(enabled)) * 0.42)
        reporter.check_cancel()
        try:
            packages = context.load_repository(repo, arches, reporter)
            all_packages.extend(packages)
            successful.append(repo)
        except context.cancelled_error:
            raise
        except Exception as exc:
            reporter.check_cancel()
            if repo.optional:
                reporter.log(f"Optional source failed; continuing with remaining providers: {repo.name}: {exc}")
            else:
                reporter.warn(f"Enabled source could not be read and will not participate unless another source in its required scope is unavailable: {repo.name}: {exc}")
    context.validate_successful(successful, enabled)
    if enforce_distribution_plan and context.active_source_method() in {
            "Public EL-compatible mirrors (recommended fallback)",
            "Public EL-compatible + EPEL (broad fallback)"}:
        base_success = [r for r in successful if context.source_tier(r) == "base"]
        if not base_success:
            raise RuntimeError("All EL-compatible fallback repositories failed. Configure RHEL media/CDN or a custom mirror.")
        reporter.log("Fallback sources available: " + ", ".join(r.name for r in base_success))
    if not scoped:
        context.store_cache(signature, all_packages)
    reporter.log(f"Loaded {len(all_packages):,} package records from {len(successful)} repositories")
    return all_packages
