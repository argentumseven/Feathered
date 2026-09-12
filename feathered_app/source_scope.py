"""Checked repository-selection rules with explicit, lazy host capabilities.

These functions select existing repository objects. They perform no metadata
I/O and do not mutate source rows. Mirror selection deliberately remains
independent of the transaction enabled flag and dependency-provider filtering.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Collection, Generic, Sequence, TypeVar

from acquisition_model import AcquisitionCapability

RepositoryT = TypeVar("RepositoryT")


@dataclass(frozen=True)
class TargetScope:
    package_family: str
    profile_key: str
    release: str
    arch: str


@dataclass(frozen=True)
class RepositoryTarget:
    repo_format: str = ""
    profile_key: str = ""
    release: str = ""
    arch: str = ""


def target_compatible(target: TargetScope | None, source: RepositoryTarget) -> bool:
    """An absent target preserves the legacy partially constructed-host case."""
    if target is None:
        return True
    expected = "apt" if target.package_family == "deb" else "pacman" if target.package_family == "arch" else "rpm"
    if (source.repo_format or expected) != expected:
        return False
    if source.profile_key and source.profile_key != target.profile_key:
        return False
    if source.release and target.release and source.release != target.release:
        return False
    if source.arch and target.arch and source.arch != target.arch:
        return False
    return True


@dataclass(frozen=True)
class ParticipationContext(Generic[RepositoryT]):
    """Host methods are invoked only on the branches that consume them."""

    enabled: Callable[[RepositoryT], bool]
    url: Callable[[RepositoryT], str]
    compatible: Callable[[RepositoryT], bool]
    mirror_mode: Callable[[], bool]
    mirror_selected: Callable[[RepositoryT], bool]
    tier: Callable[[RepositoryT], str]
    profile_managed: Callable[[RepositoryT], bool]
    identity: Callable[[RepositoryT], str | None]
    role: Callable[[RepositoryT], str]
    exact_mode: Callable[[], bool]
    exact_source_ids: Callable[[], Collection[str | None]]
    required_roles: Callable[[], Collection[str]]


def participates(repo: RepositoryT, context: ParticipationContext[RepositoryT]) -> bool:
    if not context.enabled(repo) or not context.url(repo).strip():
        return False
    if not context.compatible(repo):
        return False
    if context.mirror_mode():
        return context.mirror_selected(repo)
    if context.tier(repo) != "workload" or not context.profile_managed(repo):
        return True
    if context.exact_mode():
        selected_ids = context.exact_source_ids()
        return context.identity(repo) in selected_ids
    return context.role(repo) in context.required_roles()


@dataclass(frozen=True)
class BuildScopeContext(Generic[RepositoryT]):
    """Capabilities needed to select the final acquisition repository set."""

    participating: Callable[[], Sequence[RepositoryT]]
    root_coverage: Callable[[], Sequence[RepositoryT]]
    capability: Callable[[], AcquisitionCapability]
    repositories: Callable[[], Sequence[RepositoryT]]
    mirror_selected: Callable[[RepositoryT], bool]
    url: Callable[[RepositoryT], str]
    name: Callable[[RepositoryT], str]
    init_conflict: Callable[[RepositoryT], str | None]
    log: Callable[[str], None]


def select_build_scope(context: BuildScopeContext[RepositoryT], *,
                       package_only: bool = False) -> list[RepositoryT]:
    def init_safe(repositories: Sequence[RepositoryT]) -> list[RepositoryT]:
        out: list[RepositoryT] = []
        for repo in repositories:
            reason = context.init_conflict(repo)
            if reason:
                context.log(f"Excluded from this init-locked target: {context.name(repo)} - {reason}")
                continue
            out.append(repo)
        return out

    # Retain the evaluation order and diagnostics of the existing GUI/API
    # path, including its initial participating-source check for mirror mode.
    enabled = init_safe(context.participating())
    if package_only:
        return init_safe(context.root_coverage())
    capability = context.capability()
    if capability is AcquisitionCapability.REPOSITORY_MIRROR:
        return [repo for repo in context.repositories()
                if context.url(repo).strip() and context.mirror_selected(repo)]
    if capability is AcquisitionCapability.PACKAGE_ONLY:
        return init_safe(context.root_coverage())
    return enabled
