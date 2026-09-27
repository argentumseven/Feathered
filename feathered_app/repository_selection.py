"""Headless repository-selection policy for workload and mirror workflows.

The GUI owns widgets, notifications and cache invalidation; this module owns
which configured sources remain active, when a missing workload role acquires a
source, and which mirror candidates retain an operator's explicit selection.
No service holds or reaches back into ``App``. All state inputs are explicit so
both headless hosts and the desktop shell can use the same rules.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Collection, Iterable, MutableSequence, Sequence

from repository_config import RepoSpec


class WorkloadRepositoryService:
    """Mutate only the repository objects supplied by the caller.

    Profile-managed workload sources have a separate lifecycle from manually
    configured sources. The two materialization operations deliberately differ:
    automatic activation needs a usable URL, while an operator pressing Add may
    choose to re-enable an existing (not-yet-configured) source for editing.
    """

    @staticmethod
    def enabled_for_role(repositories: Iterable[RepoSpec], role: str) -> RepoSpec | None:
        if not role:
            return None
        candidates = [repo for repo in repositories
                      if repo.enabled and repo.url.strip() and repo.role == role]
        return min(candidates, key=lambda repo: (repo.priority, repo.name, repo.url),
                   default=None)

    @staticmethod
    def synchronize(repositories: Iterable[RepoSpec], *,
                    required_roles: Collection[str],
                    tier_of: Callable[[RepoSpec], str],
                    exact_source_ids: Collection[str] | None = None) -> tuple[str, ...]:
        """Align profile-managed sources; never disable operator-owned rows.

        In exact-package mode, selecting an actual package source turns that
        concrete source on. All other profile-managed workload candidates are
        disabled even when a previous workload had activated them.

        Returns names of previously enabled sources disabled in workload mode,
        preserving the original GUI's diagnostics without depending on logging.
        """
        disabled: list[str] = []
        if exact_source_ids is None:
            required = set(required_roles)
            for repo in repositories:
                if (tier_of(repo) == "workload"
                        and getattr(repo, "workload_profile_managed", False)
                        and repo.role not in required and repo.enabled):
                    repo.enabled = False
                    disabled.append(repo.name)
        else:
            selected = set(exact_source_ids)
            for repo in repositories:
                if (tier_of(repo) == "workload"
                        and getattr(repo, "workload_profile_managed", False)):
                    repo.enabled = repo.source_identity in selected
                elif repo.source_identity in selected:
                    repo.enabled = True
        return tuple(disabled)

    def materialize_required(self, repositories: MutableSequence[RepoSpec],
                             roles: Iterable[str], *,
                             templates_for_role: Callable[[list[str]], Iterable[Any]],
                             make_repository: Callable[[Any, str], RepoSpec],
                             recommended: bool = False) -> tuple[str, ...]:
        """Select one source per role without replacing an operator's edits.

        ``recommended=False`` runs automatically when a workload is selected:
        a configured source without a URL is not sufficient. ``True`` supports
        the explicit Add/Enable action and preserves the legacy ability to
        re-enable an incomplete, manually configured source.
        """
        changed: list[str] = []
        for role in roles:
            if not recommended and self.enabled_for_role(repositories, role) is not None:
                continue
            configured = [repo for repo in repositories if repo.role == role
                          and (recommended or repo.url.strip())]
            if configured:
                best = min(configured, key=lambda repo: (
                    repo.priority, repo.name, "" if recommended else repo.url))
                if not best.enabled:
                    best.enabled = True
                    changed.append(f"enabled {best.name}")
                continue
            templates = tuple(templates_for_role([role]))
            if not templates:
                continue
            template = min(templates, key=lambda repo: (not repo.enabled, repo.priority, repo.name))
            repo = make_repository(template, "workload")
            repo.enabled = True
            repo.workload_profile_managed = True
            repositories.append(repo)
            changed.append(f"{'added' if recommended else 'selected'} {repo.name}")
        return tuple(changed)


@dataclass(frozen=True)
class MirrorCandidate:
    """A source addressable by a stable identity and a distinct visible row."""
    index: int
    repository: RepoSpec
    tier: str
    source_id: str


@dataclass(frozen=True)
class MirrorSelectionSnapshot:
    """Complete selection state for one repository-list refresh."""
    candidates: tuple[MirrorCandidate, ...]
    unconfigured: int
    selected: frozenset[str]
    seen: frozenset[str]


class MirrorSelectionService:
    """Reconcile mirror candidates and explicit selections without widgets."""

    @staticmethod
    def reconcile(repositories: Sequence[RepoSpec], *,
                  previous_selected: Collection[str],
                  previous_seen: Collection[str],
                  tier_of: Callable[[RepoSpec], str]) -> MirrorSelectionSnapshot:
        candidates: list[MirrorCandidate] = []
        unconfigured = 0
        current: set[str] = set()
        defaults: set[str] = set()
        previous = set(previous_seen)
        for index, repo in enumerate(repositories):
            tier = tier_of(repo)
            # A workload-generated side channel is not a mirror candidate.
            # A manually configured workload repository remains eligible.
            if tier == "workload" and getattr(repo, "workload_profile_managed", False):
                continue
            if not repo.url.strip():
                unconfigured += 1
                continue
            source_id = repo.source_identity
            candidates.append(MirrorCandidate(index, repo, tier, source_id))
            current.add(source_id)
            if source_id not in previous and repo.enabled:
                defaults.add(source_id)
        return MirrorSelectionSnapshot(
            tuple(candidates), unconfigured,
            frozenset((set(previous_selected) & current) | defaults),
            frozenset(current),
        )

    @staticmethod
    def toggle(selected: set[str], source_id: str) -> None:
        if source_id in selected:
            selected.remove(source_id)
        else:
            selected.add(source_id)

    @staticmethod
    def bulk(selected: Collection[str], visible: Collection[str], action: str) -> set[str]:
        sources = set(visible)
        if action == "all":
            return sources
        if action == "none":
            return set()
        # Historical UI treats every other bulk action as invert.
        return sources - set(selected)
