from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Sequence, Tuple

from source_model import SourcePlan


TierGetter = Callable[[object], str]


def _default_tier(repo: object) -> str:
    return str(getattr(repo, "source_tier", "additional") or "additional")


def _usable(repo: object) -> bool:
    return bool(getattr(repo, "enabled", False) and str(getattr(repo, "url", "") or "").strip())


@dataclass(frozen=True)
class SourceReadiness:
    """Pure evaluation of which repository scopes can satisfy a SourcePlan.

    This deliberately contains no Tkinter state and performs no network I/O.
    It answers only the source-topology question used by coverage, probing,
    review and build gating. Reachability is evaluated by calling the same
    function with the repositories that actually responded.
    """

    plan: SourcePlan
    enabled_repositories: Tuple[object, ...]
    distribution_repositories: Tuple[object, ...]
    workload_repositories_by_role: Dict[str, Tuple[object, ...]]
    missing_scopes: Tuple[str, ...]
    package_only: bool
    dependency_provider_repositories: Tuple[object, ...] = ()

    @property
    def capability(self) -> str:
        if self.missing_scopes:
            return "blocked"
        if self.package_only:
            return "package-only"
        return "full-analysis"

    @property
    def root_repositories(self) -> Tuple[object, ...]:
        if any(root.source_kind == "enabled" for root in self.plan.roots):
            return self.enabled_repositories
        chosen: List[object] = []
        if self.plan.distribution_required:
            chosen.extend(self.distribution_repositories)
        for role in self.plan.required_roles:
            chosen.extend(self.workload_repositories_by_role.get(role, ()))
        # Preserve repository ordering while de-duplicating by object identity.
        out: List[object] = []
        seen = set()
        for repo in chosen:
            marker = id(repo)
            if marker not in seen:
                seen.add(marker)
                out.append(repo)
        return tuple(out)


def evaluate_source_readiness(
    plan: SourcePlan,
    repositories: Iterable[object],
    *,
    tier_getter: TierGetter = _default_tier,
    allow_package_only: bool = True,
) -> SourceReadiness:
    """Evaluate source topology for a plan without performing repository I/O.

    ``package-only`` is derived only when every requested root is constrained
    to workload-specific repositories and no other enabled repository remains
    to act as a dependency provider. Root-source roles constrain where requested
    packages come from; every other enabled compatible source may participate in
    dependency resolution.
    """

    enabled = tuple(repo for repo in repositories if _usable(repo))
    distribution = tuple(repo for repo in enabled if tier_getter(repo) == "base")
    by_role: Dict[str, Tuple[object, ...]] = {}
    for role in plan.required_roles:
        by_role[role] = tuple(repo for repo in enabled if getattr(repo, "role", None) == role)

    missing: List[str] = []
    if any(root.source_kind == "enabled" for root in plan.roots) and not enabled:
        missing.append("enabled")
    if plan.distribution_required and not distribution:
        missing.append("distribution")
    for role in plan.required_roles:
        if not by_role.get(role):
            missing.append(f"role:{role}")

    root_workload_ids = {
        id(repo)
        for role in plan.required_roles
        for repo in by_role.get(role, ())
    }
    dependency_providers = tuple(
        repo for repo in enabled if id(repo) not in root_workload_ids)

    package_only = bool(
        allow_package_only
        and plan.roots
        and all(root.source_kind == "workload" for root in plan.roots)
        and plan.required_roles
        and not missing
        and not dependency_providers
    )

    return SourceReadiness(
        plan=plan,
        enabled_repositories=enabled,
        distribution_repositories=distribution,
        workload_repositories_by_role=by_role,
        missing_scopes=tuple(missing),
        package_only=package_only,
        dependency_provider_repositories=dependency_providers,
    )


def repository_purpose(
    plan: SourcePlan,
    repo: object,
    *,
    tier_getter: TierGetter = _default_tier,
) -> str:
    """Describe a repository's root-source purpose under a SourcePlan."""
    purposes: List[str] = []
    if plan.distribution_required and tier_getter(repo) == "base":
        purposes.append("distribution roots")
    if getattr(repo, "role", None) in set(plan.required_roles):
        purposes.append("workload roots")
    return " + ".join(purposes) if purposes else "dependency/supplement"


def missing_reachable_scopes(
    plan: SourcePlan,
    successful_repositories: Sequence[object],
    *,
    tier_getter: TierGetter = _default_tier,
) -> Tuple[str, ...]:
    """Return required root scopes absent from the successfully loaded set."""
    readiness = evaluate_source_readiness(
        plan,
        successful_repositories,
        tier_getter=tier_getter,
        allow_package_only=False,
    )
    return readiness.missing_scopes
