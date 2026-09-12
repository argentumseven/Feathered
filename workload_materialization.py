from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

from source_model import RootSourcePolicy, SourcePlan
from transaction_model import architecture_eligible


@dataclass(frozen=True)
class MaterializedRoot:
    """One semantic workload component bound to a concrete package name.

    ``candidates`` is the ordered, explicitly approved identity set from the
    workload catalog.  Feathered never chooses a package outside this set.
    """
    component: str
    primary_package: str
    package: str
    candidates: Tuple[str, ...]
    source_kind: str
    role: Optional[str] = None
    optional: bool = False


@dataclass(frozen=True)
class MaterializedWorkload:
    workload_key: str
    catalog_revision: int
    catalog_sha256: str
    package_family: str
    catalog_signature_verified: bool = False
    roots: Tuple[MaterializedRoot, ...] = field(default_factory=tuple)
    unresolved: Tuple[RootSourcePolicy, ...] = field(default_factory=tuple)

    @property
    def complete(self) -> bool:
        return not any(not root.optional for root in self.unresolved)

    @property
    def selected_packages(self) -> Tuple[str, ...]:
        return tuple(root.package for root in self.roots)


def _arch_eligible(pkg, preferred_arch: str, family: str = "rpm") -> bool:
    arch = str(getattr(pkg, "arch", "") or "")
    return architecture_eligible(arch, preferred_arch, family)


def _source_eligible(pkg, policy: RootSourcePolicy,
                     tier_getter: Optional[Callable[[object], str]]) -> bool:
    repo = getattr(pkg, "repo", None)
    if repo is None:
        return False
    if policy.source_kind == "workload":
        return bool(policy.role) and str(getattr(repo, "role", "") or "") == policy.role
    if policy.source_kind == "distribution":
        return tier_getter is not None and tier_getter(repo) == "base"
    return True


def materialize_source_plan(
        workload_key: str,
        catalog_revision: int,
        catalog_sha256: str,
        package_family: str,
        plan: SourcePlan,
        packages: Iterable[object],
        preferred_arch: str = "",
        tier_getter: Optional[Callable[[object], str]] = None,
        catalog_signature_verified: bool = False,
) -> MaterializedWorkload:
    """Bind semantic components to concrete approved package identities.

    Candidate order is authoritative.  The first candidate present in an
    eligible repository/architecture is selected.  There is deliberately no
    fuzzy matching, substring search, or inferred rename behavior.
    """
    package_rows = list(packages)
    roots: List[MaterializedRoot] = []
    unresolved: List[RootSourcePolicy] = []
    for policy in plan.roots:
        candidates = tuple(policy.candidates or (policy.package,))
        chosen = None
        for candidate in candidates:
            if any(str(getattr(pkg, "name", "")) == candidate
                   and _arch_eligible(pkg, preferred_arch, package_family)
                   and _source_eligible(pkg, policy, tier_getter)
                   for pkg in package_rows):
                chosen = candidate
                break
        if chosen is None:
            unresolved.append(policy)
            continue
        roots.append(MaterializedRoot(
            component=policy.component or policy.package,
            primary_package=policy.package,
            package=chosen,
            candidates=candidates,
            source_kind=policy.source_kind,
            role=policy.role,
            optional=policy.optional,
        ))
    return MaterializedWorkload(
        workload_key=workload_key,
        catalog_revision=int(catalog_revision or 1),
        catalog_sha256=str(catalog_sha256 or ""),
        catalog_signature_verified=bool(catalog_signature_verified),
        package_family=package_family,
        roots=tuple(roots),
        unresolved=tuple(unresolved),
    )
