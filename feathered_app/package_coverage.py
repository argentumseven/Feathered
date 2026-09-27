"""Headless root-package and mirror source-coverage evaluation.

The wizard acquires repository metadata and renders results. This module owns
package eligibility, version/priority selection, name substitution, optional
root accounting and mirror counts. It has no Tk or ``App`` dependency, and its
immutable target snapshot can safely be passed to a background worker.

Coverage is intentionally *not* dependency resolution or package verification.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import cmp_to_key
from typing import Callable, Collection, Iterable, Mapping, Sequence

import apt_core
import arch_core
from core import compare_evr as rpm_compare_evr
import workload_resolution


CoverageRow = tuple[str, str, str, str, str, bool]


@dataclass(frozen=True)
class CoverageTarget:
    family: str
    arch: str
    workload_roles: frozenset[str] = frozenset()
    check_init_conflicts: bool = False


@dataclass(frozen=True)
class CoverageResult:
    rows: tuple[CoverageRow, ...]
    resolved_aliases: tuple[tuple[str, str], ...] = ()


class PackageCoverageService:
    """Evaluate root availability without consulting GUI or live app state."""

    @staticmethod
    def request_display(request: Sequence[object]) -> str:
        name = str(request[0]) if request else ""
        version = request[1] if len(request) > 1 else None
        role = request[2] if len(request) > 2 else None
        repo_name = request[3] if len(request) > 3 else None
        source_scope = request[5] if len(request) > 5 else None
        if version and version not in {"Latest", "Follows repositories"}:
            name += f"  {version}"
        if role:
            name += f"  [{role}]"
        if repo_name:
            name += f"  @ {repo_name}"
        if source_scope == "distribution":
            name += "  [distribution]"
        return name

    @staticmethod
    def _repo_tier(repo: object, target: CoverageTarget) -> str:
        tier = getattr(repo, "source_tier", "")
        if tier in {"base", "workload", "additional"}:
            return tier
        if getattr(repo, "role", "") in target.workload_roles:
            return "workload"
        if str(getattr(repo, "note", "") or "").lower().startswith("user-added"):
            return "additional"
        return "base"

    @classmethod
    def matches(cls, pkg: object, request: Sequence[object], target: CoverageTarget,
                *, tier_of: Callable[[object], str] | None = None) -> bool:
        name, version, role = request[:3]
        repo_name = request[3] if len(request) >= 4 else None
        exact_arch = request[4] if len(request) >= 5 else None
        source_scope = request[5] if len(request) >= 6 else None
        repo_identity = request[6] if len(request) >= 7 else None
        repo = pkg.repo
        if target.family == "deb":
            # Debian virtual provides must be resolved by APT, not mistaken for
            # a directly selectable binary-package root.
            if pkg.name != name:
                return False
            if version and version not in {"Latest", "Follows repositories"} and pkg.version != version:
                return False
            if pkg.arch not in {target.arch, "all"}:
                return False
        elif target.family == "arch" or getattr(repo, "repo_format", "") == "pacman":
            names = {pkg.name}
            names.update(getattr(p, "name", "") for p in (getattr(pkg, "provides", ()) or ())
                         if getattr(p, "name", ""))
            if name not in names:
                return False
            if version and version not in {"Latest", "Follows repositories"} and \
                    arch_core.compare_versions(pkg.version, version) != 0:
                return False
            if pkg.arch not in {target.arch, "any"}:
                return False
        else:
            names = {pkg.name}
            names.update(getattr(p, "name", "") for p in (getattr(pkg, "provides", ()) or ())
                         if getattr(p, "name", ""))
            names.update(getattr(pkg, "files", ()) or ())
            if name not in names:
                return False
            if version and version not in {"Latest", "Follows repositories"} and \
                    version not in {pkg.evr_text, pkg.version}:
                return False
            if pkg.arch not in {target.arch, "noarch"}:
                return False
        if source_scope == "distribution" and (
                tier_of(repo) if tier_of is not None else cls._repo_tier(repo, target)) != "base":
            return False
        if role and repo.role != role:
            return False
        # A stable identity disambiguates repositories that share display names.
        if repo_identity:
            if repo.source_identity != repo_identity:
                return False
        elif repo_name and repo.name != repo_name:
            return False
        if exact_arch and pkg.arch != exact_arch:
            return False
        return True

    @staticmethod
    def _compare_versions(a: object, b: object, family: str) -> int:
        if family == "arch":
            return arch_core.compare_versions(a.version, b.version)
        if family == "deb":
            return apt_core.compare_deb_versions(a.version, b.version)
        return rpm_compare_evr(a.evr, b.evr)

    @classmethod
    def best_candidate(cls, candidates: Iterable[object], target: CoverageTarget,
                       *, compare_versions: Callable[[object, object], int] | None = None):
        candidates = list(candidates)
        if not candidates:
            return None
        compare = compare_versions or (lambda a, b: cls._compare_versions(a, b, target.family))

        def cmp(a, b):
            a_arch = 0 if a.arch == target.arch else 1
            b_arch = 0 if b.arch == target.arch else 1
            if a_arch != b_arch:
                return -1 if a_arch < b_arch else 1
            a_priority = getattr(a.repo, "priority", 999)
            b_priority = getattr(b.repo, "priority", 999)
            if a_priority != b_priority:
                return -1 if a_priority < b_priority else 1
            version_cmp = compare(a, b)
            if version_cmp:
                return -version_cmp  # newest candidate first
            if a.repo.name != b.repo.name:
                return -1 if a.repo.name < b.repo.name else 1
            return 0

        return min(candidates, key=cmp_to_key(cmp))

    @classmethod
    def evaluate_roots(cls, packages: Sequence[object], requests: Iterable[Sequence[object]],
                       target: CoverageTarget, *, optional: Collection[str] = (),
                       aliases: Mapping[str, str] | None = None,
                       unresolved: Iterable[object] = ()) -> CoverageResult:
        """Evaluate coverage in request order, then append unresolved required roots."""
        requests = tuple(tuple(request) for request in requests)
        optional = frozenset(optional)
        universe_names, universe_provides = workload_resolution.universe_sets(packages)
        by_name = {pkg.name: pkg for pkg in packages} if target.check_init_conflicts else {}
        rows: list[CoverageRow] = []
        resolved_pairs: list[tuple[str, str]] = []
        for request in requests:
            resolution = workload_resolution.resolve_name(
                str(request[0]), universe_names, universe_provides, target.family, dict(aliases or {}))
            resolved = ((resolution.resolved,) + request[1:]) if resolution.substituted else request
            if resolution.substituted:
                resolved_pairs.append((resolution.requested, resolution.resolved))
            matches = [pkg for pkg in packages if cls.matches(pkg, resolved, target)]
            best = cls.best_candidate(matches, target)
            label = (f"{resolution.requested} → {resolution.resolved}"
                     if resolution.substituted else cls.request_display(resolved))
            is_optional = str(resolved[0]) in optional or resolution.requested in optional
            init_block = (workload_resolution.systemd_conflict(str(resolved[0]), by_name)
                          if target.check_init_conflicts else "")
            if init_block:
                rows.append((label, "Blocked (init)", "", init_block, "error", False))
            elif best is not None:
                candidate = getattr(best, "nevra", getattr(best, "name", str(resolved[0])))
                status = "Available" if not resolution.substituted else f"Available ({resolution.kind})"
                rows.append((label, status, best.repo.name, candidate, "ok", is_optional))
            elif is_optional:
                rows.append((label, "Optional gap", "",
                             "No approved candidate is offered by the eligible sources", "warn", True))
            else:
                rows.append((label, "Missing", "",
                             "No approved workload candidate is offered by the eligible sources", "error", False))

        requested_names = {str(request[0]) for request in requests}
        for policy in unresolved:
            if policy.optional or policy.package in requested_names:
                continue
            candidates = " / ".join(policy.candidates or (policy.package,))
            rows.append((policy.component or policy.package, "Missing", "",
                         f"No approved candidate found: {candidates}", "error", False))
        return CoverageResult(tuple(rows), tuple(resolved_pairs))

    @staticmethod
    def evaluate_mirrors(packages: Sequence[object], repositories: Iterable[object]) -> CoverageResult:
        """Count packages by stable source identity, not duplicate display name."""
        counts: dict[str, int] = {}
        for pkg in packages:
            identity = pkg.repo.source_identity
            counts[identity] = counts.get(identity, 0) + 1
        rows: list[CoverageRow] = []
        for repo in sorted(repositories, key=lambda r: (r.name.lower(), r.source_identity)):
            count = counts.get(repo.source_identity, 0)
            rows.append((repo.name, "Ready" if count else "Empty", repo.name,
                         f"{count:,} package record(s)" if count else "No package records found",
                         "ok" if count else "error", False))
        return CoverageResult(tuple(rows))
