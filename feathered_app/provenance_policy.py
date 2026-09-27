"""Headless inspection/decision rules for independent repository evidence.

The GUI supplies repository lists and immutable-ish inspection snapshots.
No Tk widget, ``App`` attribute, or worker owns the decision: unknown coverage,
confirmed checksum gaps, and complete coverage are distinct states.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from artifact_verification import package_digest_map
from repository_config import RepoSpec


@dataclass(frozen=True)
class EvidenceRequirements:
    required: tuple[RepoSpec, ...]
    pending_inspection: tuple[RepoSpec, ...]


class ProvenancePolicyService:
    """Interpret checksum inspection results and classify evidence requirements."""

    @staticmethod
    def cache_key(repo: RepoSpec) -> tuple[str, str]:
        return (repo.name, repo.normalized_url)

    @staticmethod
    def _matching_packages(repo: RepoSpec, packages: Iterable) -> list:
        target = (repo.name, repo.normalized_url)
        return [pkg for pkg in packages
                if getattr(pkg, "repo", None) is repo or (
                    getattr(pkg, "repo", None) is not None
                    and (getattr(pkg.repo, "name", ""),
                         getattr(pkg.repo, "normalized_url", "")) == target)]

    @staticmethod
    def minimum_met_by_algorithms(algorithms: Iterable[str], preference: str) -> bool:
        found = set(algorithms or ())
        acceptable = {
            "auto": {"sha256", "sha384", "sha512"},
            "sha256": {"sha256", "sha384", "sha512"},
            "sha384": {"sha384", "sha512"},
            "sha512": {"sha512"},
        }.get(preference, set())
        return bool(found & acceptable)

    def detected_algorithms(self, repo: RepoSpec, detected: Mapping,
                            packages: Iterable) -> list[str]:
        algorithms = set(detected.get(self.cache_key(repo), ()) or ())
        for pkg in self._matching_packages(repo, packages):
            algorithms.update(package_digest_map(pkg))
        order = {"sha512": 0, "sha384": 1, "sha256": 2}
        return sorted(algorithms, key=lambda a: (order.get(a, 99), a))

    def inspection_known(self, repo: RepoSpec, detected: Mapping,
                         packages: Iterable) -> bool:
        return (self.cache_key(repo) in detected or
                bool(self._matching_packages(repo, packages)))

    def meets_digest_minimum(self, repo: RepoSpec, preference: str, *,
                             coverage: Mapping, detected: Mapping,
                             packages: Iterable) -> bool:
        key = self.cache_key(repo)
        detail = coverage.get(key)
        if detail is not None:
            total = int(detail.get("total", 0) or 0)
            return total > 0 and int(detail.get(preference, 0) or 0) == total
        matched = self._matching_packages(repo, packages)
        if matched:
            return all(self.minimum_met_by_algorithms(package_digest_map(pkg), preference)
                       for pkg in matched)
        return self.minimum_met_by_algorithms(
            self.detected_algorithms(repo, detected, packages), preference)

    @staticmethod
    def evidence_requirements(repositories: Iterable[RepoSpec], strategy: str, *,
                              inspection_known, meets_digest_minimum) -> EvidenceRequirements:
        """Classify the *given* participating sources, preserving their order.

        The callers supply observations explicitly; this method never looks up
        GUI state or assumes that an uninspected repository lacks checksums.
        """
        rows = tuple(repositories)
        if strategy == "full-corroboration":
            return EvidenceRequirements(rows, ())
        if strategy != "evidence-fallback":
            return EvidenceRequirements((), ())
        required, pending = [], []
        for repo in rows:
            if not inspection_known(repo):
                pending.append(repo)
            elif not meets_digest_minimum(repo, repo.digest_preference or "auto"):
                required.append(repo)
        return EvidenceRequirements(tuple(required), tuple(pending))
