"""Checksum coverage inspection without UI access or mutations to build sources."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Callable, Sequence, TypeVar

from core import RepoSpec, Reporter, package_digest_map, select_digest_from_map

PackageT = TypeVar('PackageT')


@dataclass(frozen=True)
class ChecksumCoverage:
    algorithms: tuple[str, ...]
    package_count: int
    counts: tuple[tuple[str, int], ...]


def inspect_checksums(repo: RepoSpec, arches: set[str], reporter: Reporter,
                      load: Callable[[RepoSpec, set[str], Reporter], Sequence[PackageT]]) -> ChecksumCoverage:
    # Probe trust and evidence bookkeeping must never leak back to the configured
    # source. Inspection describes published fields; it does not certify trust.
    probe = copy.deepcopy(repo)
    probe.keyring = ''
    probe.evidence_policy = 'off'
    probe.evidence_urls = []
    probe.verification_strategy = 'checksum-available'
    probe.digest_preference = 'auto'
    packages = load(probe, set(arches), reporter)
    algorithms: set[str] = set()
    counts = dict.fromkeys(("auto", "sha256", "sha384", "sha512",
                            "exact_sha256", "exact_sha384", "exact_sha512"), 0)
    counts["total"] = len(packages)
    for package in packages:
        digests = package_digest_map(package)
        algorithms.update(digests)
        for exact in ("sha256", "sha384", "sha512"):
            counts[f"exact_{exact}"] += int(exact in digests)
        for minimum in ("auto", "sha256", "sha384", "sha512"):
            counts[minimum] += int(select_digest_from_map(digests, minimum) is not None)
    order = {'sha512': 0, 'sha384': 1, 'sha256': 2}
    return ChecksumCoverage(tuple(sorted(algorithms, key=lambda a: (order.get(a, 99), a))),
                            len(packages), tuple(counts.items()))
