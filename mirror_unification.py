"""Collapse several mirror repositories into one deduplicated package population.

Feathered's default mirror workflow publishes each selected repository into its
own directory with its own metadata, and de-duplicates nothing. That is the
right default: each output is then a faithful snapshot of one upstream, and
nothing about it is Feathered's editorial opinion.

It is not always what the operator wants. Standing up a single internal mirror
from BaseOS + AppStream + EPEL, or from a Debian release/updates/security set,
means one repository the target can point at once. Doing that by hand means
merging directories and hoping the overlaps were identical.

This module is the honest version of that merge. Two records from different
repositories are collapsed only when Feathered can *prove* they are the same
artifact:

- a strong digest published by both sides, under a shared algorithm, that agrees
- and agreeing size metadata where both sides publish it

Proof is graded, because the alternative refuses legitimate work. Repositories
do not all publish the same digest algorithms -- an older rpmmd index carrying
only sha1 against a current one carrying sha256 is ordinary, not suspicious --
and treating "no algorithm in common" as fatal would break unified mirroring
over a metadata detail rather than over any real disagreement.

  STRONG       a shared strong algorithm agrees, and sizes agree
  WEAK         only a shared weak algorithm (sha1/md5) agrees, and sizes agree
  NONE         no algorithm in common; identity cannot be checked either way
  CONTRADICTED a shared algorithm disagrees, or sizes disagree

STRONG and WEAK are merged under either policy. An agreeing sha1 plus an
agreeing size is overwhelming evidence against an accidental difference, and the
basis is recorded per package rather than being flattened into "deduplicated".

NONE and CONTRADICTED are governed by the merge policy. Under ``STRICT``, the
default, they stop the build: a unified mirror physically holds one file per
identity, so keeping one silently would be an unrecorded choice about which
upstream wins, and CONTRADICTED in particular means two repositories publish
different bytes under one name. Under ``PREFER_PRIORITY`` the operator has
explicitly asked Feathered to resolve by selection order, and it does -- but
records the basis for every such package, so the choice is auditable rather than
invisible.

Deliberately dependency-free with respect to the wizard and the package
backends: it takes any objects exposing ``nevra``, ``repo``, ``digests``,
``checksum_type``/``checksum`` and ``size``, so all three package families and
the tests use exactly the same code path.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# Strongest first: the comparison uses the best algorithm both sides published.
COMPARISON_ALGORITHMS: Tuple[str, ...] = ("sha3_512", "sha512", "sha3_256", "sha384", "sha256")
#  Not proof of provenance, but agreement plus a matching size is decisive
#  evidence against two repositories holding accidentally different artifacts.
WEAK_ALGORITHMS: Tuple[str, ...] = ("sha1", "md5")

MIXED_BYTES = "differing-bytes"
UNPROVABLE = "no-shared-digest-algorithm"
MIXED_SIZE = "differing-size"

STRONG = "strong"
WEAK = "weak"
PRIORITY = "priority"


class MergePolicy(str, Enum):
    """What to do when two repositories cannot be proven to agree."""

    STRICT = "strict"
    PREFER_PRIORITY = "prefer-priority"


MERGE_POLICY_LABELS = {
    MergePolicy.STRICT: "Stop and list them (default)",
    MergePolicy.PREFER_PRIORITY: "Prefer the higher-priority repository",
}


def merge_policy_from_label(value: str) -> MergePolicy:
    text = str(value or "").strip().lower()
    if text.startswith("prefer") or text == MergePolicy.PREFER_PRIORITY.value:
        return MergePolicy.PREFER_PRIORITY
    return MergePolicy.STRICT


def _normalize(algorithm: str) -> str:
    text = str(algorithm or "").strip().lower().replace("-", "_")
    return {"sha_256": "sha256", "sha_384": "sha384", "sha_512": "sha512"}.get(text, text)


def _digests(package, allowed: Tuple[str, ...]) -> Dict[str, str]:
    found: Dict[str, str] = {}
    for algorithm, digest in (getattr(package, "digests", None) or {}).items():
        algo = _normalize(algorithm)
        if algo in allowed and str(digest or "").strip():
            found[algo] = str(digest).strip().lower()
    algo = _normalize(getattr(package, "checksum_type", ""))
    digest = str(getattr(package, "checksum", "") or "").strip()
    if algo in allowed and digest:
        found.setdefault(algo, digest.lower())
    return found


def strong_digests(package) -> Dict[str, str]:
    """Every strong algorithm/digest pair a package record publishes."""
    return _digests(package, COMPARISON_ALGORITHMS)


def weak_digests(package) -> Dict[str, str]:
    """Weak algorithm/digest pairs, used only to corroborate an agreeing size."""
    return _digests(package, WEAK_ALGORITHMS)


def _repository_name(package) -> str:
    return str(getattr(getattr(package, "repo", None), "name", "") or "unknown repository")


def _source_identity(package) -> str:
    repo = getattr(package, "repo", None)
    return str(getattr(repo, "source_identity", getattr(repo, "name", "")) or "")


def _size(package) -> Optional[int]:
    try:
        value = int(getattr(package, "size", 0) or 0)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


@dataclass(frozen=True)
class DeduplicatedIdentity:
    """One package identity that appeared in more than one mirror repository."""

    identity: str
    kept_repository: str
    duplicate_repositories: Tuple[str, ...]
    algorithm: str
    digest: str
    #  How the merge was justified: STRONG, WEAK, or PRIORITY (resolved by
    #  operator-selected repository order because it could not be proven).
    basis: str = STRONG

    @property
    def copies(self) -> int:
        return 1 + len(self.duplicate_repositories)

    @property
    def proven(self) -> bool:
        return self.basis in (STRONG, WEAK)


@dataclass(frozen=True)
class MirrorConflict:
    """One package identity that could not be proven identical across sources."""

    identity: str
    reason: str
    repositories: Tuple[str, ...]
    detail: str

    def describe(self) -> str:
        return f"{self.identity}: {self.detail} ({', '.join(self.repositories)})"


@dataclass(frozen=True)
class UnifiedMirrorPlan:
    """The retained population plus everything Feathered had to decide to get it."""

    packages: Tuple = ()
    deduplicated: Tuple[DeduplicatedIdentity, ...] = ()
    conflicts: Tuple[MirrorConflict, ...] = ()
    source_names: Tuple[str, ...] = ()
    input_record_count: int = 0
    policy: MergePolicy = MergePolicy.STRICT

    @property
    def retained_count(self) -> int:
        return len(self.packages)

    @property
    def duplicate_record_count(self) -> int:
        """Records dropped because a proven-identical copy was retained."""
        return sum(len(row.duplicate_repositories) for row in self.deduplicated)

    @property
    def unproven_count(self) -> int:
        """Identities merged by selection order because nothing proved them equal."""
        return sum(1 for row in self.deduplicated if row.basis == PRIORITY)

    @property
    def weakly_proven_count(self) -> int:
        return sum(1 for row in self.deduplicated if row.basis == WEAK)

    @property
    def total_size(self) -> int:
        return sum(int(getattr(p, "size", 0) or 0) for p in self.packages)

    @property
    def ok(self) -> bool:
        return not self.conflicts

    def summary(self) -> str:
        if not self.source_names:
            return "Unified mirror: no repositories."
        return (
            f"Unified mirror: {len(self.source_names)} repositories, "
            f"{self.input_record_count:,} published record(s), "
            f"{self.retained_count:,} retained after removing "
            f"{self.duplicate_record_count:,} proven-identical duplicate(s)")


def _compare(first, second) -> Tuple[str, str, str, str]:
    """Grade two records: ``(basis_or_empty, algorithm, digest, reason)``.

    A non-empty basis means the pair may be merged. An empty basis means the
    merge policy decides, and ``reason`` says why.
    """
    sizes = (_size(first), _size(second))
    size_conflict = (sizes[0] is not None and sizes[1] is not None and sizes[0] != sizes[1])

    for allowed, basis in ((COMPARISON_ALGORITHMS, STRONG), (WEAK_ALGORITHMS, WEAK)):
        left, right = _digests(first, allowed), _digests(second, allowed)
        shared = [a for a in allowed if a in left and a in right]
        if not shared:
            continue
        algorithm = shared[0]
        if left[algorithm] != right[algorithm]:
            #  A disagreeing digest is decisive at any strength: these are
            #  different bytes, and no weaker algorithm can redeem that.
            return "", algorithm, "", MIXED_BYTES
        if size_conflict:
            return "", algorithm, left[algorithm], MIXED_SIZE
        return basis, algorithm, left[algorithm], ""

    return "", "", "", MIXED_SIZE if size_conflict else UNPROVABLE


_REASON_DETAIL = {
    MIXED_BYTES: ("published under one package identity with different digests, so these are not "
                  "the same artifact"),
    UNPROVABLE: ("published under one package identity with no digest algorithm in common, so "
                 "Feathered cannot check whether they are the same artifact"),
    MIXED_SIZE: ("published under one package identity with disagreeing size metadata"),
}


def unify_mirror_packages(packages: Iterable, repositories: Sequence = (),
                          policy: MergePolicy = MergePolicy.STRICT) -> UnifiedMirrorPlan:
    """Collapse proven-identical records; report everything else as a conflict.

    Ordering is deterministic and explained rather than incidental. Records are
    grouped by identity in first-appearance order, and the retained copy is the
    one from the earliest repository in the operator's selection order, so the
    same inputs always produce the same mirror and the operator can predict
    which upstream supplies each byte.
    """
    records = list(packages)
    priority = {
        str(getattr(repo, "source_identity", getattr(repo, "name", "")) or ""): index
        for index, repo in enumerate(repositories)
    }

    def rank(package) -> int:
        return priority.get(_source_identity(package), len(priority))

    grouped: Dict[str, List] = {}
    order: List[str] = []
    for package in records:
        identity = str(getattr(package, "nevra", "") or getattr(package, "name", ""))
        if identity not in grouped:
            grouped[identity] = []
            order.append(identity)
        grouped[identity].append(package)

    retained: List = []
    deduplicated: List[DeduplicatedIdentity] = []
    conflicts: List[MirrorConflict] = []

    for identity in order:
        group = grouped[identity]
        if len(group) == 1:
            retained.append(group[0])
            continue
        # Stable sort by selection order; ties keep metadata order.
        ordered = sorted(group, key=rank)
        keeper = ordered[0]
        duplicates: List[str] = []
        failure: Optional[Tuple[str, List[str]]] = None
        algorithm = digest = ""
        # The weakest basis across the group wins: one unprovable pair makes the
        # whole identity unprovable, so a PRIORITY merge is never recorded as
        # though it had been checked.
        basis = STRONG
        for other in ordered[1:]:
            pair_basis, algo, value, reason = _compare(keeper, other)
            if pair_basis:
                if pair_basis == WEAK:
                    basis = WEAK if basis == STRONG else basis
                if not algorithm:
                    algorithm, digest = algo, value
                duplicates.append(_repository_name(other))
                continue
            if policy is MergePolicy.STRICT:
                failure = (reason, [_repository_name(keeper), _repository_name(other)])
                break
            # The operator asked for resolution by selection order. Take the
            # highest-priority copy and record that nothing proved them equal.
            basis = PRIORITY
            duplicates.append(_repository_name(other))
        if failure is not None:
            reason, involved = failure
            conflicts.append(MirrorConflict(
                identity=identity, reason=reason, repositories=tuple(involved),
                detail=_REASON_DETAIL[reason]))
            continue
        retained.append(keeper)
        deduplicated.append(DeduplicatedIdentity(
            identity=identity, kept_repository=_repository_name(keeper),
            duplicate_repositories=tuple(duplicates),
            algorithm=algorithm, digest=digest, basis=basis))

    return UnifiedMirrorPlan(
        packages=tuple(retained),
        deduplicated=tuple(deduplicated),
        conflicts=tuple(conflicts),
        source_names=tuple(str(getattr(r, "name", "")) for r in repositories),
        input_record_count=len(records),
        policy=policy,
    )


def conflict_report(plan: UnifiedMirrorPlan, limit: int = 20) -> str:
    """An operator-facing explanation of why a unified mirror was refused."""
    if plan.ok:
        return ""
    lines = [
        f"{len(plan.conflicts)} package identity/identities are published by more than one "
        "selected repository and could not be proven identical.",
        "",
        "A unified mirror holds one file per package identity, so Feathered will not choose "
        "between them on your behalf.",
        "",
    ]
    lines.extend(f"  - {conflict.describe()}" for conflict in plan.conflicts[:limit])
    if len(plan.conflicts) > limit:
        lines.append(f"  ... and {len(plan.conflicts) - limit} more.")
    lines.extend([
        "",
        "Choose one of:",
        "  - set \"When repositories disagree\" to \"Prefer the higher-priority repository\", which "
        "resolves each of these by your repository selection order and records the choice per "
        "package in mirror-sources.json;",
        "  - deselect one of the overlapping repositories;",
        "  - or publish with the separate-directories mirror layout, which keeps each repository "
        "intact and merges nothing.",
    ])
    return "\n".join(lines)


def unified_mirror_note(plan: UnifiedMirrorPlan) -> str:
    """Text for the bundle's UNIFIED-MIRROR.txt."""
    lines = [
        "This directory is a UNIFIED mirror.",
        "",
        "It is the union of several upstream repositories republished as one repository,",
        "not a copy of any single one of them. Do not treat it as a faithful snapshot of",
        "any upstream: its metadata is generated by Feathered over the merged population.",
        "",
        "Repositories merged, in the order that decided which copy was retained:",
    ]
    lines.extend(f"  {index}. {name}" for index, name in enumerate(plan.source_names, 1))
    lines.extend([
        "",
        f"Published records read:        {plan.input_record_count:,}",
        f"Packages retained:             {plan.retained_count:,}",
        f"Duplicate records removed:     {plan.duplicate_record_count:,}",
        "",
        f"  of which proven by strong digest: {len(plan.deduplicated) - plan.weakly_proven_count - plan.unproven_count:,}",
        f"  of which proven by weak digest:   {plan.weakly_proven_count:,}",
        f"  of which resolved by priority:    {plan.unproven_count:,}",
        "",
        f"Disagreement policy: {plan.policy.value}",
        "",
        "'Resolved by priority' means the repositories published no digest algorithm in",
        "common, or disagreed, and you asked Feathered to resolve by repository selection",
        "order. Those packages were NOT checked for equality. mirror-sources.json records",
        "the basis for every retained package individually.",
    ])
    if plan.unproven_count:
        lines.extend([
            "",
            f"WARNING: {plan.unproven_count:,} identity/identities were resolved by priority",
            "without any equality check. Review mirror-sources.json before trusting this",
            "mirror as a substitute for its upstreams.",
        ])
    if plan.deduplicated:
        lines.extend(["", "Deduplicated identities (first 50):"])
        for row in plan.deduplicated[:50]:
            others = ", ".join(row.duplicate_repositories)
            proof = row.algorithm if row.proven else "no equality check"
            lines.append(f"  {row.identity}  kept from {row.kept_repository}; "
                         f"also published by {others} [{row.basis}: {proof}]")
        if len(plan.deduplicated) > 50:
            lines.append(f"  ... and {len(plan.deduplicated) - 50} more.")
    return "\n".join(lines) + "\n"


def mirror_sources_record(plan: UnifiedMirrorPlan) -> dict:
    """Machine-readable provenance for the merge, written beside the payload."""
    duplicates_by_identity = {row.identity: row for row in plan.deduplicated}
    packages = []
    for package in plan.packages:
        identity = str(getattr(package, "nevra", "") or getattr(package, "name", ""))
        row = duplicates_by_identity.get(identity)
        packages.append({
            "identity": identity,
            "supplied_by": _repository_name(package),
            "also_published_by": list(row.duplicate_repositories) if row else [],
            "merge_basis": row.basis if row else None,
            "duplicate_proof": (
                {"algorithm": row.algorithm, "digest": row.digest}
                if row and row.proven else None),
        })
    return {
        "mirror_layout": "unified",
        "disagreement_policy": plan.policy.value,
        "repositories": list(plan.source_names),
        "published_record_count": plan.input_record_count,
        "retained_package_count": plan.retained_count,
        "duplicate_records_removed": plan.duplicate_record_count,
        "deduplicated_identity_count": len(plan.deduplicated),
        "weakly_proven_identity_count": plan.weakly_proven_count,
        "priority_resolved_identity_count": plan.unproven_count,
        "packages": packages,
    }
