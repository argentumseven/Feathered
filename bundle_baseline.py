"""Differential bundle decisions, independent of I/O and package verification.

A caller supplies its strong-digest policy and comparison operation. This retains
legacy baseline semantics; it never turns an omission decision into a trust claim.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Dict, List, Protocol, TypeVar

DigestLookup = Callable[[str, str], tuple[str, str] | None]


class BaselinePackage(Protocol):
    @property
    def name(self) -> str: ...


P = TypeVar('P', bound=BaselinePackage)


def digest_map(entries: Iterable[Mapping[str, object]], *, digest: DigestLookup) -> dict[str, str]:
    baseline: Dict[str, str] = {}
    for entry in entries:
        key = entry.get("package_id") or entry.get("nevra") or entry.get("name")
        if key:
            # Only the digest identifies content. Falling back to the version
            # here made a republished artifact with the same NEVRA but
            # different bytes look unchanged, so it was omitted from the delta.
            # prefer a strong repository/evidence digest because it can
            # be compared before downloading a differential payload. Weak source
            # digests are not allowed to make an omission decision.
            source = digest(str(entry.get("source_digest_type") or ""),
                            str(entry.get("source_digest") or ""))
            evidence = digest(str(entry.get("evidence_digest_type") or ""),
                              str(entry.get("evidence_digest") or ""))
            baseline[str(key)] = (source or evidence or ("sha256", str(entry.get("sha256") or "")))[1]
    return baseline


def partition(selected: Iterable[P], baseline: Mapping[str, str], *,
              digest: DigestLookup, matches: Callable[[str, str], bool]) -> tuple[list[P], list[P], int]:
    """Return ship/skip lists and the missing-digest count, preserving objects."""
    if not baseline:
        return list(selected), [], 0
    ship: List[P] = []
    skip: List[P] = []
    unverifiable = 0
    for pkg in selected:
        identity = getattr(pkg, "nevra", None) or pkg.name
        recorded = (baseline.get(identity) or "").strip()
        if not recorded:
            # Absent from the baseline, or present without a digest (an older
            # manifest). Ship it rather than assume the bytes match: identity
            # alone does not establish that a republished artifact is unchanged.
            if identity in baseline:
                unverifiable += 1
            ship.append(pkg)
            continue
        primary = digest(getattr(pkg, "checksum_type", ""),
                         getattr(pkg, "checksum", ""))
        # preserve compatibility with legacy baseline
        # callers that carried a bare 64-hex checksum without its algorithm.
        # This inference is used only for pre-download differential comparison,
        # never for artifact verification where an explicit algorithm is
        # required.
        if primary is None and not getattr(pkg, "checksum_type", ""):
            bare = str(getattr(pkg, "checksum", "") or "").strip().lower()
            if len(bare) == 64 and all(ch in "0123456789abcdef" for ch in bare):
                primary = ("sha256", bare)
        record = getattr(pkg, "verification", None)
        evidence = digest(getattr(record, "evidence_digest_type", ""),
                          getattr(record, "evidence_digest", "")) if record else None
        current = (primary or evidence or ("", ""))[1]
        if current and matches(recorded.lower(), current.lower()):
            skip.append(pkg)
        else:
            ship.append(pkg)
    return ship, skip, unverifiable
