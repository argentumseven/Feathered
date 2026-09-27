"""Classify dropdown options as stable, pre-release, end-of-life or incompatible.

A dropdown sorted newest-first puts a distribution's development series or a
Kubernetes minor that has only release candidates at the top. Those entries
remain selectable (someone may genuinely target them) but must not look like
the obvious choice, and must never be chosen automatically as a default.

This module is Tk-independent: it receives plain values plus explicit
knowledge (known pre-release identities, release lifecycle rows, init
conflicts) and returns an advisory. The GUI decides how to render it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from enum import Enum
from typing import Callable, Collection, Iterable, Mapping, Optional, Sequence


class OptionStatus(Enum):
    STABLE = "stable"
    PRERELEASE = "prerelease"
    END_OF_LIFE = "end-of-life"
    INCOMPATIBLE = "incompatible"


@dataclass(frozen=True)
class OptionAdvice:
    status: OptionStatus = OptionStatus.STABLE
    reason: str = ""

    @property
    def stable(self) -> bool:
        return self.status is OptionStatus.STABLE

    @property
    def tag(self) -> str:
        """Short text suffix shown beside the value inside the open dropdown."""
        return {
            OptionStatus.PRERELEASE: "beta",
            OptionStatus.END_OF_LIFE: "end of life",
            OptionStatus.INCOMPATIBLE: "incompatible",
        }.get(self.status, "")


STABLE = OptionAdvice()

# Suite/series names that are development streams on every distribution that
# uses them. Matching is on the whole token so "devuan" or "sidecar" never match.
_DEVELOPMENT_NAMES = frozenset({
    "rawhide", "sid", "unstable", "testing", "experimental", "devel",
    "ceres", "cauldron", "factory", "tumbleweed-staging",
})

# Pre-release markers inside a version string: 28.0.0~rc.1, 1.36.0-beta.0,
# 2.0-0.1.rc1.el9, 10.2 Beta. The marker must not be glued to a preceding
# letter (so "src", "debian", "devuan", "preempt" never match).
_PRERELEASE_MARKER = re.compile(
    r"(?<![A-Za-z])(alpha|beta|rc|pre|preview|dev|nightly|snapshot|"
    r"release[ _-]?candidate|early[ _-]?access)(?![A-Za-z])",
    re.IGNORECASE,
)
_NEUTRAL_VALUES = frozenset({"", "latest", "follows repositories", "rolling", "custom"})


def version_text_is_prerelease(value: str) -> bool:
    """True when the value itself names a pre-release or development stream."""
    text = str(value or "").strip()
    if text.lower() in _NEUTRAL_VALUES:
        return False
    if text.lower() in _DEVELOPMENT_NAMES:
        return True
    return bool(_PRERELEASE_MARKER.search(text))


def ubuntu_series_unreleased(value: str, today: Optional[date] = None) -> bool:
    """Ubuntu's YY.MM identity is its planned release month.

    Before that month begins the series can only be the development release.
    This works offline; live discovery of the archive's ``devel`` alias refines
    it during the release month itself.
    """
    match = re.match(r"^(\d{2})\.(\d{2})(?:\.\d+)?$", str(value or "").strip())
    if not match:
        return False
    year, month = 2000 + int(match.group(1)), int(match.group(2))
    if not 1 <= month <= 12:
        return False
    today = today or date.today()
    return (year, month) > (today.year, today.month)


def classify_release(profile_key: str, release: str, *,
                     prerelease: Collection[str] = (),
                     codenames: Optional[Mapping[str, str]] = None,
                     today: Optional[date] = None) -> OptionAdvice:
    """Advise on a distribution release identity."""
    value = str(release or "").strip()
    if not value:
        return STABLE
    marked = {str(v).strip().lower() for v in prerelease if str(v).strip()}
    identities = {value.lower()}
    if codenames:
        codename = codenames.get(value)
        if codename:
            identities.add(codename.lower())
        # Codename-style targets also accept the version form, and vice versa.
        identities.update(v.lower() for v, c in codenames.items()
                          if c.lower() == value.lower())
    if identities & marked:
        return OptionAdvice(OptionStatus.PRERELEASE,
                            f"{value} is the distribution's development/testing series, not a "
                            "released version. Packages and vendor repositories (Docker, "
                            "Kubernetes and others) may be missing or change without notice.")
    if version_text_is_prerelease(value):
        return OptionAdvice(OptionStatus.PRERELEASE,
                            f"{value} is a pre-release or development stream. Expect missing "
                            "vendor repositories and package churn.")
    if profile_key == "ubuntu" and ubuntu_series_unreleased(value, today):
        return OptionAdvice(OptionStatus.PRERELEASE,
                            f"Ubuntu {value} has not been released yet; it is the current "
                            "development series. Vendor repositories usually publish it only "
                            "after release.")
    return STABLE


def classify_package_version(value: str) -> OptionAdvice:
    """Advise on a concrete package version offered by a repository scan."""
    if version_text_is_prerelease(value):
        return OptionAdvice(OptionStatus.PRERELEASE,
                            f"{value} is a pre-release build (alpha/beta/rc). "
                            "Prefer a final release for production targets.")
    return STABLE


def classify_kubernetes_minor(value: str, releases: Iterable[object] = (),
                              today: Optional[date] = None) -> OptionAdvice:
    """Advise on a Kubernetes minor using upstream release lifecycle rows.

    ``releases`` are objects with ``minor`` and ``end_of_life`` attributes (see
    ``k8s_knowledge.Release``). A minor newer than every *released* minor exists
    in pkgs.k8s.io only as release candidates. Unknown data yields no advice.
    """
    match = re.fullmatch(r"\s*[vV]?1\.(\d+)(?:\.\d+)?\s*", str(value or ""))
    if not match:
        return STABLE
    minor = int(match.group(1))
    rows = {}
    for row in releases:
        found = re.fullmatch(r"1\.(\d+)", str(getattr(row, "minor", "")))
        if found:
            rows[int(found.group(1))] = str(getattr(row, "end_of_life", "") or "")
    if not rows:
        return STABLE
    if minor > max(rows):
        return OptionAdvice(OptionStatus.PRERELEASE,
                            f"Kubernetes 1.{minor} has not been released upstream yet; its "
                            "repository may carry only release candidates.")
    eol = rows.get(minor)
    if eol:
        try:
            if date.fromisoformat(eol) <= (today or date.today()):
                return OptionAdvice(OptionStatus.END_OF_LIFE,
                                    f"Kubernetes 1.{minor} reached upstream end of life on {eol}.")
        except ValueError:
            pass
    return STABLE


def preferred_default(values: Sequence[str],
                      classify: Callable[[str], OptionAdvice]) -> str:
    """Newest stable choice; fall back through EOL, then pre-release, then first.

    Incompatible options are never auto-selected when any alternative exists.
    """
    ranked = {OptionStatus.STABLE: 0, OptionStatus.END_OF_LIFE: 1,
              OptionStatus.PRERELEASE: 2, OptionStatus.INCOMPATIBLE: 3}
    best, best_rank = "", 99
    for value in values:
        try:
            rank = ranked[classify(value).status]
        except Exception:
            rank = 0
        if rank < best_rank:
            best, best_rank = value, rank
            if rank == 0:
                break
    return best if best_rank < 99 else (values[0] if values else "")


def display_label(value: str, advice: OptionAdvice) -> str:
    """Text shown in the open dropdown list; the stored value never changes."""
    return f"{value}   \u00b7 {advice.tag}" if advice.tag else str(value)
