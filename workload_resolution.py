"""Dynamic workload name resolution.

Static preset lists rot as repositories drift. This module is the scaffolding
that keeps them working without hand-edits: when a requested name is absent
from the loaded package universe, it is resolved through, in order:

1. the operator/learned alias store (persisted per profile, so a mapping
   discovered once is instant forever after),
2. a small seed alias table of known cross-family irregulars,
3. deterministic derivation rules (dash/underscore, common suffix families,
   python-prefix morphology) accepted only when the derived name actually
   exists in the universe or its provides,
4. virtual-provides matching (a name another package provides is not missing).

Every substitution is reported, never silent: the coverage table shows the
resolution and its kind, the analyze log records it, and derived/learned
mappings are persisted so the next session skips the derivation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

SEED_ALIASES: Dict[str, Dict[str, str]] = {
    "arch": {
        "bpf": "bcc-tools", "gdisk": "gptfdisk", "quota": "quota-tools",
        "netcat": "openbsd-netcat", "bind-utils": "bind", "dnsutils": "bind",
        "vim-enhanced": "vim", "iproute": "iproute2", "gnupg2": "gnupg",
        "pkgconf-pkg-config": "pkgconf", "ninja-build": "ninja",
    },
    "deb": {
        "bind-utils": "dnsutils", "iproute": "iproute2", "gnupg2": "gnupg",
        "vim-enhanced": "vim", "nmap-ncat": "ncat", "xz": "xz-utils",
        "procps-ng": "procps", "sg3_utils": "sg3-utils", "lm_sensors": "lm-sensors",
    },
    "rpm": {
        "dnsutils": "bind-utils", "iproute2": "iproute", "gnupg": "gnupg2",
        "xz-utils": "xz", "procps": "procps-ng", "sg3-utils": "sg3_utils",
        "lm-sensors": "lm_sensors", "netcat-openbsd": "nmap-ncat",
    },
}

_SUFFIXES = ("-tools", "-utils", "-progs", "-server", "-cli", "-core", "-common")


@dataclass(frozen=True)
class Resolution:
    requested: str
    resolved: str
    kind: str  # exact | provides | learned | seed | derived | missing
    note: str = ""

    @property
    def substituted(self) -> bool:
        return self.kind in ("learned", "seed", "derived") and self.resolved != self.requested


def _python_forms(name: str, family: str) -> List[str]:
    for prefix in ("python3-", "python-", "python2-"):
        if name.startswith(prefix):
            stem = name[len(prefix):]
            if family == "arch":
                return [f"python-{stem}"]
            if family == "deb":
                return [f"python3-{stem}"]
            return [f"python3-{stem}", f"python-{stem}"]
    return []


def derivation_candidates(name: str, family: str) -> List[str]:
    """Deterministic spellings of the same software, most specific first."""
    out: List[str] = []
    swapped = name.replace("_", "-") if "_" in name else name.replace("-", "_")
    if swapped != name:
        out.append(swapped)
    out.extend(_python_forms(name, family))
    for suffix in _SUFFIXES:
        if name.endswith(suffix):
            out.append(name[: -len(suffix)])
        else:
            out.append(name + suffix)
    seen, ordered = set(), []
    for candidate in out:
        if candidate and candidate != name and candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)
    return ordered


def resolve_name(name: str, names: Set[str], provides: Set[str], family: str,
                 learned: Optional[Dict[str, str]] = None) -> Resolution:
    if name in names:
        return Resolution(name, name, "exact")
    learned = learned or {}
    mapped = learned.get(name)
    if mapped and (mapped in names or mapped in provides):
        return Resolution(name, mapped, "learned", "learned alias from a previous session")
    seed = SEED_ALIASES.get(family, {}).get(name)
    if seed and (seed in names or seed in provides):
        return Resolution(name, seed, "seed", "known cross-family package identity")
    for candidate in derivation_candidates(name, family):
        if candidate in names:
            return Resolution(name, candidate, "derived", "derived by spelling rule; verified present")
    if name in provides:
        return Resolution(name, name, "provides", "satisfied by a virtual provide")
    for candidate in derivation_candidates(name, family):
        if candidate in provides:
            return Resolution(name, candidate, "derived", "derived by spelling rule; satisfied by provides")
    return Resolution(name, name, "missing")


def universe_sets(packages: Sequence[object]) -> Tuple[Set[str], Set[str]]:
    names: Set[str] = set()
    provides: Set[str] = set()
    for pkg in packages:
        names.add(getattr(pkg, "name", ""))
        for rel in getattr(pkg, "provides", []) or []:
            provides.add(getattr(rel, "name", ""))
    names.discard("")
    provides.discard("")
    return names, provides


def resolve_requests(requests: Iterable[Tuple], packages: Sequence[object], family: str,
                     learned: Optional[Dict[str, str]] = None):
    """Substitute resolvable names in request tuples.

    Only the name element changes; version pins and repo identity elements are
    preserved. Returns (new_requests, resolutions_that_substituted)."""
    names, provides = universe_sets(packages)
    out: List[Tuple] = []
    substitutions: List[Resolution] = []
    for request in requests:
        request = tuple(request)
        name = str(request[0])
        resolution = resolve_name(name, names, provides, family, learned)
        if resolution.substituted:
            substitutions.append(resolution)
            out.append((resolution.resolved,) + request[1:])
        else:
            out.append(request)
    return out, substitutions


# ---------------------------------------------------------------------------
# Init-system safety
# ---------------------------------------------------------------------------

# Packages that ARE systemd or exist only to make systemd PID 1. Installing
# any of these on a non-systemd target replaces or fights the running init and
# can leave the system unbootable, so they are refused rather than warned
# about. Names that merely *link* libsystemd (libsystemd0 ships on Devuan by
# design) are deliberately absent: they are safe and common.
SYSTEMD_CRITICAL_NAMES = {
    "systemd", "systemd-sysv", "systemd-sysvinit", "systemd-init",
    "systemd-boot", "systemd-resolvconf", "systemd-timesyncd",
    "systemd-container", "systemd-coredump", "systemd-homed",
    "systemd-oomd", "systemd-userdbd", "systemd-networkd", "elogind-systemd",
}

# A dependency on one of these means the package cannot run under another init.
SYSTEMD_CRITICAL_DEPENDS = {"systemd", "systemd-sysv", "systemd-sysvinit"}


def systemd_conflict(name: str, packages_by_name: Optional[Dict[str, object]] = None) -> str:
    """Return a refusal reason if this package would break a non-systemd init.

    Checked by identity first, then by hard dependency, so a package that
    merely pulls systemd as a strict requirement is caught even when its own
    name looks innocuous."""
    bare = str(name or "").strip()
    if bare in SYSTEMD_CRITICAL_NAMES:
        return (f"{bare} is systemd itself (or a systemd PID 1 shim). Installing it on a "
                "target running another init can leave the system unbootable.")
    pkg = (packages_by_name or {}).get(bare)
    if pkg is not None:
        for attr in ("depends", "requires"):
            for rel in getattr(pkg, attr, []) or []:
                dep = str(getattr(rel, "name", "") or "")
                if dep in SYSTEMD_CRITICAL_DEPENDS:
                    return (f"{bare} hard-depends on {dep}, so it cannot run under this "
                            "target's init system.")
    return ""


def repository_init_conflict(repo_name: str, repo_url: str, profile_key: str,
                             init_system: str) -> str:
    """Return a reason if a repository must not participate on this target.

    Artix policy is explicit: Arch's own repositories (core especially) carry
    systemd-linked builds and must never be mixed in. Vendor repositories that
    publish only systemd-unit packaging for another distribution are also
    excluded from non-systemd targets by default; the operator can still add
    one deliberately as an operator repository."""
    if not init_system:
        return ""
    haystack = f"{repo_name} {repo_url}".lower()
    if profile_key == "artix":
        if "archlinux.org" in haystack or "pkgbuild.com" in haystack:
            return ("Arch Linux repositories carry systemd-linked builds and must not be mixed "
                    "into an Artix target; use the Artix system/world/galaxy repositories.")
    if "download.docker.com" in haystack:
        return ("Docker CE publishes systemd-unit packaging only. On a non-systemd target use "
                "the distribution's own container packages plus its init service scripts.")
    return ""
