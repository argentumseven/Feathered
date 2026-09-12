from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Optional

REL_EXACT_MIRROR = "exact-mirror"
REL_EXACT_ARTIFACT = "exact-artifact"
REL_REBUILD_PEER = "independent-peer"

AUTH_INDEPENDENT = "independent-authority"
AUTH_SAME = "same-authority"
AUTH_UNKNOWN = "authority-unknown"

# CentOS Stream is intentionally excluded. Stream is an upstream/development
# stream relative to RHEL releases, not another same-release rebuild peer.
EL_REBUILD_VENDORS = frozenset({"redhat", "rocky", "almalinux"})


@dataclass(frozen=True)
class EvidenceCandidate:
    """One operator-selectable evidence endpoint with explicit proof semantics."""

    url: str
    label: str = ""
    relationship: str = REL_EXACT_MIRROR
    authority: str = AUTH_UNKNOWN
    source: str = "profile"  # profile | configured | derived-peer | manual
    note: str = ""


def infer_vendor_id(name: str, url: str = "") -> str:
    """Return a stable repository/vendor identity from the strongest signal.

    Repository URLs are authoritative when they identify a distribution.  Human
    labels are secondary because Feathered intentionally appends contextual text
    such as ``RHEL-compatible fallback`` to AlmaLinux/Rocky rows.  Treating that
    generic compatibility phrase as the vendor used to collapse both rebuilds
    into ``redhat``, which in turn mislabeled Alma<->Rocky peers as exact mirrors
    and could generate a semantic peer that pointed back at the acquisition repo.
    """
    url_text = str(url or "").lower()
    name_text = str(name or "").lower()

    # Strong URL identities first.  Keep specific rebuild distributions ahead of
    # the broader RHEL family so a /rocky/ or /almalinux/ path cannot be masked by
    # descriptive UI text.
    url_rules = (
        (("download.docker.com",), "docker"),
        (("rockylinux.org", "/rocky/", "/rocky-linux/", "/rockylinux/"), "rocky"),
        (("almalinux.org", "/almalinux/"), "almalinux"),
        (("cdn.redhat.com", "access.redhat.com", "/rhel/", "/rhel9/", "/rhel8/"), "redhat"),
        (("artixlinux", "/artix/"), "artix"),
        (("archlinux", "mirror.pkgbuild.com", "/archlinux/"), "arch"),
        (("devuan", "/devuan/"), "devuan"),
        (("packages.vmware.com/photon", "/photon/"), "photon"),
        (("ubuntu", "/ubuntu/"), "ubuntu"),
        (("debian", "/debian/", "/debian-security/"), "debian"),
        (("fedoraproject", "/fedora/", "/epel/"), "fedora"),
        (("centos", "/centos-stream/"), "centos"),
    )
    for needles, vendor in url_rules:
        if any(needle in url_text for needle in needles):
            return vendor

    # Then use explicit names, again preferring concrete distributions over
    # family/compatibility wording.
    name_rules = (
        (("docker ce", "docker"), "docker"),
        (("rocky linux", "rockylinux", "rocky-linux"), "rocky"),
        (("almalinux", "alma linux"), "almalinux"),
        (("artix linux", "artix"), "artix"),
        (("arch linux",), "arch"),
        (("devuan",), "devuan"),
        (("vmware photon", "photon os", "photon"), "photon"),
        (("ubuntu",), "ubuntu"),
        (("debian",), "debian"),
        (("fedora", "epel"), "fedora"),
        (("centos",), "centos"),
        (("red hat",), "redhat"),
    )
    for needles, vendor in name_rules:
        if any(needle in name_text for needle in needles):
            return vendor
    # Bare RHEL is deliberately last.  It is meaningful for an actual RHEL row,
    # but must never outrank an AlmaLinux/Rocky identity found above.
    if re.search(r"\brhel(?:\d+)?\b", name_text):
        return "redhat"

    try:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
    except Exception:
        host = ""
    basis = host or (name or "repository")
    return re.sub(r"[^a-z0-9]+", "-", basis.lower()).strip("-") or "repository"


def vendor_display_name(vendor_id: str) -> str:
    return {
        "redhat": "Red Hat",
        "rocky": "Rocky Linux",
        "almalinux": "AlmaLinux",
        "docker": "Docker",
        "ubuntu": "Ubuntu",
        "debian": "Debian",
        "fedora": "Fedora / EPEL",
        "centos": "CentOS",
    }.get(vendor_id or "", (vendor_id or "Repository").replace("-", " ").title())


def repository_channel(repo: Any) -> str:
    """Return a conservative logical repository channel for mirror matching."""
    text = f"{getattr(repo, 'name', '')} {getattr(repo, 'url', '')}".lower()
    # Order more specific channels before generic words such as release/updates.
    aliases = (
        ("appstream", ("appstream",)),
        ("baseos", ("baseos",)),
        ("crb", ("/crb/", " crb", "crb ")),
        ("extras", ("/extras/", " extras", "extras ")),
        ("security", ("-security", " security", "/security")),
        ("backports", ("-backports", " backports", "/backports")),
        ("updates", ("-updates", " updates", "/updates/")),
        ("everything", ("everything",)),
        ("release", (" release", "/release/")),
    )
    for channel, needles in aliases:
        if any(n in text for n in needles):
            return channel
    return ""


def _component_set(repo: Any) -> frozenset[str]:
    return frozenset(str(getattr(repo, "components", "") or "main").split())


def repositories_are_exact_mirror_compatible(primary: Any, other: Any) -> bool:
    """Whether two configured repository objects describe the same archive slice."""
    repo_format = str(getattr(primary, "repo_format", "rpm") or "rpm")
    if repo_format != str(getattr(other, "repo_format", "rpm") or "rpm"):
        return False
    if repo_format == "pacman":
        # Arch mirrors are intentionally distributed across unrelated hostnames;
        # domain/vendor identity therefore cannot define mirror compatibility.
        # The ALPM repo name is the channel identity and selected-artifact byte
        # comparison remains the actual proof.
        return ((getattr(primary, "suite", "") or getattr(primary, "name", "") or "").strip().lower() ==
                (getattr(other, "suite", "") or getattr(other, "name", "") or "").strip().lower())
    pv = infer_vendor_id(getattr(primary, "name", ""), getattr(primary, "url", ""))
    ov = infer_vendor_id(getattr(other, "name", ""), getattr(other, "url", ""))
    if pv != ov:
        return False
    if repo_format == "apt":
        return ((getattr(primary, "suite", "") or "").strip() ==
                (getattr(other, "suite", "") or "").strip()
                and _component_set(primary) == _component_set(other))
    pc, oc = repository_channel(primary), repository_channel(other)
    if not pc or pc != oc:
        return False
    # The release is part of the archive identity when both sides know it.
    pr = str(getattr(primary, "target_release", "") or "").strip()
    or_ = str(getattr(other, "target_release", "") or "").strip()
    return not (pr and or_ and pr != or_)


def classify_relationship(primary: Any, evidence_url: str, *, evidence_repo: Any = None,
                          hint: str = "") -> str:
    pfmt = str(getattr(primary, "repo_format", "rpm") or "rpm")
    pv = infer_vendor_id(getattr(primary, "name", ""), getattr(primary, "url", ""))
    ev = infer_vendor_id(getattr(evidence_repo, "name", "") if evidence_repo else "", evidence_url)
    cross_vendor_el_peer = (
        pfmt == "rpm" and pv != ev and pv in EL_REBUILD_VENDORS and ev in EL_REBUILD_VENDORS
    )

    # A persisted/UI hint may come from an older catalog or application build.
    # AlmaLinux, Rocky Linux, and RHEL are independently rebuilt distributions;
    # one vendor's repository can never be an exact mirror of another vendor's
    # repository.  Refuse that impossible stale classification rather than
    # allowing it to change the runtime verification semantics.
    if hint == REL_EXACT_MIRROR and cross_vendor_el_peer:
        return REL_REBUILD_PEER
    if hint in {REL_EXACT_MIRROR, REL_EXACT_ARTIFACT, REL_REBUILD_PEER}:
        return hint
    if evidence_repo is not None and repositories_are_exact_mirror_compatible(primary, evidence_repo):
        return REL_EXACT_MIRROR
    if cross_vendor_el_peer:
        return REL_REBUILD_PEER
    # Unknown/manual sources can prove identical bytes, but Feathered does not call
    # them a mirror of the same archive without profile/configured-repo evidence.
    return REL_EXACT_ARTIFACT


def candidate_display_label(candidate: EvidenceCandidate) -> str:
    if candidate.relationship == REL_REBUILD_PEER:
        kind = "Semantic rebuild peer (Maximum only)"
    elif candidate.relationship == REL_EXACT_MIRROR:
        kind = "Exact mirror"
    else:
        kind = "Exact artifact"
    authority = {
        AUTH_INDEPENDENT: "independent operator",
        AUTH_SAME: "same authority",
        AUTH_UNKNOWN: "authority unknown",
    }.get(candidate.authority, "authority unknown")
    base = candidate.label.strip() or candidate.url
    return f"{kind} - {base} - {authority}"
