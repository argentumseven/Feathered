from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Sequence, Callable, Dict, List, Optional

from evidence_model import EvidenceCandidate, REL_EXACT_MIRROR, AUTH_INDEPENDENT


@dataclass
class RepoTemplate:
    name: str
    url: str
    role: str = "dependency"
    priority: int = 50
    enabled: bool = True
    note: str = ""
    target_release: str = ""
    repo_format: str = "rpm"
    suite: str = ""
    components: str = ""
    optional: bool = False
    # Expected numeric release identity from authenticated APT Release metadata.
    # Empty means the profile has no independent numeric identity to enforce.
    expected_release_version: str = ""
    # curated metadata-only peers for the
    # Source Bond UI. These are suggestions, not silently trusted/enabled.
    evidence_suggestions: Sequence[object] = field(default_factory=list)
    flat_repo: bool = False



@dataclass
class DistroProfile:
    key: str
    label: str
    release_url: Optional[str]
    release_pattern: str
    release_mode: str
    fixed_releases: List[str]
    arches: List[str]
    repos_factory: Callable[[str, str], List[RepoTemplate]]
    note: str = ""
    media_required: bool = False
    package_family: str = "rpm"
    release_codenames: Dict[str, str] = field(default_factory=dict)
    # Releases learned at runtime and confirmed to have a reachable repository.
    # Kept on the profile (not just in the combo widget) so switching targets
    # and back does not silently discard what was discovered.
    # How this distribution names its releases. Debian's identity is the
    # codename (trixie); Ubuntu's is the number (24.04). Feathered accepts either
    # for any target, but offers the one the distribution actually uses.
    release_style: str = "version"
    # Init systems the target may run. On Artix, service scripts are split
    # into per-init companion packages (<svc>-openrc/-runit/-s6/-dinit) in
    # galaxy, so the chosen init changes the package set. On Devuan, packages
    # carry their sysvinit scripts, so the choice is recorded and can add the
    # init's own packages but does not rename services.
    init_systems: List[str] = field(default_factory=list)
    init_style: str = ""  # "companion-packages" (Artix) or "bundled-scripts" (Devuan)
    discovered_versions: List[str] = field(default_factory=list)
    verified_versions: List[str] = field(default_factory=list)
    # Epoch timestamp/source for the last successful online release observation.
    # This lets the UI use cached last-known-good state immediately while
    # refreshing stale knowledge in the background.
    release_observed_at: float = 0.0
    release_source: str = ""
    archive_discovery_url: str = ""

    def known_versions(self) -> List[str]:
        """Every release this profile can offer, newest first.

        For codename-style distributions the identifier IS the codename, so the
        list is ordered by the version each codename corresponds to rather than
        alphabetically.
        """
        # Runtime discovery/cache is authoritative. Static fallback values are
        # used only by profiles whose identity is intrinsically fixed (for
        # example rolling/custom targets), never merged into fresh observations.
        if self.release_style == "codename":
            source = [v for v in self.discovered_versions if v]
            if not source:
                source = [v for v in self.fixed_releases if v]
            by_version = {name: version for version, name in self.release_codenames.items()
                          if "." in version or version.isdigit()}
            return sorted(set(source), key=lambda n: version_key(by_version.get(n, "0")), reverse=True)
        source = [v for v in self.discovered_versions if v]
        if not source:
            source = [v for v in self.fixed_releases if v]
        return sorted(set(source), key=version_key, reverse=True)

    def codename(self, release: str) -> str:
        return resolve_codename(release, self.release_codenames)


def resolve_codename(release: str, table: Dict[str, str]) -> str:
    """Map a release string such as '24.04.4' or '13.6' to its suite codename.

    Tries the exact release, then major.minor, then major. Falls back to the
    release itself so an unknown release produces a clearly wrong suite name in
    the URL rather than silently resolving to some other release's archive.
    """
    release = (release or "").strip()
    if release in table:
        return table[release]
    digits = re.findall(r"\d+", release)
    for candidate in (".".join(digits[:2]), digits[0] if digits else ""):
        if candidate and candidate in table:
            return table[candidate]
    return release


def discover_apt_releases(base_url: str, reporter=None, limit: int = 40, timeout: int = 45, workers: int = 1) -> Dict[str, str]:
    """Learn version -> codename by reading the archive itself.

    Release tables go stale the moment a distribution ships or promotes a new
    release. Every APT archive already publishes the mapping -- each
    dists/<suite>/Release carries both `Version` and `Codename` -- so Feathered
    reads it rather than guessing.

    Returns {version: codename}; empty on failure. Callers may then use only
    previously validated cached state or an operator-entered release.
    """
    from core import Reporter, fetch_bytes, url_join
    reporter = reporter or Reporter()
    root = base_url.rstrip("/") + "/"

    # Rolling aliases are the reliable path: several archives (deb.debian.org
    # among them) return 403 for a directory listing, but every archive serves
    # dists/stable/Release. Those aliases are also precisely what moves when a
    # release is promoted, so probing them is how Feathered notices that, say,
    # trixie has become stable and carries a version number now.
    suites = ["stable", "oldstable", "oldoldstable", "testing"]
    try:
        listing = fetch_bytes(url_join(root, "dists/"), reporter, retries=1, timeout=timeout).decode("utf-8", "replace")
    except Exception as exc:
        reporter.log(f"Release discovery: no directory listing for {root}dists/ ({exc}); "
                     "probing the rolling suite aliases instead.")
        listing = ""

    parser = _HrefParser()
    parser.feed(listing)
    for href in parser.hrefs:
        name = href.strip("/").split("/")[-1]
        # Skip rolling aliases and derived suites; a point release's own suite
        # is what carries an authoritative Version field.
        if not name or "." in name or name in {"unstable", "experimental", "devel", "sid",
                                               "stable", "oldstable", "oldoldstable", "testing"}:
            continue
        if any(name.endswith(sfx) for sfx in ("-updates", "-security", "-backports", "-proposed")):
            continue
        if name not in suites:
            suites.append(name)

    def read_suite(suite: str):
        try:
            raw = fetch_bytes(url_join(root, f"dists/{suite}/Release"), reporter,
                              retries=1, timeout=timeout)
        except Exception:
            return suite, "", ""
        version = codename = ""
        for line in raw.decode("utf-8", "replace").splitlines():
            if line.startswith("Version:"):
                version = line.split(":", 1)[1].strip()
            elif line.startswith("Codename:"):
                codename = line.split(":", 1)[1].strip()
            elif line.startswith("-----BEGIN PGP SIGNATURE"):
                break
        return suite, version, codename

    selected = suites[:limit]
    if workers > 1 and len(selected) > 1:
        # Startup self-healing can probe many distro codenames (Ubuntu in
        # particular has no useful stable/oldstable aliases). Parallelism keeps
        # the wall-clock bound close to ceil(limit/workers) * timeout while the
        # explicit refresh path retains deterministic single-threaded behavior.
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(workers, len(selected))) as pool:
            observations = list(pool.map(read_suite, selected))
    else:
        observations = [read_suite(suite) for suite in selected]

    discovered: Dict[str, str] = {}
    codenames_seen: Dict[str, str] = {}
    for suite, version, codename in observations:
        if codename:
            codenames_seen[suite] = codename
        if version and codename:
            discovered[version] = codename
            # Index the major series too, so "13" resolves as well as "13.2".
            major = version.split(".")[0]
            discovered.setdefault(major, codename)
    if codenames_seen:
        reporter.log("Release discovery: "
                     + ", ".join(f"{k}={v}" for k, v in sorted(codenames_seen.items())))
    if discovered:
        reporter.log(f"Release discovery: learned {len(discovered)} version/codename pair(s) from {root}")
    return discovered


def merge_codenames(table: Dict[str, str], discovered: Dict[str, str]) -> Dict[str, str]:
    """Discovered values win over previously known/cache-loaded mappings."""
    merged = dict(table)
    merged.update(discovered)
    return merged


class _HrefParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(); self.hrefs: List[str] = []
    def handle_starttag(self, tag: str, attrs):
        if tag.lower() != "a": return
        for key, value in attrs:
            if key.lower() == "href" and value: self.hrefs.append(value)


class _TableParser(HTMLParser):
    """Minimal HTML table reader used for distro-maintained release relations."""
    def __init__(self) -> None:
        super().__init__(); self.rows: List[List[str]] = []; self._row: Optional[List[str]] = None; self._cell: Optional[List[str]] = None
    def handle_starttag(self, tag: str, attrs):
        del attrs
        tag = tag.lower()
        if tag == "tr": self._row = []
        elif tag in {"td", "th"} and self._row is not None: self._cell = []
    def handle_data(self, data: str):
        if self._cell is not None: self._cell.append(data)
    def handle_endtag(self, tag: str):
        tag = tag.lower()
        if tag in {"td", "th"} and self._row is not None and self._cell is not None:
            self._row.append(" ".join("".join(self._cell).split())); self._cell = None
        elif tag == "tr" and self._row is not None:
            if self._row: self.rows.append(self._row)
            self._row = None; self._cell = None


def extract_devuan_debian_suites(text: str) -> Dict[str, str]:
    """Learn Devuan-codename -> Debian-codename relationships from devuan.org."""
    parser = _TableParser(); parser.feed(text)
    found: Dict[str, str] = {}
    for row in parser.rows:
        if len(row) < 5:
            continue
        left = re.match(r"([A-Za-z][A-Za-z0-9_-]*)\s*(?:\d+)?$", row[0].strip())
        right = re.match(r"([A-Za-z][A-Za-z0-9_-]*)", row[4].strip())
        if left and right and left.group(1).lower() not in {"devuan", "release"}:
            found[left.group(1).lower()] = right.group(1).lower()
    return found


def version_key(v: str):
    return tuple(int(x) for x in re.findall(r"\d+", v))


def extract_versions(text: str, pattern: str, mode: str = "href") -> List[str]:
    rx = re.compile(pattern, re.IGNORECASE)
    found = set()
    if mode == "href":
        parser = _HrefParser(); parser.feed(text)
        values = [h.strip("/") for h in parser.hrefs]
        for value in values:
            m = rx.fullmatch(value)
            if m: found.add(m.group(1) if m.groups() else value)
    else:
        visible = re.sub(r"<[^>]+>", " ", text)
        visible = re.sub(r"\s+", " ", visible)
        for m in rx.finditer(visible):
            found.add(m.group(1) if m.groups() else m.group(0))
    return sorted(found, key=version_key, reverse=True)


def _major(version: str) -> str:
    m = re.match(r"(\d+)", version)
    return m.group(1) if m else version


def _rhel_repos(version: str, arch: str) -> List[RepoTemplate]:
    major = _major(version)
    return [
        RepoTemplate("Docker CE Stable", f"https://download.docker.com/linux/rhel/{major}/{arch}/stable/",
                     "docker", 10, True, "Docker maps RHEL minor releases to the major repository.", version),
        RepoTemplate("RHEL BaseOS", "", "dependency", 40, False,
                     "Select the BaseOS repository from matching RHEL media or an entitled mirror.", version),
        RepoTemplate("RHEL AppStream", "", "dependency", 45, False,
                     "Select the AppStream repository from matching RHEL media or an entitled mirror.", version),
    ]


VAULT_NOTE = ("Vault mirror for superseded point releases. Enable this (and disable the live "
              "repository above) when the live archive no longer carries this point release.")


def _rocky_repos(version: str, arch: str) -> List[RepoTemplate]:
    major = _major(version)
    live = "https://download.rockylinux.org/pub/rocky"
    vault = "https://dl.rockylinux.org/vault/rocky"
    # Keep the legacy profile-level evidence hint inside the same US-only
    # boundary as the editable mirror catalog. The live UI now derives its
    # choices from mirror_catalogs/rocky.json, but older callers may still read
    # this compatibility suggestion.
    mirror = "https://ash.mirrors.clouvider.net/rocky"
    def rocky_mirror(release: str, channel: str) -> EvidenceCandidate:
        return EvidenceCandidate(
            f"{mirror}/{release}/{channel}/{arch}/os/",
            "Clouvider Ashburn Rocky mirror", REL_EXACT_MIRROR, AUTH_INDEPENDENT)
    return [
        RepoTemplate("Docker CE Stable", f"https://download.docker.com/linux/rhel/{major}/{arch}/stable/", "docker", 10, True,
                     "Docker RHEL-compatible packages.", version),
        RepoTemplate("Rocky BaseOS", f"{live}/{version}/BaseOS/{arch}/os/", "dependency", 40, True,
                     "Exact point release.", version, optional=True,
                     evidence_suggestions=[rocky_mirror(version, "BaseOS")]),
        RepoTemplate("Rocky AppStream", f"{live}/{version}/AppStream/{arch}/os/", "dependency", 45, True,
                     "Exact point release.", version, optional=True,
                     evidence_suggestions=[rocky_mirror(version, "AppStream")]),
        RepoTemplate("Rocky BaseOS (current stream)", f"{live}/{major}/BaseOS/{arch}/os/",
                     "dependency", 42, True,
                     "Major-version stream; resolves even when the exact point release directory "
                     "is not published.", version, optional=True,
                     evidence_suggestions=[rocky_mirror(major, "BaseOS")]),
        RepoTemplate("Rocky AppStream (current stream)", f"{live}/{major}/AppStream/{arch}/os/",
                     "dependency", 47, True, "Major-version stream fallback.", version, optional=True,
                     evidence_suggestions=[rocky_mirror(major, "AppStream")]),
        RepoTemplate("Rocky CRB", f"{live}/{version}/CRB/{arch}/os/", "dependency", 55, major != "8", "Optional dependency source.", version, optional=True),
        RepoTemplate("Rocky Extras", f"{live}/{version}/extras/{arch}/os/", "dependency", 60, True, "Distribution extras repository.", version, optional=True),
        # Once a point release is superseded it is moved off the live mirror.
        # Ship the vault locations pre-configured so recovering an exact older
        # target is a checkbox rather than a debugging session.
        RepoTemplate("Rocky BaseOS (vault)", f"{vault}/{version}/BaseOS/{arch}/os/", "dependency", 41, False, VAULT_NOTE, version, optional=True),
        RepoTemplate("Rocky AppStream (vault)", f"{vault}/{version}/AppStream/{arch}/os/", "dependency", 46, False, VAULT_NOTE, version, optional=True),
    ]


def _alma_repos(version: str, arch: str) -> List[RepoTemplate]:
    major = _major(version)
    # OSUOSL carries the AlmaLinux tree under the same relative
    # layout, making it a convenient evidence peer for the default CDN.
    evidence_base = "https://ftp.osuosl.org/pub/almalinux"
    return [
        RepoTemplate("Docker CE Stable", f"https://download.docker.com/linux/rhel/{major}/{arch}/stable/", "docker", 10, True,
                     "Docker RHEL-compatible packages.", version),
        RepoTemplate("AlmaLinux BaseOS", f"https://repo.almalinux.org/almalinux/{version}/BaseOS/{arch}/os/",
                     "dependency", 40, True, "Exact point release.", version, optional=True,
                     evidence_suggestions=[EvidenceCandidate(
                         f"{evidence_base}/{version}/BaseOS/{arch}/os/",
                         "OSU Open Source Lab AlmaLinux mirror", REL_EXACT_MIRROR, AUTH_INDEPENDENT)]),
        RepoTemplate("AlmaLinux AppStream", f"https://repo.almalinux.org/almalinux/{version}/AppStream/{arch}/os/",
                     "dependency", 45, True, "Exact point release.", version, optional=True,
                     evidence_suggestions=[EvidenceCandidate(
                         f"{evidence_base}/{version}/AppStream/{arch}/os/",
                         "OSU Open Source Lab AlmaLinux mirror", REL_EXACT_MIRROR, AUTH_INDEPENDENT)]),
        RepoTemplate("AlmaLinux BaseOS (current stream)", f"https://repo.almalinux.org/almalinux/{major}/BaseOS/{arch}/os/",
                     "dependency", 42, True,
                     "Major-version stream; resolves even when the exact point release directory "
                     "is not published.", version, optional=True,
                     evidence_suggestions=[EvidenceCandidate(
                         f"{evidence_base}/{major}/BaseOS/{arch}/os/",
                         "OSU Open Source Lab AlmaLinux mirror", REL_EXACT_MIRROR, AUTH_INDEPENDENT)]),
        RepoTemplate("AlmaLinux AppStream (current stream)", f"https://repo.almalinux.org/almalinux/{major}/AppStream/{arch}/os/",
                     "dependency", 47, True, "Major-version stream fallback.", version, optional=True,
                     evidence_suggestions=[EvidenceCandidate(
                         f"{evidence_base}/{major}/AppStream/{arch}/os/",
                         "OSU Open Source Lab AlmaLinux mirror", REL_EXACT_MIRROR, AUTH_INDEPENDENT)]),
        RepoTemplate("AlmaLinux CRB", f"https://repo.almalinux.org/almalinux/{version}/CRB/{arch}/os/", "dependency", 55, major != "8", "", version, optional=True),
        RepoTemplate("AlmaLinux Extras", f"https://repo.almalinux.org/almalinux/{version}/extras/{arch}/os/", "dependency", 60, True, "Distribution extras repository.", version, optional=True),
        RepoTemplate("AlmaLinux BaseOS (vault)", f"https://repo.almalinux.org/vault/{version}/BaseOS/{arch}/os/", "dependency", 41, False, VAULT_NOTE, version, optional=True),
        RepoTemplate("AlmaLinux AppStream (vault)", f"https://repo.almalinux.org/vault/{version}/AppStream/{arch}/os/", "dependency", 46, False, VAULT_NOTE, version, optional=True),
    ]


def _centos_repos(version: str, arch: str) -> List[RepoTemplate]:
    major = _major(version)
    stream = version if "stream" in version else f"{major}-stream"
    mirror = "https://ftp.osuosl.org/pub/centos-stream"
    def centos_mirror(channel: str) -> EvidenceCandidate:
        return EvidenceCandidate(
            f"{mirror}/{stream}/{channel}/{arch}/os/",
            "OSU Open Source Lab CentOS Stream mirror", REL_EXACT_MIRROR, AUTH_INDEPENDENT)
    return [
        RepoTemplate("Docker CE Stable", f"https://download.docker.com/linux/centos/{major}/{arch}/stable/", "docker", 10, True, "", version),
        RepoTemplate("CentOS Stream BaseOS", f"https://mirror.stream.centos.org/{stream}/BaseOS/{arch}/os/", "dependency", 40, True, "", version, evidence_suggestions=[centos_mirror("BaseOS")]),
        RepoTemplate("CentOS Stream AppStream", f"https://mirror.stream.centos.org/{stream}/AppStream/{arch}/os/", "dependency", 45, True, "", version, evidence_suggestions=[centos_mirror("AppStream")]),
        RepoTemplate("CentOS Stream CRB", f"https://mirror.stream.centos.org/{stream}/CRB/{arch}/os/", "dependency", 55, True, "", version, optional=True, evidence_suggestions=[centos_mirror("CRB")]),
    ]


def _fedora_repos(version: str, arch: str) -> List[RepoTemplate]:
    mirror = "https://ftp.osuosl.org/pub/fedora/linux"
    return [
        RepoTemplate("Docker CE Stable", f"https://download.docker.com/linux/fedora/{version}/{arch}/stable/", "docker", 10, True, "", version),
        RepoTemplate("Fedora Everything", f"https://download.fedoraproject.org/pub/fedora/linux/releases/{version}/Everything/{arch}/os/", "dependency", 40, True, "", version,
                     evidence_suggestions=[EvidenceCandidate(f"{mirror}/releases/{version}/Everything/{arch}/os/", "OSU Open Source Lab Fedora mirror", REL_EXACT_MIRROR, AUTH_INDEPENDENT)]),
        RepoTemplate("Fedora Updates", f"https://download.fedoraproject.org/pub/fedora/linux/updates/{version}/Everything/{arch}/", "dependency", 35, True, "", version,
                     evidence_suggestions=[EvidenceCandidate(f"{mirror}/updates/{version}/Everything/{arch}/", "OSU Open Source Lab Fedora mirror", REL_EXACT_MIRROR, AUTH_INDEPENDENT)]),
    ]


def _photon_repos(version: str, arch: str) -> List[RepoTemplate]:
    """Photon OS repositories.

    Photon publishes each channel as its own directory named
    photon_<channel>_<version>_<arch>, with repodata directly inside it. The
    previous pattern used photon_<version>_<arch> plus a trailing <arch>/
    component, which produced a path that does not exist on the mirror.
    """
    a = "x86_64" if arch == "x86_64" else arch
    base = "https://packages-prod.broadcom.com/photon"
    channels = [
        ("Photon Release", "release", 40, True),
        ("Photon Updates", "updates", 35, True),
        ("Photon Extras", "extras", 55, False),
    ]
    repos = []
    for label, channel, priority, enabled in channels:
        repos.append(RepoTemplate(
            label, f"{base}/{version}/photon_{channel}_{version}_{a}/", "dependency", priority,
            enabled, f"Photon {channel} channel.", version, optional=True))
    return repos


UBUNTU_CODENAMES: Dict[str, str] = {}


# Docker APT repositories are release-specific. Never silently substitute a
# different distribution suite: packages built for noble are not an acceptable
# stand-in for resolute merely because Docker had not yet published resolute
# when a static list was last edited. A missing exact suite should fail clearly
# at repository probing/resolution instead of cross-grading the target.
def docker_suite(codename: str) -> str:
    """Use exactly the target codename; vendor availability is probed live."""
    return codename


def _ubuntu_release_identity(version: str) -> str:
    """Return Ubuntu's signed base-release identity (YY.MM), if numeric."""
    match = re.match(r"^(\d+)\.(\d+)", (version or "").strip())
    return f"{match.group(1)}.{match.group(2)}" if match else ""


def _ubuntu_repos(version: str, arch: str) -> List[RepoTemplate]:
    codename = resolve_codename(version, UBUNTU_CODENAMES)
    # Only amd64 lives on archive.ubuntu.com; every other architecture Ubuntu
    # still publishes is served from the ports archive, security included.
    primary = arch in {"amd64", "i386"}
    os_base = "https://archive.ubuntu.com/ubuntu" if primary else "https://ports.ubuntu.com/ubuntu-ports"
    security_base = "https://security.ubuntu.com/ubuntu" if primary else "https://ports.ubuntu.com/ubuntu-ports"
    # Alternate mirrors of the same Ubuntu archive are the preferred evidence
    # relationship. They are expected to carry the same .deb artifacts for the
    # same suite/component/architecture; Feathered therefore uses exact-artifact
    # corroboration rather than comparing Ubuntu to a different distribution.
    # Non-amd64 ports remain manual until curated port-mirror peers are defined.
    evidence = [
        EvidenceCandidate("https://mirrors.edge.kernel.org/ubuntu", "Kernel.org Ubuntu mirror", REL_EXACT_MIRROR, AUTH_INDEPENDENT),
        EvidenceCandidate("https://ubuntu.osuosl.org/ubuntu", "OSU Open Source Lab Ubuntu mirror", REL_EXACT_MIRROR, AUTH_INDEPENDENT),
    ] if primary else []
    comps = "main restricted universe multiverse"
    return [
        RepoTemplate("Docker CE Stable", "https://download.docker.com/linux/ubuntu", "docker", 10, True,
                     "Docker's official Ubuntu APT repository.", version, "apt",
                     docker_suite(codename), "stable"),
        RepoTemplate(f"Ubuntu {codename}", os_base, "dependency", 40, True, "Base release repository.", version, "apt", codename, comps, expected_release_version=_ubuntu_release_identity(version), evidence_suggestions=evidence),
        RepoTemplate(f"Ubuntu {codename}-updates", os_base, "dependency", 40, True, "Stable updates.", version, "apt", f"{codename}-updates", comps, evidence_suggestions=evidence),
        RepoTemplate(f"Ubuntu {codename}-security", security_base, "dependency", 40, True, "Security updates.", version, "apt", f"{codename}-security", comps, evidence_suggestions=evidence),
        RepoTemplate(f"Ubuntu {codename}-backports", os_base, "dependency", 90, False, "Optional backports; disabled by default.", version, "apt", f"{codename}-backports", comps, True, evidence_suggestions=evidence),
    ]


DEBIAN_CODENAMES: Dict[str, str] = {}


def _debian_repos(version: str, arch: str) -> List[RepoTemplate]:
    codename = resolve_codename(version, DEBIAN_CODENAMES)
    # The release may be given as a codename now, so derive the major series
    # from the codename table rather than parsing digits out of the input.
    # _major("trixie") returns "trixie", which silently selected the wrong
    # component set for every codename-named release.
    major = _major(version)
    if not major.isdigit():
        by_codename = {name: ver for ver, name in DEBIAN_CODENAMES.items() if ver.isdigit()}
        major = by_codename.get(codename, "")
    comps = ("main contrib non-free non-free-firmware"
             if (not major or int(major) >= 12) else "main contrib non-free")
    # Debian evidence uses alternate mirrors of the same Debian archive. The
    # archive itself is mirrored byte-for-byte; a different distribution is not
    # treated as a generic Debian evidence source. Security remains manual because
    # Debian publishes it through the separate debian-security archive topology.
    evidence = [
        EvidenceCandidate("https://debian.osuosl.org/debian", "OSU Open Source Lab Debian mirror", REL_EXACT_MIRROR, AUTH_INDEPENDENT),
        EvidenceCandidate("https://mirrors.mit.edu/debian", "MIT Debian mirror", REL_EXACT_MIRROR, AUTH_INDEPENDENT),
    ]
    return [
        RepoTemplate("Docker CE Stable", "https://download.docker.com/linux/debian", "docker", 10, True,
                     "Docker's official Debian APT repository.", version, "apt",
                     docker_suite(codename), "stable"),
        RepoTemplate(f"Debian {codename}", "https://deb.debian.org/debian", "dependency", 40, True, "Base release repository.", version, "apt", codename, comps, evidence_suggestions=evidence),
        RepoTemplate(f"Debian {codename}-updates", "https://deb.debian.org/debian", "dependency", 40, True, "Stable updates.", version, "apt", f"{codename}-updates", comps, evidence_suggestions=evidence),
        # APT source configuration uses the canonical component names here.
        # Debian security's Release metadata historically advertises semantic
        # names such as "updates/main" while its signed checksum paths and
        # actual indexes live at "main/binary-<arch>/...". apt_core therefore
        # treats Components: as identity metadata, not as a filesystem prefix.
        RepoTemplate(f"Debian {codename}-security", "https://security.debian.org/debian-security",
                     "dependency", 40, True, "Security updates.", version, "apt",
                     f"{codename}-security", comps),
        RepoTemplate(f"Debian {codename}-backports", "https://deb.debian.org/debian", "dependency", 90, False, "Optional backports; disabled by default.", version, "apt", f"{codename}-backports", comps, True, evidence_suggestions=evidence),
    ]



DEVUAN_CODENAMES: Dict[str, str] = {}

# Each Devuan release tracks a Debian codename; used only for vendor
# repositories (e.g. Docker CE) that publish Debian suites but no Devuan ones.
DEVUAN_TO_DEBIAN: Dict[str, str] = {}


def _devuan_repos(version: str, arch: str) -> List[RepoTemplate]:
    """Devuan merged archive. Unlike Debian, updates and security live in the
    same merged archive with plain components (no updates/ prefix)."""
    codename = resolve_codename(version, DEVUAN_CODENAMES)
    # Devuan 4/Chimaera tracks Debian 11, before non-free-firmware became a
    # separate archive component.  Newer Devuan releases publish it explicitly.
    major = _major(version)
    old_component_layout = codename == "chimaera" or (major.isdigit() and int(major) <= 4)
    comps = ("main contrib non-free" if old_component_layout
             else "main contrib non-free non-free-firmware")
    evidence = [
        EvidenceCandidate("https://pkgmaster.devuan.org/merged", "Devuan package master (mirror network origin)", REL_EXACT_MIRROR, AUTH_INDEPENDENT),
    ]
    debian_suite = DEVUAN_TO_DEBIAN.get(codename, "")
    rows = [
        RepoTemplate(f"Devuan {codename}", "http://deb.devuan.org/merged", "dependency", 40, True,
                     "Devuan merged base release repository (systemd-free; Devuan recommends deb.devuan.org over http).",
                     version, "apt", codename, comps, evidence_suggestions=evidence),
        RepoTemplate(f"Devuan {codename}-updates", "http://deb.devuan.org/merged", "dependency", 40, True,
                     "Stable updates from the same merged archive.", version, "apt", f"{codename}-updates", comps, evidence_suggestions=evidence),
        RepoTemplate(f"Devuan {codename}-security", "http://deb.devuan.org/merged", "dependency", 40, True,
                     "Security updates. Devuan publishes security in the merged archive with plain components.",
                     version, "apt", f"{codename}-security", comps, evidence_suggestions=evidence),
    ]
    if debian_suite:
        rows.insert(0, RepoTemplate(
            "Docker CE Stable (Debian packages)", "https://download.docker.com/linux/debian", "docker", 10, False,
            f"Docker publishes no Devuan repository. These are the Debian {debian_suite} packages, which install on "
            f"Devuan {codename} but ship systemd unit files only; you must provide the init scripts for your init "
            "system (sysvinit/openrc/runit). Disabled until you opt in.",
            version, "apt", docker_suite(debian_suite), "stable", True))
    return rows


# Artix mirrors carrying the main repository set. Do not anchor the defaults to
# mirror1.artixlinux.org: it has repeatedly been absent/broken while the official
# mirror list continued to publish healthy peers.  The canonical source is the
# artix-mirrorlist package maintained by Artix itself.
ARTIX_MIRRORLIST_URL = (
    "https://gitea.artixlinux.org/packages/artix-mirrorlist/raw/branch/master/mirrorlist"
)
ARTIX_MIRRORS = [
    # US-only mirrors verified/current in August 2026. Keep this compatibility
    # list aligned with mirror_catalogs/artix.json; the catalog is authoritative
    # for automatic evidentiary choices.
    "https://artix.wheaton.edu/repos",
    "https://mirror.clarkson.edu/artix-linux/repos",
    "https://mirrors.lug.mtu.edu/artixlinux",
    "https://mirrors.ocf.berkeley.edu/artix-linux",
]

ARTIX_MIRROR_NOTE = (
    "If this mirror fails, edit the URL and choose another server from Artix's official "
    "mirrorlist. Feathered expects the mirrorlist's $repo/os/$arch layout; for this row "
    "that becomes <mirror>/<name>/os/<arch>/. Canonical list: " + ARTIX_MIRRORLIST_URL)


def _artix_repos(version: str, arch: str) -> List[RepoTemplate]:
    """Official Artix Linux repositories (systemd-free pacman target).

    Artix replaces Arch core with system; galaxy carries Artix-specific
    additions and init-script packages (<name>-openrc/-runit/-s6/-dinit)."""
    base = ARTIX_MIRRORS[0]
    return [
        RepoTemplate("Artix system", f"{base}/system/os/{arch}/", "dependency", 40, True,
                     "Official Artix system repository (replaces Arch core; never mix Arch core into an Artix target). " + ARTIX_MIRROR_NOTE,
                     "rolling", "pacman", "system"),
        RepoTemplate("Artix world", f"{base}/world/os/{arch}/", "dependency", 45, True,
                     "Official Artix world repository. " + ARTIX_MIRROR_NOTE, "rolling", "pacman", "world"),
        RepoTemplate("Artix galaxy", f"{base}/galaxy/os/{arch}/", "dependency", 50, True,
                     "Official Artix galaxy repository: Artix additions and per-init service scripts "
                     "(e.g. docker-openrc, docker-runit, docker-s6, docker-dinit).", "rolling", "pacman", "galaxy"),
        RepoTemplate("Artix lib32", f"{base}/lib32/os/{arch}/", "dependency", 80, False,
                     "Optional 32-bit support repository; disabled by default.", "rolling", "pacman", "lib32", optional=True),
    ]


def _arch_repos(version: str, arch: str) -> List[RepoTemplate]:
    """Official Arch Linux rolling repositories for the supported x86_64 target."""
    base = "https://fastly.mirror.pkgbuild.com"
    return [
        RepoTemplate("Arch Linux core", f"{base}/core/os/{arch}/", "dependency", 40, True,
                     "Official Arch Linux core repository on Arch's Fastly mirror.",
                     "rolling", "pacman", "core"),
        RepoTemplate("Arch Linux extra", f"{base}/extra/os/{arch}/", "dependency", 45, True,
                     "Official Arch Linux extra repository on Arch's Fastly mirror.",
                     "rolling", "pacman", "extra"),
        RepoTemplate("Arch Linux multilib", f"{base}/multilib/os/{arch}/", "dependency", 80, False,
                     "Official optional multilib repository; disabled by default.",
                     "rolling", "pacman", "multilib", optional=True),
    ]

def _custom_repos(version: str, arch: str) -> List[RepoTemplate]:
    return []


PROFILES: Dict[str, DistroProfile] = {
    "rhel": DistroProfile(
        "rhel", "Red Hat Enterprise Linux (RHEL)",
        "https://access.redhat.com/articles/red-hat-enterprise-linux-release-dates",
        r"RHEL\s+(\d+\.\d+)", "text", [],
        ["x86_64", "aarch64", "s390x"], _rhel_repos,
        "Choose the exact target minor release. Docker uses the matching major repository; OS dependencies should come from matching RHEL BaseOS/AppStream media or an entitled mirror.",
        media_required=True,
    ),
    "rocky": DistroProfile(
        "rocky", "Rocky Linux", "https://download.rockylinux.org/pub/rocky/", r"(\d+\.\d+)", "href",
        [], ["x86_64", "aarch64", "ppc64le", "s390x"], _rocky_repos,
        "Uses Docker's RHEL-compatible CE packages plus Rocky repositories.",
    ),
    "alma": DistroProfile(
        "alma", "AlmaLinux", "https://repo.almalinux.org/almalinux/", r"(\d+\.\d+)", "href",
        [], ["x86_64", "aarch64", "ppc64le", "s390x"], _alma_repos,
        "Uses Docker's RHEL-compatible CE packages plus AlmaLinux repositories.",
    ),
    "centos-stream": DistroProfile(
        "centos-stream", "CentOS Stream", "https://mirror.stream.centos.org/", r"(\d+-stream)", "href",
        [], ["x86_64", "aarch64", "ppc64le"], _centos_repos,
    ),
    "fedora": DistroProfile(
        "fedora", "Fedora", "https://dl.fedoraproject.org/pub/fedora/linux/releases/", r"(\d+)", "href",
        [], ["x86_64", "aarch64", "ppc64le"], _fedora_repos,
    ),
    "photon": DistroProfile(
        "photon", "VMware Photon OS", "https://github.com/vmware/photon/releases", r"(\d+\.\d+)\s+GA", "text", [], ["x86_64", "aarch64"], _photon_repos,
        "Photon uses its own RPM repository and package naming.",
    ),
    "ubuntu": DistroProfile(
        "ubuntu", "Ubuntu", "https://www.releases.ubuntu.com/releases/", r"Ubuntu\s+(\d+\.\d+(?:\.\d+)?)", "text",
        [],
        ["amd64", "arm64", "armhf", "ppc64el", "s390x", "riscv64"], _ubuntu_repos,
        "APT/DEB target. Point releases map to their Ubuntu codename; dependency resolution uses release, updates and security repositories for that codename.",
        package_family="deb", release_codenames=UBUNTU_CODENAMES,
        archive_discovery_url="https://archive.ubuntu.com/ubuntu",
    ),
    "debian": DistroProfile(
        "debian", "Debian", "https://www.debian.org/releases/", r"version\s+(\d+(?:\.\d+)?)", "text",
        [],
        ["amd64", "arm64", "armhf", "ppc64el", "s390x", "riscv64", "i386"], _debian_repos,
        "APT/DEB target. Debian point releases use the same codename archive; for byte-for-byte historical package sets use a Debian snapshot/local mirror.",
        package_family="deb", release_codenames=DEBIAN_CODENAMES,
        # Debian's release identity is the codename, not the point number.
        release_style="codename",
        archive_discovery_url="https://deb.debian.org/debian",
    ),
    "arch": DistroProfile(
        "arch", "Arch Linux", None, r"(.+)", "href", ["rolling"],
        ["x86_64"], _arch_repos,
        "Rolling-release pacman/ALPM target. Feathered reads native core/extra repository databases and accepts packages built for x86_64 or any.",
        package_family="arch", release_style="rolling",
    ),
    "artix": DistroProfile(
        "artix", "Artix Linux", None, r"(.+)", "href", ["rolling"],
        ["x86_64"], _artix_repos,
        "Systemd-free rolling pacman/ALPM target using Artix system/world/galaxy repositories. Package names follow "
        "Arch; service scripts for your init system come from galaxy as <name>-openrc/-runit/-s6/-dinit packages, "
        "which you can add via Exact packages or Custom packages.",
        package_family="arch", release_style="rolling",
        init_systems=["openrc", "runit", "s6", "dinit"], init_style="companion-packages",
    ),
    "devuan": DistroProfile(
        "devuan", "Devuan", "https://www.devuan.org/os/releases", r"(.+)", "href",
        [],
        ["amd64", "arm64", "armhf", "armel", "ppc64el", "riscv64", "i386"], _devuan_repos,
        "Systemd-free APT/DEB target using the Devuan merged archive. Package names follow Debian; packages "
        "requiring systemd (e.g. Cockpit) are not available and will be reported unresolved.",
        package_family="deb", release_codenames=DEVUAN_CODENAMES,
        release_style="codename",
        archive_discovery_url="https://pkgmaster.devuan.org/merged",
        init_systems=["sysvinit", "openrc", "runit"], init_style="bundled-scripts",
    ),
    "custom-rpm": DistroProfile(
        "custom-rpm", "Custom RPM repositories", None, r"(.+)", "href", ["custom"],
        ["x86_64", "aarch64", "s390x", "ppc64le"], _custom_repos,
        "Add one or more repository roots containing repodata/repomd.xml.", package_family="rpm",
    ),
    "custom-apt": DistroProfile(
        "custom-apt", "Custom APT repositories", None, r"(.+)", "href", ["custom"],
        ["amd64", "arm64", "armhf", "ppc64el", "s390x", "riscv64", "i386"], _custom_repos,
        "Add APT repository roots plus suite/codename and components. The repository should expose dists/<suite>/Release or InRelease.", package_family="deb",
    ),
}


def profile_by_label(label: str) -> DistroProfile:
    for p in PROFILES.values():
        if p.label == label: return p
    return PROFILES["rhel"]
