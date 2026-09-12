"""Offline release snapshot for responsive first-use selectors.

These are advertised release identities, not a claim that every architecture or
repository is reachable. Live discovery and the user's cache remain authoritative.
Sources were checked 2026-09-10; no seed suppresses background refresh.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class ReleaseSeed:
    releases: tuple[str, ...]
    codenames: tuple[tuple[str, str], ...] = ()
    source: str = ""
    vendor_suites: tuple[tuple[str, str], ...] = ()


RELEASE_SEEDS: dict[str, ReleaseSeed] = {
    "rhel": ReleaseSeed(("10.2", "9.8", "8.10"), source="https://access.redhat.com/articles/red-hat-enterprise-linux-release-dates"),
    "rocky": ReleaseSeed(("10.2", "9.8", "8.10"), source="https://dl.rockylinux.org/pub/rocky/"),
    "alma": ReleaseSeed(("10.2", "9.8", "8.10"), source="https://wiki.almalinux.org/release-notes/"),
    "centos-stream": ReleaseSeed(("10-stream", "9-stream"), source="https://mirror.stream.centos.org/"),
    "fedora": ReleaseSeed(("44",), source="https://fedoraproject.org/workstation/download"),
    "photon": ReleaseSeed(("5.0",), source="https://github.com/vmware/photon/wiki/Downloading-Photon-OS"),
    "ubuntu": ReleaseSeed(("26.04", "24.04"), (("26.04", "resolute"), ("24.04", "noble")),
                          "https://archive.ubuntu.com/ubuntu/dists/"),
    "debian": ReleaseSeed(("trixie",), (("13", "trixie"),), "https://deb.debian.org/debian/dists/stable/Release"),
    "devuan": ReleaseSeed(("excalibur", "daedalus"), (("6", "excalibur"), ("5", "daedalus")),
                          "https://www.devuan.org/os/releases", (("excalibur", "trixie"), ("daedalus", "bookworm"))),
}
