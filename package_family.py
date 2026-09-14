"""Stable payload conventions; dependency and trust semantics stay in backends."""
from dataclasses import dataclass


@dataclass(frozen=True)
class PackageFamily:
    progress_label: str
    manifest_identity: str
    checksum_glob: str
    stale_message: str
    stale_log_first: bool = False
    log_reuse: bool = True


RPM = PackageFamily('RPM', 'nevra', '*.rpm',
                    'Cached file failed verification, re-fetching: ', stale_log_first=True)
DEB = PackageFamily('DEB', 'package_id', '*.deb', 'Healing corrupt cached DEB: ')
ARCH = PackageFamily('ALPM', 'package_id', '*.pkg.tar.*',
                     'Healing corrupt cached ALPM package: ', log_reuse=False)
