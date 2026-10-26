"""Bounded VKS image-building evidence, separate from OS package acquisition.

The historical Image Builder publishes a supported OS list per minor branch.
That is *not* an exact VKr, patch, architecture or VKS release support matrix.
Image Baker support must be checked against its release-specific schema/tooling;
no local static allowlist is used to claim compatibility for 1.35 and later.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re


BUILDER_UNSELECTED = ''
BUILDER_LEGACY = 'legacy-image-builder'
BUILDER_IMAGE_BAKER = 'image-baker'
BUILDERS = frozenset({BUILDER_UNSELECTED, BUILDER_LEGACY, BUILDER_IMAGE_BAKER})

LEGACY_SUPPORT = {
    31: frozenset({'photon-5', 'ubuntu-2204-efi'}),
    32: frozenset({'photon-5', 'ubuntu-2204-efi'}),
    33: frozenset({'photon-5', 'ubuntu-2204-efi', 'ubuntu-2404-efi'}),
    34: frozenset({'photon-5', 'ubuntu-2204-efi', 'ubuntu-2404-efi'}),
}
LEGACY_EVIDENCE = (
    'https://github.com/vmware/vks-image-builder/blob/release-1.{minor}/supported-context.json'
)
BUILDER_TRANSITION = 'https://github.com/vmware/vks-image-builder#deprecation-notice'
IMAGE_BAKER_EVIDENCE = (
    'https://blogs.vmware.com/cloud-foundation/2026/02/13/'
    'vsphere-kubernetes-service-3-6-rhel-support/'
)
# Historical +vmware.2 and current ---vmware.2-vkr.4 are both published.
EXACT_VKR = re.compile(r'^v?1\.(\d+)\.\d+(?:\+|---)vmware\.[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*$')


def vkr_minor(value: str) -> int | None:
    match = EXACT_VKR.fullmatch(value)
    return int(match.group(1)) if match else None


def legacy_os_target(distribution: str, release: str) -> str | None:
    if distribution == 'VMware Photon OS' and release.split('.')[0] == '5':
        return 'photon-5'
    if distribution == 'Ubuntu' and '.'.join(release.split('.')[:2]) in ('22.04', '24.04'):
        return 'ubuntu-' + ''.join(release.split('.')[:2]) + '-efi'
    if distribution == 'Red Hat Enterprise Linux (RHEL)' and release.split('.')[0] == '9':
        return 'rhel-9'
    return None


@dataclass(frozen=True)
class Compatibility:
    status: str
    message: str
    builder: str
    exact_vkr: str
    vks_release: str
    legacy_os_target: str | None = None
    evidence_url: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


def assess(distribution: str, release: str, *, vks_release: str = '',
           exact_vkr: str = '', builder: str = '') -> Compatibility:
    """Determine whether the specified OS is *listed*, never claim bake success.

    An absent field keeps the status unverified. A known historical exclusion
    is reported even if the intended VKS platform release has not been entered.
    """
    minor = vkr_minor(exact_vkr) if exact_vkr else None
    os_target = legacy_os_target(distribution, release)
    details = dict(builder=builder, exact_vkr=exact_vkr, vks_release=vks_release,
                   legacy_os_target=os_target)
    if not exact_vkr or not builder:
        return Compatibility('unverified', 'Enter the exact VKr and select its image builder. The offline OS package bundle remains usable independently.', **details)
    if minor is None or builder not in BUILDERS:
        return Compatibility('unverified', 'The exact VKr or image builder is not recognized; no image-building compatibility is established.', **details)
    if builder == BUILDER_LEGACY:
        if minor >= 35:
            return Compatibility('not_listed', 'The legacy VKS Image Builder ends at VKr 1.34; use Image Baker for 1.35+ and validate its exact release.',
                                 evidence_url=BUILDER_TRANSITION, **details)
        listed = LEGACY_SUPPORT.get(minor)
        if listed is None or os_target is None:
            return Compatibility('unverified', 'No matching historical branch/OS evidence is bundled for this target.', **details)
        evidence = LEGACY_EVIDENCE.format(minor=minor)
        if os_target not in listed:
            return Compatibility('not_listed', f'{os_target} is absent from the published release-1.{minor} Image Builder supported_os list. This does not prevent a generic package bundle.',
                                 evidence_url=evidence, **details)
        return Compatibility('os_listed', f'{os_target} appears on the release-1.{minor} Image Builder OS list; exact VKr patch, VKS release, architecture and actual bake are NOT verified.' +
                             ('' if vks_release else ' Enter the target VKS release.'),
                             evidence_url=evidence, **details)
    if minor < 35:
        return Compatibility('unverified', 'Image Baker compatibility for pre-1.35 VKr has not been established; the published legacy builder covers 1.31–1.34.',
                             evidence_url=BUILDER_TRANSITION, **details)
    return Compatibility('unverified', 'Image Baker is the 1.35+ path, but this exact VKr, OS image, architecture and schema are not verified. Validate against the installed Image Baker release.',
                         evidence_url=IMAGE_BAKER_EVIDENCE, **details)
