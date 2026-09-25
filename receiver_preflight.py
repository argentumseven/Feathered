"""Offline receiver checks. Standard library only; no network or shell evaluation."""
from __future__ import annotations
import json
import platform
from pathlib import Path
import subprocess
import sys


def query(argv):
    return subprocess.run(argv, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True).stdout


def installed(family):
    rows = {}
    if family == 'deb':
        for line in query(['dpkg-query', '-W', '-f=${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n']).splitlines():
            status, name, version, arch = line.split('\t')
            if status[:2] in {'ii', 'hi'}:
                rows[(name, arch)] = version
    elif family == 'rpm':
        for line in query(['rpm', '-qa', '--qf', '%{NAME}\t%{EPOCHNUM}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n']).splitlines():
            name, epoch, version, arch = line.split('\t')
            version = (epoch + ':' if epoch not in {'0', '(none)', ''} else '') + version
            rows.setdefault((name, arch), set()).add(version)
    elif family == 'arch':
        for line in query(['pacman', '-Q']).splitlines():
            name, version = line.split()
            rows[(name, '')] = version
    else:
        raise RuntimeError('Unknown installation contract family')
    return rows


# ---------------------------------------------------------------------------
# Target identity: architecture and release
# ---------------------------------------------------------------------------
# Debian-family architecture names differ from the kernel's machine names, and
# several are not one-to-one (armel userland runs on armv5-armv7 kernels; a
# 32-bit armhf userland on a 64-bit kernel reports aarch64). For deb targets the
# authoritative answer is therefore dpkg's own native architecture; the machine
# table is only the fallback for hosts that have no dpkg.
DEB_ARCH_MACHINES = {
    'amd64': {'x86_64'},
    'arm64': {'aarch64'},
    'i386': {'i386', 'i486', 'i586', 'i686'},
    'armhf': {'armv7l', 'armv8l'},
    'armel': {'armv5tel', 'armv5tejl', 'armv6l', 'armv7l'},
    'ppc64el': {'ppc64le'},
    'riscv64': {'riscv64'},
    's390x': {'s390x'},
}


def native_arch(family, machine=None):
    """(value, kind): dpkg's architecture for deb targets, else the kernel machine."""
    if machine is not None:
        return machine, 'machine'
    if family == 'deb':
        try:
            value = query(['dpkg', '--print-architecture']).strip()
        except (OSError, subprocess.CalledProcessError):
            value = ''
        if value:
            return value, 'dpkg'
    return platform.machine(), 'machine'


def arch_matches(expected, observed, kind):
    if kind == 'dpkg':
        return expected == observed
    return observed == expected or observed in DEB_ARCH_MACHINES.get(expected, set())


# os-release ID for each built-in profile. Custom repository profiles have no
# distribution identity to check.
PROFILE_OS_IDS = {
    'rhel': 'rhel', 'rocky': 'rocky', 'alma': 'almalinux', 'centos-stream': 'centos',
    'fedora': 'fedora', 'photon': 'photon', 'ubuntu': 'ubuntu', 'debian': 'debian',
    'devuan': 'devuan', 'arch': 'arch', 'artix': 'artix',
}
# How many leading version components identify one release. Enterprise Linux
# minor releases share a major stream; Ubuntu's identity is YY.MM.
RELEASE_COMPONENTS = {
    'rhel': 1, 'rocky': 1, 'alma': 1, 'centos-stream': 1, 'photon': 1,
    'fedora': 1, 'debian': 1, 'devuan': 1, 'ubuntu': 2,
}
# Moving targets whose os-release carries no stable release identity.
UNVERSIONED_RELEASES = {'', 'rolling', 'custom', 'testing', 'unstable', 'sid'}


def read_os_release(path=Path('/etc/os-release')):
    import shlex
    release = {}
    if path.is_file():
        for line in path.read_text().splitlines():
            if '=' in line and not line.startswith('#'):
                key, value = line.split('=', 1)
                parsed = shlex.split(value)
                release[key.lower()] = parsed[0] if parsed else ''
    return release


def _version_key(value, components):
    import re
    digits = re.findall(r'\d+', value or '')
    return tuple(digits[:components]) if len(digits) >= components else None


def check_target_release(contract, os_release):
    """Refuse a bundle built for a different distribution or release.

    The inventory-based check in main() only runs when a target inventory was
    captured, and inventory is optional. Without this, a bundle built for one
    release installs on another: APT or DNF then upgrades core libraries as
    dependencies of the requested packages, leaving a system that mixes two
    releases. That is an unsupported partial release upgrade, and it is hard to
    undo. Release upgrades belong to the vendor's own tooling.
    """
    target = contract.get('target') or {}
    profile = target.get('profile', '')
    expected_id = PROFILE_OS_IDS.get(profile)
    if not expected_id:
        return  # older contract, custom repositories, or unknown profile
    if not os_release:
        raise RuntimeError('Cannot read /etc/os-release to confirm this is a '
                           f"{target.get('distribution') or profile} target")
    actual_id = os_release.get('id', '')
    if actual_id != expected_id:
        raise RuntimeError(
            f"This bundle was built for {target.get('distribution') or profile} "
            f"(os-release ID {expected_id!r}) but this system reports ID {actual_id!r}. "
            'Rebuild the bundle for this distribution.')
    release = str(target.get('release', '')).strip()
    codename = str(target.get('codename', '')).strip().lower()
    if release.lower() in UNVERSIONED_RELEASES:
        return
    actual_codename = os_release.get('version_codename', '').lower()
    if profile in {'debian', 'devuan', 'ubuntu'} and codename and actual_codename \
            and codename not in UNVERSIONED_RELEASES and not codename[:1].isdigit():
        if codename != actual_codename:
            raise RuntimeError(
                f"This bundle was built for {target.get('distribution')} {release} ({codename}) "
                f"but this system is {actual_codename}. Installing it would mix two releases; "
                "rebuild the bundle for this release, or use the vendor's release-upgrade "
                'procedure against a mirrored repository.')
        return
    components = RELEASE_COMPONENTS.get(profile)
    if components is None:
        return
    wanted = _version_key(release, components)
    have = _version_key(os_release.get('version_id', ''), components)
    if wanted is None or have is None:
        return  # nothing comparable on one side; the native solver still decides
    if wanted != have:
        raise RuntimeError(
            f"This bundle was built for {target.get('distribution')} {release} but this "
            f"system reports version {os_release.get('version_id')}. Installing it would mix "
            "two releases; rebuild the bundle for this release, or use the vendor's "
            'release-upgrade procedure against a mirrored repository.')


def validate(contract, actual, post=False, machine=None):
    family = contract['family']
    expected_arch = contract.get('target', {}).get('arch', '')
    if expected_arch:
        observed, kind = native_arch(family, machine)
        if not arch_matches(expected_arch, observed, kind):
            raise RuntimeError(
                f'Target architecture differs from this bundle ({expected_arch} bundle, '
                f'{observed} receiver); rebuild for this receiver')
    required = contract['selected'] if post else contract.get('baseline_required', [])
    for package in required:
        key = (package['name'], '' if family == 'arch' else package['architecture'])
        installed_version = actual.get(key)
        if isinstance(installed_version, (set, frozenset, list, tuple)):
            present = package['version'] in installed_version
        else:
            present = installed_version == package['version']
        if not present:
            if post:
                raise RuntimeError(
                    'Resolved transaction was not installed exactly: '
                    f"{package['package_id']}. Capture this target and rebuild, "
                    'or install the baseline first.')
            raise RuntimeError(
                'Required baseline package identity is not present exactly: '
                f"{package['package_id']}. This differential bundle was built against the "
                'captured installed identity of that package and omits it; recapture the '
                'target or install that baseline first.')
    if not post and family == 'arch' and contract.get("arch_full_upgrade"):
        snapshot = contract.get('inventory')
        if snapshot is None:
            raise RuntimeError('This Arch bundle declares a captured full-upgrade plan but does not contain its inventory snapshot.')
        if {k[0]: v for k, v in actual.items()} != snapshot:
            raise RuntimeError('Arch installed state changed since capture. Re-collect the inventory and rebuild the full upgrade plan.')


def main():
    path = Path(sys.argv[1])
    contract = json.loads(path.read_text(encoding='utf-8'))
    if contract.get('schema') not in (1, 2):
        raise RuntimeError('Unsupported installation contract')
    import configparser
    import os
    release = read_os_release()
    if '--post' not in sys.argv[2:]:
        if os.environ.get('FEATHERED_ALLOW_RELEASE_MISMATCH') == '1':
            print('WARNING: FEATHERED_ALLOW_RELEASE_MISMATCH=1 set; target release check skipped.',
                  file=sys.stderr)
        else:
            try:
                check_target_release(contract, release)
            except RuntimeError as exc:
                raise RuntimeError(f'{exc} (Override only if you are certain: '
                                   'FEATHERED_ALLOW_RELEASE_MISMATCH=1.)') from None
    captured = contract.get('captured_target', {})
    for key in ['id', 'version_id', 'platform_id']:
        expected = captured.get(key)
        if expected and expected != 'unknown' and release.get(key) != expected:
            raise RuntimeError(f'Target {key} differs from the captured inventory; rebuild for this receiver')
    if contract.get('module_states') is not None:
        states = {}
        for path in sorted(Path('/etc/dnf/modules.d').glob('*.module')):
            parser = configparser.ConfigParser(interpolation=None); parser.read(path)
            for section in parser.sections():
                states[section] = dict(parser[section])
        if states != json.loads(contract['module_states']):
            raise RuntimeError('Module state differs from the captured inventory; rebuild for the active streams')
    validate(contract, installed(contract['family']), post='--post' in sys.argv[2:])
    print('Target installation contract checked.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)
