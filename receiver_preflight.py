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
            rows[(name, arch)] = version
    elif family == 'arch':
        for line in query(['pacman', '-Q']).splitlines():
            name, version = line.split()
            rows[(name, '')] = version
    else:
        raise RuntimeError('Unknown installation contract family')
    return rows


def validate(contract, actual, post=False, machine=None):
    family = contract['family']
    expected_arch = contract.get('target', {}).get('arch', '')
    aliases = {'amd64': 'x86_64', 'arm64': 'aarch64'}
    if expected_arch and aliases.get(expected_arch, expected_arch) != (machine or platform.machine()):
        raise RuntimeError('Target architecture differs from this bundle; rebuild for this receiver')
    required = contract['selected'] if post else contract.get('baseline_required', [])
    for package in required:
        key = (package['name'], '' if family == 'arch' else package['architecture'])
        if actual.get(key) != package['version']:
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
    import shlex
    release = {}
    if Path('/etc/os-release').is_file():
        for line in Path('/etc/os-release').read_text().splitlines():
            if '=' in line and not line.startswith('#'):
                key, value = line.split('=', 1)
                parsed = shlex.split(value)
                release[key.lower()] = parsed[0] if parsed else ''
    captured = contract.get('captured_target', {})
    for key in ['id', 'version_id']:
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
