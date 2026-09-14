"""Exercise installed launchers with a real DEB and optional GUI startup.

Run after install_linux.sh, under Xvfb or a desktop for the GUI check. Requires
native dpkg fixture tools; missing tools fail this check rather than skipping it.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from build_spec import (BuildSpec, ContentSpec, ExactPackageRecord, OutputSpec,
                        RepositoryRecord, SourceSpec, TargetSpec)
from core import RepoSpec

ROOT = Path(__file__).resolve().parent


def check(root: Path, workspace: Path, cli_only: bool) -> None:
    for tool in ('dpkg-deb', 'dpkg-scanpackages'):
        if not shutil.which(tool):
            raise RuntimeError(f'{tool} is required for the Linux installed-client check')
    repo = workspace / 'fixture repository'
    index = repo / 'dists/stable/main/binary-amd64'
    index.mkdir(parents=True)
    (repo / 'pool').mkdir()
    control = workspace / 'package source/DEBIAN'
    control.mkdir(parents=True)
    (control / 'control').write_text('Package: demo-tool\nVersion: 1.0\nArchitecture: amd64\n'
        'Maintainer: Fixture <test@example.invalid>\nDescription: launcher fixture\n', encoding='utf-8')
    original = repo / 'pool/demo-tool_1.0_amd64.deb'
    subprocess.run(['dpkg-deb', '--build', str(control.parent), str(original)], check=True)
    raw = subprocess.run(['dpkg-scanpackages', '-m', 'pool', '/dev/null'], cwd=repo,
                         capture_output=True, check=True).stdout
    (index / 'Packages').write_bytes(raw)
    (repo / 'dists/stable/Release').write_text(
        'Suite: stable\nCodename: stable\nComponents: main\nArchitectures: amd64\nSHA256:\n '
        f'{hashlib.sha256(raw).hexdigest()} {len(raw)} main/binary-amd64/Packages\n', encoding='utf-8')
    row = RepoSpec('Local fixture', repo.as_uri() + '/', 'dependency', repo_format='apt',
                   suite='stable', components='main', allow_unverified_index=True)
    spec = BuildSpec(
        target=TargetSpec(distribution='Debian', release='12', arch='amd64'),
        content=ContentSpec(selection_mode='Choose packages', workload='Custom', exact_packages=(
            ExactPackageRecord('demo-tool', '1.0', 'dependency', row.name, 'amd64', row.source_identity),)),
        sources=SourceSpec(method='Custom repositories', repositories=(RepositoryRecord.capture(row),)),
        output=OutputSpec(directory='output bundles', folder_scheme='Custom label', folder_label='bundle',
                          folder_stamp='none', emit_repository=True))
    (workspace / 'saved request.json').write_text(spec.to_json(), encoding='utf-8')
    env = dict(os.environ)
    for name in ('DISPLAY', 'WAYLAND_DISPLAY', 'FEATHERED_PYTHON', 'PYTHONPATH'):
        env.pop(name, None)
    command = ['/bin/sh', str(root / 'run_cli.sh'), 'build', '--spec', 'saved request.json', '--quiet']
    declined = subprocess.run(command, cwd=workspace, env=env, capture_output=True, text=True, timeout=60)
    assert declined.returncode == 2, declined.stdout + declined.stderr
    assert not list((workspace / 'output bundles').rglob('*.deb'))
    built = subprocess.run(command + ['--accept-trust-findings'], cwd=workspace, env=env,
                           capture_output=True, text=True, timeout=60)
    assert built.returncode == 0, built.stdout + built.stderr
    payload = next((workspace / 'output bundles').rglob('*.deb'))
    assert payload.read_bytes() == original.read_bytes()
    manifest = json.loads((payload.parent / 'manifest.json').read_text())
    assert manifest['packages'][0]['sha256'] == hashlib.sha256(original.read_bytes()).hexdigest()
    assert (payload.parent / 'provenance.json').is_file()
    assert (payload.parent / 'ASSURANCE.txt').is_file()
    print('Installed CLI: decline=2, publication=0, real DEB bytes/checksum/provenance preserved; no display.')
    if not cli_only:
        gui_env = dict(os.environ)
        gui_env.pop('FEATHERED_PYTHON', None)
        gui_env.pop('PYTHONPATH', None)
        # Keep this validation from reading or migrating the operator's settings.
        gui_env['XDG_CONFIG_HOME'] = str(workspace / 'isolated GUI settings')
        subprocess.run(['/bin/sh', str(root / 'run_gui.sh'), '--check'], cwd=workspace,
                       env=gui_env, check=True, timeout=45)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli-only', action='store_true')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='Feathered installed client ') as name:
        check(ROOT, Path(name), args.cli_only)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
