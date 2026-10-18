"""Package verified tag artifacts for GitHub without changing the signed distribution."""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import re
import subprocess
from zipfile import ZIP_DEFLATED, ZipFile

from source_manifest import MANIFEST_NAME, is_excluded
from verify_release_checksums import sha256, verify_distribution
from write_source_manifest import build_manifest


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def source_version(root: Path) -> str:
    for node in ast.parse((root / 'core.py').read_text(encoding='utf-8')).body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == 'FEATHERED_VERSION'
                for target in node.targets):
            value = ast.literal_eval(node.value)
            if isinstance(value, str) and re.fullmatch(r'\d+\.\d+\.\d+', value):
                return value
    raise RuntimeError('Source does not declare a stable FEATHERED_VERSION')


def prepare(root: Path, tag: str, *, self_signed: bool = False) -> list[Path]:
    root = root.resolve()
    version = source_version(root)
    if tag != f'v{version}':
        raise RuntimeError(f'Tag {tag!r} does not match source version v{version}')
    commit = _git(root, 'rev-parse', '--verify', 'HEAD^{commit}')
    if _git(root, 'rev-parse', '--verify', f'refs/tags/{tag}^{{commit}}') != commit:
        raise RuntimeError('Release tag does not point to the checked-out commit')
    changed = _git(root, 'diff', '--name-only', '-z', 'HEAD').split('\0')
    if any(name and not is_excluded(name) for name in changed):
        raise RuntimeError('Refusing to package modified tracked source')

    sources = build_manifest(root)
    tracked = set(_git(root, 'ls-files', '-z').split('\0'))
    untracked = set(sources) - tracked
    if untracked:
        raise RuntimeError('Refusing to publish untracked source: ' + ', '.join(sorted(untracked)))
    manifest_path = root / MANIFEST_NAME
    if json.loads(manifest_path.read_text(encoding='utf-8')) != sources:
        raise RuntimeError('Source checksum manifest is stale')

    dist = root / 'dist'
    verify_distribution(dist)
    release = json.loads((dist / 'RELEASE-MANIFEST.json').read_text(encoding='utf-8'))
    if (release.get('build_mode') != 'release' or release.get('source_commit') != commit
            or release.get('feathered_version') != version):
        raise RuntimeError('Distribution is not a production build of this release commit/version')
    if not (dist / 'Feathered.exe').is_file():
        raise RuntimeError('Production executable is missing')
    signing = release.get('signing', {})
    if self_signed:
        certificate = dist / 'Feathered-CodeSigning.cer'
        if (signing.get('kind') != 'self-signed' or not certificate.is_file()
                or signing.get('certificate_sha256') != sha256(certificate)
                or not (dist / 'SIGNING-NOTICE.txt').is_file()):
            raise RuntimeError('Self-signed publication requires its certificate and signing notice')
    elif signing.get('kind') == 'self-signed':
        raise RuntimeError('Self-signed publication must be explicitly selected')
    notes = root / f'RELEASE-{version}.md'
    if not notes.is_file():
        raise RuntimeError('Version-specific release notes are missing')

    destination = root / 'build' / 'github-release'
    if destination.exists():
        raise RuntimeError('Release asset directory already exists; preserve or remove it before retrying')
    destination.mkdir(parents=True)
    prefix = f'Feathered_{version}/'
    source_zip = destination / f'Feathered_{version}.zip'
    with ZipFile(source_zip, 'w', ZIP_DEFLATED) as archive:
        for name in sorted(sources):
            archive.write(root / name, prefix + name)
        archive.write(manifest_path, prefix + MANIFEST_NAME)
    suffix = '_self_signed' if self_signed else ''
    windows_zip = destination / f'Feathered_{version}_windows_x64{suffix}.zip'
    with ZipFile(windows_zip, 'w', ZIP_DEFLATED) as archive:
        for path in sorted(dist.rglob('*')):
            if path.is_file():
                archive.write(path, prefix + path.relative_to(dist).as_posix())

    downloads = [source_zip, windows_zip]
    if self_signed:
        certificate_asset = destination / f'Feathered_{version}_CodeSigning.cer'
        certificate_asset.write_bytes((dist / 'Feathered-CodeSigning.cer').read_bytes())
        downloads.append(certificate_asset)
    sums = destination / 'SHA256SUMS.txt'
    rows = []
    for path in downloads:
        digest = sha256(path)
        rows.append(f'{digest}  {path.name}')
    sums.write_text('\n'.join(rows) + '\n', encoding='utf-8')
    return [*downloads, sums]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--self-signed', action='store_true', help='Label and include an explicitly self-signed certificate')
    args = parser.parse_args()
    for path in prepare(args.source_root, args.tag, self_signed=args.self_signed):
        print(path)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
