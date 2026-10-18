"""Add the public certificate and explicit trust notice to an already verified signed build."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from verify_release_checksums import sha256, verify_distribution


def finalize(dist: Path, certificate: Path, thumbprint: str, commit: str, automation_commit: str) -> None:
    verify_distribution(dist)
    manifest_path = dist / 'RELEASE-MANIFEST.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    cert = certificate.read_bytes()
    if (manifest.get('build_mode') != 'release' or manifest.get('source_commit') != commit
            or re.fullmatch(r'[0-9a-f]{40}', commit) is None
            or re.fullmatch(r'[0-9a-f]{40}', automation_commit) is None
            or hashlib.sha1(cert).hexdigest().upper() != thumbprint.upper()):
        raise RuntimeError('Certificate fingerprint or production source identity does not match')
    public = dist / 'Feathered-CodeSigning.cer'
    notice = dist / 'SIGNING-NOTICE.txt'
    if public.exists() or notice.exists():
        raise RuntimeError('Preserve existing signing certificate/notice before retrying')
    public.write_bytes(cert)
    notice.write_text(
        f"Feathered {manifest['feathered_version']} - SELF-SIGNED code-signing certificate\n\n"
        'Windows does not automatically trust this publisher. The signature authenticates\n'
        'this build against the included public certificate; it is not a public CA identity.\n'
        'The release private key was generated on the ephemeral build worker and is not distributed.\n\n'
        f'Source commit: {commit}\nRelease automation commit: {automation_commit}\n'
        f'Certificate SHA-256: {sha256(public)}\nCertificate SHA-1 thumbprint: {thumbprint.upper()}\n',
        encoding='utf-8')
    manifest['signing'] = {
        'kind': 'self-signed', 'certificate_file': public.name,
        'certificate_sha256': sha256(public), 'certificate_thumbprint_sha1': thumbprint.upper(),
        'automation_commit': automation_commit,
    }
    paths = sorted((p for p in dist.rglob('*') if p.is_file()
                    and p not in {manifest_path, dist / 'SHA256SUMS.txt'}),
                   key=lambda p: p.relative_to(dist).as_posix())
    manifest['files'] = [{'path': p.relative_to(dist).as_posix(), 'bytes': p.stat().st_size,
                          'sha256': sha256(p)} for p in paths]
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    sums = [f"{row['sha256']}  {row['path']}" for row in manifest['files']]
    sums.append(f'{sha256(manifest_path)}  {manifest_path.name}')
    (dist / 'SHA256SUMS.txt').write_text('\n'.join(sums) + '\n', encoding='utf-8')
    verify_distribution(dist)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dist', required=True, type=Path)
    parser.add_argument('--certificate', required=True, type=Path)
    parser.add_argument('--thumbprint', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--automation-commit', required=True)
    args = parser.parse_args()
    finalize(args.dist, args.certificate, args.thumbprint, args.commit, args.automation_commit)
    print('Public certificate and self-signed notice are covered by distribution integrity metadata.')


if __name__ == '__main__':
    main()
