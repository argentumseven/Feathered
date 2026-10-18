"""Public-certificate metadata must not mask tampering or change the source being released."""
import hashlib
import json
from zipfile import ZipFile

import pytest

from finalize_self_signed_release import finalize
from prepare_release_assets import prepare
from verify_release_checksums import verify_distribution
import test_release_assets as fixtures

# Reuse the real Git/tag/distribution fixture without rebuilding a fake source tree.
release = fixtures.release


def certificate(root):
    # Metadata tests use controlled certificate bytes; the Windows workflow
    # validates the actual X.509 certificate and Authenticode leaf identity.
    public = root.parent / 'public.cer'
    public.write_bytes(b'controlled public certificate fixture')
    return public, hashlib.sha1(public.read_bytes()).hexdigest()


def test_public_certificate_is_covered_and_self_signed_download_is_explicit(release):
    root, commit = release
    public, thumbprint = certificate(root)
    original = (root / 'dist/RELEASE-MANIFEST.json').read_text()
    finalize(root / 'dist', public, thumbprint, commit, 'b' * 40)
    assert verify_distribution(root / 'dist')
    manifest = json.loads((root / 'dist/RELEASE-MANIFEST.json').read_text())
    assert manifest['signing']['kind'] == 'self-signed'
    assert manifest['build_mode'] == json.loads(original)['build_mode'] == 'release'
    assert manifest['source_commit'] == commit
    assert 'not a public CA identity' in (root / 'dist/SIGNING-NOTICE.txt').read_text()
    with pytest.raises(RuntimeError, match='explicitly selected'):
        prepare(root, 'v1.4.1')
    source, windows, cert_asset, sums = prepare(root, 'v1.4.1', self_signed=True)
    assert windows.name.endswith('_windows_x64_self_signed.zip')
    assert cert_asset.read_bytes() == public.read_bytes()
    with ZipFile(windows) as archive:
        assert archive.read('Feathered_1.4.1/Feathered-CodeSigning.cer') == public.read_bytes()
        assert 'Feathered_1.4.1/SIGNING-NOTICE.txt' in archive.namelist()
        assert not any(name.endswith(('.pfx', '.key')) for name in archive.namelist())
    for row in sums.read_text().splitlines():
        digest, name = row.split('  ')
        assert hashlib.sha256((sums.parent / name).read_bytes()).hexdigest() == digest


@pytest.mark.parametrize('mismatch', ['thumbprint', 'commit', 'tampered'])
def test_finalization_refuses_wrong_identity_or_existing_tampering(release, mismatch):
    root, commit = release
    public, thumbprint = certificate(root)
    if mismatch == 'thumbprint':
        thumbprint = '0' * 40
    elif mismatch == 'commit':
        commit = '0' * 40
    else:
        (root / 'dist/Feathered.exe').write_bytes(b'tampered')
    with pytest.raises(RuntimeError):
        finalize(root / 'dist', public, thumbprint, commit, 'b' * 40)
    assert not (root / 'dist/Feathered-CodeSigning.cer').exists()


def test_self_signed_option_cannot_relabel_an_unmarked_distribution(release):
    with pytest.raises(RuntimeError, match='certificate and signing notice'):
        prepare(release[0], 'v1.4.1', self_signed=True)
