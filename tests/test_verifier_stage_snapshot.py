"""Source gates must not change the authenticated verifier before signing."""
import pytest

from verifier_stage_snapshot import record, verify


@pytest.fixture
def staged(tmp_path):
    root = tmp_path / 'verifier with spaces'
    root.mkdir()
    (root / 'gpgv.exe').write_bytes(b'authenticated verifier')
    (root / 'runtime.dll').write_bytes(b'authenticated runtime')
    snapshot = tmp_path / 'snapshot.json'
    record(root, snapshot)
    return root, snapshot


def test_unchanged_authenticated_staging_passes(staged):
    verify(*staged)


@pytest.mark.parametrize('change', ['tamper', 'missing', 'extra'])
def test_changed_staging_cannot_be_signed(staged, change):
    root, snapshot = staged
    if change == 'tamper':
        (root / 'runtime.dll').write_bytes(b'swapped runtime')
    elif change == 'missing':
        (root / 'runtime.dll').unlink()
    else:
        (root / 'unexpected.dll').write_bytes(b'extra runtime')
    with pytest.raises(RuntimeError):
        verify(root, snapshot)


def test_linked_staging_is_rejected(staged):
    root, snapshot = staged
    outside = root.parent / 'outside.dll'
    outside.write_bytes(b'outside runtime')
    (root / 'linked.dll').symlink_to(outside)
    with pytest.raises(RuntimeError, match='link/reparse'):
        verify(root, snapshot)


def test_incomplete_initial_verifier_cannot_be_sealed(tmp_path):
    root = tmp_path / 'incomplete'
    root.mkdir()
    (root / 'gpgv.exe').write_bytes(b'verifier without runtime')
    with pytest.raises(RuntimeError, match='incomplete'):
        record(root, tmp_path / 'snapshot.json')
