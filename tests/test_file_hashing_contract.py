"""Public/private core hash entry points retain bytes, errors and patching seams."""
import hashlib
from types import SimpleNamespace

import pytest
import core


@pytest.mark.parametrize('entry', ['sha256_file', '_sha256_file', 'hash_file'])
@pytest.mark.parametrize('size', [0, 1024 * 1024 + 17])
def test_existing_hash_entry_points(entry, size, tmp_path):
    path = tmp_path / 'payload'
    content = (bytes(range(256)) * (size // 256 + 1))[:size]
    path.write_bytes(content)
    args = ('sha256',) if entry == 'hash_file' else ()
    assert getattr(core, entry)(path, *args) == hashlib.sha256(content).hexdigest()


@pytest.mark.parametrize('algorithm, reference', [('SHA', 'sha1'), ('SHA512', 'sha512'), ('', 'sha256')])
def test_generic_hash_algorithm_contract(tmp_path, algorithm, reference):
    path = tmp_path / 'payload'; path.write_bytes(b'payload')
    assert core.hash_file(path, algorithm) == hashlib.new(reference, b'payload').hexdigest()


@pytest.mark.parametrize('entry', ['sha256_file', '_sha256_file', 'hash_file'])
def test_core_constructor_patch_remains_visible(tmp_path, monkeypatch, entry):
    path = tmp_path / 'payload'; path.write_bytes(b'payload')
    seen = []
    class Digest:
        def update(self, data):
            seen.append(data)
        def hexdigest(self):
            return 'patched-digest'
    constructors = []
    def named():
        constructors.append('sha256')
        return Digest()
    def generic(algorithm):
        constructors.append(algorithm)
        return Digest()
    monkeypatch.setattr(core, 'hashlib', SimpleNamespace(sha256=named, new=generic))
    args = ('SHA',) if entry == 'hash_file' else ()
    assert getattr(core, entry)(path, *args) == 'patched-digest'
    assert seen == [b'payload']
    assert constructors == (['sha1'] if args else ['sha256'])


def test_invalid_algorithm_is_rejected_before_opening_missing_file(tmp_path):
    with pytest.raises(ValueError):
        core.hash_file(tmp_path / 'missing', 'not-a-digest')
    # Leading/trailing whitespace was never accepted by the raw hash helper.
    with pytest.raises(ValueError):
        core.hash_file(tmp_path / 'missing', ' sha256 ')


@pytest.mark.parametrize('entry', ['sha256_file', '_sha256_file', 'hash_file'])
def test_missing_file_error_is_preserved(tmp_path, entry):
    args = ('sha256',) if entry == 'hash_file' else ()
    with pytest.raises(FileNotFoundError):
        getattr(core, entry)(tmp_path / 'missing', *args)
