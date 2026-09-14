"""Observe actual hash reads and invalidation, not just ledger internals."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path

import pytest
import core
import artifact_digests as ledger
from tests.test_bundle_characterization import FAMILIES, characterize


def reader(reads):
    def read(path):
        reads.append(path)
        return hashlib.sha256(path.read_bytes()).hexdigest()
    return read


def test_scope_reuses_bytes_but_not_across_builds(tmp_path):
    path = tmp_path / 'payload'; path.write_bytes(b'original')
    reads = []; read = reader(reads)
    with ledger.digest_scope():
        expected = ledger.payload_sha256(path, read)
        assert ledger.payload_sha256(path, read) == expected
        with ledger.digest_scope():
            assert ledger.payload_sha256(path, read) == expected
        assert ledger.payload_sha256(path, read) == expected
        with ThreadPoolExecutor(1) as pool:
            assert pool.submit(ledger.payload_sha256, path, read).result() == expected
    assert ledger.payload_sha256(path, read) == expected
    assert len(reads) == 4


@pytest.mark.parametrize('mutation', ['overwrite', 'replace', 'delete'])
def test_changed_file_invalidates_even_with_original_size_and_mtime(tmp_path, mutation):
    path = tmp_path / 'payload'; path.write_bytes(b'original')
    reads = []; read = reader(reads)
    with ledger.digest_scope():
        first = ledger.payload_sha256(path, read)
        before = path.stat()
        if mutation == 'delete':
            path.unlink()
            with pytest.raises(FileNotFoundError):
                ledger.payload_sha256(path, read)
            return
        if mutation == 'replace':
            replacement = tmp_path / 'replacement'; replacement.write_bytes(b'modified')
            replacement.replace(path)
        else:
            path.write_bytes(b'modified')
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        assert ledger.payload_sha256(path, read) != first
        assert len(reads) == 2


def test_change_during_hash_is_not_remembered(tmp_path):
    path = tmp_path / 'payload'; path.write_bytes(b'original')
    reads = []; read = reader(reads)
    def changing_read(path):
        digest = read(path)
        path.write_bytes(b'modified')
        return digest
    with ledger.digest_scope():
        first = ledger.payload_sha256(path, changing_read)
        assert ledger.payload_sha256(path, read) != first
    assert len(reads) == 2


def test_exception_closes_scope(tmp_path):
    path = tmp_path / 'payload'; path.write_bytes(b'original')
    reads = []; read = reader(reads)
    with pytest.raises(RuntimeError), ledger.digest_scope():
        ledger.payload_sha256(path, read)
        raise RuntimeError('cancelled')
    ledger.payload_sha256(path, read)
    assert len(reads) == 2


def package(tmp_path, algo='sha256'):
    path = tmp_path / 'demo.rpm'; path.write_bytes(b'original')
    repo = core.RepoSpec('Fixture', tmp_path.as_uri() + '/', verification_strategy='checksum-required')
    pkg = core.Package('demo', 'x86_64', '0', '1', '1', path.name, algo,
                       hashlib.new(algo, path.read_bytes()).hexdigest(), repo, size=8)
    return pkg, path


@pytest.mark.parametrize('algo', ['sha256', 'sha512'])
def test_verification_reuse_and_controlled_rename(tmp_path, algo):
    pkg, path = package(tmp_path, algo)
    reads = []; read = reader(reads)
    with ledger.digest_scope():
        assert core.verify_package_artifact(pkg, path, core.BuildOptions(), core.Reporter())
        destination = tmp_path / 'published.rpm'
        ledger.publish_payload(path, destination)
        assert ledger.payload_sha256(destination, read) == hashlib.sha256(b'original').hexdigest()
        ledger.payload_sha256(destination, read)
    assert len(reads) == (0 if algo == 'sha256' else 1)


def test_failed_verification_does_not_leave_a_reusable_digest(tmp_path):
    pkg, path = package(tmp_path)
    reads = []; read = reader(reads)
    with ledger.digest_scope():
        core.verify_package_artifact(pkg, path, core.BuildOptions(), core.Reporter())
        pkg.checksum = '0' * 64
        with pytest.raises(RuntimeError, match='mismatch'):
            core.verify_package_artifact(pkg, path, core.BuildOptions(), core.Reporter())
        ledger.payload_sha256(path, read)
    assert len(reads) == 1


def test_failed_independent_evidence_does_not_cache_primary_digest(tmp_path, monkeypatch):
    pkg, path = package(tmp_path)
    pkg.repo.verification_strategy = 'full-corroboration'
    pkg.repo.evidence_urls = ['https://evidence.invalid/']
    def reject(*args):
        raise RuntimeError('independent mismatch')
    monkeypatch.setattr(core, '_verify_independent_evidence_payload', reject)
    reads = []; read = reader(reads)
    with ledger.digest_scope():
        with pytest.raises(RuntimeError, match='independent mismatch'):
            core.verify_package_artifact(pkg, path, core.BuildOptions(), core.Reporter())
        ledger.payload_sha256(path, read)
    assert len(reads) == 1


def test_mutation_between_verification_and_rename_forces_read(tmp_path):
    pkg, path = package(tmp_path)
    reads = []; read = reader(reads)
    with ledger.digest_scope():
        core.verify_package_artifact(pkg, path, core.BuildOptions(), core.Reporter())
        path.write_bytes(b'modified')
        destination = tmp_path / 'published.rpm'
        ledger.publish_payload(path, destination)
        assert ledger.payload_sha256(destination, read) == hashlib.sha256(b'modified').hexdigest()
    assert len(reads) == 1


@pytest.mark.parametrize('family', FAMILIES)
def test_fresh_build_hashes_each_payload_once_for_records(tmp_path, monkeypatch, family):
    reads = []
    original = core.hash_file
    def hashing(path, algo):
        reads.append((Path(path).name, algo))
        return original(path, algo)
    monkeypatch.setattr(core, 'hash_file', hashing)
    backend = FAMILIES[family][0]
    def reread(path):
        pytest.fail(f'Unexpected payload SHA256 reread: {path}')
    monkeypatch.setattr(core, 'sha256_file', reread)
    monkeypatch.setattr(backend, 'sha256_file', reread)
    characterize(tmp_path, monkeypatch, family, 'fresh')
    assert len(reads) == 2
    assert all(algo == 'sha256' for _, algo in reads)


def test_unavailable_windows_change_time_falls_back_to_reading(tmp_path, monkeypatch):
    path = tmp_path / 'payload'; path.write_bytes(b'original')
    monkeypatch.setattr(ledger, '_WINDOWS', True)
    monkeypatch.setattr(ledger, '_windows_change_time', lambda *args: None)
    reads = []; read = reader(reads)
    with ledger.digest_scope():
        first = ledger.payload_sha256(path, read)
        assert ledger.payload_sha256(path, read) == first
    assert len(reads) == 2


def test_final_seal_reads_bytes_independently_of_digest_ledger(tmp_path):
    import json
    pkg, path = package(tmp_path)
    with ledger.digest_scope():
        # Even a bad ledger entry cannot become the canonical bundle seal.
        ledger.remember_verified(path, ledger.begin_verification(path), {'sha256': '0' * 64})
        index = core.write_bundle_index(tmp_path, core.Reporter(), {})
        entries = json.loads(index.read_text())['files']
    assert next(item['sha256'] for item in entries if item['path'] == path.name) == pkg.checksum
