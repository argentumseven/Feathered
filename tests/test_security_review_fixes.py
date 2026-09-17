import hashlib
import io
import json
import os
from pathlib import Path
import stat
import typing

import pytest

import arch_core
import artifact_cache
import core
import receiver_preflight
import repository_tools
import repository_transport
import trusted_receiver


def test_rpm_receiver_keeps_all_installed_versions(monkeypatch):
    output = (
        'kernel\t0\t6.1.1-1\tx86_64\n'
        'kernel\t0\t6.1.2-1\tx86_64\n'
    )
    monkeypatch.setattr(receiver_preflight, 'query', lambda argv: output)
    actual = receiver_preflight.installed('rpm')
    assert actual[('kernel', 'x86_64')] == {'6.1.1-1', '6.1.2-1'}

    package = {
        'name': 'kernel',
        'version': '6.1.1-1',
        'architecture': 'x86_64',
        'package_id': 'kernel-6.1.1-1.x86_64',
    }
    contract = {
        'family': 'rpm',
        'target': {'arch': 'x86_64'},
        'baseline_required': [package],
        'selected': [package],
    }
    receiver_preflight.validate(contract, actual, machine='x86_64')
    receiver_preflight.validate(contract, actual, post=True, machine='x86_64')


def _write_receiver_index(root, names):
    entries = []
    for name in names:
        data = (root / name).read_bytes()
        entries.append({
            'path': name,
            'sha256': hashlib.sha256(data).hexdigest(),
            'size': str(len(data)),
        })
    index = {
        'format': 'feathered-bundle-index/1',
        'file_count': len(entries),
        'total_bytes': sum(int(entry['size']) for entry in entries),
        'files': entries,
    }
    (root / 'bundle-index.json').write_text(json.dumps(index), encoding='utf-8')
    (root / 'bundle-index.json.asc').write_text('index-signature', encoding='utf-8')


def _make_receiver_bundle(root, extra_names=()):
    root.mkdir()
    (root / 'verify-bundle.py').write_text('print("verified")\n', encoding='utf-8')
    (root / 'verify-bundle.py.asc').write_text('verifier-signature', encoding='utf-8')
    for name in extra_names:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name, encoding='utf-8')
    _write_receiver_index(root, ['verify-bundle.py', 'verify-bundle.py.asc', *extra_names])


def test_trusted_receiver_rejects_symlinks_while_staging(tmp_path):
    source = tmp_path / 'bundle'
    destination = tmp_path / 'staged'
    source.mkdir()
    destination.mkdir()
    outside = tmp_path / 'outside.txt'
    outside.write_text('outside', encoding='utf-8')
    link = source / 'payload'
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip('symbolic links are unavailable on this platform')

    digest = hashlib.sha256(outside.read_bytes()).hexdigest()
    entries = [('payload', ('payload',), outside.stat().st_size, digest)]
    with pytest.raises(RuntimeError, match='symbolic link'):
        trusted_receiver._stage_indexed_files(
            source, destination, entries, outside.stat().st_size)


def test_trusted_receiver_rejects_keyring_inside_untrusted_bundle(tmp_path):
    source = tmp_path / 'bundle'
    source.mkdir()
    keyring = source / 'operator.gpg'
    keyring.write_bytes(b'keyring')

    with pytest.raises(RuntimeError, match='outside the untrusted bundle'):
        trusted_receiver.verify(source, keyring)


def test_trusted_receiver_rejects_oversized_bootstrap_before_authentication(tmp_path, monkeypatch):
    source = tmp_path / 'bundle'
    source.mkdir()
    for name in trusted_receiver._BOOTSTRAP_LIMITS:
        (source / name).write_bytes(b'x')
    (source / 'bundle-index.json').write_bytes(b'12345')
    limits = dict(trusted_receiver._BOOTSTRAP_LIMITS)
    limits['bundle-index.json'] = 4
    monkeypatch.setattr(trusted_receiver, '_BOOTSTRAP_LIMITS', limits)

    with pytest.raises(RuntimeError, match='pre-authentication size limit'):
        trusted_receiver._stage_bootstrap(source, tmp_path / 'staged')


def test_trusted_receiver_copies_only_files_from_authenticated_index(tmp_path, monkeypatch):
    source = tmp_path / 'bundle'
    _make_receiver_bundle(source, ['install-offline.sh', 'packages/needed.pkg'])
    (source / 'unlisted.bin').write_bytes(b'x' * 1024 * 1024)
    keyring = tmp_path / 'operator.gpg'
    keyring.write_bytes(b'keyring')
    observed = {}

    monkeypatch.setattr(trusted_receiver, '_authenticate_bootstrap', lambda directory, supplied: None)

    def fake_verify(directory, supplied_keyring):
        directory = Path(directory)
        observed['files'] = {
            path.relative_to(directory).as_posix()
            for path in directory.rglob('*') if path.is_file()
        }
        assert Path(supplied_keyring) == keyring.resolve()

    monkeypatch.setattr(trusted_receiver, '_verify_bundle', fake_verify)
    trusted_receiver.verify(source, keyring)

    assert 'packages/needed.pkg' in observed['files']
    assert 'unlisted.bin' not in observed['files']


def test_trusted_receiver_rejects_indexed_file_size_change_before_copy(tmp_path, monkeypatch):
    source = tmp_path / 'bundle'
    _make_receiver_bundle(source, ['payload.bin'])
    (source / 'payload.bin').write_bytes(b'payload changed after sealing')
    keyring = tmp_path / 'operator.gpg'
    keyring.write_bytes(b'keyring')
    monkeypatch.setattr(trusted_receiver, '_authenticate_bootstrap', lambda directory, supplied: None)

    with pytest.raises(RuntimeError, match='size does not match the signed index'):
        trusted_receiver.verify(source, keyring)


def test_trusted_receiver_installs_only_from_staged_tree(tmp_path, monkeypatch):
    source = tmp_path / 'bundle'
    _make_receiver_bundle(source, ['install-offline.sh'])
    keyring = tmp_path / 'operator.gpg'
    keyring.write_bytes(b'keyring')
    staging_base = tmp_path / 'staging'
    staging_base.mkdir()

    events = []
    monkeypatch.setattr(trusted_receiver, '_secure_temp_base', lambda: staging_base)
    monkeypatch.setattr(trusted_receiver, '_authenticate_bootstrap', lambda directory, supplied: None)
    monkeypatch.setattr(
        trusted_receiver,
        '_lock_stage_as_root',
        lambda root: events.append(('lock', Path(root))),
    )

    def fake_verify(directory, supplied_keyring):
        directory = Path(directory)
        events.append(('verify', directory))
        assert directory != source
        assert (directory / 'install-offline.sh').read_text(encoding='utf-8') == 'install-offline.sh'
        assert Path(supplied_keyring) == keyring.resolve()

    monkeypatch.setattr(trusted_receiver, '_verify_bundle', fake_verify)
    monkeypatch.setattr(
        trusted_receiver,
        '_cleanup_staging',
        lambda root, locked: events.append(('cleanup', Path(root), locked)),
    )

    def fake_run(argv, **kwargs):
        events.append(('run', list(argv), Path(kwargs.get('cwd'))))
        class Result:
            returncode = 0
        return Result()

    monkeypatch.setattr(trusted_receiver.subprocess, 'run', fake_run)
    trusted_receiver.verify(source, keyring, install=True)

    assert [event[0] for event in events] == ['lock', 'verify', 'run', 'cleanup']
    staged = events[1][1]
    assert staged.parent == events[0][1]
    assert events[2][1][0] == 'bash'
    assert Path(events[2][1][1]).parent == staged
    assert events[2][2] == staged


def test_artifact_cache_rejects_group_or_world_writable_root(tmp_path):
    if os.name == 'nt' or not hasattr(os, 'geteuid'):
        pytest.skip('POSIX ownership and mode checks are not available')
    root = tmp_path / '.feathered-cache'
    root.mkdir()
    root.chmod(0o777)
    with pytest.raises(RuntimeError, match='group- or world-writable'):
        artifact_cache._root(tmp_path)


def test_artifact_cache_rejects_root_owned_by_another_uid(tmp_path, monkeypatch):
    if os.name == 'nt' or not hasattr(os, 'geteuid'):
        pytest.skip('POSIX ownership checks are not available')
    root = tmp_path / '.feathered-cache'
    root.mkdir(mode=0o700)
    actual_uid = root.lstat().st_uid
    monkeypatch.setattr(artifact_cache.os, 'geteuid', lambda: actual_uid + 1)
    with pytest.raises(RuntimeError, match='owned by the current user'):
        artifact_cache._root(tmp_path)


def test_artifact_cache_tightens_safe_existing_permissions(tmp_path):
    if os.name == 'nt' or not hasattr(os, 'geteuid'):
        pytest.skip('POSIX ownership and mode checks are not available')
    root = tmp_path / '.feathered-cache'
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    assert artifact_cache._root(tmp_path) == root
    assert stat.S_IMODE(root.lstat().st_mode) == 0o700


def test_arch_stdlib_zstd_fallback_enforces_limit_while_streaming(monkeypatch):
    class FakeStdlibZstd:
        @staticmethod
        def ZstdFile(fileobj, mode='rb'):
            assert mode == 'rb'
            return io.BytesIO(b'12345')

        @staticmethod
        def decompress(data):
            raise AssertionError('unbounded decompress() must not be used')

    monkeypatch.setattr(core, 'zstd', None)
    monkeypatch.setattr(core, 'stdlib_zstd', FakeStdlibZstd)
    monkeypatch.setattr(core, 'MAX_METADATA_EXPANDED_BYTES', 4)

    with pytest.raises(RuntimeError, match='metadata limit'):
        arch_core._zstd_decompress(b'compressed')


def test_repository_transport_type_hints_are_resolvable():
    hints = typing.get_type_hints(repository_transport.credential_redirect_allow_origins)
    assert hints['return'] == set[str]


def test_repository_scan_rejects_package_symlink_outside_root(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    outside = tmp_path / 'outside.rpm'
    outside.write_bytes(b'not an rpm')
    link = root / 'demo.rpm'
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip('symbolic links are unavailable on this platform')

    with pytest.raises(RuntimeError, match='refuses symbolic links'):
        repository_tools.scan_repository_folder(root)


def _nested_quote(value: str, passes: int) -> str:
    import urllib.parse
    for _ in range(passes):
        value = urllib.parse.quote(value, safe='')
    return value


def test_repository_location_rejects_deeply_encoded_traversal():
    hostile = _nested_quote('../../secret.rpm', 8)
    with pytest.raises(RuntimeError, match='escapes the repository'):
        core.repo_relative_url('https://repo.example/rpm/release/', hostile)


def test_repository_location_fails_closed_on_excessive_encoding_depth():
    encoded = _nested_quote('Packages/tool.rpm', 20)
    with pytest.raises(RuntimeError, match='nested too deeply'):
        core.repo_relative_url('https://repo.example/rpm/release/', encoded)


def test_repository_location_rejects_nested_encoded_nul():
    hostile = _nested_quote('Packages/tool\x00.rpm', 5)
    with pytest.raises(RuntimeError, match='NUL byte'):
        core.repo_relative_url('https://repo.example/rpm/release/', hostile)


def test_source_runtime_installers_require_hashed_binary_lock():
    root = Path(__file__).resolve().parents[1]
    lock = (root / 'requirements-runtime.lock').read_text(encoding='utf-8')
    requirements = [line for line in lock.splitlines()
                    if line and not line.startswith('#') and '==' in line]
    assert requirements == ['zstandard==0.25.0 \\', 'PyYAML==6.0.3 \\']
    assert lock.count('--hash=sha256:') == 20

    run_gui = (root / 'run_gui.bat').read_text(encoding='utf-8')
    deps = (root / 'install_python_deps.bat').read_text(encoding='utf-8')
    linux = (root / 'linux_setup.py').read_text(encoding='utf-8')
    for text in (run_gui, deps, linux):
        assert '--require-hashes' in text
        assert '--only-binary=:all:' in text
        assert 'requirements-runtime.lock' in text
