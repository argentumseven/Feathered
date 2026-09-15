import io
from pathlib import Path
import typing

import pytest

import arch_core
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


def test_trusted_receiver_rejects_symlinks_while_staging(tmp_path):
    source = tmp_path / 'bundle'
    destination = tmp_path / 'staged'
    source.mkdir()
    outside = tmp_path / 'outside.txt'
    outside.write_text('outside', encoding='utf-8')
    link = source / 'payload'
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip('symbolic links are unavailable on this platform')

    with pytest.raises(RuntimeError, match='symbolic link'):
        trusted_receiver._copy_bundle_tree(source, destination)


def test_trusted_receiver_installs_only_from_staged_tree(tmp_path, monkeypatch):
    source = tmp_path / 'bundle'
    source.mkdir()
    for name in [
        'bundle-index.json', 'bundle-index.json.asc',
        'verify-bundle.py', 'verify-bundle.py.asc', 'install-offline.sh',
    ]:
        (source / name).write_text(name, encoding='utf-8')
    keyring = tmp_path / 'operator.gpg'
    keyring.write_bytes(b'keyring')
    staging_base = tmp_path / 'staging'
    staging_base.mkdir()

    events = []
    monkeypatch.setattr(trusted_receiver, '_secure_temp_base', lambda: staging_base)
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
