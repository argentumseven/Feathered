"""Freeze family precedence and retain late-bound backend monkeypatch seams."""
from types import SimpleNamespace
from pathlib import Path
import pytest
import core, apt_core, arch_core
from feathered_app.build_backend import BuildBackendMixin

BACKENDS = {'rpm': core, 'deb': apt_core, 'arch': arch_core}


def host(family):
    return SimpleNamespace(_is_arch=lambda: family == 'arch', _is_deb=lambda: family == 'deb')


@pytest.mark.parametrize('family', BACKENDS)
@pytest.mark.parametrize('operation', ('resolve', 'write_bundle', 'parse_target_inventory'))
def test_target_dispatch_retains_backend_hooks(monkeypatch, family, operation, tmp_path):
    sentinel = object()
    calls = []
    for key, backend in BACKENDS.items():
        def call(*args, key=key):
            calls.append((key, args))
            return sentinel
        monkeypatch.setattr(backend, operation, call)
    target = host(family)
    reporter = core.Reporter()
    options = core.BuildOptions()
    if operation == 'resolve':
        args = ([], [], 'x86_64', options, reporter)
        value = BuildBackendMixin._resolve_backend(target, *args)
    elif operation == 'write_bundle':
        args = (object(), tmp_path, options, reporter, {})
        value = BuildBackendMixin._write_bundle_backend(target, *args)
    else:
        args = (Path('inventory.txt'),)
        value = BuildBackendMixin._parse_target_inventory_backend(target, *args)
    assert value is sentinel
    assert calls == [(family, args)]


@pytest.mark.parametrize('family', BACKENDS)
@pytest.mark.parametrize('format', ('rpm', 'apt', 'pacman', 'auto'))
def test_repository_dispatch_precedence(monkeypatch, family, format):
    expected = 'arch' if format == 'pacman' or family == 'arch' else 'deb' if format == 'apt' or family == 'deb' else 'rpm'
    calls = []
    for key, backend in BACKENDS.items():
        monkeypatch.setattr(backend, 'load_repository', lambda *args, key=key: calls.append((key, args)) or [])
    repo = core.RepoSpec('fixture', 'https://example.test/repo/', repo_format=format)
    reporter = core.Reporter()
    args = (repo, {'x86_64'}, reporter)
    assert BuildBackendMixin._load_repository_backend(host(family), *args) == []
    assert calls == [(expected, args)]


def test_pacman_repository_does_not_query_host_predicates(monkeypatch):
    def unexpected():
        pytest.fail('Explicit pacman format must short-circuit the host predicates')
    target = SimpleNamespace(_is_arch=unexpected, _is_deb=unexpected)
    monkeypatch.setattr(arch_core, 'load_repository', lambda *args: [])
    assert BuildBackendMixin._load_repository_backend(target, core.RepoSpec(
        'fixture', 'https://example.test/', repo_format='pacman'), set(), core.Reporter()) == []
