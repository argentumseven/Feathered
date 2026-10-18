"""Exercise workload isolation through the report writer without live network."""
import json
import sys
from types import SimpleNamespace

import apt_core
import core
from profiles import RepoTemplate
import verify_workload_matrix as drift
from workloads import WorkloadProfile


def test_vendor_failure_does_not_hide_distribution_workload(tmp_path, monkeypatch):
    base = RepoTemplate('base', 'https://example.invalid/base/', 'dependency', repo_format='apt')
    vendor = RepoTemplate('docker', 'https://example.invalid/docker/', 'docker', repo_format='apt')
    profile = SimpleNamespace(key='fixture', package_family='deb', arches=['amd64'],
                              init_systems=[], init_style='',
                              repos_factory=lambda release, arch: [base, vendor])
    catalog = {
        'native': WorkloadProfile('native', 'native', ['demo'], ''),
        'docker': WorkloadProfile('docker', 'docker', ['docker-ce'], '', requires_docker_repo=True),
    }
    loaded = []

    def load(repo, arches, reporter):
        loaded.append(repo.role)
        if repo.role == 'docker':
            raise RuntimeError('vendor does not publish this release')
        return [apt_core.DebPackage('demo', 'amd64', '1', 'demo.deb', 'sha256', '0' * 64, repo)]

    monkeypatch.setattr(drift.profiles_module, 'PROFILES', {'fixture': profile})
    monkeypatch.setattr(drift, 'discover_current_release', lambda *_: '1')
    monkeypatch.setattr(drift.workloads_module, 'load_workloads', lambda: catalog)
    monkeypatch.setattr(drift.apt_core, 'load_repository', load)
    output = tmp_path / 'report.json'
    monkeypatch.setattr(sys, 'argv', ['verify_workload_matrix.py', '--out', str(output)])
    assert drift.main() == 1
    report = json.loads(output.read_text())['fixture']['workloads']
    assert report['native/default']['status'] == 'ok'
    assert report['docker/default']['status'] == 'source-unavailable'
    assert 'vendor does not publish' in report['docker/default']['errors'][0]
    assert loaded == ['dependency', 'docker']


def test_flat_kubernetes_repository_reaches_loader(monkeypatch):
    from kubernetes_workflow import repository_template
    template = repository_template('deb', '1.35')
    profile = SimpleNamespace(key='fixture', package_family='deb')
    observed = []

    def load(repo, arches, reporter):
        assert repo.flat_repo and repo.suite == '/'
        assert repo.source_tier == 'workload'
        assert arches == {'amd64', 'all'}
        observed.append(repo.url)
        return []

    monkeypatch.setattr(drift.apt_core, 'load_repository', load)
    packages, errors = drift.load_universe(profile, '1', 'amd64', core.Reporter(),
                                         templates=[template])
    assert not errors
    assert observed == [template.url]


def test_cache_keeps_distinct_source_names_and_priorities(monkeypatch):
    from dataclasses import replace
    first = RepoTemplate('one', 'https://example.invalid/base/', 'dependency',
                         priority=10, repo_format='apt')
    second = replace(first, name='two', priority=20)
    profile = SimpleNamespace(key='fixture', package_family='deb')
    calls = []

    def load(repo, arches, reporter):
        calls.append(repo.name)
        return [apt_core.DebPackage('demo', 'amd64', '1', 'demo.deb', 'sha256', '0' * 64, repo)]

    monkeypatch.setattr(drift.apt_core, 'load_repository', load)
    cache = {}
    one, _ = drift.load_universe(profile, '1', 'amd64', core.Reporter(), templates=[first], cache=cache)
    two, _ = drift.load_universe(profile, '1', 'amd64', core.Reporter(), templates=[second], cache=cache)
    again, _ = drift.load_universe(profile, '1', 'amd64', core.Reporter(), templates=[first], cache=cache)
    assert calls == ['one', 'two']
    assert one[0].repo.name == 'one' and two[0].repo.name == 'two'
    assert one[0].repo.priority == 10 and two[0].repo.priority == 20
    assert again[0] is one[0]
