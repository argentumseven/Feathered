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
        'restricted': WorkloadProfile('restricted', 'restricted', ['demo'], '',
                                      supported_releases={'fixture': ['2']}),
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
    assert 'restricted/default' not in report
    assert 'vendor does not publish' in report['docker/default']['errors'][0]
    assert loaded == ['dependency', 'docker']


def test_disabled_opt_in_vendor_source_is_reported_without_false_drift(tmp_path, monkeypatch):
    base = RepoTemplate('Devuan', 'https://example.invalid/base/', 'dependency', repo_format='apt')
    disabled = RepoTemplate('Docker CE (Debian)', 'https://example.invalid/docker/', 'docker',
                            enabled=False, repo_format='apt', optional=True)
    profile = SimpleNamespace(key='devuan', package_family='deb', arches=['amd64'],
                              init_systems=['sysvinit', 'openrc', 'runit'], init_style='bundled-scripts',
                              repos_factory=lambda release, arch: [base, disabled])
    catalog = {'docker': WorkloadProfile('docker', 'docker', ['docker-ce'], '',
                                        requires_docker_repo=True)}

    def load(repo, arches, reporter):
        assert repo.role == 'dependency'
        return [apt_core.DebPackage('demo', 'amd64', '1', 'demo.deb', 'sha256', '0' * 64, repo)]

    monkeypatch.setattr(drift.profiles_module, 'PROFILES', {'devuan': profile})
    monkeypatch.setattr(drift, 'discover_current_release', lambda *_: 'excalibur')
    monkeypatch.setattr(drift.workloads_module, 'load_workloads', lambda: catalog)
    monkeypatch.setattr(drift.apt_core, 'load_repository', load)
    output = tmp_path / 'report.json'
    monkeypatch.setattr(sys, 'argv', ['verify_workload_matrix.py', '--out', str(output)])
    assert drift.main() == 0
    report = json.loads(output.read_text())['devuan']['workloads']
    for init in profile.init_systems:
        assert report[f'docker/{init}']['status'] == 'operator-source-required'
        assert report[f'docker/{init}']['roles'] == ['docker']


def test_blocked_rpm_report_identifies_failing_provider_branch():
    repo = core.RepoSpec('base', 'https://example.invalid/', repo_format='rpm')
    app = core.Package('app', 'x86_64', '0', '1', '1', 'app.rpm', 'sha256', '0' * 64,
                       repo, requires=[core.Requirement('missing')])
    workload = WorkloadProfile('fixture', 'fixture', ['app'], '')
    profile = SimpleNamespace(package_family='rpm', key='fedora', init_style='')
    outcome = drift.check_workload(workload, profile, [app], 'x86_64')
    assert outcome['status'] == 'blocked'
    assert outcome['unresolved'] == ['missing']
    assert outcome['unresolved_participants']
    assert outcome['conflict_participants'] == []


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


def test_rpm_provider_index_reused_only_for_identical_universe(monkeypatch):
    repo = core.RepoSpec('base', 'https://example.invalid/', repo_format='rpm')
    app = core.Package('app', 'x86_64', '0', '1', '1', 'app.rpm', 'sha256', '0' * 64, repo)
    dep = core.Package('dep', 'x86_64', '0', '1', '1', 'dep.rpm', 'sha256', '0' * 64, repo)
    counted = []
    original = core.build_provider_index

    def build(packages, reporter=None):
        counted.append(tuple(id(p) for p in packages))
        return original(packages, reporter)

    monkeypatch.setattr(core, 'build_provider_index', build)
    cached = drift.cached_rpm_index_builder()
    first = cached([app], core.Reporter())
    assert cached([app], core.Reporter()) is first
    assert cached([app, dep], core.Reporter()) is not first
    assert len(counted) == 2


def test_rpm_workloads_reuse_index_without_changing_outcomes(monkeypatch):
    repo = core.RepoSpec('base', 'https://example.invalid/', repo_format='rpm')
    package = core.Package('app', 'x86_64', '0', '1', '1', 'app.rpm', 'sha256', '0' * 64, repo)
    workload = WorkloadProfile('fixture', 'fixture', ['app'], '')
    profile = SimpleNamespace(package_family='rpm', key='alma', init_style='')
    calls = []
    original = core.build_provider_index

    def counted(packages, reporter=None):
        calls.append(1)
        return original(packages, reporter)

    monkeypatch.setattr(core, 'build_provider_index', counted)
    builder = drift.cached_rpm_index_builder()
    first = drift.check_workload(workload, profile, [package], 'x86_64',
                                 rpm_index_builder=builder)
    first_count = len(calls)
    second = drift.check_workload(workload, profile, [package], 'x86_64',
                                  rpm_index_builder=builder)
    second_count = len(calls)
    expected = drift.check_workload(workload, profile, [package], 'x86_64')
    assert first == second == expected
    assert first_count == second_count
    assert len(calls) > second_count
