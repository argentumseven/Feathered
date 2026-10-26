"""Exercise workload isolation through the report writer without live network."""
import json
import sys
from types import SimpleNamespace

import apt_core
import core
import profiles
from profiles import RepoTemplate
import verify_workload_matrix as drift
from workloads import WorkloadProfile


def test_live_devuan_release_discovery_restores_disabled_docker_opt_in_source(monkeypatch):
    """Use Devuan's documented Debian-suite table, not a compiled codename."""
    profile = profiles.PROFILES['devuan']
    published_table = '''<table><tr><th>Devuan release</th><th>Suite</th><th>Released</th>
    <th>Planet nr.</th><th>Debian release</th></tr>
    <tr><td>Excalibur 6</td><td>stable</td><td>2025-11-02</td><td>9499</td>
    <td>Trixie 13</td></tr></table>'''
    monkeypatch.setattr(profiles, 'DEVUAN_TO_DEBIAN', {})
    monkeypatch.setattr(drift.profiles_module, 'discover_apt_releases',
                        lambda *_args, **_kwargs: {'6.0': 'excalibur'})
    monkeypatch.setattr(drift, 'fetch_text', lambda url, _: published_table)
    assert drift.discover_current_release(profile, core.Reporter()) == 'excalibur'
    optional = [row for row in profile.repos_factory('excalibur', 'amd64')
                if row.role == 'docker']
    assert len(optional) == 1
    assert not optional[0].enabled and optional[0].optional
    assert optional[0].suite == 'trixie'
    workload = WorkloadProfile('docker', 'docker', ['docker-ce'], '',
                              requires_docker_repo=True)
    assert drift._requires_operator_opt_in(workload, 'deb',
                                           profile.repos_factory('excalibur', 'amd64'))


def test_failed_vendor_mapping_never_fabricates_docker_source(monkeypatch):
    profile = profiles.PROFILES['devuan']
    monkeypatch.setattr(profiles, 'DEVUAN_TO_DEBIAN', {})
    monkeypatch.setattr(drift.profiles_module, 'discover_apt_releases',
                        lambda *_args, **_kwargs: {'6.0': 'excalibur'})
    monkeypatch.setattr(drift, 'fetch_text', lambda *_: '<table></table>')
    reporter = core.Reporter()
    assert drift.discover_current_release(profile, reporter) == 'excalibur'
    assert not [row for row in profile.repos_factory('excalibur', 'amd64')
                if row.role == 'docker']
    assert any('vendor-suite relationship unavailable' in warning
               for warning in reporter.warnings)


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


def test_rpm_matrix_empty_target_skips_inactive_rich_condition():
    """An absent installed-target capability must not become a fake drift."""
    repo = core.RepoSpec('fedora', 'https://example.invalid/', repo_format='rpm')
    app = core.Package('app', 'x86_64', '0', '1', '1', 'app.rpm', 'sha256', '0' * 64,
                       repo, requires=[core.Requirement('(missing if kernel-rt-core)')])
    workload = WorkloadProfile('fixture', 'fixture', ['app'], '')
    profile = SimpleNamespace(package_family='rpm', key='fedora', init_style='')
    empty = drift.check_workload(workload, profile, [app], 'x86_64')
    unknown = drift.check_workload(workload, profile, [app], 'x86_64', rpm_target_mode='unknown')
    assert empty['status'] == 'ok'
    assert empty['validation_scope'].startswith('empty-target')
    assert unknown['status'] == 'blocked'
    assert unknown['unresolved'] == ['missing']


def test_rpm_matrix_empty_target_still_enforces_active_rich_condition():
    repo = core.RepoSpec('fedora', 'https://example.invalid/', repo_format='rpm')
    app = core.Package('app', 'x86_64', '0', '1', '1', 'app.rpm', 'sha256', '0' * 64,
                       repo, requires=[core.Requirement('(missing if kernel-rt-core)')])
    condition = core.Package('kernel-rt-core', 'x86_64', '0', '1', '1', 'core.rpm',
                             'sha256', '0' * 64, repo)
    workload = WorkloadProfile('fixture', 'fixture', ['app', 'kernel-rt-core'], '')
    profile = SimpleNamespace(package_family='rpm', key='fedora', init_style='')
    result = drift.check_workload(workload, profile, [app, condition], 'x86_64')
    assert result['status'] == 'blocked'
    assert result['unresolved'] == ['missing']


def test_alma_10_does_not_advertise_absent_openjdk_17_root():
    from workloads import load_workloads

    java = load_workloads()['java-runtime']
    assert not java.supports_target('alma', '10.2')
    assert java.supports_target('alma', '9.7')


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
