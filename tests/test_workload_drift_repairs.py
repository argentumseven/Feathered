"""Failures observed in the live workload matrix, without network dependencies."""
from types import SimpleNamespace

import pytest

import apt_core
import arch_core
import core
import profiles
import rpm_resolution as rpm
import transaction_inventory
import verify_workload_matrix as drift
import workloads
from source_model import RootSourcePolicy, SourcePlan
from workload_materialization import materialize_source_plan


def package(name, requires=(), provides=(), version='1'):
    return core.Package(name, 'x86_64', '0', version, '1', name + '.rpm', 'sha256',
                        '0' * 64, core.RepoSpec('base', 'https://example.invalid/'),
                        requires=list(requires), provides=list(provides))


@pytest.mark.parametrize('family,arch', [('rpm', 'x86_64'), ('deb', 'amd64'), ('arch', 'x86_64')])
def test_materialization_accepts_explicit_virtual_provides(family, arch):
    repo = SimpleNamespace(role='dependency')
    provider = SimpleNamespace(name='implementation', arch=arch, repo=repo,
                               provides=[SimpleNamespace(name='approved-capability')])
    plan = SourcePlan([RootSourcePolicy('approved-capability', 'distribution')])
    result = materialize_source_plan('fixture', 1, '', family, plan, [provider], arch, lambda _: 'base')
    assert result.complete and result.selected_packages == ('approved-capability',)


@pytest.mark.parametrize('tier,architecture', [('additional', 'amd64'), ('base', 'arm64')])
def test_virtual_provides_do_not_escape_source_or_architecture(tier, architecture):
    provider = SimpleNamespace(name='implementation', arch=architecture,
        repo=SimpleNamespace(role='dependency'), provides=[SimpleNamespace(name='approved-capability')])
    plan = SourcePlan([RootSourcePolicy('approved-capability', 'distribution')])
    result = materialize_source_plan('fixture', 1, '', 'deb', plan, [provider], 'amd64', lambda _: tier)
    assert not result.complete


@pytest.mark.parametrize('profile_key,mapping,development,expected', [
    ('debian', {'13.6': 'trixie', '14': 'forky'}, {'forky'}, 'trixie'),
    ('devuan', {'6.0': 'excalibur', '7.0': 'freia'}, {'freia'}, 'excalibur'),
    ('ubuntu', {'26.04': 'resolute', '26.10': 'stonking'}, {'stonking'}, '26.04'),
])
def test_matrix_selects_latest_stable_release(monkeypatch, profile_key, mapping, development, expected):
    def discover(root, reporter, *, prerelease_out):
        prerelease_out.update(development)
        return mapping
    monkeypatch.setattr(profiles, 'discover_apt_releases', discover)
    assert drift.discover_current_release(profiles.PROFILES[profile_key], core.Reporter()) == expected


def test_matrix_does_not_fall_back_to_a_development_release(monkeypatch):
    def discover(root, reporter, *, prerelease_out):
        prerelease_out.add('future')
        return {'99.0': 'future'}
    monkeypatch.setattr(profiles, 'discover_apt_releases', discover)
    with pytest.raises(RuntimeError, match='no stable release'):
        drift.discover_current_release(profiles.PROFILES['ubuntu'], core.Reporter())


@pytest.mark.parametrize('key,version,codename', [('devuan', '7.0', 'freia'), ('debian', '14', 'forky')])
def test_explicit_development_target_does_not_fabricate_stable_pockets(monkeypatch, key, version, codename):
    profile = profiles.PROFILES[key]
    monkeypatch.setattr(profile, 'prerelease_versions', [codename])
    monkeypatch.setitem(profile.release_codenames, version, codename)
    rows = profile.repos_factory(version, 'amd64')
    assert [row.suite for row in rows if row.role == 'dependency' and row.enabled] == [codename]


@pytest.mark.parametrize('trigger', ['PackageKit', 'libdnf5-plugin-appstream'])
def test_rpm_conditional_or_activates_for_either_selected_trigger(trigger):
    expression = core.Requirement('(appstream-data if (PackageKit or libdnf5-plugin-appstream))')
    app = package('app', [expression])
    result = core.resolve([('app', None, None), (trigger, None, None)],
        [app, package(trigger), package('appstream-data')], 'x86_64',
        core.BuildOptions(target_inventory=core.TargetInventory()), core.Reporter())
    assert not result.unresolved
    assert 'appstream-data' in {p.name for p in result.selected}


def test_rpm_conditional_or_is_inactive_for_known_empty_inventory():
    app = package('app', [core.Requirement('(appstream-data if (PackageKit or libdnf5-plugin-appstream))')])
    result = core.resolve([('app', None, None)], [app], 'x86_64',
        core.BuildOptions(target_inventory=core.TargetInventory()), core.Reporter())
    assert not result.unresolved and result.selected == [app]


def test_rpm_parenthesized_leaf_keeps_version_bound():
    app = package('app', [core.Requirement('(linux-firmware >= 20150904-56.git6ebf5d57)')])
    older = package('linux-firmware', version='20100101')
    newer = package('linux-firmware', version='20260101')
    result = core.resolve([('app', None, None)], [app, older, newer], 'x86_64', core.BuildOptions(), core.Reporter())
    assert not result.unresolved and newer in result.selected and older not in result.selected


def test_fedora_release_unversioned_provide_satisfies_lvm2_rich_requirement():
    """RPM matches unversioned Provides against versioned Requires (existence test)."""
    lvm = package('lvm2', [core.Requirement('(system-release >= 23 if system-release)')])
    release = package('fedora-release', provides=[core.Requirement('system-release', kind='provides')],
                      version='44')
    root = package('storage-tools', [core.Requirement('lvm2'), core.Requirement('fedora-release')])
    result = core.resolve([('storage-tools', None, None)], [root, release, lvm], 'x86_64',
                          core.BuildOptions(), core.Reporter())
    assert not result.unresolved
    assert {p.name for p in result.selected} == {'storage-tools', 'lvm2', 'fedora-release'}


def test_unversioned_rpm_provide_is_an_existence_match_but_versioned_provides_still_compare():
    versioned = core.Requirement('system-release', 'GE', '0', '23')
    assert rpm.evr_satisfies(core.Requirement('system-release', kind='provides'), versioned)
    assert not rpm.evr_satisfies(core.Requirement('system-release', 'EQ', '0', '22'), versioned)
    distinct = package('fedora-release', provides=[core.Requirement('system-release(44)', kind='provides')])
    assert not rpm.package_satisfies(distinct, versioned)


@pytest.mark.parametrize('present,missing', [([], False), (['PackageKit'], True),
    (['libdnf5-plugin-appstream', 'appstream-data'], False)])
def test_retained_inventory_conditional_or_matches_forward_semantics(present, missing):
    owner = package('owner', [core.Requirement('(appstream-data if (PackageKit or libdnf5-plugin-appstream))')])
    retained = [owner, *[package(name) for name in present]]
    inventory = core.TargetInventory(nevras={p.nevra for p in retained},
        relationships_complete=True, retained_packages=retained)
    assert bool(transaction_inventory.rpm_retained_failures([], inventory)) is missing


def test_grouped_parser_does_not_accept_unknown_boolean_grammar():
    assert rpm.parse_grouped_requirement(core.Requirement('(one unless two)')) is None


def test_apt_virtual_workload_root_resolves_and_installer_uses_concrete_identity():
    from transaction_model import installation_roots
    repo = core.RepoSpec('base', 'https://example.invalid/', repo_format='apt')
    implementation = apt_core.DebPackage('postgresql', 'all', '17+278', 'postgresql.deb', 'sha256', '', repo,
        provides=[apt_core.DebAtom('postgresql-contrib', '=', '17')])
    result = apt_core.resolve([('postgresql-contrib', None, None, None, None, 'distribution')],
        [implementation], 'amd64', core.BuildOptions(), core.Reporter())
    assert not result.unresolved and result.roots == [implementation]
    assert installation_roots(result, 'deb') == ['postgresql:all=17+278']
    assert apt_core._find_root(('postgresql-contrib', '17', None), [implementation], 'amd64') is implementation
    assert apt_core._find_root(('postgresql-contrib', '18', None), [implementation], 'amd64') is None


def test_apt_exact_artifact_and_distribution_scopes_remain_binding():
    repo = core.RepoSpec('vendor', 'https://example.invalid/vendor/', repo_format='apt')
    repo.source_tier = 'workload'
    implementation = apt_core.DebPackage('implementation', 'amd64', '99', 'impl.deb', 'sha256', '', repo,
        provides=[apt_core.DebAtom('virtual')])
    assert apt_core._find_root(('virtual', None, None, None, None, 'distribution'), [implementation], 'amd64') is None
    assert apt_core._find_root(('virtual', None, None, 'vendor', 'amd64'), [implementation], 'amd64') is None


def test_arch_virtual_workload_root_honors_capability_version():
    repo = core.RepoSpec('base', 'https://example.invalid/', repo_format='pacman')
    implementation = arch_core.ArchPackage('implementation', 'x86_64', '99-1', 'implementation.pkg.tar.zst',
        'sha256', '', repo, provides=[arch_core.ArchRelation('virtual', '=', '17')])
    assert arch_core._find_root(('virtual', '17', None), [implementation], 'x86_64') is implementation
    assert arch_core._find_root(('virtual', '18', None), [implementation], 'x86_64') is None
    assert arch_core._find_root(('virtual', None, None, 'base', 'x86_64'), [implementation], 'x86_64') is None


@pytest.mark.parametrize('key', ['security-audit', 'monitoring-agents'])
def test_arch_catalog_requires_native_syslog_service_and_companion(key):
    workload = workloads.load_workloads()[key]
    assert 'syslog-ng' in workload.packages_for('arch')
    assert 'syslog-ng' not in workload.optional_for('arch')
    assert 'syslog-ng' in workloads.ARTIX_SERVICE_COMPANIONS[key]
    assert 'rsyslog' in workload.packages_for('rpm')


@pytest.mark.parametrize('key', ['buildah', 'skopeo', 'podman-build-stack'])
def test_unavailable_artix_container_build_presets_are_not_advertised(key):
    """Artix system/world/galaxy lacked these required roots in the 2026-10-20 live matrix."""
    workload = workloads.load_workloads()[key]
    assert not workload.supports_target('artix', 'rolling')
    assert 'arch' in workload.supported_distros
    assert workload.supports_target('arch', 'rolling')
    assert 'devuan' in workload.supported_distros


def test_devuan_docker_ce_preserves_explicit_compatible_source_path():
    workload = workloads.load_workloads()['docker']
    assert workload.supports_target('devuan', 'excalibur')
    assert workload.supports_target('debian', 'trixie')


@pytest.mark.parametrize('distro,release', [
    ('centos-stream', '10-stream'), ('rocky', '10.2'), ('fedora', '44'),
    ('debian', 'trixie'), ('debian', '13.2'),
    ('devuan', 'excalibur'), ('devuan', '6.0'),
])
def test_unavailable_openjdk17_is_not_advertised(distro, release):
    workload = workloads.load_workloads()['java-runtime']
    assert not workload.supports_target(distro, release)
    assert workload.supports_target('arch', 'rolling')
    assert workload.supports_target('ubuntu', '26.10')


def test_monitoring_htop_absence_does_not_invalidate_available_core_tools():
    workload = workloads.load_workloads()['monitoring-agents']
    assert 'htop' in workload.optional_for('rpm')
    assert 'htop' in workload.optional_for('deb')
    assert 'htop --version' not in workload.verification_commands


def test_centos_baseos_and_appstream_do_not_force_stale_sibling_builds():
    """Native DNF can choose a newer AppStream sibling over an older BaseOS copy."""
    templates = profiles.PROFILES['centos-stream'].repos_factory('10-stream', 'x86_64')
    base = next(row for row in templates if row.name == 'CentOS Stream BaseOS')
    appstream = next(row for row in templates if row.name == 'CentOS Stream AppStream')
    assert base.priority == appstream.priority

    old_repo = core.RepoSpec(base.name, base.url, priority=base.priority)
    new_repo = core.RepoSpec(appstream.name, appstream.url, priority=appstream.priority)
    older = core.Package('python3-libselinux', 'x86_64', '0', '3.10', '2.el10',
        'old.rpm', 'sha256', '0' * 64, old_repo)
    newer = core.Package('python3-libselinux', 'x86_64', '0', '3.11', '3.el10',
        'new.rpm', 'sha256', '0' * 64, new_repo)
    match = rpm.choose_provider(
        [core.ProviderMatch(older, core.Requirement('python3-libselinux')),
         core.ProviderMatch(newer, core.Requirement('python3-libselinux'))],
        'x86_64', 'python3-libselinux')
    assert match is not None and match.package is newer

    def row(name, repo, version, release, requires=()):
        return core.Package(name, 'x86_64', '0', version, release,
            f'{name}.rpm', 'sha256', '0' * 64, repo, requires=list(requires))

    exact_old = core.Requirement('libselinux(x86-64)', 'EQ', '0', '3.10', '2.el10')
    exact_new = core.Requirement('libselinux(x86-64)', 'EQ', '0', '3.11', '3.el10')
    older.requires.append(exact_old)
    newer.requires.append(exact_new)
    root = row('container-tools', old_repo, '1', '1',
        [core.Requirement('python3-libselinux'), core.Requirement('libselinux-utils')])
    util = row('libselinux-utils', old_repo, '3.11', '3.el10', [exact_new])
    packages = [root, older, newer, util,
                row('libselinux', old_repo, '3.10', '2.el10'),
                row('libselinux', old_repo, '3.11', '3.el10')]
    profile = SimpleNamespace(key='centos-stream', package_family='rpm', init_style='')
    workload = workloads.WorkloadProfile('fixture', 'fixture', ['container-tools'], '')
    outcome = drift.check_workload(workload, profile, packages, 'x86_64')
    assert outcome['status'] == 'ok'
