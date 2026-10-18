import core
import profiles
import pytest
import verify_workload_matrix as drift
import workloads

RICH = '((rpm-build >= 4.14.90 with (rpm-build < 4.19.90 or rpm-build >= 4.19.91-8)) if rpm-build)'


def package(name, version='1', release='1', requires=(), provides=()):
    return core.Package(name, 'x86_64', '0', version, release, name + '.rpm',
                        'sha256', '0' * 64, core.RepoSpec('base', 'https://example.invalid/'),
                        requires=list(requires), provides=list(provides))


def test_arch_docker_uses_distribution_sources():
    catalog = workloads.load_workloads()
    profile = profiles.PROFILES['arch']
    templates = list(profile.repos_factory('rolling', 'x86_64'))
    selected, errors = drift._templates_for_workload(
        profile, 'rolling', 'x86_64', catalog['docker'], templates,
        drift._known_workload_roles(catalog), '1.35')
    assert not errors
    assert selected == [t for t in templates if t.enabled]


def test_nested_rich_can_fall_back_after_replacing_invalid_pending_dependency():
    app = package('example', requires=[core.Requirement('rpm-build'), core.Requirement(RICH)])
    invalid = package('rpm-build', '4.19.90')
    broken = package('rpm-build', '4.19.1.1', '2', [core.Requirement('unavailable')])
    valid = package('rpm-build', '4.19.1.1', '1')
    result = core.resolve([('example', None, None)],
                          [app, invalid, broken, valid], 'x86_64',
                          core.BuildOptions(max_resolution_passes=16), core.Reporter())
    assert not result.unresolved, result.unresolved_notes
    assert valid in result.selected


def test_invalid_kubernetes_minor_is_reported_per_workload():
    catalog = workloads.load_workloads()
    profile = profiles.PROFILES['rocky']
    selected, errors = drift._templates_for_workload(
        profile, '9', 'x86_64', catalog['kubernetes-client'],
        list(profile.repos_factory('9', 'x86_64')),
        drift._known_workload_roles(catalog), 'invalid')
    assert errors and 'minor' in errors[0].lower()


@pytest.mark.parametrize('inventory,expected', [(core.TargetInventory(), {'example'}), (None, {'example', 'rpm-build'})])
def test_nested_rich_respects_inventory_and_conservative_mode(inventory, expected):
    app = package('example', requires=[core.Requirement(RICH)])
    valid = package('rpm-build', '4.19.1.1')
    result = core.resolve([('example', None, None)], [app, valid], 'x86_64',
                          core.BuildOptions(target_inventory=inventory), core.Reporter())
    assert not result.unresolved
    assert {p.name for p in result.selected} == expected


def test_nested_with_must_not_combine_different_packages():
    app = package('example', requires=[core.Requirement('((left with (right or other)) if trigger)')])
    left = package('left')
    right = package('right')
    result = core.resolve([('example', None, None)], [app, left, right], 'x86_64',
                          core.BuildOptions(), core.Reporter())
    assert result.unresolved


@pytest.mark.parametrize('version,release,missing', [
    ('4.19.1.1', '1', False),
    ('4.19.90', '1', True),
    ('4.19.91', '7', True),
    ('4.19.91', '8', False),
])
def test_retained_inventory_uses_same_nested_semantics(version, release, missing):
    from transaction_inventory import rpm_retained_failures
    owner = package('retained', requires=[core.Requirement(RICH)])
    installed = package('rpm-build', version, release)
    inventory = core.TargetInventory(nevras={owner.nevra, installed.nevra},
        relationships_complete=True, retained_packages=[owner, installed])
    problems = rpm_retained_failures([], inventory)
    assert bool(problems) is missing
    if missing:
        assert problems[0][0] is owner
        assert problems[0][1].name == RICH


def test_retained_nested_dependency_is_inactive_without_condition():
    from transaction_inventory import rpm_retained_failures
    owner = package('retained', requires=[core.Requirement(RICH)])
    inventory = core.TargetInventory(nevras={owner.nevra},
        relationships_complete=True, retained_packages=[owner])
    assert not rpm_retained_failures([], inventory)
