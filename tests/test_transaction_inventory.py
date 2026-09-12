"""Installed-state ownership and family-policy regressions."""
import copy
from dataclasses import replace

import pytest

import apt_core as apt
import arch_core as arch
import core
import transaction_inventory as policy
from transaction_model import RootRequest, arch_upgrade_requests, retained_failures, retained_inventory
from test_transaction_contract import ap, dp
from test_feather import rpm_pkg


def rpm_inventory(packages):
    inventory = core.TargetInventory(relationships_complete=True, retained_packages=packages)
    for package in packages:
        capabilities = list(package.provides)
        inventory.nevras.add(package.nevra)
        inventory.package_capabilities[package.nevra] = capabilities
        for cap in capabilities:
            for key in core._index_keys(cap.name):
                inventory.capabilities[key].append(cap)
    return inventory


def test_rpm_retained_capabilities_are_owned_by_the_returned_snapshot():
    installed = rpm_pkg('keep-library', '1')
    original = rpm_inventory([installed])
    before = copy.deepcopy(original)
    active = retained_inventory(original, [rpm_pkg('unrelated', '2')], 'rpm')
    assert active.package_capabilities == original.package_capabilities
    # Mutating a pass-local snapshot must not alter future passes or callers.
    active.package_capabilities[installed.nevra].append(core.Requirement('injected'))
    active.capabilities['keep-library'].clear()
    active.retained_packages[0].requires.append(core.Requirement('not-original'))
    assert original == before
    assert original.retained_packages[0].requires == before.retained_packages[0].requires
    assert active.package_capabilities[installed.nevra] is not original.package_capabilities[installed.nevra]


def test_rpm_replacement_and_versioned_obsoletes_remove_only_matching_owners():
    old = rpm_pkg('hyphenated-owner', '1')
    obsolete = rpm_pkg('legacy', '1')
    retained = rpm_pkg('newer-legacy', '4')
    retained.provides.append(core.Requirement('legacy', 'EQ', '0', '4', '1.el9'))
    replacement = rpm_pkg('hyphenated-owner', '2')
    replacement.obsoletes = [core.Requirement('legacy', 'LT', '0', '2', '1.el9')]
    original = rpm_inventory([old, obsolete, retained])
    active = policy.retained_rpm_inventory(original, [replacement])
    assert active.nevras == {retained.nevra}
    assert old.nevra in original.nevras and obsolete.nevra in original.nevras
    assert all(cap.version == '4' for cap in active.capabilities['legacy'])


def test_rpm_legacy_unowned_provides_survive_only_without_replacements():
    original = core.TargetInventory()
    original.capabilities['virtual'].append(core.Requirement('virtual'))
    assert policy.retained_rpm_inventory(original, []).capabilities['virtual']
    active = policy.retained_rpm_inventory(original, [rpm_pkg('new', '1')])
    assert not active.capabilities and original.capabilities['virtual']


def test_deb_replacement_drops_owned_virtual_provides_across_architectures():
    original = apt.AptTargetInventory(
        packages={('lib', 'amd64'): '1', ('lib', 'arm64'): '1', ('keep', 'amd64'): '1'},
        provides={'virtual': [('lib=1', 'amd64', '1'), ('keep=1', 'amd64', None)]})
    active = policy.retained_deb_inventory(original, [dp('lib', '2')])
    assert active.packages == {('keep', 'amd64'): '1'}
    assert active.provides['virtual'] == [('keep=1', 'amd64', None)]
    active.provides['virtual'].clear()
    assert len(original.provides['virtual']) == 2


def test_arch_replaces_honors_version_limits_and_owns_returned_state():
    original = arch.ArchTargetInventory(packages={'old': '1-1', 'keep': '4-1'})
    replacement = ap('new')
    replacement.replaces = [arch.parse_relation('old<2'), arch.parse_relation('keep<2')]
    active = policy.retained_arch_inventory(original, [replacement])
    assert active.packages == {'keep': '4-1'}
    active.packages.clear()
    assert original.packages == {'old': '1-1', 'keep': '4-1'}


@pytest.mark.parametrize('family', ['rpm', 'deb', 'arch'])
def test_uncaptured_relationships_do_not_claim_reverse_validation(family):
    inventory = {'rpm': core.TargetInventory, 'deb': apt.AptTargetInventory,
                 'arch': arch.ArchTargetInventory}[family]()
    assert retained_inventory(None, [], family) is None
    result = type('Result', (), {'selected': []})()
    assert retained_failures(result, None, family, '') == []
    assert retained_failures(result, inventory, family, '') == []


@pytest.mark.parametrize('expression,providers,missing', [
    ('rpmlib(CompressedFileNames)', [], False),
    ('(required if trigger)', ['trigger'], True),
    ('(required if trigger)', [], False),
    ('(one or two)', ['two'], False),
    ('(one with two)', ['one', 'two'], True),
    ('(one with two)', ['combined'], False),
])
def test_retained_rpm_rich_relationships_preserve_owner_semantics(expression, providers, missing):
    owner = rpm_pkg('consumer', '1', [core.Requirement(expression)])
    selected = [rpm_pkg(name, '1') for name in providers]
    if providers == ['combined']:
        selected[0].provides.extend([core.Requirement('one'), core.Requirement('two')])
    problems = policy.rpm_retained_failures(selected, rpm_inventory([owner]))
    assert bool(problems) == missing
    if missing:
        assert problems[0][0] is owner and problems[0][1] is owner.requires[0]


def test_deb_reverse_validation_checks_alternatives_and_predepends():
    owner = dp('consumer', depends='one | two')
    owner.pre_depends = apt.parse_dependency_field('bootstrap (>= 2)', 'pre-depends')
    inventory = apt.AptTargetInventory(packages={('consumer', 'amd64'): '1'},
                                      relationships_complete=True, retained_packages=[owner])
    problems = policy.deb_retained_failures([dp('two'), dp('bootstrap', '1')], inventory)
    assert len(problems) == 1 and problems[0][1] is owner.pre_depends[0]
    assert policy.deb_retained_failures([dp('two'), dp('bootstrap', '2')], inventory) == []


def test_arch_reverse_validation_uses_versioned_provides():
    owner = ap('consumer', depends=['virtual>=2'])
    inventory = arch.ArchTargetInventory(packages={'consumer': '1-1'},
                                        relationships_complete=True, retained_packages=[owner])
    provider = ap('provider')
    provider.provides = [arch.parse_relation('virtual=1')]
    assert policy.arch_retained_failures([provider], inventory)[0][1] is owner.depends[0]
    provider.provides = [arch.parse_relation('virtual=2')]
    assert policy.arch_retained_failures([provider], inventory) == []


@pytest.mark.parametrize('managed', [False, True])
def test_arch_upgrade_distinguishes_foreign_and_managed_missing_packages(managed):
    installed = ap('installed')
    installed.managed = managed
    inventory = arch.ArchTargetInventory(packages={'installed': '1-1'},
                                        relationships_complete=True, retained_packages=[installed])
    options = core.BuildOptions(target_inventory=inventory)
    if managed:
        with pytest.raises(RuntimeError, match='repository-managed package has no candidate'):
            arch_upgrade_requests([], [], 'x86_64', options)
    else:
        assert arch_upgrade_requests([], [], 'x86_64', options) == ([], True)


@pytest.mark.parametrize('mode', ['incomplete', 'older', 'pin', 'source'])
def test_arch_upgrade_rejects_inconsistent_snapshot_or_exact_root(mode):
    installed = ap('installed', '2-1')
    inventory = arch.ArchTargetInventory(packages={'installed': '2-1'},
                                        relationships_complete=mode != 'incomplete', retained_packages=[installed])
    candidate = ap('installed', '1-1' if mode == 'older' else '3-1')
    roots = []
    if mode == 'pin':
        roots = [RootRequest('installed', '2-1')]
    if mode == 'source':
        roots = [RootRequest('installed', source_identity='other-source')]
    with pytest.raises(RuntimeError, match='fresh inventory|older than|exact root conflicts'):
        arch_upgrade_requests(roots, [candidate], 'x86_64', core.BuildOptions(target_inventory=inventory))
    assert inventory.packages == {'installed': '2-1'}


def test_arch_upgrade_preserves_caller_roots_and_adds_source_pinned_requests():
    installed = ap('installed')
    inventory = arch.ArchTargetInventory(packages={'installed': '1-1'},
                                        relationships_complete=True, retained_packages=[installed])
    candidate = ap('installed', '2-1')
    roots = [RootRequest('app')]
    options = core.BuildOptions(target_inventory=inventory)
    upgraded, full = arch_upgrade_requests(roots, [candidate], 'x86_64', options)
    assert full and roots == [RootRequest('app')]
    assert upgraded[1].source_identity == candidate.repo.source_identity
    assert upgraded[1].version == '2-1' and upgraded[1].architecture == 'x86_64'
    assert replace(inventory).retained_packages == [installed]
    bypass, full = arch_upgrade_requests(roots, [], 'x86_64', replace(options, include_dependencies=False))
    assert bypass is roots and not full
