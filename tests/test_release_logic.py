"""Regressions for captured conflicts, RPM accounts, and module scope."""
import json

import pytest

import apt_core as apt
import arch_core as arch
import core
import inventory_relationships
from test_feather import APT_REPO, deb_pkg, rpm_pkg
from tests.test_module_runtime import default, module


def deb(name, version='1', depends=''):
    return deb_pkg(name, version, APT_REPO, depends=depends)


def deb_inventory(package):
    inv = apt.AptTargetInventory(packages={(package.name, package.arch): package.version})
    inv.relationships_complete = True
    inv.retained_packages = [package]
    return inv


def rpm_inventory(package):
    inv = core.TargetInventory(nevras={package.nevra})
    inv.package_capabilities[package.nevra] = list(package.provides)
    for cap in package.provides:
        inv.capabilities[cap.name].append(cap)
    inv.relationships_complete = True
    inv.retained_packages = [package]
    return inv


@pytest.mark.parametrize('field', ['conflicts', 'breaks'])
@pytest.mark.parametrize('reverse', [False, True])
def test_deb_conflicts_with_installed_packages_in_both_directions(field, reverse):
    installed, app = deb('guard'), deb('app')
    owner, target = (installed, app) if reverse else (app, installed)
    setattr(owner, field, apt.parse_dependency_field(target.name + ' (<< 2)', field))
    result = apt.resolve([('app', None, None)], [app], 'amd64',
                         core.BuildOptions(target_inventory=deb_inventory(installed)), core.Reporter())
    assert result.conflicts
    assert any('guard' in text and 'app' in text for text in result.conflicts)


@pytest.mark.parametrize('reverse', [False, True])
def test_rpm_installed_conflict_is_not_lost(reverse):
    installed, app = rpm_pkg('guard', '1'), rpm_pkg('app', '1')
    owner, target = (installed, app) if reverse else (app, installed)
    owner.conflicts = [core.Requirement(target.name)]
    result = core.resolve([('app', None, None)], [app], 'x86_64',
                          core.BuildOptions(target_inventory=rpm_inventory(installed)), core.Reporter())
    assert result.conflicts


def test_deb_alternative_can_avoid_installed_conflict():
    guard = deb('guard')
    guard.conflicts = apt.parse_dependency_field('bad-provider', 'conflicts')
    app, bad, good = deb('app', depends='bad-provider | good-provider'), deb('bad-provider'), deb('good-provider')
    result = apt.resolve([('app', None, None)], [app, bad, good], 'amd64',
                         core.BuildOptions(target_inventory=deb_inventory(guard)), core.Reporter())
    assert not result.conflicts and not result.unresolved
    assert {p.name for p in result.selected} == {'app', 'good-provider'}


def test_rpm_provider_search_can_avoid_installed_conflict():
    guard = rpm_pkg('guard', '1'); guard.conflicts = [core.Requirement('bad-provider')]
    app = rpm_pkg('app', '1', [core.Requirement('virtual')])
    bad, good = rpm_pkg('bad-provider', '2'), rpm_pkg('good-provider', '1')
    for p in (bad, good):
        p.provides.append(core.Requirement('virtual'))
    result = core.resolve([('app', None, None)], [app, bad, good], 'x86_64',
                          core.BuildOptions(target_inventory=rpm_inventory(guard)), core.Reporter())
    assert not result.conflicts and not result.unresolved
    assert {p.name for p in result.selected} == {'app', 'good-provider'}


def test_deb_replaced_installed_conflict_does_not_block_upgrade():
    old, new, app = deb('guard'), deb('guard', '2'), deb('app')
    old.conflicts = apt.parse_dependency_field('app', 'conflicts')
    result = apt.resolve([('app', None, None), ('guard', '2', None)], [app, new], 'amd64',
                         core.BuildOptions(target_inventory=deb_inventory(old)), core.Reporter())
    assert not result.conflicts and not result.unresolved


def test_deb_forward_conflict_uses_legacy_installed_version_records():
    app = deb('app'); app.breaks = apt.parse_dependency_field('guard (<< 2)', 'breaks')
    for version, expected in [('1', True), ('2', False)]:
        inv = apt.AptTargetInventory(packages={('guard', 'amd64'): version})
        result = apt.resolve([('app', None, None)], [app], 'amd64',
                             core.BuildOptions(target_inventory=inv), core.Reporter())
        assert bool(result.conflicts) is expected


@pytest.mark.parametrize('reverse', [False, True])
def test_arch_foreign_installed_conflict_is_reported(reverse):
    from tests.test_transaction_contract import ap
    guard, app = ap('foreign-guard'), ap('app')
    guard.managed = False
    owner, target = (guard, app) if reverse else (app, guard)
    owner.conflicts = [arch.parse_relation(target.name, 'conflicts')]
    inv = arch.ArchTargetInventory(packages={guard.name: guard.version})
    inv.relationships_complete = True; inv.retained_packages = [guard]
    result = arch.resolve([('app', None, None)], [app], 'x86_64', core.BuildOptions(target_inventory=inv), core.Reporter())
    assert result.conflicts or result.unresolved


def test_inventory_hydration_retains_deb_and_arch_conflicts():
    inv = apt.AptTargetInventory(packages={('guard', 'amd64'): '1'}, metadata={'relationships': 'complete'})
    data = {'Package': 'guard', 'Version': '1', 'Architecture': 'amd64', 'Conflicts': 'app', 'Breaks': 'library (<< 2)'}
    inventory_relationships.attach(inv, 'DETAIL|' + json.dumps(data), 'deb')
    assert inv.retained_packages[0].conflicts[0].alternatives[0].name == 'app'
    assert inv.retained_packages[0].breaks[0].alternatives[0].name == 'library'
    inv = arch.ArchTargetInventory(packages={'guard': '1-1'}, metadata={'relationships': 'complete'})
    data = {'NAME': ['guard'], 'VERSION': ['1-1'], 'CONFLICTS': ['app<2'], 'managed': False}
    inventory_relationships.attach(inv, 'DETAIL|' + json.dumps(data), 'arch')
    assert inv.retained_packages[0].conflicts[0].name == 'app'


def test_rpm_conflicts_are_captured_and_hydrated(monkeypatch, capsys, tmp_path):
    import target_inventory_details
    def query(args):
        assert '%{CONFLICTNAME}' in args[-1] and '%{CONFLICTVERSION}' in args[-1]
        return 'PKG\tguard\t0\t1\t1.el9\tx86_64\nCON\tapp\t<\t2\n'
    monkeypatch.setattr(target_inventory_details, 'query', query)
    target_inventory_details.collect('rpm')
    output = capsys.readouterr().out
    path = tmp_path / 'inventory.txt'
    path.write_text('PKG|guard|0|1|1.el9|x86_64\n' + output)
    inv = core.parse_target_inventory(path)
    assert inv.metadata['conflicts'] == 'complete'
    conflict = inv.retained_packages[0].conflicts[0]
    assert (conflict.name, conflict.flags, conflict.version) == ('app', '<', '2')


@pytest.mark.parametrize('capability', ['user(service-account)', 'group(service-account)'])
def test_rpm_account_provider_is_included_or_reported_missing(capability):
    app = rpm_pkg('app', '1', [core.Requirement(capability)])
    provider = rpm_pkg('accounts', '1'); provider.provides.append(core.Requirement(capability))
    for packages in ([app], [app, provider]):
        result = core.resolve([('app', None, None)], packages, 'x86_64', core.BuildOptions(), core.Reporter())
        if len(packages) == 1:
            assert [r.name for r in result.unresolved] == [capability]
        else:
            assert not result.unresolved
            assert {p.name for p in result.selected} == {'app', 'accounts'}


def mixed_packages():
    repo = core.RepoSpec('mixed', 'https://fixture.invalid')
    app, modular = rpm_pkg('plain-app', '1', repo=repo), rpm_pkg('modular-tool', '1', repo=repo)
    artifact = 'modular-tool-0:1-1.el9.x86_64'
    repo.module_documents = [default('tools'), module('tools', context='first', artifacts=[artifact]),
                             module('tools', context='second', artifacts=[artifact])]
    return app, modular


def test_unrelated_module_ambiguity_does_not_block_plain_root_or_dependency():
    app, modular = mixed_packages()
    leaf = rpm_pkg('plain-leaf', '1', repo=app.repo)
    app.requires = [core.Requirement('plain-leaf')]
    result = core.resolve([('plain-app', None, None)], [app, leaf, modular], 'x86_64', core.BuildOptions(), core.Reporter())
    assert not result.conflicts and not result.unresolved
    assert {p.name for p in result.selected} == {'plain-app', 'plain-leaf'}


def test_affected_modular_root_keeps_its_diagnostic():
    app, modular = mixed_packages()
    with pytest.raises(RuntimeError, match='Ambiguous module'):
        core.resolve([('modular-tool', None, None)], [app, modular], 'x86_64', core.BuildOptions(), core.Reporter())


def test_affected_dependency_is_unresolved_with_module_reason():
    app, modular = mixed_packages()
    app.requires = [core.Requirement('modular-tool')]
    result = core.resolve([('plain-app', None, None)], [app, modular], 'x86_64', core.BuildOptions(), core.Reporter())
    assert [r.name for r in result.unresolved] == ['modular-tool']
    assert 'Ambiguous module' in result.unresolved_notes['modular-tool']


def test_failed_module_still_masks_nonmodular_same_name_and_provides():
    app, modular = mixed_packages()
    replacement = rpm_pkg('modular-tool', '2', repo=app.repo)
    alias = rpm_pkg('replacement', '1', repo=app.repo)
    alias.provides.append(core.Requirement('modular-tool'))
    app.requires = [core.Requirement('modular-tool')]
    result = core.resolve([('plain-app', None, None)], [app, modular, replacement, alias], 'x86_64', core.BuildOptions(), core.Reporter())
    assert result.unresolved
    assert result.selected == [app]


def test_selected_independent_modules_must_agree_on_platform():
    repo = core.RepoSpec('mixed', 'https://fixture.invalid')
    old, new = rpm_pkg('old', '1', repo=repo), rpm_pkg('new', '1', repo=repo)
    repo.module_documents = [default('old'), default('new'),
        module('old', requires={'platform': ['el8']}, artifacts=['old-0:1-1.el9.x86_64']),
        module('new', requires={'platform': ['el9']}, artifacts=['new-0:1-1.el9.x86_64'])]
    with pytest.raises(RuntimeError, match='No compatible module'):
        core.resolve([('old', None, None), ('new', None, None)], [old, new], 'x86_64', core.BuildOptions(), core.Reporter())
