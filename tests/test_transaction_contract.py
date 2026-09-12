"""Behavioral regressions for runtime contracts; inputs vary names and versions."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import core
import apt_core as apt
import arch_core as arch
from test_feather import rpm_pkg, deb_pkg, APT_REPO
from transaction_model import installation_roots, write_installation_contract


def dp(name, version='1', depends=''):
    return deb_pkg(name, version, APT_REPO, depends)


def ap(name, version='1-1', depends=(), repo=None, architecture='x86_64'):
    repo = repo or core.RepoSpec('arch', 'https://example.invalid/arch/', repo_format='pacman')
    return arch.ArchPackage(name, architecture, version, name+'.pkg.tar.zst', 'sha256', '', repo,
                           depends=[arch.parse_relation(x) for x in depends])


@pytest.mark.parametrize('name,old,new', [('lib', '1', '2'), ('hyphenated-component', '7.2', '11.4')])
@pytest.mark.parametrize('family', ['rpm', 'deb', 'arch'])
def test_replaced_inventory_does_not_satisfy_old_requirement(name, old, new, family):
    if family == 'rpm':
        inv = core.TargetInventory()
        inv.capabilities[name].append(core.Requirement(name, 'EQ', '0', old, '1.el9'))
        packages = [rpm_pkg('application', '1', [core.Requirement(name, 'LE', '0', old, '1.el9')]), rpm_pkg(name, new)]
        backend, architecture = core, 'x86_64'
    elif family == 'deb':
        inv = apt.AptTargetInventory(packages={(name, 'amd64'): old})
        packages = [dp('application', depends=f'{name} (<= {old})'), dp(name, new)]
        backend, architecture = apt, 'amd64'
    else:
        old, new = old+'-1', new+'-1'
        inv = arch.ArchTargetInventory(packages={name: old})
        installed = ap(name, old); installed.managed = True
        inv.relationships_complete = True; inv.retained_packages = [installed]
        packages = [ap('application', depends=[f'{name}<={old}']), ap(name, new)]
        backend, architecture = arch, 'x86_64'
    result = backend.resolve([('application', None, None), (name, new, None)], packages, architecture,
                             core.BuildOptions(target_inventory=inv), core.Reporter())
    assert result.unresolved or result.conflicts


@pytest.mark.parametrize('depth', [1, 4, 11])
def test_late_rpm_condition_is_closed_at_fixed_point(depth):
    chain = [rpm_pkg(f'node{i}', '1', [core.Requirement(f'node{i+1}')]) for i in range(depth)]
    chain.append(rpm_pkg(f'node{depth}', '1', [core.Requirement('trigger')]))
    root = rpm_pkg('root', '1', [core.Requirement('(needed if trigger)'), core.Requirement('node0')])
    result = core.resolve([('root', None, None)], [root, *chain, rpm_pkg('trigger','1'), rpm_pkg('needed','1')],
                          'x86_64', core.BuildOptions(), core.Reporter())
    assert not result.unresolved
    assert 'needed' in {p.name for p in result.selected}


@pytest.mark.parametrize('family,independent', [('rpm','noarch'), ('deb','all'), ('arch','any')])
def test_workload_materialization_family_architecture(family, independent):
    from source_model import SourcePlan, RootSourcePolicy
    from workload_materialization import materialize_source_plan
    package = SimpleNamespace(name='portable', arch=independent, repo=SimpleNamespace(role='dependency'))
    plan = SourcePlan([RootSourcePolicy('portable', 'distribution')])
    result = materialize_source_plan('custom', 1, '', family, plan, [package], 'target-cpu', lambda r: 'base')
    assert result.complete and result.selected_packages == ('portable',)


@pytest.mark.parametrize('name', ['app', 'other-app'])
def test_arch_root_source_scope(name):
    base = ap(name); base.repo.source_tier = 'base'
    extra = ap(name, '999-1', repo=core.RepoSpec('extra','https://extra.invalid',priority=1,repo_format='pacman'))
    extra.repo.source_tier = 'additional'
    result = arch.resolve([(name,None,None,None,None,'distribution')], [base, extra], 'x86_64', core.BuildOptions(),core.Reporter())
    assert result.roots == [base]


@pytest.mark.parametrize('qualifier,expected', [('', False), ('no', False), ('same', False), ('foreign', False), ('allowed', True)])
def test_apt_any_respects_multi_arch(qualifier, expected):
    library = dp('library'); library.multi_arch = qualifier
    result = apt.resolve([('app',None,None)], [dp('app',depends='library:any'),library], 'amd64',core.BuildOptions(),core.Reporter())
    assert (not result.unresolved) == expected


def test_rpm_root_constraints_and_missing_root_only():
    lib1,lib2 = rpm_pkg('lib','1'),rpm_pkg('lib','2')
    app = rpm_pkg('app','1',[core.Requirement('lib','EQ','0','1','1.el9')])
    result = core.resolve([('lib',None,None),('app',None,None)],[lib1,lib2,app],'x86_64',core.BuildOptions(),core.Reporter())
    assert not result.unresolved and lib1 in result.selected and lib2 not in result.selected
    result = core.resolve([('lib',None,None),('absent',None,None)],[lib1],'x86_64',core.BuildOptions(include_dependencies=False),core.Reporter())
    assert result.unresolved


def test_root_only_and_conflicting_pins():
    root,dep = ap('app',depends=['lib']),ap('lib')
    result = arch.resolve([('app',None,None)],[root,dep],'x86_64',core.BuildOptions(include_dependencies=False),core.Reporter())
    assert result.selected == [root]
    with pytest.raises(RuntimeError,match='Contradictory'):
        apt.resolve([('app','1',None),('app','2',None)],[dp('app'),dp('app','2')],'amd64',core.BuildOptions(),core.Reporter())


@pytest.mark.parametrize('version', ['1.2', '3:7.8-4'])
def test_optional_roots_and_exact_contract_reach_published_installer(tmp_path, version):
    payload = tmp_path / 'app.deb'; payload.write_bytes(b'test package')
    package = dp('app', version); package.location=payload.name; package.repo=core.RepoSpec('local',tmp_path.as_uri(),repo_format='apt'); package.checksum=hashlib.sha256(payload.read_bytes()).hexdigest()
    options = core.BuildOptions(optional_roots={'absent'})
    result = apt.resolve([('app',version,None),('absent',None,None)],[package],'amd64',options,core.Reporter())
    out = tmp_path/'bundle'
    apt.write_bundle(result,out,options,core.Reporter(),{'requested_packages':['app','absent']})
    roots=(out/'debs/REQUESTED-ROOTS.txt').read_text().splitlines()
    assert roots == [f'app:amd64={version}']
    assert (out/'debs/TRANSACTION-ARGS.txt').read_text().splitlines()==roots
    contract=json.loads((out/'debs/INSTALLATION-CONTRACT.json').read_text())
    assert contract['roots'][0]['source_identity']==package.repo.source_identity
    script=(out/'install-offline.sh').read_text()
    assert script.index('gpgv --keyring') < script.index('receiver-preflight.py') < script.index('sudo apt-get')
    assert '--simulate --no-remove' in script


def test_receiver_baseline_and_post_install_are_exact():
    from receiver_preflight import validate
    package={'name':'app','version':'2','architecture':'amd64','package_id':'app_2_amd64'}
    contract={'family':'deb','target':{'arch':'amd64'},'baseline_required':[package],'selected':[package]}
    validate(contract,{('app','amd64'):'2'},machine='x86_64')
    for actual in [{}, {('app','amd64'):'1'}, {('app','arm64'):'2'}]:
        with pytest.raises(RuntimeError):
            validate(contract,actual,machine='x86_64')
        with pytest.raises(RuntimeError):
            validate(contract,actual,post=True,machine='x86_64')


def test_full_arch_upgrade_changes_with_target_inventory():
    inv=arch.ArchTargetInventory(packages={'system-lib':'1-1'})
    installed=ap('system-lib');installed.managed=True
    inv.relationships_complete=True; inv.retained_packages=[installed]
    packages=[ap('app'),ap('system-lib','2-1')]
    result=arch.resolve([('app',None,None)],packages,'x86_64',core.BuildOptions(target_inventory=inv),core.Reporter())
    assert result.arch_full_upgrade
    assert {p.name:p.version for p in result.selected} == {'app':'1-1','system-lib':'2-1'}
    from receiver_preflight import validate
    contract={'family':'arch','arch_full_upgrade':True,'inventory':inv.packages,'baseline_required':[]}
    validate(contract,{('system-lib',''):'1-1'})
    with pytest.raises(RuntimeError,match='changed'):
        validate(contract,{('system-lib',''):'2-1'})


@pytest.mark.parametrize('repair_available', [False, True])
def test_retained_reverse_dependency_is_repaired_or_blocked(repair_available):
    inv=apt.AptTargetInventory(packages={('consumer','amd64'):'1',('lib','amd64'):'1'})
    inv.relationships_complete=True;inv.retained_packages=[dp('consumer',depends='lib (= 1)'),dp('lib')]
    packages=[dp('lib','2')]
    if repair_available:
        packages.append(dp('consumer','2',depends='lib (= 2)'))
    result=apt.resolve([('lib','2',None)],packages,'amd64',core.BuildOptions(target_inventory=inv),core.Reporter())
    if repair_available:
        assert not result.unresolved
        assert {p.name for p in result.selected}=={'lib','consumer'}
    else:
        assert result.unresolved
        assert any('Retained target' in note for note in result.unresolved_notes.values())


def test_cache_survives_failure_but_rejects_tampering(tmp_path):
    from artifact_cache import remember, restore
    package=dp('cached');source=tmp_path/'source.deb';source.write_bytes(b'verified')
    package.checksum=hashlib.sha256(source.read_bytes()).hexdigest()
    remember(package,source,tmp_path,core.Reporter())
    source.unlink()
    dest=tmp_path/'restored.deb'
    restore(package,dest,tmp_path,core.BuildOptions(),core.Reporter())
    assert dest.read_bytes()==b'verified'
    dest.unlink()
    next((tmp_path/'.feathered-cache').glob('*.payload')).write_bytes(b'changed')
    restore(package,dest,tmp_path,core.BuildOptions(),core.Reporter())
    assert not dest.exists()


def test_additive_changed_retained_bytes_block_publication(tmp_path):
    from transaction_model import validate_retained_payloads
    directory=tmp_path/'debs';directory.mkdir()
    old=directory/'old.deb';old.write_bytes(b'old verified bytes')
    row={'filename':old.name,'sha256':hashlib.sha256(old.read_bytes()).hexdigest()}
    (directory/'provenance.json').write_text(json.dumps({'packages':[row]}))
    validate_retained_payloads(directory,[],'deb',core.Reporter())
    old.write_bytes(b'changed')
    with pytest.raises(RuntimeError,match='changed'):
        validate_retained_payloads(directory,[],'deb',core.Reporter())


def test_repository_cache_tracks_participating_sources():
    from feathered_app.application.build import BuildMixin
    loaded=[]
    current=core.RepoSpec('current','https://current.invalid')
    stale=core.RepoSpec('stale','https://stale.invalid')
    scope=[current]
    shell=SimpleNamespace(_signature=lambda:'same-settings',loaded_signature=None,loaded_packages=[],
        _build_repository_scope=lambda:list(scope),_mirror_mode=lambda:False,
        arch_var=SimpleNamespace(get=lambda:'x86_64'),repo_rows=[current,stale],
        _load_repository_backend=lambda repo,*args: loaded.append(repo.name) or [rpm_pkg(repo.name,'1',repo=repo)],
        _validate_successful_source_scopes=lambda *args:None,_active_source_method=lambda:'Custom repositories')
    BuildMixin._load_enabled_repos(shell,core.Reporter())
    BuildMixin._load_enabled_repos(shell,core.Reporter())
    assert loaded==['current']
    scope[:]=[stale]
    result=BuildMixin._load_enabled_repos(shell,core.Reporter())
    assert loaded==['current','stale'] and result[0].repo is stale


def test_rpm_module_streams_follow_defaults_and_captured_state(tmp_path):
    from module_policy import filter_candidates, emit_supplemental
    repo=core.RepoSpec('modular','https://modules.invalid')
    old,new=rpm_pkg('tool','1',repo=repo),rpm_pkg('tool','2',repo=repo)
    def doc(p,stream):
        return {'document':'modulemd','version':2,'data':{'name':'tools','stream':stream,'context':'ctx','arch':'x86_64','artifacts':{'rpms':[f'tool-0:{p.version}-1.el9.x86_64']}}}
    repo.module_documents=[doc(old,'stable'),doc(new,'next'),{'document':'modulemd-defaults','data':{'module':'tools','stream':'stable'}}]
    assert filter_candidates([old,new],None,'x86_64')==[old]
    inv=core.TargetInventory(metadata={'module_states':json.dumps({'tools':{'state':'enabled','stream':'next'}})})
    assert filter_candidates([old,new],inv,'x86_64')==[new]
    import yaml
    repo.supplemental_metadata={'modules':yaml.safe_dump_all(repo.module_documents).encode()}
    core.emit_rpm_repository(tmp_path,[new],core.Reporter())
    refs=core.get_repo_data(core.RepoSpec('local',tmp_path.as_uri()),core.Reporter())
    assert 'modules' in refs


def test_module_yaml_alias_bombs_are_rejected():
    from module_policy import documents
    with pytest.raises(RuntimeError,match='aliases'):
        documents(b'a: &a [1,2]\nb: *a\n')


def test_live_matrix_runs_materialization_optionality_and_closure():
    from workloads import WorkloadProfile, WorkloadComponent
    from verify_workload_matrix import check_workload
    workload = WorkloadProfile('fixture', 'Fixture', [], '', components=[
        WorkloadComponent('portable', ['portable']), WorkloadComponent('optional', ['optional'], required=False)])
    profile = SimpleNamespace(key='arch', package_family='arch', init_style='')
    root = ap('portable', architecture='any', depends=['transitive'])
    root.repo.source_tier = 'base'
    result = check_workload(workload, profile, [root], 'x86_64')
    assert result['status'] == 'blocked'
    assert result['skipped_optional'] == ['optional']
    result = check_workload(workload, profile, [root, ap('transitive')], 'x86_64')
    assert result['status'] == 'ok' and result['selected'] == 2
    assert result['installation_roots'] == ['portable=1-1']


def test_inventory_relationships_reject_inconsistent_capture(tmp_path):
    path = tmp_path / 'inventory.txt'
    row = {'Package':'retained', 'Version':'2', 'Architecture':'amd64'}
    path.write_text('META|package_family|deb\nMETA|relationships|complete\nDEB|retained|1|amd64|\nDETAIL|' + json.dumps(row) + '\n')
    with pytest.raises(RuntimeError, match='do not match'):
        apt.parse_target_inventory(path)


def test_modular_header_without_modulemd_is_rejected(tmp_path):
    package = rpm_pkg('modular-tool', '1')
    package.modularity_label = 'tools:stable:1:context'
    with pytest.raises(RuntimeError, match='no matching modulemd'):
        core.emit_rpm_repository(tmp_path, [package], core.Reporter())


def test_rpm_module_label_survives_record_copy_without_changing_package_equality():
    from dataclasses import replace

    package = rpm_pkg('tool', '1')
    plain = replace(package)
    package.modularity_label = 'tools:stable:1:context'
    copied = replace(package)
    assert copied.modularity_label == 'tools:stable:1:context'
    # The formerly dynamic field did not participate in dataclass equality.
    assert package == plain == copied
