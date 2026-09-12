"""Repository choice, advisory policy, migration and real flat-APT acquisition."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import gzip
import hashlib
import json
import shutil
import subprocess

import pytest
import apt_core
import core
import build_spec
from feathered_app.build_backend import BuildBackendMixin
from feathered_app.build_api import prepare_build
from feathered_app.build_services import BuildServices
from kubernetes_workflow import (LABELS, WorkloadContext, repository_template, synchronize_repository,
    report, check_acknowledgement, enforce_baseline, rolling_source)
from k8s_version import parse
from k8s_policy import evaluate, managed_kind
from k8s_discovery import discover, save, read
from workloads import load_workloads
from tests.test_cli_replay import invoke, spec_for

@pytest.mark.parametrize('text,qualifier', [('1.33',''),('1.33.4',''),('v1.33.4',''),
    ('v1.33.4+vmware.1','+vmware.1'),('v1.33.4---vmware.1-fips.1-tkg.1','---vmware.1-fips.1-tkg.1'),
    ('1.33.4-1.ph5','-1.ph5'),('1.33.4-150500.1.1','-150500.1.1'),('1:1.33.4-00','-00')])
def test_vendor_version_precision(text, qualifier):
    version = parse(text)
    assert version.line == '1.33' and version.qualifier == qualifier
    assert version.patch == (None if text == '1.33' else 4)

@pytest.mark.parametrize('text', ['1.34.0-rc.1','2.0.0','latest','','1.33.4junk','1.33.4+','1.33.4-rc1'])
def test_unusable_version_has_actionable_error(text):
    with pytest.raises(ValueError): parse(text)
    if text == '2.0.0':
        with pytest.raises(ValueError, match='VKr'): parse(text)

@pytest.mark.parametrize('name', ['kernel-headers','kernel-devel','kernel-rt-devel','linux-headers-generic','nginx','helm'])
def test_ordinary_and_development_packages_are_not_managed(name):
    assert not managed_kind(name)

@pytest.mark.parametrize('name,kind', [('kernel','node image'),('linux-image-6.1.0-generic','node image'),
    ('containerd','node image'),('kubelet','node/control-plane'),('kubernetes','node/control-plane'),('antrea','cluster add-on')])
def test_managed_classification_is_only_advice(name, kind):
    assert managed_kind(name) == kind

@pytest.mark.parametrize('name,minor,old,new,flag', [('kubelet',30,33,33,False),('kubelet',29,33,33,True),
    ('kubelet',34,33,33,True),('kubelet',24,27,27,True),('kubectl',32,33,33,False),('kubectl',34,33,33,False),
    ('kube-controller-manager',31,33,33,True),('kubelet',30,33,34,True),('kubelet',31,33,34,False),
    ('kube-controller-manager',32,33,34,True),('kubectl',32,33,34,True),('kube-apiserver',34,33,33,False)])
def test_skew_intersects_all_api_servers(name, minor, old, new, flag):
    rows = [SimpleNamespace(name=name, version=f'1.{minor}.0')]
    assert bool(evaluate(rows, 33, old, new)) == flag


def test_only_conflicts_need_acknowledgement():
    pkg = apt_core.DebPackage('kubeadm','amd64','1.32.0','k.deb','sha256','',core.RepoSpec('repo','https://example.invalid/'))
    context = WorkloadContext(workload='kubernetes-node', minor='1.33')
    data = report(context, [pkg])
    with pytest.raises(ValueError, match='kubeadm.*1.32'): check_acknowledgement(data)
    check_acknowledgement(report(replace(context, acknowledged=True), [pkg]))
    advisory = replace(pkg, name='kubectl', version='1.30.0')
    check_acknowledgement(report(context, [advisory]))
    assert report(context, [pkg])['apiserver_assumed']

@pytest.mark.parametrize('distro,release,offered', [('photon','5.0',True),('ubuntu','22.04',True),('ubuntu','24.04',True),
    ('rhel','9',True),('rhel','9.6',True),('photon','4.0',False),('debian','12',False),('arch','rolling',False),('rocky','9',False)])
def test_vks_release_availability(distro, release, offered):
    assert load_workloads()['vks-node-additions'].supports_target(distro,release) is offered

@pytest.mark.parametrize('family,tail,flat', [('rpm','rpm/',False),('deb','deb/',True)])
def test_minor_materialization_is_idempotent_and_rewrites_owned_row(family,tail,flat):
    def factory(t, _tier):
        return core.RepoSpec(t.name,t.url,role=t.role,repo_format=t.repo_format,flat_repo=t.flat_repo,suite=t.suite,components=t.components)
    rows=[]
    synchronize_repository(rows,family,'v1.33.4+vmware.1',factory)
    first=rows[0]
    synchronize_repository(rows,family,'1.33',factory)
    assert len(rows)==1 and rows[0] is first
    synchronize_repository(rows,family,'1.34',factory)
    assert len(rows)==1 and '/v1.34/' in rows[0].url and rows[0].url.endswith(tail)
    assert rows[0].flat_repo is flat
    if flat: assert rows[0].suite == '/' and rows[0].components == ''
    first.workload_profile_managed=False
    first.url='https://operator.invalid/custom/'
    synchronize_repository(rows,family,'1.35',factory)
    assert rows[0].url == 'https://operator.invalid/custom/'


def test_discovery_has_no_fallback_list_and_stops_after_three_misses(tmp_path):
    urls=[]
    def probe(url):
        urls.append(url)
        return any(f'/v1.{n}/' in url for n in range(24,34))
    observation=discover('deb',probe)
    assert observation.versions[0]=='1.33' and len(urls)==16  # The final bounded batch finishes its already-started probes.
    assert not discover('rpm',lambda _:False).versions
    assert discover('rpm',lambda _:False).error
    urls.clear()
    assert len(discover('rpm',lambda url: urls.append(url) or True).versions)==60
    assert len(urls)==60
    save(tmp_path/'observation.json',observation)
    assert read(tmp_path/'observation.json')==observation


def test_schema_two_migrates_without_replacing_exact_roots():
    source={'spec_version':2,'target':{'environment':'VMware VKS','kubernetes_purpose':'Client tools',
        'kubernetes_version':'v1.33.4+vmware.1','api_server_versions':'1.32.8,1.33.4',
        'platform_release':'release-x','kubernetes_release':'VKr-independent','os_image':'image-y'},
        'content':{'selection_mode':'Choose packages','exact_packages':[{'name':'kubectl','version':'1.33.4-1'}]}}
    spec=build_spec.BuildSpec.from_dict(source)
    assert spec.content.workload==LABELS['kubernetes-client'] and spec.content.k8s_minor=='1.33'
    assert spec.content.selection_mode=='Choose packages' and spec.content.exact_packages[0].version=='1.33.4-1'
    assert spec.content.apiserver_oldest_minor=='32' and spec.content.apiserver_newest_minor=='33'
    assert 'VKr-independent' in spec.target.platform_note
    assert not hasattr(spec.target,'environment') and spec.spec_version==3
    assert source['spec_version']==2 and 'environment' in source['target']
    assert build_spec.BuildSpec.from_json(spec.to_json())==spec


def flat_repo(tmp_path, *, architectures='amd64', signed=False, bad_digest=False):
    repo=tmp_path/'flat';repo.mkdir()
    raw=gzip.compress(b'Package: kubectl\nVersion: 1.33.4\nArchitecture: amd64\nFilename: kubectl.deb\nSHA256: '+b'a'*64+b'\nSize: 1\n\n')
    (repo/'Packages.gz').write_bytes(raw)
    digest='0'*64 if bad_digest else hashlib.sha256(raw).hexdigest()
    (repo/'Release').write_text((f'Architectures: {architectures}\n' if architectures else '')+f'SHA256:\n {digest} {len(raw)} Packages.gz\n')
    if signed: (repo/'Release.gpg').write_bytes(b'test signature')
    return core.RepoSpec('Flat fixture',repo.as_uri()+'/',repo_format='apt',flat_repo=True,
                        keyring='fixture-keyring' if signed else '')


def test_flat_repository_verifies_index_and_attempts_signature(tmp_path,monkeypatch):
    repo=flat_repo(tmp_path,signed=True)
    verify=Mock();monkeypatch.setattr(apt_core,'verify_openpgp',verify)
    packages=apt_core.load_repository(repo,{'amd64'},core.Reporter())
    assert [p.name for p in packages]==['kubectl']
    assert packages[0].verification.index_digest_verified
    assert verify.call_count==1 and verify.call_args.args[1]==b'test signature'
    record=build_spec.RepositoryRecord.capture(repo)
    restored=build_spec.repositories_from(build_spec.BuildSpec(sources=build_spec.SourceSpec(repositories=(record,))),core.RepoSpec)[0]
    assert restored.flat_repo and restored.source_identity==repo.source_identity

@pytest.mark.parametrize('problem', ['checksum','architecture','missing-release'])
def test_flat_repository_failures_preserve_provenance(tmp_path,problem):
    repo=flat_repo(tmp_path,bad_digest=problem=='checksum',architectures='arm64' if problem=='architecture' else 'amd64')
    if problem=='missing-release': (tmp_path/'flat/Release').unlink()
    with pytest.raises(RuntimeError,match='SHA256 mismatch' if problem=='checksum' else 'architecture' if problem=='architecture' else 'flat root'):
        apt_core.load_repository(repo,{'amd64'},core.Reporter())


def test_flat_missing_architecture_is_observed_not_invented(tmp_path):
    repo=flat_repo(tmp_path,architectures='')
    reporter=core.Reporter()
    assert apt_core.load_repository(repo,{'amd64'},reporter)
    assert any('not confirmed' in w for w in reporter.warnings)


@pytest.fixture
def local_kubernetes(tmp_path):
    if not shutil.which('dpkg-deb') or not shutil.which('dpkg-scanpackages'):
        pytest.skip('native dpkg fixture tools required; enforced in Debian CI')
    repo=tmp_path/'repo';repo.mkdir()
    for name,version in [('kubectl','1.33.4'),('kubectl','1.34.1'),('kubeadm','1.32.0'),('kubelet','1.33.4'),
                         ('cri-tools','1.33.0'),('kubernetes-cni','1.6.0'),('kernel-headers','5.0'),('cryptsetup','2.0')]:
        source=tmp_path/(name+version)/'DEBIAN';source.mkdir(parents=True)
        (source/'control').write_text(f'Package: {name}\nVersion: {version}\nArchitecture: amd64\nMaintainer: Test <test@example.invalid>\nDescription: fixture\n')
        subprocess.run(['dpkg-deb','--build',str(source.parent),str(repo/f'{name}_{version}.deb')],check=True,capture_output=True)
    raw=subprocess.run(['dpkg-scanpackages','-m','.','/dev/null'],cwd=repo,check=True,capture_output=True).stdout
    body=gzip.compress(raw);(repo/'Packages.gz').write_bytes(body)
    (repo/'Release').write_text(f'SHA256:\n {hashlib.sha256(body).hexdigest()} {len(body)} Packages.gz\n')
    return repo


def workload_spec(repo,out,key='kubernetes-client',names=()):
    spec=spec_for(repo,out)
    source=core.RepoSpec('Fixture',repo.as_uri()+'/',role='dependency' if key=='vks-node-additions' else 'kubernetes',
                        repo_format='apt',flat_repo=True)
    records=tuple(build_spec.ExactPackageRecord(name,'',source.role,source.name,'amd64',source.source_identity) for name in names)
    return replace(spec,target=replace(spec.target,distribution='Ubuntu',release='24.04',platform_note='VKr recorded-only'),
        content=replace(spec.content,selection_mode='Choose packages' if names else 'Workload preset',
            workload=LABELS[key],k8s_minor='1.33',exact_packages=records,image_baker_name='node-additions'),
        sources=replace(spec.sources,repositories=(build_spec.RepositoryRecord.capture(source),)))


def test_cli_keeps_other_minor_visible_and_records_advice(local_kubernetes,tmp_path):
    spec=workload_spec(local_kubernetes,tmp_path/'out')
    result=invoke(tmp_path,spec,'--accept-trust-findings','--accept-package-only')
    assert result.returncode==0,result.stdout+result.stderr
    assert list((tmp_path/'out').rglob('kubectl_1.34.1.deb'))
    metadata=json.loads(next((tmp_path/'out').rglob('manifest.json')).read_text())['metadata']['kubernetes']
    assert metadata['selected_minor']=='1.33' and metadata['component_sources'][0]['version']=='1.34.1'
    assert any(f['code']=='selected-minor-source' for f in metadata['findings'])
    assert 'Records' in metadata['proves'] and metadata['apiserver_assumed']
    assert 'DOES NOT PROVE' in next((tmp_path/'out').rglob('ASSURANCE.txt')).read_text()


def test_cli_conflict_lists_package_and_acknowledgement_allows_build(local_kubernetes,tmp_path):
    spec=workload_spec(local_kubernetes,tmp_path/'out',names=('kubeadm',))
    result=invoke(tmp_path,spec,'--accept-trust-findings')
    assert result.returncode!=0 and 'kubeadm' in result.stdout+result.stderr
    assert not list((tmp_path/'out').rglob('*.deb'))
    spec=replace(spec,content=replace(spec.content,advisories_acknowledged=True))
    result=invoke(tmp_path,spec,'--accept-trust-findings')
    assert result.returncode==0,result.stdout+result.stderr
    assert list((tmp_path/'out').rglob('kubeadm_1.32.0.deb'))


def test_catalog_and_resolver_never_hide_managed_or_other_minor_packages(local_kubernetes):
    repo=core.RepoSpec('Fixture',local_kubernetes.as_uri()+'/',repo_format='apt',flat_repo=True)
    rows=apt_core.load_repository(repo,{'amd64'},core.Reporter())
    before=list(rows)
    host=SimpleNamespace(_is_arch=lambda:False,_is_deb=lambda:True)
    for context in [None,WorkloadContext(workload='kubernetes-client',minor='1.33'),WorkloadContext(workload='vks-node-additions')]:
        opts=core.BuildOptions(include_dependencies=False,workload_context=context)
        result=BuildBackendMixin._resolve_backend(host,[('kernel-headers',None,None),('kubelet',None,None)],rows,'amd64',opts,core.Reporter())
        assert {p.name for p in result.selected}=={'kernel-headers','kubelet'}
        assert rows==before and len(rows)==8


def test_vks_missing_inventory_has_rolling_channel_explanation(local_kubernetes,tmp_path):
    spec=workload_spec(local_kubernetes,tmp_path/'out','vks-node-additions',('cryptsetup',))
    with pytest.raises(RuntimeError,match='rolling channels'):
        prepare_build(spec,BuildServices(core.Reporter()))


def test_baseline_rejects_installed_changes_but_keeps_ordinary_headers():
    repo=core.RepoSpec('base','https://example.invalid/')
    installed=apt_core.DebPackage('libc6','amd64','1','libc.deb','sha256','',repo)
    inv=apt_core.AptTargetInventory(retained_packages=[installed])
    headers=replace(installed,name='kernel-headers')
    enforce_baseline(SimpleNamespace(selected=[headers]),inv)
    with pytest.raises(ValueError,match='libc6'):
        enforce_baseline(SimpleNamespace(selected=[replace(installed,version='2')]),inv)
    assert rolling_source(core.RepoSpec('Photon Updates','https://host/photon/5.0/photon_updates_5.0_x86_64/'))


def test_vks_build_emits_image_draft_and_keeps_inventory_baseline(local_kubernetes,tmp_path):
    spec=workload_spec(local_kubernetes,tmp_path/'out','vks-node-additions',('cryptsetup','kernel-headers'))
    inventory=tmp_path/'inventory.txt'
    inventory.write_text('META|family|deb\nMETA|relationships|complete\nDEB|libc6|1.0|amd64\nDETAIL|'+json.dumps(
        {'Package':'libc6','Version':'1.0','Architecture':'amd64'})+'\n')
    spec=replace(spec,target=replace(spec.target,inventory_path=str(inventory)))
    result=invoke(tmp_path,spec,'--accept-trust-findings')
    assert result.returncode==0,result.stdout+result.stderr
    drafts=list((tmp_path/'out').rglob('imagebaker-image.yaml'))
    assert len(drafts)==1
    text=drafts[0].read_text()
    assert 'UNVALIDATED' in text and 'node-additions' in text and 'kubernetesSpec: {}' in text
    assert 'cryptsetup' in text and 'kernel-headers' in text and 'dists/' in text
    assert len(list((tmp_path/'out').rglob('*.deb')))==2
    manifest=json.loads(next((tmp_path/'out').rglob('manifest.json')).read_text())['metadata']['kubernetes']
    assert manifest['pin_to_inventory_baseline'] and manifest['platform_note']=='VKr recorded-only'


def test_flat_kubernetes_repository_can_be_mirrored(local_kubernetes,tmp_path):
    spec=workload_spec(local_kubernetes,tmp_path/'out')
    repo=build_spec.repositories_from(spec,core.RepoSpec)[0]
    spec=replace(spec,content=replace(spec.content,selection_mode='Entire repository (mirror)'),
        mirror=replace(spec.mirror,selected_repositories=(repo.source_identity,)))
    result=invoke(tmp_path,spec,'--accept-trust-findings')
    # kubeadm's off-minor finding still needs an explicit acknowledgement.
    if result.returncode:
        assert 'kubeadm' in result.stdout+result.stderr
        spec=replace(spec,content=replace(spec.content,advisories_acknowledged=True))
        result=invoke(tmp_path,spec,'--accept-trust-findings')
    assert result.returncode==0,result.stdout+result.stderr
    assert len(list((tmp_path/'out').rglob('*.deb')))==8


def test_frozen_context_does_not_read_any_widgets():
    from feathered_app.build_request import BuildRequestMixin
    class Tripwire:
        def get(self): raise AssertionError('read a widget')
    spec=build_spec.BuildSpec(target=build_spec.TargetSpec(platform_note='recorded'),
        content=build_spec.ContentSpec(k8s_minor='1.33',advisories_acknowledged=True))
    host=SimpleNamespace(_build_snapshot=spec,_workload=lambda:SimpleNamespace(key='kubernetes-client'))
    for name in build_spec.captured_variable_names(): setattr(host,name,Tripwire())
    context=BuildRequestMixin._selected_workload_context(host)
    assert context.minor=='1.33' and context.acknowledged and context.platform_note=='recorded'


def test_kubernetes_bundle_supports_additive_publication(local_kubernetes,tmp_path):
    spec=workload_spec(local_kubernetes,tmp_path/'out',names=('kubectl',))
    assert invoke(tmp_path,spec,'--accept-trust-findings').returncode==0
    result=invoke(tmp_path,spec,'--accept-trust-findings','--existing-output','add','--existing-metadata','regenerate')
    assert result.returncode==0,result.stdout+result.stderr
    metadata=json.loads(next((tmp_path/'out').rglob('manifest.json')).read_text())['metadata']['kubernetes']
    assert 'retained additive files are outside' in metadata['proves']


def test_discovery_result_defers_during_build_and_keeps_other_family_separate(tmp_path):
    from feathered_app.ui.kubernetes import KubernetesWorkloadMixin
    from k8s_discovery import Observation
    host=KubernetesWorkloadMixin()
    host._busy=lambda:True
    host.after=Mock()
    observation=Observation(('1.33',),'timestamp','source')
    host._receive_k8s_observation('deb',observation)
    assert host.after.called and '_k8s_observations' not in host.__dict__
    host._busy=lambda:False
    host._profile=lambda:SimpleNamespace(package_family='rpm')
    host._release_cache_path=lambda:tmp_path/'releases.json'
    host._sync_kubernetes_controls=Mock()
    host._receive_k8s_observation('deb',observation)
    assert host._k8s_observations['deb']==observation
    assert not host._sync_kubernetes_controls.called


def test_generated_repository_changes_do_not_drop_operator_policy():
    t=repository_template('rpm','1.33')
    repo=core.RepoSpec(t.name,t.url,role='kubernetes',verification_strategy='signed-metadata')
    repo.workload_profile_managed=True
    rows=[repo]
    synchronize_repository(rows,'rpm','1.34',lambda *_:None)
    assert rows[0] is repo and repo.verification_strategy=='signed-metadata'


def test_complete_rpm_inventory_satisfies_libraries_without_upgrading_them(tmp_path):
    from test_feather import rpm_pkg
    # The fixture mirrors a pinned node with older installed libraries and an
    # addition whose dependencies that node already satisfies.
    lib= rpm_pkg('glibc','1.0')
    ssl= rpm_pkg('openssl','1.0')
    addition=rpm_pkg('cryptsetup','2.0',requires=[core.Requirement('glibc','GE','0','1.0','1'),core.Requirement('openssl','GE','0','1.0','1')])
    inventory=core.TargetInventory(nevras={lib.nevra,ssl.nevra},retained_packages=[lib,ssl],relationships_complete=True)
    for p in [lib,ssl]:
        inventory.capabilities[p.name]=list(p.provides)
        inventory.package_capabilities[p.nevra]=list(p.provides)
    host=SimpleNamespace(_is_arch=lambda:False,_is_deb=lambda:False)
    result=BuildBackendMixin._resolve_backend(host,[('cryptsetup',None,None)],
        [addition,rpm_pkg('glibc','2.0'),rpm_pkg('openssl','2.0')],'x86_64',core.BuildOptions(target_inventory=inventory),core.Reporter())
    assert not result.unresolved
    assert [p.name for p in result.selected]==['cryptsetup']
    enforce_baseline(result,inventory)


@pytest.mark.parametrize('updates', [{'k8s_minor':'latest'}, {'advisories_acknowledged':'false'}])
def test_invalid_workload_request_rejected_before_fetch(local_kubernetes,tmp_path,updates):
    from feathered_app.build_preparation import PreparationRejected
    spec=workload_spec(local_kubernetes,tmp_path/'out')
    spec=replace(spec,content=replace(spec.content,**updates))
    with pytest.raises(PreparationRejected):
        prepare_build(spec,BuildServices(core.Reporter()))
    assert not (tmp_path/'out').exists()



def test_workload_artifacts_exist_before_indexing(local_kubernetes,tmp_path,monkeypatch):
    repo=core.RepoSpec('Fixture',local_kubernetes.as_uri()+'/',repo_format='apt',flat_repo=True)
    packages=apt_core.load_repository(repo,{'amd64'},core.Reporter())
    chosen=next(p for p in packages if p.name=='cryptsetup')
    result=apt_core.DebResolutionResult(selected=[chosen],roots=[chosen],unresolved=[])
    context=WorkloadContext(workload='vks-node-additions',image_name='draft',distribution='Ubuntu',release='24.04')
    opts=core.BuildOptions(workload_context=context,target_inventory=apt_core.AptTargetInventory(),
                           emit_repository=True,sign_bundle_index=True)
    original=apt_core.write_bundle_index
    checked=[]
    def inspect_index(folder,reporter,metadata,signing_key):
        assert (folder/'imagebaker-image.yaml').is_file()
        assert list(folder.rglob('ASSURANCE.txt'))
        checked.append(True)
        return original(folder,reporter,metadata,signing_key)
    monkeypatch.setattr(apt_core,'write_bundle_index',inspect_index)
    host=SimpleNamespace(_is_arch=lambda:False,_is_deb=lambda:True)
    BuildBackendMixin._write_bundle_backend(host,result,tmp_path/'sealed',opts,core.Reporter(),{})
    assert checked==[True]
    index=json.loads((tmp_path/'sealed/bundle-index.json').read_text())
    assert 'imagebaker-image.yaml' in json.dumps(index) and 'ASSURANCE.txt' in json.dumps(index)


def test_saved_workload_patch_pin_builds_requested_version(local_kubernetes, tmp_path):
    spec = workload_spec(local_kubernetes, tmp_path/'out')
    spec = replace(spec, content=replace(spec.content, package_version='1.33.4'))
    spec = build_spec.BuildSpec.from_json(spec.to_json())
    result = invoke(tmp_path, spec, '--accept-trust-findings', '--accept-package-only')
    assert result.returncode == 0, result.stdout + result.stderr
    assert list((tmp_path/'out').rglob('kubectl_1.33.4.deb'))
    assert not list((tmp_path/'out').rglob('kubectl_1.34.1.deb'))


def test_unavailable_workload_patch_never_falls_back_to_latest(local_kubernetes, tmp_path):
    spec = workload_spec(local_kubernetes, tmp_path/'out')
    spec = replace(spec, content=replace(spec.content, package_version='1.33.99'))
    result = invoke(tmp_path, spec, '--accept-trust-findings', '--accept-package-only')
    assert result.returncode != 0
    assert not list((tmp_path/'out').rglob('*.deb'))


def test_node_build_requests_pin_components_but_not_cri_or_cni(local_kubernetes, tmp_path):
    from feathered_app.headless_host import HeadlessHost
    spec = workload_spec(local_kubernetes, tmp_path/'out', 'kubernetes-node')
    spec = replace(spec, content=replace(spec.content, package_version='1.33.4-1.1'))
    host = HeadlessHost(spec, BuildServices(core.Reporter()), build_spec.repositories_from(spec, core.RepoSpec))
    requests = {r[0]: r[1] for r in host._package_requests()}
    assert {name: requests[name] for name in ('kubelet', 'kubeadm', 'kubectl')} == {
        name: '1.33.4-1.1' for name in ('kubelet', 'kubeadm', 'kubectl')}
    assert requests['cri-tools'] is None and requests['kubernetes-cni'] is None
