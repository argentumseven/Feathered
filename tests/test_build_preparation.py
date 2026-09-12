"""Preparation contracts: policies, inputs, isolation and terminal outcomes."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import queue

import pytest

from acquisition_model import AcquisitionCapability
from core import Reporter
from feathered_app.build_api import PreparationInputs, prepare_build, execute_build
from feathered_app.build_outcome import BuildStatus
from feathered_app.build_preparation import DecisionDeclined, PreparationRejected
from feathered_app.build_services import BuildServices
from tests import test_headless_execution as fixture_source
from tests.test_cli_replay import spec_for
from workloads import WorkloadProfile

local_repository = fixture_source.local_repository


def services(**kwargs):
    return BuildServices(Reporter(), **kwargs)


def test_preparation_is_owned_and_does_not_publish(local_repository,tmp_path):
    spec=spec_for(local_repository,tmp_path/'out','workload')
    first=prepare_build(spec,services())
    second=prepare_build(spec,services())
    assert not (tmp_path/'out').exists()
    first.plan.opts.optional_roots.add('changed')
    first.plan.build_repositories[0].enabled=False
    assert 'changed' not in second.plan.opts.optional_roots
    assert second.plan.build_repositories[0].enabled
    assert spec.sources.repositories[0].enabled
    assert first.host._folder_name()==first.plan.locked_output_folder_name


def test_optional_catalogue_members_and_dependency_mode_reach_plan(local_repository,tmp_path):
    spec=spec_for(local_repository,tmp_path/'out','workload')
    workload=WorkloadProfile('fixture','Fixture',['podman','absent'],'test',optional_packages=['absent'])
    spec=replace(spec,content=replace(spec.content,workload='Fixture',dependency_mode='Complete + weak dependencies'))
    prepared=prepare_build(spec,services(),PreparationInputs(workloads={'fixture':workload},resolution_pass_budget=11))
    assert prepared.plan.opts.optional_roots=={'absent'}
    assert prepared.plan.opts.include_recommends
    assert prepared.plan.opts.max_resolution_passes==11
    assert {r[0] for r in prepared.plan.requests}=={'podman','absent'}


def test_package_only_requires_its_own_policy_and_never_parses_inventory(local_repository,tmp_path):
    spec=spec_for(local_repository,tmp_path/'out','workload')
    vendor=replace(spec.sources.repositories[0],role='fixture-vendor',workload_profile_managed=True)
    workload=WorkloadProfile('fixture','Fixture',['podman'],'test',repository_roles=['fixture-vendor'])
    spec=replace(spec,sources=replace(spec.sources,repositories=(vendor,)),
                 content=replace(spec.content,workload='Fixture',dependency_mode='Target-aware complete'),
                 target=replace(spec.target,inventory_path=str(tmp_path/'absent-inventory')))
    inputs=PreparationInputs(workloads={'fixture':workload})
    with pytest.raises(DecisionDeclined):
        prepare_build(spec,services(decision_policy=lambda *args:True),inputs)
    prepared=prepare_build(spec,services(package_only_policy=lambda *args:True),inputs)
    assert prepared.plan.state.capability is AcquisitionCapability.PACKAGE_ONLY
    assert not prepared.plan.opts.include_dependencies
    assert prepared.plan.opts.target_inventory is None
    outcome=execute_build(spec,services(package_only_policy=lambda *args:True,trust_policy=lambda rows:True),inputs)
    assert outcome.status is BuildStatus.SUCCESS,outcome
    assert list((tmp_path/'out').rglob('PACKAGE-ONLY*'))


@pytest.mark.parametrize('contents,valid',[
    ('META|package_family|deb\nDEB|already|1.0|amd64\n',True),
    ('META|package_family|rpm\nPKG|already|0|1|1|x86_64\n',False)])
def test_inventory_is_parsed_by_the_target_backend(local_repository,tmp_path,contents,valid):
    inventory=tmp_path/'inventory.txt';inventory.write_text(contents)
    spec=spec_for(local_repository,tmp_path/'out','workload')
    spec=replace(spec,target=replace(spec.target,inventory_path=str(inventory)),
                 content=replace(spec.content,dependency_mode='Target-aware complete'))
    if valid:
        prepared=prepare_build(spec,services())
        assert prepared.plan.opts.target_inventory.packages[('already','amd64')]=='1.0'
    else:
        with pytest.raises(PreparationRejected,match='dpkg|APT|family'):
            prepare_build(spec,services())
    assert not (tmp_path/'out').exists()


def test_mirrors_ignore_stale_inventory_and_baseline(local_repository,tmp_path):
    spec=spec_for(local_repository,tmp_path/'out','separate')
    spec=replace(spec,target=replace(spec.target,inventory_path='missing',baseline_path='missing'),
                 output=replace(spec.output,emit_repository=False))
    prepared=prepare_build(spec,services())
    assert prepared.plan.opts.target_inventory is None
    assert prepared.plan.opts.baseline_manifest==''
    assert prepared.plan.opts.emit_repository
    assert len(prepared.plan.locked_mirror_publications)==2


def test_explicit_sealing_without_key_is_rejected(local_repository,tmp_path):
    spec=spec_for(local_repository,tmp_path/'out','workload')
    spec=replace(spec,output=replace(spec.output,sign_bundle_index=True))
    with pytest.raises(PreparationRejected,match='no signing key'):
        prepare_build(spec,services())
    assert not (tmp_path/'out').exists()


def test_credentials_are_attached_by_identity_without_mutating_spec(local_repository,tmp_path):
    spec=spec_for(local_repository,tmp_path/'out','workload')
    from build_spec import repositories_from
    from core import RepoSpec
    identity=repositories_from(spec,RepoSpec)[0].source_identity
    inputs=PreparationInputs(repository_credentials={identity:{'client_cert':'cert.pem','client_key':'key.pem','ca_cert':'ca.pem'}})
    prepared=prepare_build(spec,services(),inputs)
    repo=prepared.plan.build_repositories[0]
    assert (repo.client_cert,repo.client_key,repo.ca_cert)==('cert.pem','key.pem','ca.pem')
    assert 'key.pem' not in spec.to_json()
    with pytest.raises(PreparationRejected,match='source absent'):
        prepare_build(spec,services(),PreparationInputs(repository_credentials={'unknown':{'keyring':'k'}}))


def test_cancellation_and_timeout_are_distinct_from_invalid_request(local_repository,tmp_path):
    spec=spec_for(local_repository,tmp_path/'out','workload')
    assert execute_build(spec,services(should_cancel=lambda:True)).status is BuildStatus.CANCELLED
    assert execute_build(spec,services(),timeout=0).status is BuildStatus.TIMED_OUT
    assert execute_build(replace(spec,target=replace(spec.target,arch='wrong')),services()).status is BuildStatus.INVALID
    assert not (tmp_path/'out').exists()


def test_cancel_during_metadata_prevents_publication(local_repository,tmp_path):
    cancelled={'value':False}
    spec=spec_for(local_repository,tmp_path/'out','workload')
    reporter=Reporter(progress=lambda label,value:cancelled.update(value=True))
    outcome=execute_build(spec,BuildServices(reporter,trust_policy=lambda rows:True,
                                           should_cancel=lambda:cancelled['value']))
    assert outcome.status is BuildStatus.CANCELLED
    assert not list((tmp_path/'out').rglob('*.deb'))


def test_runner_returns_the_same_terminal_outcome_it_emits(local_repository,tmp_path):
    from feathered_app.build_runner import run
    events=queue.Queue()
    prepared=prepare_build(spec_for(local_repository,tmp_path/'out','workload'),
                           services(trust_policy=lambda rows:True,events=events))
    outcome=run(prepared.host,prepared.plan)
    terminal=[item for item in events.queue if item[0]=='done']
    assert outcome.status is BuildStatus.SUCCESS
    assert terminal==[('done',True,outcome.message,outcome.output_path)]
    assert Path(outcome.output_path).is_dir()


def test_portable_source_scope_and_evidence_hints_survive_roundtrip(local_repository,tmp_path):
    from build_spec import BuildSpec, repositories_from
    from core import RepoSpec
    spec=spec_for(local_repository,tmp_path/'out','workload')
    row=replace(spec.sources.repositories[0],source_tier='workload',workload_profile_managed=True,
                target_profile_key='debian',target_arch='amd64',
                evidence_relationship_hints=(('https://proof.invalid/','exact-mirror'),),
                evidence_authority_hints=(('https://proof.invalid/','independent'),))
    restored=BuildSpec.from_json(replace(spec,sources=replace(spec.sources,repositories=(row,))).to_json())
    repo=repositories_from(restored,RepoSpec)[0]
    assert repo.source_tier=='workload' and repo.workload_profile_managed
    assert repo.target_profile_key=='debian' and repo.target_arch=='amd64'
    assert repo.evidence_relationship_hints=={'https://proof.invalid/':'exact-mirror'}
    assert repo.evidence_authority_hints=={'https://proof.invalid/':'independent'}


def test_runtime_vendor_requirement_is_never_downgraded(local_repository,tmp_path):
    spec=spec_for(local_repository,tmp_path/'out','workload')
    row=replace(spec.sources.repositories[0],repo_format='rpm',vendor_id='redhat',suite='',components='')
    spec=replace(spec,target=replace(spec.target,distribution='Red Hat Enterprise Linux (RHEL)',arch='x86_64'),
                 sources=replace(spec.sources,repositories=(row,),vendor_signature_policy='Require signatures',required_signature_vendors=('redhat',)))
    inputs=PreparationInputs(vendor_signature_profiles={'redhat':{'policy':'record','keyring':'vendor.gpg'}})
    prepared=prepare_build(spec,services(),inputs)
    assert prepared.plan.opts.vendor_keyrings=={'redhat':'vendor.gpg'}
    assert prepared.plan.opts.require_vendor_signatures_by_vendor=={'redhat'}
    assert inputs.vendor_signature_profiles['redhat']['policy']=='record'


def test_timeout_during_metadata_has_a_timeout_outcome(local_repository,tmp_path,monkeypatch):
    from feathered_app import build_api
    clock={'now':0}
    monkeypatch.setattr(build_api.time,'monotonic',lambda:clock['now'])
    reporter=Reporter(progress=lambda label,value:clock.update(now=2))
    outcome=execute_build(spec_for(local_repository,tmp_path/'out','workload'),BuildServices(reporter),timeout=1)
    assert outcome.status is BuildStatus.TIMED_OUT
    assert not list((tmp_path/'out').rglob('*.deb'))


def test_incompatible_repository_does_not_participate(local_repository,tmp_path):
    spec=spec_for(local_repository,tmp_path/'out','workload')
    row=replace(spec.sources.repositories[0],target_profile_key='ubuntu')
    spec=replace(spec,sources=replace(spec.sources,repositories=(row,)))
    with pytest.raises(PreparationRejected):prepare_build(spec,services())
    assert not (tmp_path/'out').exists()


@pytest.mark.parametrize('data',[
    {'repository_credentials':{'x':{'password':'not a supported field'}}},
    {'vendor_signature_profiles':{'vendor':{'policy':'ignore'}}},
    {'resolution_pass_budget':-1},
    {'unexpected':'value'}])
def test_runtime_configuration_rejects_unknown_or_invalid_fields(data):
    with pytest.raises(PreparationRejected):PreparationInputs.from_dict(data)


def test_signature_requirements_capture_every_vendor_without_keyring_paths():
    from types import SimpleNamespace
    from build_spec import capture, BuildSpec, apply
    host=SimpleNamespace(vendor_signature_profiles={
        'redhat':{'policy':'require','keyring':'private-keyring.gpg'},
        'docker':{'policy':'record','keyring':'other-private.gpg'},
        'epel':{'policy':'require','keyring':'epel-local.gpg'}})
    spec=BuildSpec.from_json(capture(host).to_json())
    assert spec.sources.required_signature_vendors==('epel','redhat')
    assert 'private' not in spec.to_json()
    restored=SimpleNamespace(vendor_signature_profiles={'redhat':{'keyring':'existing-local.gpg'}})
    apply(restored,spec)
    assert restored.vendor_signature_profiles['redhat']=={'keyring':'existing-local.gpg','policy':'require'}
    assert restored.vendor_signature_profiles['epel']['policy']=='require'


@pytest.mark.parametrize('label',['','.','..'])
def test_custom_name_must_not_resolve_to_the_output_parent(local_repository,tmp_path,label):
    spec=spec_for(local_repository,tmp_path/'out','workload')
    spec=replace(spec,output=replace(spec.output,folder_label=label))
    with pytest.raises(PreparationRejected):prepare_build(spec,services())
    assert not (tmp_path/'out').exists()
