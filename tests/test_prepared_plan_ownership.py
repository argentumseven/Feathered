"""A prepared run owns its graph; backend verification state stays mutable."""
from dataclasses import replace
import pytest
import core
import apt_core
import arch_core
from acquisition_model import AcquisitionIntent, derive_acquisition_state
from feathered_app.build_runner import BuildPlan


def plan_parts(inventory=None):
    repo=core.RepoSpec('Origin','https://repo.invalid/packages',evidence_urls=['https://proof.invalid/index'])
    opts=core.BuildOptions(target_inventory=inventory,optional_roots={'optional'})
    roots=[['demo','1.2',None,None,None,None,repo.source_identity]]
    metadata=[{'package':'demo','source_policy':'repository','repository_identity':repo.source_identity}]
    repos=[repo];picked={'demo-1.2'};forks=[(repo.source_identity,'output',opts)]
    state=derive_acquisition_state(AcquisitionIntent.REPOSITORY_MIRROR,mirror_repository_count=1)
    return (state,opts,roots,metadata,repos,False,picked,True,'output',forks)


def test_plan_detaches_every_caller_owned_collection():
    parts=plan_parts();plan=BuildPlan(*parts)
    parts[1].optional_roots.add('changed')
    parts[2][0][0]='changed'
    parts[3][0]['package']='changed'
    parts[4][0].evidence_urls.append('https://changed.invalid/')
    parts[6].clear();parts[9].clear()
    assert plan.opts.optional_roots=={'optional'}
    assert plan.requests[0][0]=='demo'
    assert plan.requested_source_plan[0]['package']=='demo'
    assert plan.build_repositories[0].evidence_urls==['https://proof.invalid/index']
    assert plan.picked_at_start=={'demo-1.2'}
    assert len(plan.locked_mirror_publications)==1


@pytest.mark.parametrize('inventory_type',[core.TargetInventory,apt_core.AptTargetInventory,arch_core.ArchTargetInventory])
def test_two_plans_do_not_share_execution_state_or_erase_inventory_family(inventory_type):
    parts=plan_parts(inventory_type());one=BuildPlan(*parts);two=BuildPlan(*parts)
    assert type(one.opts.target_inventory) is inventory_type
    assert one.opts.target_inventory is not two.opts.target_inventory
    one.opts.optional_roots.add('only-first');one.build_repositories[0].enabled=False
    assert two.opts.optional_roots=={'optional'} and two.build_repositories[0].enabled
    # Copies preserve intentional internal aliases, such as a publication's
    # options, without sharing them with the caller or another run.
    assert one.locked_mirror_publications[0][2] is one.opts


def test_mutable_verification_fields_can_still_be_annotated_by_execution():
    plan=BuildPlan(*plan_parts())
    plan.build_repositories[0].allow_unverified_index=True
    plan.opts.additive_publish=True
    assert plan.build_repositories[0].allow_unverified_index and plan.opts.additive_publish
