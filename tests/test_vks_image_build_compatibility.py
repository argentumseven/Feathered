"""Published legacy OS support evidence is not a package-availability gate."""
from __future__ import annotations

from dataclasses import replace
import json

import pytest

from build_spec import BuildSpec, ContentSpec, TargetSpec
from kubernetes_workflow import VKS_KEY, WorkloadContext, report, write_image_handoff
from vks_compatibility import (BUILDER_IMAGE_BAKER, BUILDER_LEGACY,
                               assess, vkr_minor)


OS_TARGETS = (
    ('VMware Photon OS', '5.0'),
    ('Ubuntu', '22.04'),
    ('Ubuntu', '24.04'),
    ('Red Hat Enterprise Linux (RHEL)', '9.7'),
)


@pytest.mark.parametrize('minor', (31, 32, 33, 34))
@pytest.mark.parametrize('os_index', range(4))
def test_legacy_builder_release_specific_supported_os_grid(minor, os_index):
    distribution, release = OS_TARGETS[os_index]
    result = assess(distribution, release, vks_release='3.6',
                    exact_vkr=f'v1.{minor}.9+vmware.2', builder=BUILDER_LEGACY)
    listed = os_index in (0, 1) or (os_index == 2 and minor >= 33)
    assert result.status == ('os_listed' if listed else 'not_listed')
    assert result.evidence_url == f'https://github.com/vmware/vks-image-builder/blob/release-1.{minor}/supported-context.json'
    assert 'not verified' in result.message.lower() if listed else 'absent' in result.message


@pytest.mark.parametrize('distribution,release', OS_TARGETS)
@pytest.mark.parametrize('builder', (BUILDER_LEGACY, BUILDER_IMAGE_BAKER))
def test_builder_transition_is_not_a_blanket_135_os_approval(distribution, release, builder):
    result = assess(distribution, release, vks_release='3.6',
                    exact_vkr='v1.35.0---vmware.2-vkr.4', builder=builder)
    assert result.status == ('not_listed' if builder == BUILDER_LEGACY else 'unverified')
    assert result.evidence_url


@pytest.mark.parametrize('minor', (31, 32, 33, 34))
@pytest.mark.parametrize('distribution,release', OS_TARGETS)
def test_image_baker_on_older_vkr_is_unverified_not_disallowed(minor, distribution, release):
    assert assess(distribution, release, exact_vkr=f'v1.{minor}.2+vmware.1',
                  builder=BUILDER_IMAGE_BAKER).status == 'unverified'


@pytest.mark.parametrize('text,expected', (
    ('v1.34.9+vmware.2', 34),
    ('v1.31.14+vmware.1-fips', 31),
    ('v1.35.0---vmware.2-vkr.4', 35),
    ('1.35.0---vmware.2-vkr.4', 35),
    ('1.34', None),
    ('v1.35.0', None),
    ('garbage', None),
))
def test_vendor_vkr_parser_only_recognizes_exact_vendor_format(text, expected):
    assert vkr_minor(text) == expected


def test_compatibility_is_advisory_and_round_trips_saved_cli_intent(tmp_path):
    spec = BuildSpec(target=TargetSpec(distribution='Red Hat Enterprise Linux (RHEL)', release='9.7'),
                     content=ContentSpec(vks_release='3.6', exact_vkr='v1.34.9+vmware.2',
                                         image_builder=BUILDER_LEGACY))
    restored = BuildSpec.from_json(spec.to_json())
    assert restored == spec
    context = WorkloadContext(workload=VKS_KEY, distribution=restored.target.distribution,
                              release=restored.target.release, vks_release=restored.content.vks_release,
                              exact_vkr=restored.content.exact_vkr,
                              image_builder=restored.content.image_builder)
    context.validate()
    assert report(context, [])['vks_image_build_compatibility']['status'] == 'not_listed'
    write_image_handoff(tmp_path, context, type('Result', (), {'roots': []})())
    handoff = json.loads((tmp_path / 'vks-image-baker-handoff.json').read_text())
    assert handoff['vks_target'] == {'platform_release': '3.6',
                                    'exact_vkr': 'v1.34.9+vmware.2',
                                    'image_builder': BUILDER_LEGACY}
    assert handoff['image_build_compatibility']['status'] == 'not_listed'
    assert handoff['usable_as_image_baker_config'] is False


def test_missing_vkr_fields_keep_existing_bundle_specs_compatible():
    prior = BuildSpec().to_dict()
    for key in ('vks_release', 'exact_vkr', 'image_builder'):
        prior['content'].pop(key)
    spec = BuildSpec.from_dict(prior)
    assert spec.content.vks_release == spec.content.exact_vkr == spec.content.image_builder == ''
    context = WorkloadContext(workload=VKS_KEY, distribution='Ubuntu', release='24.04')
    context.validate()
    assert report(context, [])['vks_image_build_compatibility']['status'] == 'unverified'


@pytest.mark.parametrize('updates', (
    {'exact_vkr': '1.34'},
    {'image_builder': 'invented-builder'},
    {'vks_release': 'not a version'},
))
def test_invalid_image_build_intent_rejected_as_input_error(updates):
    context = replace(WorkloadContext(workload=VKS_KEY), **updates)
    with pytest.raises(ValueError):
        context.validate()
