"""VKS acquisition mode smoke grid using real local metadata and synthetic payloads.

These fixtures test Feathered's offline package path, not vendor-supported
VKr/OS image combinations or native target package-manager acceptance.
"""
from __future__ import annotations

import json

import pytest

import core
from build_spec import (BuildSpec, ContentSpec, ExactPackageRecord, MirrorSpec,
                        OutputSpec, RepositoryRecord, SourceSpec, TargetSpec)
from kubernetes_workflow import LABELS
from profiles import PROFILES
from tests.test_cli_replay import invoke
from tests.test_publication_workflows import package_fixture


@pytest.mark.parametrize('profile_key,release,family', [
    ('photon', '5.0', 'rpm'),
    ('ubuntu', '22.04', 'deb'),
    ('ubuntu', '24.04', 'deb'),
    ('rhel', '9.7', 'rpm'),
])
@pytest.mark.parametrize('mode,pin', [
    ('Choose packages', False),
    ('Choose packages', True),
    ('Entire repository (mirror)', False),
    ('Entire repository (mirror)', True),
])
def test_vks_os_bundle_and_repository_mirror_remain_distinct(
        tmp_path, profile_key, release, family, mode, pin):
    backend, _directory, source, package, _, _ = package_fixture(
        tmp_path, family, name='cryptsetup')
    if family == 'rpm':
        core.emit_rpm_repository(source, [package], core.Reporter(),
                                 preserve_package_locations=True)
    else:
        backend.emit_apt_repository(source, [package], core.Reporter(),
                                    preserve_package_locations=True)
    repo = package.repo
    profile = PROFILES[profile_key]
    choosing_packages = mode == 'Choose packages'
    spec = BuildSpec(
        target=TargetSpec(distribution=profile.label, release=release, arch=package.arch),
        content=ContentSpec(
            selection_mode=mode, workload=LABELS['vks-node-additions'],
            exact_packages=(ExactPackageRecord.capture(package),) if choosing_packages else (),
            pin_to_inventory_baseline=pin, image_baker_name=''),
        sources=SourceSpec(method='Custom repositories',
                           repositories=(RepositoryRecord.capture(repo),)),
        mirror=MirrorSpec(selected_repositories=(repo.source_identity,)),
        output=OutputSpec(directory=str(tmp_path / 'out'), folder_scheme='Custom label',
                          folder_label='result', folder_stamp='none', emit_repository=True),
    )
    outcome = invoke(tmp_path, spec, '--accept-trust-findings', '--accept-package-only')
    assert outcome.returncode == 0, (profile_key, release, mode, pin,
                                     outcome.stdout, outcome.stderr)
    assert len(list((tmp_path / 'out').rglob('manifest.json'))) == 1
    handoffs = list((tmp_path / 'out').rglob('vks-image-baker-handoff.json'))
    # A repository mirror is its own deliverable, not a VKS OS-addition plan.
    assert len(handoffs) == int(choosing_packages)
    if choosing_packages:
        handoff = json.loads(handoffs[0].read_text(encoding='utf-8'))
        assert not handoff['usable_as_image_baker_config']
        assert handoff['requested_package_roots'] == ['cryptsetup']
        assert handoff['handoff_label'] == ''  # Optional for package acquisition.
    assert not list((tmp_path / 'out').rglob('imagebaker-image.yaml'))
