"""RPM/Arch CLI orchestration fixtures; these are not native install tests.

Metadata is emitted by the real backends. Payload bytes are intentionally small
synthetic fixtures, so this exercises loading/resolution/publication and proves
no native package-manager acceptance claim.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from build_spec import (BuildSpec, ContentSpec, ExactPackageRecord, OutputSpec,
                        RepositoryRecord, SourceSpec, TargetSpec)
import core
import arch_core
from tests.test_cli_replay import invoke


@pytest.mark.parametrize('family',['rpm','arch'])
def test_other_families_prepare_and_execute_without_tk(tmp_path,family):
    source=tmp_path/'source';source.mkdir()
    filename='demo-1.0-1.x86_64.rpm' if family=='rpm' else 'demo-1.0-1-x86_64.pkg.tar.gz'
    payload=source/filename;payload.write_bytes(b'fixture package payload')
    digest=hashlib.sha256(payload.read_bytes()).hexdigest()
    repo=core.RepoSpec('Local',source.as_uri()+'/',repo_format='rpm' if family=='rpm' else 'pacman',
                       suite='feathered' if family=='arch' else '',allow_unverified_index=True)
    if family=='rpm':
        pkg=core.Package('demo','x86_64','0','1.0','1',filename,'sha256',digest,repo,size=payload.stat().st_size)
        core.emit_rpm_repository(source,[pkg],core.Reporter(),preserve_package_locations=True)
    else:
        pkg=arch_core.ArchPackage('demo','x86_64','1.0-1',filename,'sha256',digest,repo,
                                  size=payload.stat().st_size,digests={'sha256':digest})
        arch_core.emit_arch_repository(source,[pkg],core.Reporter())
    inventory=tmp_path/'inventory.txt'
    inventory.write_text('META|package_family|arch\nMETA|relationships|complete\nMETA|id|arch\nMETA|arch|x86_64\nPAC|existing|1-1\nDETAIL|' + json.dumps({'NAME':['existing'],'VERSION':['1-1'],'ARCH':['x86_64'],'managed':False})+'\n')
    spec=BuildSpec(
        target=TargetSpec(distribution='Red Hat Enterprise Linux (RHEL)' if family=='rpm' else 'Arch Linux',
                          release='9' if family=='rpm' else 'rolling',arch='x86_64',
                          inventory_path=str(inventory) if family=='arch' else ''),
        content=ContentSpec(selection_mode='Choose packages',exact_packages=(ExactPackageRecord.capture(pkg),)),
        sources=SourceSpec(method='Custom repositories',repositories=(RepositoryRecord.capture(repo),)),
        output=OutputSpec(directory=str(tmp_path/'out'),folder_scheme='Custom label',folder_label='bundle',folder_stamp='none',emit_repository=True))
    result=invoke(tmp_path,spec,'--accept-trust-findings')
    assert result.returncode==0,result.stdout+result.stderr
    artifacts=list((tmp_path/'out').rglob(filename))
    assert len(artifacts)==1
    assert artifacts[0].read_bytes()==payload.read_bytes()
    assert list((tmp_path/'out').rglob('manifest.json'))
