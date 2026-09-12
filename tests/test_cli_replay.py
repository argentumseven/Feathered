"""Public CLI builds from saved JSON in a process that cannot import Tk."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from build_spec import (BuildSpec, ContentSpec, ExactPackageRecord, MirrorSpec,
                        OutputSpec, RepositoryRecord, SourceSpec, TargetSpec)
from core import RepoSpec
from tests import test_headless_execution as fixture_source

local_repository = fixture_source.local_repository
ROOT = Path(__file__).resolve().parents[1]
CLI_RUN = '''
import builtins, runpy, sys
real = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.split('.')[0] in {'tkinter', 'app'}:
        raise ImportError('GUI imports are forbidden during a CLI build')
    return real(name, *args, **kwargs)
builtins.__import__ = guarded
sys.argv = ['feathered_cli.py'] + sys.argv[1:]
runpy.run_module('feathered_cli', run_name='__main__')
'''


def spec_for(repository, output, mode='exact', version='1.0'):
    repo = RepoSpec('Local', repository.as_uri()+'/', 'dependency', repo_format='apt',
                    suite='stable', components='main', allow_unverified_index=True)
    rows = [repo]
    if mode in {'separate', 'unified'}:
        second = repository.with_name('second-repository')
        shutil.copytree(repository, second)
        rows.append(RepoSpec('Second', second.as_uri()+'/', 'dependency', repo_format='apt',
                            suite='stable', components='main', allow_unverified_index=True))
    return BuildSpec(
        target=TargetSpec(distribution='Devuan' if mode == 'devuan' else 'Debian',
                          release='12', arch='amd64', init_system='runit' if mode == 'devuan' else ''),
        content=ContentSpec(selection_mode='Entire repository (mirror)' if len(rows)>1 else
                            'Choose packages' if mode == 'exact' else 'Workload preset', workload='Podman',
                            package_version='Latest', exact_packages=(ExactPackageRecord(
                                'podman', version, 'dependency', 'Local', 'amd64', repo.source_identity),)
                            if mode == 'exact' else ()),
        sources=SourceSpec(method='Custom repositories', mirror_method='Custom repositories',
                           repositories=tuple(RepositoryRecord.capture(r) for r in rows)),
        mirror=MirrorSpec(layout=mode if mode in {'separate','unified'} else 'separate',
                          selected_repositories=tuple(r.source_identity for r in rows) if len(rows)>1 else ()),
        output=OutputSpec(directory=str(output), folder_scheme='Custom label', folder_label='bundle',
                          folder_stamp='none', emit_repository=True))


def invoke(tmp_path, spec, *args):
    path=tmp_path/'request.json';path.write_text(spec.to_json())
    env=dict(os.environ);env.pop('DISPLAY',None);env.pop('WAYLAND_DISPLAY',None)
    return subprocess.run([sys.executable,'-c',CLI_RUN,'build','--spec',str(path),'--quiet',*args],
                          env=env,cwd=ROOT,capture_output=True,text=True,timeout=45)


@pytest.mark.parametrize('mode',['workload','exact','separate','unified','devuan'])
def test_public_cli_prepares_and_publishes_without_tk(local_repository,tmp_path,mode):
    spec=spec_for(local_repository,tmp_path/'out',mode)
    result=invoke(tmp_path,spec,'--accept-trust-findings')
    assert result.returncode==0,result.stdout+result.stderr
    payloads={p.name for p in (tmp_path/'out').rglob('*.deb')}
    assert f'podman_{"1.0" if mode=="exact" else "1.1"}_amd64.deb' in payloads
    if mode=='exact':assert 'podman_1.1_amd64.deb' not in payloads
    if mode=='devuan':assert 'runit_1.0_amd64.deb' in payloads
    folders=[p for p in (tmp_path/'out').iterdir() if p.is_dir() and not p.name.startswith('.')]
    assert len(folders)==(2 if mode=='separate' else 1)
    if mode=='unified':
        merged=json.loads(next((tmp_path/'out').rglob('mirror-sources.json')).read_text())
        assert merged['duplicate_records_removed']==3
    assert list((tmp_path/'out').rglob('manifest.json'))


def test_stable_source_identity_survives_display_label_change(local_repository,tmp_path):
    spec=spec_for(local_repository,tmp_path/'out')
    row=replace(spec.sources.repositories[0],name='Renamed')
    spec=replace(spec,sources=replace(spec.sources,repositories=(row,)))
    result=invoke(tmp_path,spec,'--accept-trust-findings')
    assert result.returncode==0,result.stderr
    assert list((tmp_path/'out').rglob('podman_1.0_amd64.deb'))


def test_missing_pin_is_rejected_before_publication(local_repository,tmp_path):
    result=invoke(tmp_path,spec_for(local_repository,tmp_path/'out',version='0.9'))
    assert result.returncode==5
    assert 'Saved exact package is unavailable' in result.stderr
    assert not (tmp_path/'out').exists()


def test_unsigned_metadata_requires_trust_consent(local_repository,tmp_path):
    result=invoke(tmp_path,spec_for(local_repository,tmp_path/'out','workload'))
    assert result.returncode==2,result.stderr
    assert 'TRUST:' in result.stderr
    assert not list((tmp_path/'out').rglob('*.deb'))


@pytest.mark.parametrize('mode',['exact','workload'])
def test_expired_request_does_not_start_preparation(local_repository,tmp_path,mode):
    result=invoke(tmp_path,spec_for(local_repository,tmp_path/'out',mode),'--timeout','0')
    assert result.returncode==4,result.stderr
    assert not (tmp_path/'out').exists()


def test_existing_output_requires_separate_consent(local_repository,tmp_path):
    spec=spec_for(local_repository,tmp_path/'out')
    occupied=tmp_path/'out'/'bundle';occupied.mkdir(parents=True)
    marker=occupied/'keep.txt';marker.write_text('existing user content')
    result=invoke(tmp_path,spec,'--accept-trust-findings','--accept-conflict-notices')
    assert result.returncode==2,result.stderr
    assert marker.read_text()=='existing user content'
    assert list(occupied.iterdir())==[marker]
    result=invoke(tmp_path,spec,'--accept-trust-findings','--existing-output','sibling')
    assert result.returncode==0,result.stderr
    assert marker.read_text()=='existing user content'
    assert list((tmp_path/'out').glob('bundle-refresh-*'))


def test_additive_metadata_requires_its_own_choice(local_repository,tmp_path):
    spec=spec_for(local_repository,tmp_path/'out')
    assert invoke(tmp_path,spec,'--accept-trust-findings').returncode==0
    index=next((tmp_path/'out').rglob('Release'));before=index.read_bytes()
    result=invoke(tmp_path,spec,'--accept-trust-findings','--existing-output','add')
    assert result.returncode==2,result.stderr
    assert index.read_bytes()==before
    result=invoke(tmp_path,spec,'--accept-trust-findings','--existing-output','add','--existing-metadata','regenerate')
    assert result.returncode==0,result.stderr


def test_invalid_request_has_diagnostic_and_nonzero_exit(tmp_path):
    result=invoke(tmp_path,BuildSpec())
    assert result.returncode==5
    assert 'recognized target distribution' in result.stderr


def test_dry_run_describes_settings_without_preparing(tmp_path):
    result=invoke(tmp_path,BuildSpec(),'--dry-run')
    assert result.returncode==0,result.stderr
    assert 'nothing was fetched or written' in result.stdout


@pytest.mark.parametrize('accept',[False,True])
def test_real_conflict_requires_explicit_consent(local_repository,tmp_path,accept):
    index=local_repository/'dists/stable/main/binary-amd64/Packages'
    text=index.read_text().replace('Package: podman\n','Package: podman\nConflicts: runit\n')
    index.write_text(text)
    release=local_repository/'dists/stable/Release'
    release.write_text('Suite: stable\nCodename: stable\nComponents: main\nArchitectures: amd64\n'
                       f'SHA256:\n {hashlib.sha256(index.read_bytes()).hexdigest()} {index.stat().st_size} main/binary-amd64/Packages\n')
    spec=spec_for(local_repository,tmp_path/'out')
    root=replace(spec.content.exact_packages[0],name='runit')
    spec=replace(spec,content=replace(spec.content,exact_packages=(*spec.content.exact_packages,root)))
    flags=['--accept-trust-findings']+(['--accept-conflict-notices'] if accept else [])
    result=invoke(tmp_path,spec,*flags)
    assert result.returncode==(0 if accept else 2),result.stdout+result.stderr
    assert 'runit' in result.stderr and 'podman' in result.stderr
    if not accept:assert not list((tmp_path/'out').rglob('*.deb'))


def test_captured_draft_is_invalid_until_release_is_selected(local_repository, tmp_path, capsys):
    """Capture is lossless; preparation distinguishes invalid from declined.

    Reproduces the empty release in a freshly opened form without needing a
    display, then verifies the existing trust exit-code contract on that same
    captured request after an explicit release selection.
    """
    from types import SimpleNamespace
    from build_spec import FIELD_TO_VARIABLE, capture, repositories_from
    from feathered_cli import run_build

    spec = spec_for(local_repository, tmp_path / 'out', 'workload')
    def control(value):
        return SimpleNamespace(get=lambda: value)

    controls = {
        variable: control(getattr(getattr(spec, section), field))
        for section, field, variable in FIELD_TO_VARIABLE
    }
    controls['release_var'] = SimpleNamespace(get=lambda: '')
    host = SimpleNamespace(**controls, repository_rows=lambda: repositories_from(spec, RepoSpec))
    draft = BuildSpec.from_json(capture(host).to_json())
    assert draft.target.release == '', 'capture must not invent a target release'
    assert run_build(draft, quiet=True) == 5
    rejected = capsys.readouterr()
    assert 'Choose a target release' in rejected.err
    assert 'TRUST:' not in rejected.err
    assert not (tmp_path / 'out').exists()

    host.release_var = SimpleNamespace(get=lambda: '12')
    ready = BuildSpec.from_json(capture(host).to_json())
    assert ready.target.release == '12'
    assert run_build(ready, quiet=True) == 2
    assert 'TRUST:' in capsys.readouterr().err
    assert not list((tmp_path / 'out').rglob('*.deb'))
    assert run_build(ready, quiet=True, accept_trust=True) == 0
    assert list((tmp_path / 'out').rglob('podman_1.1_amd64.deb'))
