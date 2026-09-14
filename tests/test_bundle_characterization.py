"""Golden output and event ordering for each backend, before shared extraction.

Fixture clocks, source roots and source IDs are normalized; object key order and
all payload-scoped file contents remain observable. Payloads are synthetic bytes,
so these tests establish writer equivalence, not native installer acceptance.
"""
from datetime import datetime, timezone
import hashlib
import json
import re
from pathlib import Path

import pytest
import core
import apt_core
import arch_core
import provenance

FAMILIES={'rpm':(core,'rpms','.rpm'), 'deb':(apt_core,'debs','.deb'), 'arch':(arch_core,'packages','.pkg.tar.gz')}
SCENARIOS=('fresh','reuse','corrupt','differential','additive')
GOLDENS=Path(__file__).parent/'fixtures/bundle_snapshots'


class FrozenDateTime(datetime):
    @classmethod
    def now(cls,tz=None):return cls(2020,1,2,3,4,5,tzinfo=tz)


def characterize(tmp_path,monkeypatch,family,scenario):
    backend,directory,suffix=FAMILIES[family]
    monkeypatch.setattr(provenance,'datetime',FrozenDateTime)
    source=tmp_path/'source';source.mkdir()
    repo=core.RepoSpec('Fixture',source.as_uri()+'/',repo_format={'rpm':'rpm','deb':'apt','arch':'pacman'}[family],suite='fixture',allow_unverified_index=True)
    packages=[]
    for name in (('demo','extra','retained') if scenario=='additive' else ('demo','extra')):
        filename=name+suffix;content=(name+' fixture payload\n').encode()
        (source/filename).write_bytes(content)
        digest=hashlib.sha256(content).hexdigest()
        if family=='rpm':pkg=core.Package(name,'x86_64','0','1.2','3',filename,'sha256',digest,repo,size=len(content))
        elif family=='deb':pkg=apt_core.DebPackage(name,'amd64','1.2-3',filename,'sha256',digest,repo,size=len(content))
        else:pkg=arch_core.ArchPackage(name,'x86_64','1.2-3',filename,'sha256',digest,repo,size=len(content),digests={'sha256':digest})
        packages.append(pkg)
    result_type={'rpm':core.ResolutionResult,'deb':apt_core.DebResolutionResult,'arch':arch_core.ArchResolutionResult}[family]
    result=result_type(packages,[],packages,reasons={p.nevra:'requested' for p in packages},
        skipped_installed=['installed fixture'],installed_satisfied=['target capability'],conflicts=['fixture notice'])
    options=core.BuildOptions(emit_repository=False,additive_publish=scenario=='additive')
    output=tmp_path/'bundle'
    metadata={'distribution':'Fixture','release':'1','arch':packages[0].arch,
        'package_family':family,'workload':'Fixture','repositories':[{'name':repo.name,'url':repo.url}]}
    if scenario=='additive':
        backend.write_bundle(result,output,core.BuildOptions(emit_repository=False),core.Reporter(),metadata)
        result.selected=packages[:2];result.roots=packages[:2]
    if scenario in ('reuse','corrupt'):

        payload=output/directory;payload.mkdir(parents=True)
        for pkg in packages:
            (payload/pkg.location).write_bytes(b'broken' if scenario=='corrupt' else (source/pkg.location).read_bytes())
    if scenario=='differential':
        baseline=tmp_path/'baseline.json';baseline.write_text(json.dumps({'packages':[{'package_id':packages[0].nevra,'sha256':packages[0].checksum}]}))
        options.baseline_manifest=str(baseline)
    events=[]
    reporter=core.Reporter(log=lambda message:events.append(['log',message]),
        item=lambda identity,state,info:events.append(['item',identity,state,info]),
        progress=lambda label,value:events.append(['progress',label,value]))
    backend.write_bundle(result,output,options,reporter,metadata)
    def normalized(text):
        text = text.replace(repo.source_identity,'<SOURCE-ID>').replace(source.as_uri(),'file:///fixture/source').replace(str(tmp_path),'<ROOT>').replace('\\','/').replace('\r\n','\n')
        return re.sub(
            r'Feathered [0-9]+(?:\.[0-9]+){2}; python [^;\"\n]+; zstandard [^\"\n]+',
            'Feathered <VERSION>; python <PYTHON>; zstandard <ZSTANDARD>',
            text,
        )
    payload=output/directory
    return {'listing':sorted(p.name for p in payload.iterdir()),
        'files':{p.name:normalized(p.read_text()) for p in sorted(payload.iterdir()) if p.is_file()},
        'events':[[normalized(value) if isinstance(value,str) else value for value in event] for event in events]}


@pytest.mark.parametrize('family',FAMILIES)
@pytest.mark.parametrize('scenario',SCENARIOS)
def test_bundle_output_and_event_order(tmp_path,monkeypatch,family,scenario):
    expected=json.loads((GOLDENS/f'{family}-{scenario}.json').read_text())
    assert characterize(tmp_path,monkeypatch,family,scenario)==expected
