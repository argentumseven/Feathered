"""Credentials are hidden in summaries; repository provenance remains visible."""
from dataclasses import replace
from io import BytesIO
import json
from types import SimpleNamespace

import pytest
import core
import feathered_cli as cli
from build_spec import BuildSpec, RepositoryRecord, SourceSpec


@pytest.mark.parametrize('auth', ['user:PRIVATE_PASSWORD@', 'PRIVATE_BEARER@', ''])
@pytest.mark.parametrize('command', ['show', 'dry-run'])
def test_summary_keeps_repository_location_and_public_query(tmp_path, capsys, auth, command):
    url = f'https://{auth}repo.example:8443/linux/ubuntu/dists/noble?arch=amd64&label=a%2Bb&token=PRIVATE_TOKEN&X-Amz-Signature=PRIVATE_SIGNATURE'
    spec = BuildSpec(sources=SourceSpec(repositories=(RepositoryRecord(name='Ubuntu origin',url=url),)))
    path=tmp_path/'spec.json'; path.write_text(spec.to_json())
    args=['show','--spec',str(path)] if command=='show' else ['build','--dry-run','--spec',str(path)]
    assert cli.main(args)==0
    shown=capsys.readouterr().out
    for secret in ('PRIVATE_PASSWORD','PRIVATE_BEARER','PRIVATE_TOKEN','PRIVATE_SIGNATURE'):
        assert secret not in shown
    assert 'repo.example:8443/linux/ubuntu/dists/noble' in shown
    assert 'arch=amd64&label=a%2Bb' in shown
    assert 'Ubuntu origin' in shown
    assert json.loads(path.read_text())['sources']['repositories'][0]['url']==url


def test_display_does_not_change_transport_url_or_source_identity(tmp_path, monkeypatch):
    url='https://repo.example/linux/?token=PRIVATE_TOKEN&arch=amd64'
    repo=core.RepoSpec('Origin',url)
    before=repo.source_identity
    spec=BuildSpec(sources=SourceSpec(repositories=(RepositoryRecord.capture(repo),)))
    cli.describe(spec)
    seen=[]
    def open_url(address, **kwargs):
        seen.append(address)
        return BytesIO(b'payload')
    monkeypatch.setattr(core,'_urlopen',open_url)
    monkeypatch.setattr(core,'verify_package_artifact',lambda *a:True)
    package=core.Package('demo','x86_64','0','1','1','demo.rpm','sha256','',repo,size=7)
    core._copy_or_download(package,tmp_path/'demo.rpm',core.BuildOptions(),core.Reporter())
    assert seen==[core.repo_relative_url(url,'demo.rpm')]
    assert 'PRIVATE_TOKEN' in seen[0] and repo.source_identity==before and repo.url==url


def test_terminal_failure_scrubs_credentials(capsys, monkeypatch):
    import feathered_app.build_api as api
    from feathered_app.build_outcome import BuildOutcome, BuildStatus
    monkeypatch.setattr(api,'execute_build',lambda *a,**kw:BuildOutcome(BuildStatus.FAILED,'Failed https://u:PRIVATE_PASSWORD@repo.example/linux?token=PRIVATE_TOKEN'))
    assert cli.run_build(BuildSpec())==1
    shown=capsys.readouterr().err
    assert 'PRIVATE_PASSWORD' not in shown and 'PRIVATE_TOKEN' not in shown
    assert 'repo.example/linux' in shown
