"""APT delegation must retain its backend-specific transport/verifier hooks."""
from io import BytesIO
from pathlib import Path
import pytest
import apt_core
import core


def test_apt_transfer_keeps_transport_url_and_verifier_hooks(tmp_path,monkeypatch):
    url='https://repo.invalid/linux/?token=PRIVATE&arch=amd64'
    repo=core.RepoSpec('Fixture',url,repo_format='apt')
    pkg=apt_core.DebPackage('demo','amd64','1','demo.deb','sha256','',repo,size=7)
    seen=[]
    def opener(address,**kwargs):seen.append(('open',address,kwargs['repo']));return BytesIO(b'payload')
    def verify(package,path,options,reporter):seen.append(('verify',package,path.read_bytes()));return True
    monkeypatch.setattr(apt_core,'_urlopen',opener)
    monkeypatch.setattr(apt_core,'verify_package_artifact',verify)
    monkeypatch.setattr(core,'_urlopen',lambda *a,**kw:pytest.fail('APT transport hook bypassed'))
    monkeypatch.setattr(core,'verify_package_artifact',lambda *a,**kw:pytest.fail('APT verifier hook bypassed'))
    output=tmp_path/'demo.deb'
    apt_core._copy_or_download(pkg,output,core.BuildOptions(),core.Reporter())
    assert seen==[('open',core.repo_relative_url(url,pkg.location),repo),('verify',pkg,b'payload')]
    assert output.read_bytes()==b'payload'
    assert not output.with_suffix('.deb.partial').exists()


def test_apt_verifier_failure_keeps_destination_and_cleans_partial(tmp_path,monkeypatch):
    repo=core.RepoSpec('Fixture',tmp_path.as_uri()+'/',repo_format='apt')
    source=tmp_path/'source.deb';source.write_bytes(b'payload')
    pkg=apt_core.DebPackage('demo','amd64','1',source.name,'sha256','',repo,size=7)
    def reject(*args):raise RuntimeError('rejected fixture')
    monkeypatch.setattr(apt_core,'verify_package_artifact',reject)
    output=tmp_path/'output.deb';output.write_bytes(b'existing')
    with pytest.raises(RuntimeError,match='rejected fixture'):
        apt_core._copy_or_download(pkg,output,core.BuildOptions(retries=1),core.Reporter())
    assert output.read_bytes()==b'existing'
    assert not output.with_suffix('.deb.partial').exists()
