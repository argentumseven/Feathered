"""Compare actual GUI-worker output to a headless replay of its captured intent."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path

from build_spec import apply, capture, repositories_from
from core import RepoSpec
from tests import test_application_startup as startup
from tests import test_headless_execution as fixtures
from tests.test_cli_replay import spec_for, invoke
from tests.test_end_to_end_build import _run_to_completion

application= startup.application
isolated_state=startup.isolated_state
local_repository=fixtures.local_repository


@startup.requires_display
def test_gui_and_cli_preserve_payloads_sources_provenance_and_installer(application,local_repository,tmp_path,monkeypatch):
    from feathered_app.ui import theme
    window=application
    for name in ('showerror','showinfo','showwarning'):
        monkeypatch.setattr(theme.messagebox,name,lambda *a,**kw:None)
    monkeypatch.setattr(theme.messagebox,'askyesno',lambda *a,**kw:True)
    spec=spec_for(local_repository,tmp_path/'gui','workload')
    apply(window,spec)
    window.repo_rows=repositories_from(spec,RepoSpec)
    window.__dict__['_trust_policy']=lambda findings:True
    captured=capture(window)
    _run_to_completion(window)
    assert window.__dict__.get('_activity_state')=='idle',window.log_lines[-10:]
    gui=Path(window.last_output_path)
    replay=replace(captured,output=replace(captured.output,directory=str(tmp_path/'cli')))
    outcome=invoke(tmp_path,replay,'--accept-trust-findings')
    assert outcome.returncode==0,outcome.stdout+outcome.stderr
    cli=next(p for p in (tmp_path/'cli').iterdir() if p.is_dir() and not p.name.startswith('.'))
    def payloads(root):
        return {p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*.deb')}
    assert payloads(gui)==payloads(cli) and payloads(gui)
    left=json.loads((gui/'debs/manifest.json').read_text())
    right=json.loads((cli/'debs/manifest.json').read_text())
    assert left['packages']==right['packages']
    assert left['summary']==right['summary']
    for key in ('repositories','job.requested_source_plan','dependency_completeness'):
        assert key in left['metadata'] and left['metadata'][key]==right['metadata'][key]
    def provenance(root):
        data=json.loads((root/'debs/provenance.json').read_text())
        # Only the generated bundle identifier and creation instant vary.
        data.pop('created');data.pop('bundle_id')
        return data
    assert provenance(gui)==provenance(cli)
    assert (gui/'install-offline.sh').read_bytes()==(cli/'install-offline.sh').read_bytes()
