"""The new platform validation paths must be required and retain diagnostics."""
from pathlib import Path
import yaml
ROOT = Path(__file__).resolve().parents[1]


def test_linux_client_matrix_is_a_release_prerequisite():
    workflow = yaml.safe_load((ROOT / '.github/workflows/linux-client.yml').read_text())
    job = workflow['jobs']['installed-client']
    assert set(job['strategy']['matrix']['image']) == {'debian:12', 'ubuntu:22.04', 'ubuntu:24.04'}
    commands = '\n'.join(step.get('run', '') for step in job['steps'])
    assert 'check_linux_installation.py' in commands
    assert 'client-bin/feathered" --help' in commands
    assert 'client-bin/feathered-gui" --check' in commands
    release = yaml.safe_load((ROOT / '.github/workflows/windows-release.yml').read_text())
    assert release['jobs']['linux-client']['uses'] == './.github/workflows/linux-client.yml'
    assert 'linux-client' in release['jobs']['production-release']['needs']
    assert "needs.linux-client.result == 'success'" in release['jobs']['production-release']['if']


def test_both_windows_bootstraps_retain_failure_logs():
    jobs = yaml.safe_load((ROOT / '.github/workflows/windows-release.yml').read_text())['jobs']
    for name in ('windows-source-gate', 'production-release'):
        uploads = [step for step in jobs[name]['steps'] if step.get('with', {}).get('path', '').endswith('/feathered-python-diagnostics/')]
        assert len(uploads) == 1
        assert uploads[0]['if'] == 'always()'
