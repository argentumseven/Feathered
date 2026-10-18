"""Recovery may skip a failed signer, never a source test or a source identity check."""
import copy

import pytest

from verify_release_gate_run import REQUIRED_JOBS, verify

COMMIT = 'a' * 40


def evidence():
    run = dict(head_sha=COMMIT, path='.github/workflows/windows-release.yml',
               event='push', status='completed', conclusion='failure')
    jobs = [dict(name=name, head_sha=COMMIT, status='completed', conclusion='success')
            for name in REQUIRED_JOBS]
    jobs.append(dict(name='Signed production build', head_sha=COMMIT,
                     status='completed', conclusion='failure'))
    return run, jobs


def test_failed_signer_does_not_hide_passing_required_source_jobs():
    verify(*evidence(), COMMIT)


@pytest.mark.parametrize('field,value', [('head_sha', 'b' * 40), ('path', 'other.yml'),
    ('event', 'pull_request'), ('status', 'in_progress')])
def test_unrelated_or_incomplete_run_is_rejected(field, value):
    run, jobs = evidence()
    run[field] = value
    with pytest.raises(RuntimeError, match='exact source commit'):
        verify(run, jobs, COMMIT)


@pytest.mark.parametrize('change', ['missing', 'duplicate', 'failed', 'skipped', 'running', 'wrong_sha'])
def test_every_platform_gate_must_really_pass(change):
    run, jobs = evidence()
    if change == 'missing':
        jobs.pop(0)
    elif change == 'duplicate':
        jobs.append(copy.deepcopy(jobs[0]))
    elif change == 'running':
        jobs[0]['status'] = 'in_progress'
    elif change == 'wrong_sha':
        jobs[0]['head_sha'] = 'b' * 40
    else:
        jobs[0]['conclusion'] = change
    with pytest.raises(RuntimeError, match='did not pass exactly once'):
        verify(run, jobs, COMMIT)
