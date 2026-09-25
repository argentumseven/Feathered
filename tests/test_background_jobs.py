"""Bound worker concurrency and obsolete completions without depending on Tk."""
from queue import Queue
from threading import Event, Lock
from unittest.mock import Mock

import pytest
from background_jobs import BackgroundJobs, JobCompletion


def test_many_replacements_bound_workers_and_only_latest_result_is_current():
    done=Queue();release=Event();entered=Event();lock=Lock();active=0;maximum=0
    def slow(cancel):
        nonlocal active,maximum
        with lock:
            active+=1;maximum=max(maximum,active)
            if active==2:entered.set()
        assert release.wait(5)
        with lock:active-=1
        return 'old'
    jobs=BackgroundJobs(done.put)
    jobs.submit('versions',slow);jobs.submit('versions',slow)
    assert entered.wait(5)
    for i in range(100):latest=jobs.submit('versions',lambda cancel,i=i:i)
    release.set()
    results=[done.get(timeout=5) for _ in range(102)]
    current=[result for result in results if jobs.accepts(result)]
    assert maximum==2
    assert len(current)==1 and current[0].generation==latest and current[0].value==99
    assert len({r.generation for r in results})==102
    jobs.close()


def test_cancel_is_cooperative_and_releases_capacity():
    done=Queue();entered=Event()
    def work(cancel):entered.set();assert cancel.wait(5);return 'obsolete'
    jobs=BackgroundJobs(done.put,max_workers=1)
    jobs.submit('versions',work);assert entered.wait(5)
    jobs.cancel('versions')
    old=done.get(timeout=5)
    assert old.cancelled and not jobs.accepts(old)
    jobs.submit('versions',lambda cancel:'recovered')
    current=done.get(timeout=5)
    assert jobs.accepts(current) and current.value=='recovered'
    jobs.close()


def test_failure_and_worker_exit_release_capacity():
    done=Queue();jobs=BackgroundJobs(done.put,max_workers=1)
    def failed(cancel):raise SystemExit('worker stopped')
    jobs.submit('one',failed)
    result=done.get(timeout=5);assert 'SystemExit' in result.error
    jobs.submit('one',lambda cancel:'ok')
    assert done.get(timeout=5).value=='ok'
    jobs.close()


def test_close_cancels_active_and_pending_and_rejects_new_work():
    done=Queue();entered=Event()
    def work(cancel):entered.set();assert cancel.wait(5);return 'old'
    jobs=BackgroundJobs(done.put,max_workers=1)
    jobs.submit('one',work);assert entered.wait(5)
    jobs.submit('two',lambda cancel:pytest.fail('pending work started'))
    jobs.close()
    results=[done.get(timeout=5) for _ in range(2)]
    assert all(r.cancelled and not jobs.accepts(r) for r in results)
    with pytest.raises(RuntimeError):jobs.submit('one',lambda cancel:None)


def test_thread_start_failure_is_reported_and_does_not_hold_capacity(monkeypatch):
    import background_jobs as module
    done=Queue();jobs=BackgroundJobs(done.put,max_workers=1)
    real=module.Thread
    monkeypatch.setattr(module,'Thread',Mock(side_effect=RuntimeError('cannot start')))
    jobs.submit('one',lambda cancel:None)
    assert 'cannot start' in done.get(timeout=5).error
    monkeypatch.setattr(module,'Thread',real)
    jobs.submit('one',lambda cancel:'ok')
    assert done.get(timeout=5).value=='ok'
    jobs.close()


def test_operation_keys_are_bounded():
    done=Queue();jobs=BackgroundJobs(done.put,max_operations=1)
    jobs.submit('one',lambda cancel:None);done.get(timeout=5)
    with pytest.raises(ValueError):jobs.submit('two',lambda cancel:None)
    jobs.close()



def test_stale_cancelled_workers_do_not_block_other_lanes():
    done=Queue();release=Event();started=Event()
    def stuck(cancel):started.set();assert release.wait(5);return 'stale'
    jobs=BackgroundJobs(done.put,max_workers=1,max_cancelled=1)
    jobs.submit('slow',stuck);assert started.wait(5)
    jobs.cancel('slow')                       # worker is still inside release.wait()
    jobs.submit('other',lambda cancel:'fresh')
    result=done.get(timeout=5)                # must arrive while 'slow' is still stuck
    assert result.operation=='other' and jobs.accepts(result) and result.value=='fresh'
    release.set()
    stale=done.get(timeout=5)
    assert stale.operation=='slow' and not jobs.accepts(stale)
    jobs.close()


def test_cancelled_workers_are_themselves_bounded():
    done=Queue();release=Event();lock=Lock();running=[0];both=Event();third=Event()
    def stuck(cancel):
        with lock:
            running[0]+=1
            if running[0]==2:both.set()
        assert release.wait(5)
    jobs=BackgroundJobs(done.put,max_workers=1,max_cancelled=1)
    jobs.submit('a',stuck);jobs.cancel('a')
    jobs.submit('b',stuck);assert both.wait(5);jobs.cancel('b')
    jobs.submit('c',lambda cancel:third.set())
    assert not third.wait(0.3)                # two stale workers fill the bound
    release.set()
    assert third.wait(5)
    jobs.close()
