"""Runtime ownership and race regressions; all tests run without Tkinter."""
from __future__ import annotations

import threading

import pytest

from feathered_app.operation_runtime import OperationRuntime, OperationRuntimeMixin


def test_runtime_claim_cancel_release_and_reuse():
    runtime = OperationRuntime()
    token = runtime.cancel_event
    assert runtime.claim('build', 'Building…', cancellable=True)
    assert runtime.busy()
    assert not runtime.claim('scan', 'Scanning')
    runtime.request_cancel()
    assert token.is_set()
    runtime.release('Cancelled')
    assert not runtime.busy()
    assert runtime.claim('inspect', 'Inspecting', cancellable=False)
    assert runtime.cancel_event is token
    assert not token.is_set()
    runtime.request_cancel()
    assert not token.is_set(), 'noncancellable work must ignore UI cancellation'


def test_worker_requires_active_lease():
    runtime = OperationRuntime()
    with pytest.raises(RuntimeError, match='requires an active operation'):
        runtime.start_worker(lambda: None)


def test_worker_ownership_rejects_overlapping_starts_and_claims():
    runtime = OperationRuntime()
    started = threading.Event()
    release = threading.Event()
    assert runtime.claim('build', 'Building')

    def work():
        started.set()
        assert release.wait(5)

    thread = runtime.start_worker(work)
    try:
        assert started.wait(5)
        with pytest.raises(RuntimeError, match='Another worker'):
            runtime.start_worker(lambda: None)
        runtime.release('Incorrect early release')
        assert runtime.busy(), 'the worker blocks even if a legacy caller releases early'
        assert not runtime.claim('inspect', 'Inspecting')
    finally:
        release.set()
        thread.join(5)
    runtime.finish_worker()
    assert runtime.claim('inspect', 'Inspecting')


def test_queued_completion_cannot_start_next_job_until_worker_exits():
    runtime = OperationRuntime()
    posted = threading.Event()
    exit_worker = threading.Event()
    assert runtime.claim('build', 'Building')

    def work():
        posted.set()  # Simulates posting ("done", ...) to the event queue.
        assert exit_worker.wait(5)

    thread = runtime.start_worker(work)
    assert posted.wait(5)
    try:
        runtime.finish_worker()  # GUI consumes completion before thread exits.
        runtime.release('Done')
        assert runtime.worker is None
        assert runtime.busy()
        assert not runtime.claim('scan', 'Scanning')
    finally:
        exit_worker.set()
        thread.join(5)
    assert runtime.claim('scan', 'Scanning')


def test_start_exception_rolls_back_worker(monkeypatch):
    class BrokenThread:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def start(self):
            raise RuntimeError('no threads available')

    monkeypatch.setattr(threading, 'Thread', BrokenThread)
    runtime = OperationRuntime()
    assert runtime.claim('build', 'Building')
    with pytest.raises(RuntimeError, match='no threads available'):
        runtime.start_worker(lambda: None)
    assert runtime.worker is None
    runtime.release('Failed to start')
    assert runtime.claim('scan', 'Scanning')


def test_legacy_runtime_fields_migrate_without_shared_state():
    class Host(OperationRuntimeMixin):
        pass

    host, other = Host(), Host()
    legacy_cancel = threading.Event()
    host.__dict__.update({'worker': None, 'cancel_event': legacy_cancel})
    assert host.cancel_event is legacy_cancel
    assert host.operation_runtime.operation_state is host.operation_state
    assert not other.operation_runtime.busy()
    assert other.cancel_event is not host.cancel_event
    assert not {'cancel_event', 'worker'}.intersection(host.__dict__)
    host.__dict__['worker'] = 'legacy worker'  # Tests direct legacy injection.
    assert host.worker == 'legacy worker'
    assert not host.operation_runtime.claim('build', 'Building')
    host.worker = None
    assert host.operation_runtime.claim('build', 'Building')
