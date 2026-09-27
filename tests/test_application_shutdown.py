"""Shutdown must reject new work and unblock waits without touching Tk from threads."""
from __future__ import annotations

import queue
import threading
from types import SimpleNamespace

import pytest

from feathered_app.application.results import ResultsMixin
from feathered_app.application.tools import ToolsMixin
from feathered_app.operation_runtime import OperationRuntime


def test_runtime_close_unblocks_every_registered_ui_wait():
    runtime = OperationRuntime()
    assert runtime.claim("build", "Building", cancellable=False)
    waiting = [threading.Event(), threading.Event()]
    for event in waiting:
        assert runtime.register_ui_wait(event)
    runtime.close()
    runtime.close()  # Teardown can be requested more than once.
    assert runtime.closed and runtime.cancel_event.is_set()
    assert all(event.is_set() for event in waiting)
    assert not runtime.claim("another", "Another")
    with pytest.raises(RuntimeError, match="closed"):
        runtime.start_worker(lambda: None)
    late = threading.Event()
    assert not runtime.register_ui_wait(late)
    assert late.is_set()
    for event in waiting:
        runtime.unregister_ui_wait(event)  # Races with teardown are harmless.


def test_close_wakes_worker_waiting_for_gui_decision_and_declines():
    host = ResultsMixin()
    host._operation_runtime = OperationRuntime()
    scheduled = []
    queued = threading.Event()

    def schedule(_delay, callback):
        scheduled.append(callback)
        queued.set()

    host.after = schedule
    outcome = []
    thread = threading.Thread(
        target=lambda: outcome.append(host._gui_ask_on_ui_thread("Trust", "Proceed?")),
        daemon=True,
    )
    thread.start()
    try:
        assert queued.wait(3)
        assert thread.is_alive(), "the worker should be waiting for a UI reply"
        host._operation_runtime.close()
        thread.join(3)
        assert not thread.is_alive()
        assert outcome == [False]
        # A late Tk callback cannot turn a declined decision into an approval.
        scheduled.pop()()
        assert outcome == [False]
    finally:
        host._operation_runtime.close()
        thread.join(3)


def test_close_wakes_worker_waiting_for_trust_review():
    host = ResultsMixin()
    host._operation_runtime = OperationRuntime()
    queued = threading.Event()
    host.after = lambda delay, callback: queued.set()
    host.show_details = lambda **kwargs: pytest.fail("closed review must not open")
    outcome = []
    thread = threading.Thread(
        target=lambda: outcome.append(host._gui_trust_review(["missing signature"])),
        daemon=True,
    )
    thread.start()
    try:
        assert queued.wait(3)
        host._operation_runtime.close()
        thread.join(3)
        assert not thread.is_alive()
        assert outcome == [False]
    finally:
        host._operation_runtime.close()
        thread.join(3)


def test_close_wakes_download_plan_handshake_without_false_timeout():
    host = ToolsMixin()
    host._operation_runtime = OperationRuntime()
    host.events = queue.Queue()
    host.DOWNLOAD_PLAN_ACK_TIMEOUT_S = 5
    messages = []
    host._log = messages.append
    thread = threading.Thread(target=lambda: host._gui_publish_download_plan(4, 500), daemon=True)
    thread.start()
    try:
        event = host.events.get(timeout=3)
        assert event[:3] == ("download_plan", 4, 500)
        host._operation_runtime.close()
        thread.join(3)
        assert not thread.is_alive()
        assert event[3].is_set()
        assert not messages
    finally:
        host._operation_runtime.close()
        thread.join(3)


def test_destroy_closes_each_owner_only_for_root_and_disarms_old_timer():
    from app import App

    class Scheduler:
        def __init__(self):
            self.callbacks = {}
            self.serial = 0
        def after(self, delay, callback):
            self.serial += 1
            self.callbacks[self.serial] = callback
            return self.serial
        def cancel(self, handle):
            self.callbacks.pop(handle, None)

    class Jobs:
        def __init__(self):
            self.close_count = 0
        def close(self):
            self.close_count += 1

    host = object.__new__(App)
    host.__dict__["tk"] = object()  # Controller can run without a Tcl interpreter.
    host._operation_runtime = OperationRuntime()
    assert host.operation_runtime.claim("build", "Building")
    host.events = queue.Queue()
    scheduler = Scheduler()
    host.after = scheduler.after
    host.after_cancel = scheduler.cancel
    jobs = Jobs()
    host._background_query_jobs = jobs
    host._start_activity_animation()
    assert len(scheduler.callbacks) == 1
    stale_tick = next(iter(scheduler.callbacks.values()))
    host._on_app_destroy(SimpleNamespace(widget=object()))
    assert not host.operation_runtime.closed
    host._on_app_destroy(SimpleNamespace(widget=host))
    host._on_app_destroy(SimpleNamespace(widget=host))
    assert host._app_closing and host.operation_runtime.closed
    assert host._activity_state == "idle" and not scheduler.callbacks
    assert jobs.close_count == 1
    stale_tick()
    assert not scheduler.callbacks, "queued callbacks cannot resurrect a destroyed UI"
    host.events.put(("warnings", ["must not touch closed widgets"]))
    host._drain_events()
    assert host.events.qsize() == 1
    with pytest.raises(RuntimeError, match="shutting down"):
        host._query_jobs()


def test_closed_runtime_never_clears_cancellation_when_released():
    runtime = OperationRuntime()
    assert runtime.claim("build", "Building")
    runtime.close()
    runtime.finish_worker()
    runtime.release("Shutdown")
    assert runtime.cancel_event.is_set()
    assert not runtime.claim("build", "Building")
