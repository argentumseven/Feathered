"""Headless owner of the desktop application's exclusive long-running worker.

The UI owns *when* an operation is requested and the queue on which its result
is delivered. This object owns the worker thread, cancellation signal and the
existing exclusive operation lease. It never reads Tk state or invokes widgets.

Workers post completion to the UI queue; the UI calls ``finish_worker`` only
when it consumes the completion. That keeps the lease occupied during the
interval between the worker posting its result and the GUI handling it.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from feathered_app.operation_state import OperationState, OperationStateMixin, _state_for


@dataclass
class OperationRuntime:
    """One operation lease, at most one tracked worker, and one cancel signal."""

    operation_state: OperationState = field(default_factory=OperationState)
    cancel_event: threading.Event = field(default_factory=threading.Event)
    worker: threading.Thread | None = None
    _retiring_worker: threading.Thread | None = field(default=None, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)
    _ui_waits: set[threading.Event] = field(default_factory=set, init=False, repr=False)
    _wait_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def _worker_running(self) -> bool:
        if self.worker is not None:
            return True
        # A worker may post "done" immediately before returning from its
        # target. The UI can consume that event before the worker exits. Keep
        # the lease unavailable until that last worker really terminates.
        if self._retiring_worker is not None:
            if self._retiring_worker.is_alive():
                return True
            self._retiring_worker = None
        return False

    def busy(self) -> bool:
        return self.operation_state.busy(worker_running=self._worker_running())

    @property
    def closed(self) -> bool:
        return self._closed

    def claim(self, key: str, label: str, *, cancellable: bool = False) -> bool:
        if self._closed:
            return False
        if not self.operation_state.claim(
            key, label, cancellable=cancellable, worker_running=self._worker_running(),
        ):
            return False
        # Retain the event identity: existing reporters and embedders may hold it.
        # The new lease is acquired only after the preceding worker has been
        # acknowledged by the UI event loop.
        self.cancel_event.clear()
        return True

    def start_worker(self, target: Callable[..., Any], *, args: tuple = (),
                     kwargs: dict[str, Any] | None = None,
                     name: str | None = None, daemon: bool = True) -> threading.Thread:
        """Register a worker before starting it, rolling back a failed start.

        Called by the Tk event loop after a successful claim. No Tk callbacks
        execute here, and the target itself must only post results to the queue.
        """
        if self._closed:
            raise RuntimeError("Operation runtime is closed")
        if self.operation_state.active_operation is None:
            raise RuntimeError("A worker requires an active operation lease")
        if self._worker_running():
            raise RuntimeError("Another worker is still owned by this operation")
        thread = threading.Thread(
            target=target, args=args, kwargs=kwargs or {}, name=name, daemon=daemon,
        )
        self.worker = thread
        try:
            thread.start()
        except BaseException:
            self.worker = None
            raise
        return thread

    def request_cancel(self, *, force: bool = False) -> None:
        # Cancellation is cooperative; do not release the lease until a result
        # is consumed. Explicit App.cancel() requests preserve the legacy
        # behavior even for partially constructed test/embedding hosts; regular
        # callers can enforce the lease's cancellable flag.
        if force or (self.operation_state.active_operation is not None and self.operation_state.operation_cancellable):
            self.cancel_event.set()

    def register_ui_wait(self, ready: threading.Event) -> bool:
        """Track a worker blocked on a GUI decision or progress handshake.

        Closing the application releases the wait without accepting a decision.
        The lock makes registration and closing atomic across UI/worker threads.
        """
        with self._wait_lock:
            if self._closed:
                ready.set()
                return False
            self._ui_waits.add(ready)
            return True

    def unregister_ui_wait(self, ready: threading.Event) -> None:
        with self._wait_lock:
            self._ui_waits.discard(ready)

    def close(self) -> None:
        """Reject new work and request cooperative cancellation on shutdown.

        Never join a worker on the GUI thread: a network request or a worker
        waiting for the UI would deadlock shutdown. The worker retains the
        cancellation event and owns its normal rollback/cleanup path.
        """
        with self._wait_lock:
            if self._closed:
                return
            self._closed = True
            self.cancel_event.set()
            for ready in self._ui_waits:
                ready.set()
            self._ui_waits.clear()

    def finish_worker(self) -> None:
        """Acknowledge a worker completion on the event-loop thread."""
        alive = getattr(self.worker, "is_alive", None)
        if callable(alive) and alive():
            self._retiring_worker = self.worker
        self.worker = None

    def release(self, final_status: str | None = None) -> None:
        self.operation_state.release(final_status)


def _runtime_for(instance: Any) -> OperationRuntime:
    """Adopt existing fields from legacy/partially constructed App hosts."""
    values = vars(instance)
    runtime = values.get("_operation_runtime")
    if runtime is None:
        runtime = OperationRuntime(operation_state=_state_for(instance))
        values["_operation_runtime"] = runtime
    # Direct __dict__ injection is used by some lightweight hosts and test
    # fixtures. As with the v6 operation lease, consume it on the next read.
    if "worker" in values:
        runtime.worker = values.pop("worker")
    if "cancel_event" in values:
        runtime.cancel_event = values.pop("cancel_event")
    return runtime


class _RuntimeField:
    def __init__(self, name: str):
        self.name = name

    def __get__(self, instance: Any, owner: type | None = None) -> Any:
        if instance is None:
            return self
        return getattr(_runtime_for(instance), self.name)

    def __set__(self, instance: Any, value: Any) -> None:
        runtime = _runtime_for(instance)
        if self.name == "worker" and value is not None and runtime.worker is not None and runtime.worker is not value:
            raise RuntimeError("Cannot replace an operation's existing worker")
        setattr(runtime, self.name, value)

    def __delete__(self, instance: Any) -> None:
        runtime = _runtime_for(instance)
        setattr(runtime, self.name, None if self.name == "worker" else threading.Event())


class OperationRuntimeMixin(OperationStateMixin):
    """Preserve App's worker/cancel_event fields while moving their ownership."""

    worker = _RuntimeField("worker")
    cancel_event = _RuntimeField("cancel_event")

    @property
    def operation_runtime(self) -> OperationRuntime:
        return _runtime_for(self)
