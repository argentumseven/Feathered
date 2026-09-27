"""Headless operation lease for Feathered's long-running desktop workflows.

The lease is the sole owner of operation identity, operator-facing detail, and
cancellability. Tk control locking, animation timers, worker threads, and the
threading cancellation event deliberately remain with the desktop shell.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class OperationState:
    """One application's exclusive operation lease; independent of Tkinter."""

    active_operation: str | None = None
    active_operation_label: str = ""
    operation_cancellable: bool = False
    operation_detail: str = ""

    def busy(self, *, worker_running: bool = False) -> bool:
        """An untracked legacy worker also blocks new operations."""
        return self.active_operation is not None or worker_running

    def claim(self, key: str, label: str, *, cancellable: bool = False,
              worker_running: bool = False) -> bool:
        """Claim an idle session without overwriting one already running.

        The desktop event loop is the single writer. Background workers must
        post completion through the event queue rather than claiming directly.
        """
        if self.busy(worker_running=worker_running):
            return False
        self.active_operation = key
        self.active_operation_label = label.rstrip(" .…")
        self.operation_cancellable = bool(cancellable)
        self.operation_detail = ""
        return True

    def describe(self, detail: object) -> None:
        self.operation_detail = str(detail)

    def release(self, final_status: str | None = None) -> None:
        self.active_operation = None
        self.active_operation_label = ""
        self.operation_cancellable = False
        self.operation_detail = str(final_status or "")


_OPERATION_FIELDS = {
    "active_operation": "active_operation",
    "active_operation_label": "active_operation_label",
    "_operation_cancellable": "operation_cancellable",
    "_operation_detail": "operation_detail",
}


def _state_for(instance: Any) -> OperationState:
    """Adopt existing fields from lightweight/legacy hosts exactly once.

    Direct injection through ``instance.__dict__`` is still supported after
    state creation; descriptors consume those values on their next read.
    """
    values = vars(instance)
    state = values.get("_operation_state")
    if state is None:
        state = OperationState()
        for name, field_name in _OPERATION_FIELDS.items():
            if name in values:
                setattr(state, field_name, values.pop(name))
        values["_operation_state"] = state
    return state


class _OperationField:
    """Legacy attribute adapter for the operation-state owner."""

    def __init__(self, name: str, field_name: str):
        self.name = name
        self.field_name = field_name

    def __get__(self, instance: Any, owner: type | None = None) -> Any:
        if instance is None:
            return self
        state = _state_for(instance)
        values = vars(instance)
        if self.name in values:
            setattr(state, self.field_name, values.pop(self.name))
        return getattr(state, self.field_name)

    def __set__(self, instance: Any, value: Any) -> None:
        state = _state_for(instance)
        vars(instance).pop(self.name, None)
        setattr(state, self.field_name, value)

    def __delete__(self, instance: Any) -> None:
        state = _state_for(instance)
        vars(instance).pop(self.name, None)
        setattr(state, self.field_name, getattr(OperationState(), self.field_name))


class OperationStateMixin:
    """Compatibility surface for callers using historical App field names."""

    active_operation = _OperationField("active_operation", "active_operation")
    active_operation_label = _OperationField("active_operation_label", "active_operation_label")
    _operation_cancellable = _OperationField("_operation_cancellable", "operation_cancellable")
    _operation_detail = _OperationField("_operation_detail", "operation_detail")

    @property
    def operation_state(self) -> OperationState:
        return _state_for(self)
