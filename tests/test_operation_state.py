"""Headless operation lease and compatibility tests for the v6 extraction."""
from __future__ import annotations

import threading

from feathered_app.operation_state import OperationState, OperationStateMixin
from feathered_app.state import ApplicationStateView


def test_operation_lease_rejects_overlap_without_erasing_running_session():
    lease = OperationState()
    assert lease.claim("build", "Building…  ", cancellable=True)
    lease.describe("Downloading package 2 of 3")
    assert lease.active_operation == "build"
    assert lease.active_operation_label == "Building"
    assert lease.operation_cancellable is True
    assert lease.busy()
    assert not lease.claim("inspect", "Inspecting", worker_running=False)
    assert (lease.active_operation, lease.active_operation_label, lease.operation_detail) == (
        "build", "Building", "Downloading package 2 of 3"
    )
    lease.release("Build complete")
    assert not lease.busy()
    assert lease.active_operation_label == ""
    assert lease.operation_cancellable is False
    assert lease.operation_detail == "Build complete"
    assert lease.claim("inspect", "Inspecting", cancellable=False)
    assert lease.operation_detail == ""  # Never leak previous operation's status.


def test_untracked_worker_blocks_claim_even_without_a_lease():
    lease = OperationState()
    assert lease.busy(worker_running=True)
    assert not lease.claim("build", "Building", worker_running=True)
    assert lease.active_operation is None
    assert lease.claim("build", "Building")
    assert lease.busy(worker_running=False)


def test_operation_state_is_instance_isolated_and_headless():
    one, two = OperationState(), OperationState()
    assert one.claim("build", "Building")
    assert not two.busy()
    assert two.claim("scan", "Scanning", cancellable=True)
    one.release("Complete")
    assert two.active_operation == "scan"
    assert two.operation_cancellable is True


def test_legacy_fields_are_migrated_and_direct_injection_is_consumed():
    class Host(OperationStateMixin):
        pass

    host = Host()
    host.__dict__.update({
        "active_operation": "inspect",
        "active_operation_label": "Inspecting",
        "_operation_cancellable": True,
        "_operation_detail": "Starting",
    })
    assert host.active_operation == "inspect"
    assert host.operation_state.active_operation_label == "Inspecting"
    assert host.operation_state.operation_cancellable is True
    assert host.operation_state.operation_detail == "Starting"
    assert "active_operation" not in host.__dict__
    host.__dict__["active_operation"] = "build"
    assert host.active_operation == "build"
    assert host.operation_state.active_operation == "build"
    host._operation_detail = "Building"
    assert host.operation_state.operation_detail == "Building"
    del host.active_operation
    assert host.active_operation is None


def test_grouped_app_state_view_uses_the_same_lease():
    class Host(OperationStateMixin):
        pass

    host = Host()
    host.app_state = ApplicationStateView(host)
    host.app_state.operation.active_operation = "build"
    host.app_state.operation.operation_detail = "Transferring"
    assert host.operation_state.active_operation == "build"
    assert host.operation_state.operation_detail == "Transferring"
    host.operation_state.release("Done")
    assert host.app_state.operation.active_operation is None
    assert host.app_state.operation.operation_detail == "Done"


def test_app_claim_release_still_restores_widget_states_without_tk():
    from app import App

    class Widget:
        def __init__(self, state="normal"):
            self.state = state

        def winfo_exists(self):
            return True

        def cget(self, option):
            assert option == "state"
            return self.state

        def configure(self, **kwargs):
            self.state = kwargs["state"]

    class Var:
        def __init__(self):
            self.value = None

        def set(self, value):
            self.value = value

    # Real App methods with no Tk interpreter: control state is a GUI concern;
    # ownership of the exclusive lease is not.
    class Host(App):
        def __init__(self):
            self.worker = None
            self.cancel_event = threading.Event()
            self._operation_controls = set()
            self._operation_saved_states = {}
            self.progress_var = Var()
            self.status_var = Var()
            self.cancel_btn = Widget("disabled")
            self._sync_review_action_states = lambda: None

    host = Host()
    enabled = Widget("normal")
    disabled = Widget("disabled")
    host._register_operation_control(enabled)
    host._register_operation_control(disabled)
    host.cancel_event.set()
    assert host._claim_operation("build", "Building…", cancellable=True)
    assert host.cancel_event.is_set() is False
    assert host.cancel_btn.state == "normal"
    assert (enabled.state, disabled.state) == ("disabled", "disabled")
    assert not host._claim_operation("scan", "Scanning")
    assert host.operation_state.active_operation == "build"
    host._release_operation("Completed")
    assert (enabled.state, disabled.state) == ("normal", "disabled")
    assert host.cancel_btn.state == "disabled"
    assert host.status_var.value == "Completed"
    assert host.operation_state.active_operation is None
    assert host.operation_state.operation_detail == "Completed"
