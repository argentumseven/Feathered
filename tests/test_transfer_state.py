"""Headless transfer accounting and compatibility tests for the v7 extraction."""
from __future__ import annotations

from queue import Queue
from types import SimpleNamespace

from feathered_app.transfer_state import (
    TransferProgressState, TransferStateMixin, sync_legacy_transfer_host,
    transfer_state_for,
)
from feathered_app.application.tools import ToolsMixin
from feathered_app.application.operations import OperationsMixin
from feathered_app.state import ApplicationStateView
from core import SEAL_PHASE_START


MIB = 1024 * 1024


class Var:
    def __init__(self, value=None):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class NoRows:
    def exists(self, _identity):
        return False


class HeadlessTransferHost(ToolsMixin, OperationsMixin):
    """Exercise real GUI adapters without constructing a Tk interpreter."""

    def __init__(self, *, signing=False, mirror=False):
        self.sign_index_var = Var(signing)
        self.download_size_var = Var()
        self.progress_var = Var()
        self._mirror = mirror
        self._result_item_states = {}
        self.result_rows = {}
        self.result_tree = NoRows()
        self.logs = []
        self.statuses = []
        self._log = self.logs.append
        self._operation_status = self.statuses.append
        self._stop_review_work_glow = lambda: None

    def _mirror_mode(self):
        return self._mirror

    def _selected_mirror_repositories(self):
        return ["first", "second"]


def test_headless_owner_isolated_between_instances_and_sessions():
    one, two = TransferProgressState(), TransferProgressState()
    one.begin(2, 2 * MIB, started=20)
    two.begin(1, MIB, started=30)
    one.record_bytes("alpha", MIB // 2, MIB)
    one.record_item("alpha", "done", MIB)
    assert one.done == 1 and one.transferred == MIB
    assert two.done == 0 and two.transferred == 0
    assert one.payload_active and two.payload_active
    one.begin(1, 0, started=40)
    assert one.done == one.failed == one.reused == one.transferred == 0
    assert not one.item_bytes and not one.item_sizes and not one.terminal_items
    assert two.total == 1 and two.started == 30


def test_duplicate_terminals_and_late_bytes_do_not_corrupt_accounting():
    state = TransferProgressState()
    state.begin(2, 3 * MIB)
    assert state.record_item("cached", "reused", MIB)
    assert not state.record_item("cached", "done", MIB)
    assert state.record_bytes("cached", MIB // 2, MIB) == (MIB, MIB, False)
    assert state.record_item("missing", "failed", 2 * MIB)
    assert not state.record_item("missing", "reused", 2 * MIB)
    assert state.done == 1 and state.reused == 1 and state.failed == 1
    assert state.transferred == MIB and state.completed == 2
    assert not state.payload_active


def test_monotone_bytes_and_size_less_completion_retains_observed_size():
    state = TransferProgressState()
    state.begin(1, MIB)
    assert state.record_bytes("pkg", MIB // 2, MIB) == (MIB // 2, MIB, True)
    assert state.record_bytes("pkg", MIB // 4, 0) == (MIB // 2, MIB, True)
    assert state.record_item("pkg", "done", 0)
    assert state.transferred == MIB
    assert state.record_bytes("pkg", MIB * 2, MIB) == (MIB, MIB, False)
    assert state.transferred == MIB


def test_snapshot_progress_signing_reserved_span_and_eta():
    state = TransferProgressState()
    state.begin(4, 4 * MIB, progress_span=SEAL_PHASE_START, started=100.0)
    state.record_bytes("pkg", MIB, 2 * MIB)
    snapshot = state.snapshot(now=101.0)
    assert snapshot.completed == 0
    assert snapshot.bytes_per_second == MIB
    assert snapshot.eta_seconds == 3
    assert snapshot.progress_percent == SEAL_PHASE_START * 25
    assert "~3s left" in state.status_parts(lambda n: f"{n}", now=101.0)
    state.record_item("pkg", "done", 2 * MIB)
    assert state.snapshot(now=102).progress_percent == SEAL_PHASE_START * 50


def test_unavailable_expected_bytes_do_not_invent_eta_or_fraction():
    state = TransferProgressState()
    state.begin(1, 0, started=100)
    state.record_bytes("pkg", MIB, 0)
    snapshot = state.snapshot(now=101)
    assert snapshot.progress_percent is None and snapshot.eta_seconds is None
    assert snapshot.transferred == MIB


def test_legacy_field_adapter_migrates_raw_writes_and_is_instance_local():
    class Host(TransferStateMixin):
        pass

    first, second = Host(), Host()
    first.__dict__.update({"transfer_done": 2, "transfer_total": 5, "_transfer_item_bytes": {"old": 7}})
    assert first.transfer_done == 2
    assert first.transfer_progress.total == 5
    assert first._transfer_item_bytes == {"old": 7}
    assert "transfer_done" not in first.__dict__
    first.__dict__["transfer_done"] = 4
    assert first.transfer_done == first.transfer_progress.done == 4
    first.transfer_bytes = 9
    assert first.transfer_progress.transferred == 9
    assert second.transfer_total == 0
    assert second._transfer_item_bytes == {}
    del first._transfer_item_bytes
    assert first._transfer_item_bytes == {}
    view = ApplicationStateView(first)
    view.transfer.transfer_failed = 3
    assert first.transfer_progress.failed == 3
    assert first.transfer_failed == 3


def test_bare_legacy_host_still_uses_plain_attributes():
    host = SimpleNamespace(transfer_total=1, transfer_done=0)
    state = transfer_state_for(host)
    state.record_item("pkg", "done", 17)
    sync_legacy_transfer_host(host, state)
    assert host.transfer_total == 1 and host.transfer_done == 1
    assert host.transfer_bytes == 17
    assert host._transfer_terminal_items == {"pkg"}


def test_headless_gui_adapter_formats_mirror_transfer_and_counts():
    host = HeadlessTransferHost(mirror=True, signing=True)
    host._begin_transfer(2, 4 * MIB)
    assert host.transfer_progress.total == 2
    assert host.transfer_progress.progress_span == SEAL_PHASE_START
    assert "2 repository mirror(s)" in host.download_size_var.get()
    host._apply_item_event("one", "active", {"size": 2 * MIB})
    host._apply_transfer_event("one", MIB, 2 * MIB)
    assert host.transfer_progress.transferred == MIB
    assert host.progress_var.get() == 25 * SEAL_PHASE_START
    host._apply_item_event("one", "done", {"size": 2 * MIB})
    assert host.transfer_done == 1
    assert host._result_item_states["one"]["status"] == "downloaded"
    host._apply_transfer_event("one", MIB, 2 * MIB)
    host._apply_item_event("one", "failed", {"size": 2 * MIB})
    assert host._result_item_states["one"]["status"] == "downloaded"
    assert host.transfer_done == 1 and host.transfer_failed == 0
    assert "1/2 package records" in host.statuses[-1]


def test_event_pump_respects_descriptor_backed_transfer_counters():
    host = HeadlessTransferHost()
    host.events = Queue()
    host.after = lambda *_args: None
    host.active_operation = None
    host.transfer_progress.begin(2, 2 * MIB)
    host.transfer_progress.record_item("first", "done", MIB)
    host.events.put(("progress", "Resolving", 0.5))
    OperationsMixin._drain_events(host)
    assert not host.statuses and host.progress_var.get() is None
    host.transfer_progress.record_item("second", "done", MIB)
    host.events.put(("progress", "Sealing bundle", 0.9))
    OperationsMixin._drain_events(host)
    assert host.statuses[-1] == "Sealing bundle"
    assert host.progress_var.get() == 90
