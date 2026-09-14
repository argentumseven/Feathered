from __future__ import annotations

import io
import time
from queue import Queue
from types import SimpleNamespace

import core
from acquisition_model import AcquisitionIntent
from feathered_app.application.sources import SourcesMixin
from feathered_app.application.tools import ToolsMixin
from feathered_app.application.operations import OperationsMixin
from feathered_app.ui.layout import LayoutMixin
from feathered_app.ui.panes import PaneMixin


class Var:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class Tree:
    def __init__(self):
        self.rows = []

    def get_children(self):
        return tuple(str(i) for i in range(len(self.rows)))

    def delete(self, *_items):
        self.rows.clear()

    def insert(self, _parent, _where, **kwargs):
        self.rows.append(kwargs.get("values"))


class ResultTree:
    def exists(self, _iid):
        return False


class SourceHost(SourcesMixin):
    pass


def test_exact_package_roots_are_cleared_when_content_owner_changes():
    host = SourceHost()
    host.selection_mode_var = Var("Choose packages")
    host.workload_var = Var("Docker Engine")
    host._package_selection_context = "mode:Choose packages"
    host.selected_packages = [object()]
    host.single_browser_rows = {"old": object()}
    host.loaded_signature = "old"
    host.loaded_packages = [object()]
    host.last_result = object()
    host.analysis_signature = ("old",)
    host.package_source_coverage_signature = ("old",)
    host._log = lambda _message: None
    refreshed = []
    host._refresh_review_contract = lambda: refreshed.append("review")
    host._sync_review_action_states = lambda: refreshed.append("actions")

    host.selection_mode_var.set("Workload preset")
    host.workload_var.set("VKS node OS package additions")

    assert host._sync_package_selection_context()
    assert host.selected_packages == []
    assert host.single_browser_rows == {}
    assert host.loaded_signature is None
    assert host.loaded_packages == []
    assert host.last_result is None
    assert host.analysis_signature is None
    assert refreshed == ["review", "actions"]


def test_exact_package_roots_survive_navigation_inside_same_content_choice():
    host = SourceHost()
    host.selection_mode_var = Var("Workload preset")
    host.workload_var = Var("VKS node OS package additions")
    host._package_selection_context = "workload:VKS node OS package additions"
    marker = object()
    host.selected_packages = [marker]
    host.single_browser_rows = {}

    assert not host._sync_package_selection_context()
    assert host.selected_packages == [marker]


def test_vks_content_plan_explains_that_additions_are_selected_on_repositories():
    host = SimpleNamespace(
        package_source_plan_tree=Tree(),
        package_source_plan_status_var=Var(),
        selected_packages=[],
        selection_mode_var=Var("Workload preset"),
        _mirror_mode=lambda: False,
        _single_mode=lambda: True,
        _workload=lambda: SimpleNamespace(key="vks-node-additions"),
    )

    PaneMixin._refresh_package_source_plan(host)

    assert host.package_source_plan_tree.rows == [(
        "No VKS node OS additions selected",
        "Choose exact target OS packages on Repositories",
    )]
    assert "does not add OS packages by itself" in host.package_source_plan_status_var.get()


def test_package_validation_error_routes_to_exact_package_chooser():
    calls = []
    host = SimpleNamespace(
        exact_package_selection_card=object(),
        package_selection_card=object(),
        _acquisition_intent=lambda: AcquisitionIntent.PACKAGES,
        show_pane=lambda pane: calls.append(("show", pane)),
        _focus_validation=lambda pane, widget, message: calls.append(("focus", pane, widget, message)),
    )

    assert LayoutMixin._route_validation_error(
        host, "Choose at least one exact package on Repositories")
    assert calls[0] == ("show", "repositories")
    assert calls[1][0:2] == ("focus", "repositories")
    assert calls[1][2] is host.exact_package_selection_card


def test_streaming_package_copy_reports_bytes_as_each_chunk_arrives():
    size = 2 * 1024 * 1024 + 123
    package = SimpleNamespace(nevra="kubectl-1.32.13", size=size)
    events = []
    reporter = core.Reporter(
        transfer=lambda identity, transferred, total: events.append((identity, transferred, total)))
    target = io.BytesIO()

    copied = core.copy_package_stream_bounded(io.BytesIO(b"x" * size), target, package, reporter, size)

    assert copied == size
    assert [transferred for _identity, transferred, _total in events] == [
        1024 * 1024, 2 * 1024 * 1024, size]
    assert all(total == size for _identity, _transferred, total in events)


def test_transfer_status_moves_before_package_finishes():
    host = SimpleNamespace(
        transfer_total=1,
        transfer_done=0,
        transfer_failed=0,
        transfer_reused=0,
        transfer_bytes=0,
        transfer_expected_bytes=4 * 1024 * 1024,
        transfer_started=time.monotonic() - 1,
        _transfer_progress_span=1.0,
        _result_item_states={},
        result_rows={},
        result_tree=ResultTree(),
        progress_var=Var(0),
        download_size_var=Var(),
        _mirror_mode=lambda: False,
        _operation_status=lambda text: setattr(host, "operation_status", text),
    )
    host._update_transfer_status = lambda: ToolsMixin._update_transfer_status(host)

    ToolsMixin._apply_item_event(host, "kubectl", "active", {"size": 4 * 1024 * 1024})
    ToolsMixin._apply_transfer_event(host, "kubectl", 1024 * 1024, 4 * 1024 * 1024)

    assert host.transfer_bytes == 1024 * 1024
    assert host.progress_var.get() == 25.0
    assert "1.0 MB / 4.0 MB" in host.download_size_var.get()
    assert "downloading 1.0 MB / 4.0 MB" == host._result_item_states["kubectl"]["status"]

    ToolsMixin._apply_item_event(host, "kubectl", "done", {"size": 4 * 1024 * 1024})
    assert host.transfer_done == 1
    assert host.transfer_bytes == 4 * 1024 * 1024
    assert host.progress_var.get() == 100.0


def test_package_boundary_progress_does_not_override_live_byte_progress():
    host = SimpleNamespace(
        events=Queue(),
        transfer_total=2,
        transfer_done=1,
        transfer_failed=0,
        progress_var=Var(10.0),
        active_operation=None,
        after=lambda *_args: None,
        _operation_status=lambda text: setattr(host, "operation_status", text),
        operation_status="Transferring   1/2 packages   1.0 MB / 10.0 MB",
    )
    host._drain_events = lambda: None
    host.events.put(("progress", "RPM 1/2", 0.5))

    OperationsMixin._drain_events(host)

    assert host.progress_var.get() == 10.0
    assert host.operation_status.startswith("Transferring")


def test_progress_events_resume_after_payload_transfer_finishes():
    host = SimpleNamespace(
        events=Queue(),
        transfer_total=2,
        transfer_done=2,
        transfer_failed=0,
        progress_var=Var(80.0),
        active_operation=None,
        after=lambda *_args: None,
        _operation_status=lambda text: setattr(host, "operation_status", text),
        operation_status="Transferring",
    )
    host._drain_events = lambda: None
    host.events.put(("progress", "Sealing bundle", 0.9))

    OperationsMixin._drain_events(host)

    assert host.progress_var.get() == 90.0
    assert host.operation_status == "Sealing bundle"
