"""Behavioral checks for the actual typed service/publication implementations."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from build_spec import BuildSpec
from core import BuildOptions
from feathered_app.build_host_contracts import BuildEvent
from feathered_app.build_publication import PublicationContext, confirm_publication
from feathered_app.build_services import BuildServices
from feathered_app.headless_host import HeadlessHost


class Recorder:
    def __init__(self):
        self.messages = []
        self.progress_values = []

    def log(self, message: str) -> None:
        self.messages.append(message)

    def warn(self, message: str) -> None:
        self.messages.append(message)

    def progress(self, label: str, value: float) -> None:
        self.progress_values.append((label, value))


class Sink:
    def __init__(self):
        self.events: list[BuildEvent] = []

    def put(self, event: BuildEvent) -> None:
        self.events.append(event)


def test_real_headless_host_uses_typed_services_and_caller_event_sink():
    recorder, sink, plans = Recorder(), Sink(), []
    host = HeadlessHost(BuildSpec(), BuildServices(
        reporter=recorder, events=sink,
        download_plan_sink=lambda count, size: plans.append((count, size))))
    host._log(42)
    host._progress("transfer", 0.5)
    host._publish_download_plan(3, 42)
    info = {"bytes": 42}
    host._on_item_event("package", "done", info)
    assert recorder.messages == ["42"]
    assert recorder.progress_values == [("transfer", 0.5)]
    assert plans == [(3, 42)]
    assert sink.events == [("item", "package", "done", info)]
    assert host.events is sink


def test_caller_cancellation_and_local_cancellation_are_independent():
    caller = {"cancelled": False}
    host = HeadlessHost(BuildSpec(), BuildServices(
        reporter=Recorder(), should_cancel=lambda: caller["cancelled"]))
    assert not host.cancel_event.is_set()
    caller["cancelled"] = True
    assert host.cancel_event.is_set()
    caller["cancelled"] = False
    assert not host.cancel_event.is_set()
    host.request_cancel()
    assert host.cancel_event.is_set()


def test_trust_and_conflict_decisions_use_separate_policies():
    decisions, findings = [], []
    host = HeadlessHost(BuildSpec(), BuildServices(
        reporter=Recorder(),
        trust_policy=lambda rows: findings.append(list(rows)) or False,
        decision_policy=lambda title, message: decisions.append((title, message)) or True))
    assert host._confirm_warnings([])
    assert findings == []
    assert not host._confirm_warnings(["unsigned"])
    assert host._confirm_conflicts(["collision"])
    assert findings == [["unsigned"]]
    assert len(decisions) == 1 and "collision" in decisions[0][1]


def context_for(dest, *, mirror=False):
    return PublicationContext(
        resolve_path=lambda name: dest,
        is_mirror=lambda: mirror,
        summarize=lambda path: "occupied",
        suggest_sibling=lambda name: name + "-next",
        has_repository_metadata=lambda path: True,
        log=lambda message: None,
    )


@pytest.mark.parametrize("mirror,answers,expected,additive,emit", [
    (False, ["add", "keep"], "bundle", True, False),
    (False, ["add", "regenerate"], "bundle", True, True),
    (False, ["sibling"], "bundle-next", False, True),
    (True, ["sibling"], "bundle-next", False, True),
    (True, ["add"], None, False, True),
    (False, ["cancel"], None, False, True),
])
def test_publication_choices_preserve_existing_content(tmp_path, mirror, answers, expected, additive, emit):
    dest = tmp_path / "bundle"
    dest.mkdir()
    old = dest / "old-package"
    old.write_bytes(b"preserve me")
    remaining = iter(answers)
    options = BuildOptions(emit_repository=True)
    result = confirm_publication(
        context_for(dest, mirror=mirror), "bundle", options,
        choose=lambda *args, **kwargs: next(remaining))
    assert result == expected
    assert options.additive_publish is additive
    assert options.emit_repository is emit
    assert old.read_bytes() == b"preserve me"


def test_legacy_publication_adapter_needs_no_unused_callbacks_for_new_folder(tmp_path):
    from feathered_app.build_output import confirm_publication as legacy_confirm

    # Existing callers may supply only the methods reached by this branch.
    host = SimpleNamespace(_resolved_output_path=lambda name: tmp_path / name)
    assert legacy_confirm(host, "new", choose=lambda *a, **k: "cancel") == "new"
