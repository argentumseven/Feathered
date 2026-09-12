"""A failed build must leave something behind on the machine that ran it.

Bundle-side evidence is only written when a build reaches publication, and the
Activity log is an in-memory list discarded with the window. A crash, a cancel,
or a resolution failure therefore left no artifact at all -- on a machine the
operator often cannot casually copy text off.

These tests cover the durable mirror and, more importantly, the two properties
that make it safe to feed from the log path: it never raises into a build, and
it never receives text that has not already been redacted.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from feathered_app.activity_log import ActivityLogFile, open_activity_log


def test_lines_reach_the_file(tmp_path):
    sink = open_activity_log(tmp_path, header="Feathered test")
    assert sink is not None

    sink.write_lines(["Resolving workload", "Downloading 3 packages"])

    text = sink.path.read_text(encoding="utf-8")
    assert "Feathered session" in text
    assert "Resolving workload" in text
    assert "Downloading 3 packages" in text


def test_a_session_banner_separates_runs(tmp_path):
    open_activity_log(tmp_path)
    open_activity_log(tmp_path)
    assert (tmp_path / "feathered-activity.log").read_text(
        encoding="utf-8").count("Feathered session") == 2


def test_rotation_bounds_the_file(tmp_path):
    sink = ActivityLogFile(tmp_path, max_bytes=400, keep=2)
    for index in range(400):
        sink.write(f"line {index} " + "x" * 40)

    assert sink.path.stat().st_size < 4000
    assert sink.path.with_suffix(".1").exists()
    assert not sink.path.with_suffix(".3").exists(), "keep must bound the rotations"


def test_a_write_failure_disables_the_sink_instead_of_raising(tmp_path):
    """A full disk must not take a build down, and must not retry per line."""
    sink = ActivityLogFile(tmp_path)
    sink.write("first")

    calls = []
    original = Path.open

    def explode(self, *args, **kwargs):
        if self == sink.path:
            calls.append(1)
            raise OSError(28, "No space left on device")
        return original(self, *args, **kwargs)

    Path.open = explode
    try:
        assert sink.write("second") is False
        assert sink.write("third") is False
    finally:
        Path.open = original

    assert len(calls) == 1, "a disabled sink must not retry on every line"
    assert "No space left" in sink.disabled_reason


def test_open_returns_none_rather_than_a_dead_sink(tmp_path):
    unusable = tmp_path / "file-not-a-directory"
    unusable.write_text("x", encoding="utf-8")
    assert open_activity_log(unusable / "nested") is None
    assert open_activity_log(None) is None


def test_the_log_path_redacts_before_it_reaches_the_file(tmp_path):
    """The sink must never be handed raw exception text."""
    from feathered_app.application.operations import OperationsMixin

    shell = SimpleNamespace()
    shell.log_lines = []
    sink = ActivityLogFile(tmp_path)
    shell.__dict__["_activity_log_sink"] = sink
    shell._activity_log_file = lambda: sink

    import core
    core._remember_secret("hunter2-swordfish")
    try:
        OperationsMixin._log(shell, "connecting with password hunter2-swordfish")
    finally:
        with core._KNOWN_SECRETS_LOCK:
            core._KNOWN_SECRETS.discard("hunter2-swordfish")

    written = sink.path.read_text(encoding="utf-8")
    assert "hunter2-swordfish" not in written
    assert "hunter2-swordfish" not in "\n".join(shell.log_lines)


def test_a_host_without_a_state_directory_still_logs_in_memory():
    """The durable mirror is additive; its absence must not break logging."""
    from feathered_app.application.operations import OperationsMixin

    shell = SimpleNamespace()
    shell.log_lines = []
    OperationsMixin._log(shell, "resolution failed")
    assert shell.log_lines == ["resolution failed"]


def test_sink_failure_is_surfaced_rather_than_swallowed(tmp_path):
    from feathered_app.application.operations import OperationsMixin

    class Dead(ActivityLogFile):
        def write_lines(self, lines):
            self.disabled_reason = "OSError: read-only file system"
            return False

    shell = SimpleNamespace()
    shell.log_lines = []
    shell._activity_log_file = lambda: Dead(tmp_path)

    OperationsMixin._log(shell, "resolution failed")

    assert "resolution failed" in shell.log_lines
    assert any("Host-side activity log stopped" in line for line in shell.log_lines)
