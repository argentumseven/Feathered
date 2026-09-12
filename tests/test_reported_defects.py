"""Four defects reported from a real Windows session, and their bug classes.

Each of these shipped through a green suite, a passing release gate and clean
static analysis. What they have in common is that none of them was reachable by
any test: three needed a live window, and the fourth was a constant nobody
compared against anything.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import core

tk = pytest.importorskip("tkinter")


def _display_available() -> bool:
    if sys.platform.startswith("win") or sys.platform == "darwin":
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


requires_display = pytest.mark.skipif(
    not _display_available(), reason="no display; run under xvfb-run")


@pytest.fixture
def application(tmp_path, monkeypatch):
    for variable in ("APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(variable, str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(parents=True, exist_ok=True)
    import app

    window = app.App()
    try:
        yield window
    finally:
        try:
            window.destroy()
        except tk.TclError:
            pass


# --------------------------------------------------------------------------
# 1. The version the operator sees
# --------------------------------------------------------------------------

def test_the_reported_version_matches_the_newest_changelog_entry():
    """1.2.9 displayed "1.2.4" in the window title for five releases.

    Nothing compared the constant to anything, so the release number lived in
    the changelog, the directory name and the archive name while the running
    program reported something else entirely -- including in provenance.json,
    where it becomes part of a bundle's permanent record.
    """
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = re.findall(r"^# (\d+\.\d+\.\d+)", changelog, re.MULTILINE)
    assert headings, "CHANGELOG.md must open with a versioned heading"
    assert core.FEATHERED_VERSION == headings[0], (
        f"FEATHERED_VERSION is {core.FEATHERED_VERSION} but the newest CHANGELOG.md "
        f"entry is {headings[0]}; the running program would misreport itself")


def test_the_version_reaches_the_gui_and_provenance_identically():
    from feathered_app.context import APP_VERSION

    assert APP_VERSION == core.FEATHERED_VERSION
    assert core.FEATHERED_VERSION in core.USER_AGENT


# --------------------------------------------------------------------------
# 2. Stale widget references after a pane rebuild
# --------------------------------------------------------------------------

@requires_display
def test_rebuilding_the_repository_pane_drops_dead_widget_references(application):
    """The reported TclError: a destroyed combobox still stored on the app.

    Switching source method after the pane had rebuilt reached a widget that no
    longer existed and raised "invalid command name .!frame3...!combobox" out of
    a Tk callback, where the operator can neither see nor act on it.
    """
    application.show_pane("repositories")
    application.update_idletasks()

    frame = tk.Frame(application)
    application.__dict__["a_probe_widget"] = frame
    frame.destroy()

    application._clear_repository_workflow_widgets()

    assert application.__dict__["a_probe_widget"] is None, (
        "a destroyed widget must not survive a pane rebuild as a live reference")


@requires_display
def test_live_lookup_refuses_a_destroyed_widget(application):
    frame = tk.Frame(application)
    application.__dict__["a_probe_widget"] = frame
    assert application._live("a_probe_widget") is frame

    frame.destroy()
    assert application._live("a_probe_widget") is None
    assert application._live("never_existed") is None


@requires_display
def test_changing_source_method_after_a_rebuild_does_not_raise(application):
    """The exact reported reproduction, end to end."""
    application.show_pane("repositories")
    application.update_idletasks()
    application._clear_repository_workflow_widgets()

    application._sync_mirror_source_controls()
    application._source_method_changed()
    application.update_idletasks()


# --------------------------------------------------------------------------
# 3. Priority semantics are visible
# --------------------------------------------------------------------------

def test_the_priority_rule_is_stated_where_the_column_is_shown():
    """Lower number wins, and nothing in the UI said so.

    The rule is real: _choose_candidate sorts on architecture match, then
    repository priority ascending, then version. An operator selecting several
    repositories cannot predict which one supplies a package without it.
    """
    source = (ROOT / "feathered_app" / "ui" / "panes.py").read_text(encoding="utf-8")
    assert "the lowest number wins" in source
    assert source.count('"Priority \\u2193 wins"') == 2, (
        "both repository tables must label the column with its direction")


def test_lower_priority_number_actually_wins():
    """Pin the behaviour the label now claims."""
    from feathered_app.ui.panes import PaneMixin

    def candidate(priority):
        return SimpleNamespace(
            name="p", arch="x86_64", version="1",
            repo=SimpleNamespace(name=f"repo{priority}", priority=priority))

    shell = SimpleNamespace(
        arch_var=SimpleNamespace(get=lambda: "x86_64"),
        _compare_package_versions=lambda a, b: 0)

    chosen = PaneMixin._best_coverage_candidate(
        shell, [candidate(50), candidate(10), candidate(30)])

    assert chosen.repo.priority == 10, "the lowest priority number must win"


# --------------------------------------------------------------------------
# 4. Repository metadata is opt-in outside mirror mode
# --------------------------------------------------------------------------

@requires_display
def test_repository_metadata_is_not_preselected_for_package_workflows(application):
    """It is the point of a mirror and an extra for a workload bundle."""
    assert application.emit_repo_var.get() is False


@requires_display
def test_switching_intent_corrects_the_metadata_selection_both_ways(
        application, monkeypatch):
    """Doubling back to change the dropdown must not leave a mirror's forcing on.

    The capability is patched on the class rather than the instance because the
    sync calls ``App._acquisition_state(self)`` unbound, so an instance
    attribute is ignored by that dispatch path.
    """
    import app
    from acquisition_model import AcquisitionCapability

    application.show_pane("transfer")
    application.update_idletasks()
    assert application.emit_repo_var.get() is False

    def as_capability(capability):
        monkeypatch.setattr(app.App, "_acquisition_state",
                            lambda _self: SimpleNamespace(capability=capability),
                            raising=False)

    as_capability(AcquisitionCapability.FULL_TRANSACTION)
    application._sync_output_capability_controls()

    as_capability(AcquisitionCapability.REPOSITORY_MIRROR)
    application._sync_output_capability_controls()
    assert application.emit_repo_var.get() is True, "a mirror requires its metadata"

    as_capability(AcquisitionCapability.FULL_TRANSACTION)
    application._sync_output_capability_controls()
    assert application.emit_repo_var.get() is False, (
        "returning to a workload must clear the mirror's forced selection")


@requires_display
def test_an_incomplete_selection_does_not_flicker_the_metadata_checkbox(
        application, monkeypatch):
    """BLOCKED means "not enough chosen yet" and every workflow passes through it."""
    import app
    from acquisition_model import AcquisitionCapability

    application.show_pane("transfer")
    application.emit_repo_var.set(True)
    monkeypatch.setattr(app.App, "_acquisition_state",
                        lambda _self: SimpleNamespace(
                            capability=AcquisitionCapability.BLOCKED),
                        raising=False)

    application._sync_output_capability_controls()

    assert application.emit_repo_var.get() is True, (
        "an incomplete selection must not discard a deliberate tick")


@requires_display
def test_a_deliberate_tick_survives_navigation_within_one_mode(application):
    """Only a capability change resets it; moving between panes must not."""
    application.show_pane("transfer")
    application.emit_repo_var.set(True)

    application._sync_output_capability_controls()
    application.show_pane("review")
    application._sync_output_capability_controls()

    assert application.emit_repo_var.get() is True
