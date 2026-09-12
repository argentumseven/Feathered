"""A paused build must always have a way out.

Reported from a real session: a workload build reached the trust review, the
footer showed "Review required - build paused pending your decision in Activity
log", the wizard pulsed for attention, and nothing was clickable. The operator
could not continue, could not cancel, and could not retrieve a log to report it.

The mechanism: ``_confirm_warnings`` blocks its worker on an ``Event`` until the
review dialog calls back, and ``show_details`` called ``grab_set()`` immediately
after creating the Toplevel but did not wire ``WM_DELETE_WINDOW`` until the
window was fully built. Anything raising in between left a modal grab over the
whole application with no close handler and a build that could never finish.
The traceback went to stderr, which does not exist in a windowed Windows build,
so the failure was invisible as well as unescapable.

Two independent guards are tested here, because the second exists precisely for
the failures the first does not anticipate:

  * every escape route on a decision dialog is wired before the grab is taken;
  * ``report_callback_exception`` releases any stuck grab and records the
    traceback where it can actually be retrieved.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

tk = pytest.importorskip("tkinter")


def _display_available() -> bool:
    if sys.platform.startswith("win") or sys.platform == "darwin":
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


requires_display = pytest.mark.skipif(
    not _display_available(), reason="no display; run under xvfb-run")


def close_via_window_manager(dialog) -> None:
    """Do exactly what clicking the window's X does.

    ``protocol()`` returns the registered Tcl command name, not a Python
    callable, so the handler has to be evaluated rather than called.
    """
    dialog.tk.eval(dialog.protocol("WM_DELETE_WINDOW"))


@pytest.fixture
def silent_dialogs(monkeypatch):
    """The handler shows a modal error box; a pumped test would block on it."""
    from feathered_app.ui import theme

    shown = []
    monkeypatch.setattr(theme.messagebox, "showerror",
                        lambda *a, **k: shown.append(a), raising=False)
    return shown


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
# The dialog always has an exit
# --------------------------------------------------------------------------

@requires_display
def test_closing_the_review_dialog_cancels_rather_than_hanging(application):
    answers = []
    application.show_details(focus_trust=True, warnings=["a trust finding"],
                             decision_callback=answers.append)
    application.update_idletasks()

    dialog = application.grab_current()
    assert dialog is not None, "a decision dialog must be modal"
    close_via_window_manager(dialog)
    application.update_idletasks()

    assert answers == [False], "closing must answer the worker, not abandon it"
    assert application.grab_current() is None, "the grab must be released"


@requires_display
def test_escape_answers_the_waiting_worker(application):
    answers = []
    application.show_details(focus_trust=True, warnings=["f"],
                             decision_callback=answers.append)
    application.update_idletasks()

    dialog = application.grab_current()
    dialog.focus_force()
    application.update()
    dialog.event_generate("<Escape>", when="now")
    application.update()

    assert answers == [False]


@requires_display
def test_destroying_the_dialog_by_any_other_means_still_answers(application):
    """The last-resort guard: nothing may destroy the window silently."""
    answers = []
    application.show_details(focus_trust=True, warnings=["f"],
                             decision_callback=answers.append)
    application.update_idletasks()

    application.grab_current().destroy()
    application.update_idletasks()

    assert answers == [False]


@requires_display
def test_the_decision_is_answered_exactly_once(application):
    answers = []
    application.show_details(focus_trust=True, warnings=["f"],
                             decision_callback=answers.append)
    application.update_idletasks()
    dialog = application.grab_current()

    # Capture the handler before the first close destroys the window, so the
    # second invocation exercises the guard rather than failing on a dead path.
    handler = dialog.protocol("WM_DELETE_WINDOW")
    dialog.tk.eval(handler)
    application.update_idletasks()
    try:
        dialog.tk.eval(handler)
    except tk.TclError:
        pass  # the window is already gone; the guard was not even reached
    application.update_idletasks()

    assert answers == [False], "a second close must not answer the worker twice"


@requires_display
def test_confirm_warnings_returns_once_the_dialog_is_closed(application):
    """The contract the reported lock violated: the call must return.

    ``_confirm_warnings`` blocks on an Event until the dialog answers. Driven
    here on the main thread with ``after`` running its callback immediately,
    because scheduling from a worker thread needs a live mainloop that a pumped
    test does not have -- the threading is not what this is asserting.
    """
    from feathered_app.application.results import ResultsMixin

    application.after = lambda _delay, callback=None, *a: (callback and callback())

    closed = {}
    real_show_details = application.show_details

    def show_and_close(**kwargs):
        real_show_details(**kwargs)
        dialog = application.grab_current()
        closed["dialog"] = dialog
        close_via_window_manager(dialog)

    application.show_details = show_and_close

    accepted = ResultsMixin._confirm_warnings(
        application, ["repository index was not signed"])

    assert accepted is False, "closing the review cancels the build"
    assert closed["dialog"] is not None
    assert application.grab_current() is None


@requires_display
def test_confirm_warnings_returns_even_if_the_dialog_cannot_open(application):
    """The failure that produced the lock: the dialog raises after grabbing."""
    from feathered_app.application.results import ResultsMixin

    application.after = lambda _delay, callback=None, *a: (callback and callback())

    def explode(**_kwargs):
        stuck = tk.Toplevel(application)
        stuck.grab_set()
        raise RuntimeError("dialog construction failed after grab_set")

    application.show_details = explode

    with pytest.raises(RuntimeError):
        ResultsMixin._confirm_warnings(application, ["a finding"])

    application.update_idletasks()
    assert application.grab_current() is None, (
        "a dialog that failed after grabbing must not lock the application")


# --------------------------------------------------------------------------
# The safety net for failures the first guard does not anticipate
# --------------------------------------------------------------------------

@requires_display
def test_a_dialog_that_fails_after_grabbing_does_not_lock_the_window(application, silent_dialogs):
    """The exact shape of the reported bug, forced.

    A Toplevel that grabs and then raises before wiring its close handler holds
    every click in the application. The handler must release it.
    """
    stuck = tk.Toplevel(application)
    stuck.grab_set()
    application.update_idletasks()
    assert application.grab_current() is stuck

    try:
        raise RuntimeError("dialog construction failed after grab_set")
    except RuntimeError:
        application.report_callback_exception(*sys.exc_info())
    application.update_idletasks()

    assert application.grab_current() is None, (
        "a failed dialog must not keep the application locked")


@requires_display
def test_an_interface_error_is_recorded_where_it_can_be_retrieved(application, silent_dialogs):
    """The operator could not send a log, because stderr does not exist here."""
    application.log_lines.clear()
    try:
        raise ValueError("something went wrong in a callback")
    except ValueError:
        application.report_callback_exception(*sys.exc_info())

    joined = "\n".join(application.log_lines)
    assert "unexpected error in the interface" in joined
    assert "something went wrong in a callback" in joined
    assert "Traceback" in joined


@requires_display
def test_the_interface_error_reaches_the_host_side_log_file(application, silent_dialogs, tmp_path):
    application._log("prime the sink")
    sink = application.__dict__.get("_activity_log_sink")
    if not sink:
        pytest.skip("host-side log sink unavailable in this environment")

    try:
        raise ValueError("written to disk")
    except ValueError:
        application.report_callback_exception(*sys.exc_info())

    assert "written to disk" in sink.path.read_text(encoding="utf-8")


@requires_display
def test_the_handler_is_installed_on_the_real_application(application):
    """Tkinter only uses it if it is defined on the widget class."""
    import app

    assert app.App.report_callback_exception is not tk.Tk.report_callback_exception
