"""The build worker must never read a Tk widget.

Found by attempting the first end-to-end headless build: it failed on
``RuntimeError: main thread is not in main loop``, raised from ``_signature()``
reading ``self.arch_var.get()`` from inside the build worker thread. Tk is not
thread-safe. On an unthreaded Tcl that raises; on a threaded one it is undefined
behaviour that works until it does not, which is the worst kind of bug to have
in the middle of a long download.

Enumerating the hazard by reading code does not work -- the census is 121 Tk
variable reads across the six application modules the worker calls into, and
only some are reachable from the thread. So this finds them by execution
instead: every Tk variable on the application is swapped for a tripwire that
records any read attributed to a non-main thread, the build path is exercised,
and the recorded set must be empty.

This makes the worker-isolation guarantee executable rather than relying on
comments or manual inspection.
"""
from __future__ import annotations

import os
import sys
import datetime
import threading
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


class Tripwire:
    """Wraps a Tk variable and records reads made off the main thread."""

    def __init__(self, name, variable, offences):
        self._name = name
        self._variable = variable
        self._offences = offences
        self._main = threading.main_thread()
        try:
            self._last = variable.get()
        except Exception:
            self._last = ""

    def get(self):
        if threading.current_thread() is not self._main:
            # Record and return a benign value rather than delegating: the real
            # read is exactly what raises "main thread is not in main loop", and
            # the point is to collect every offender in one pass instead of
            # stopping at the first.
            self._offences.append(self._name)
            return self._last
        self._last = self._variable.get()
        return self._last

    def set(self, value):
        return self._variable.set(value)

    def __getattr__(self, item):
        return getattr(self._variable, item)


def arm(application, offences):
    """Swap every Tk variable on the application for a tripwire."""
    armed = []
    for name, value in list(application.__dict__.items()):
        if isinstance(value, tk.Variable):
            application.__dict__[name] = Tripwire(name, value, offences)
            armed.append(name)
    return armed


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


@requires_display
def test_the_tripwire_detects_a_read_from_another_thread(application):
    """The instrument itself, before trusting what it reports."""
    offences: list[str] = []
    armed = arm(application, offences)
    assert len(armed) > 10, "the application should expose many Tk variables"

    def worker():
        application.arch_var.get()

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()

    assert offences == ["arch_var"]


@requires_display
def test_main_thread_reads_are_not_flagged(application):
    offences: list[str] = []
    arm(application, offences)
    application.arch_var.get()
    application.selection_mode_var.get()
    assert offences == []


@requires_display
def test_the_snapshot_serves_the_values_the_worker_needs(application):
    """After the snapshot is taken, these must not touch a widget."""
    from feathered_app.application.build import BuildMixin
    from feathered_app.application.sources import SourcesMixin

    application._snapshot_build_inputs()
    offences: list[str] = []
    arm(application, offences)

    results = {}

    def worker():
        results["arch"] = BuildMixin._selected_arch(application)
        results["intent"] = SourcesMixin._acquisition_intent(application)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()

    assert offences == [], f"worker read Tk variables: {sorted(set(offences))}"
    assert results["arch"]
    assert results["intent"] is not None


@requires_display
def test_releasing_the_snapshot_returns_the_wizard_to_live_controls(application):
    """Only the worker is pinned; the interactive UI must stay live."""
    from feathered_app.application.build import BuildMixin

    application.arch_var.set("amd64")
    application._snapshot_build_inputs()
    application.arch_var.set("arm64")

    assert BuildMixin._selected_arch(application) == "amd64", (
        "a running build must not follow the operator changing the target")

    application._release_build_inputs()
    assert BuildMixin._selected_arch(application) == "arm64"
    assert application.__dict__.get("_build_snapshot") is None


@requires_display
def test_a_build_snapshot_is_taken_before_the_worker_is_created():
    """Ordering is the whole guarantee; assert it in the source."""
    source = (ROOT / "feathered_app" / "application" / "build.py").read_text(encoding="utf-8")
    snapshot_at = source.index("self._snapshot_build_inputs()")
    # The worker now runs build_runner.run with an explicit plan rather than a
    # closure; the ordering guarantee is unchanged.
    thread_at = source.index("target=build_runner.run")
    assert snapshot_at < thread_at, (
        "inputs must be frozen before the worker exists, not after")


@requires_display
def test_the_snapshot_is_dropped_when_the_operation_ends(application):
    application._snapshot_build_inputs()
    assert application.__dict__.get("_build_snapshot") is not None

    application._release_operation()

    assert application.__dict__.get("_build_snapshot") is None, (
        "a stale snapshot would make the next build resolve against the old target")


@requires_display
def test_the_wider_build_path_reads_no_widgets_from_the_worker(application):
    """Everything the worker calls before touching the network.

    Deliberately broader than the two accessors that were fixed by name: the
    point of the tripwire is to find offenders rather than confirm known ones,
    so this list should grow as more of the build path is exercised.
    """
    from feathered_app.application.build import BuildMixin
    from feathered_app.application.output import OutputMixin
    from feathered_app.application.selection import SelectionMixin
    from feathered_app.application.sources import SourcesMixin

    application._snapshot_build_inputs()
    offences: list[str] = []
    arm(application, offences)

    def worker():
        BuildMixin._selected_arch(application)
        SourcesMixin._acquisition_intent(application)
        # _profile is the hot one: family predicates, backend dispatch and
        # every metadata builder go through it on the worker thread.
        SourcesMixin._profile(application)
        SourcesMixin._is_deb(application)
        SourcesMixin._is_arch(application)
        SelectionMixin._active_source_method(application)
        SourcesMixin._mirror_mode(application)
        SourcesMixin._mirror_layout(application)
        SourcesMixin._merge_policy(application)
        SourcesMixin._unified_mirror_mode(application)
        OutputMixin._layout(application)
        try:
            SourcesMixin._workload(application)
        except Exception:
            pass

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()

    assert offences == [], (
        "these must come from the frozen request, not a widget: "
        + ", ".join(sorted(set(offences))))


@requires_display
def test_folder_naming_cannot_drift_between_confirmation_and_write(application):
    """Folder names read the clock, so the request must freeze the instant too.

    A build confirmed at 23:59:59 and written at 00:00:01 previously derived two
    different folder names from one request. ``locked_output_folder_name``
    exists to notice that; freezing the moment makes the two names identical by
    construction, so the lock has nothing left to catch.
    """
    from feathered_app.application.output import OutputMixin

    application.folder_stamp_var.set("date")
    application._snapshot_build_inputs()

    at_confirmation = OutputMixin._folder_name(application)
    # Roll the frozen clock forward past midnight; a live clock would change the
    # name here, which is exactly the hazard.
    application.__dict__["_build_naming_time"] += datetime.timedelta(days=1, seconds=3)
    after_rollover = OutputMixin._folder_name(application)

    assert after_rollover != at_confirmation, (
        "sanity: the stamp must actually depend on the frozen moment")

    application.__dict__["_build_naming_time"] -= datetime.timedelta(days=1, seconds=3)
    assert OutputMixin._folder_name(application) == at_confirmation, (
        "the same frozen request must always name the same folder")


@requires_display
def test_naming_follows_the_clock_when_no_build_is_running(application):
    """Only a running build is pinned; the preview should track the clock."""
    from feathered_app.application.output import OutputMixin

    application._release_build_inputs()
    assert application.__dict__.get("_build_naming_time") is None
    # No exception and a usable name: the accessor falls back to now().
    assert OutputMixin._folder_name(application)


#  Empty since 1.2.12. The build worker's one UI dependency was the trust
#  review, and it is now an injection point: `_confirm_warnings` calls whatever
#  `_trust_policy` the caller supplied, and only falls back to the interactive
#  `_gui_trust_review` when nobody supplied one. With a policy injected -- as
#  the CLI and these tests do -- the whole build path is Tk-free.
#
#  This set is deliberately empty: with an injected policy, worker execution
#  must not reach any Tk-bound method.
TK_BOUND_ON_THE_BUILD_PATH: set[str] = set()


@requires_display
def test_the_build_path_has_exactly_one_ui_dependency(tmp_path, monkeypatch):
    """Measure the boundary a headless core has to cut along, and hold it.

    Every estimate of A2's size in this project has been guesswork. This runs a
    real build with every App method instrumented, records which ones the worker
    thread actually calls, and classifies them by whether their source touches
    Tk. The answer is 36 called, 35 already clean.

    Holding that as a test means the boundary cannot quietly move: adding a
    widget call to anything the worker reaches fails here, with the method
    named, rather than growing A2 silently.
    """
    import inspect
    import re
    import shutil
    import subprocess

    if not (shutil.which("dpkg-deb") and shutil.which("dpkg-scanpackages")):
        pytest.skip("needs dpkg tooling to build the repository fixture")

    for variable in ("APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(variable, str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(parents=True, exist_ok=True)

    from tests.test_end_to_end_build import build_repository

    repo = build_repository(tmp_path, "repo", (("podman", "4.3.1"),))

    import app
    from core import RepoSpec
    from feathered_app.ui import theme

    for name in ("showerror", "showinfo", "showwarning"):
        monkeypatch.setattr(theme.messagebox, name, lambda *a, **k: None, raising=False)
    monkeypatch.setattr(theme.messagebox, "askyesno", lambda *a, **k: True, raising=False)

    main = threading.main_thread()
    called: set[str] = set()
    seen: set[str] = set()
    for klass in app.App.__mro__:
        if klass.__module__.startswith("tkinter") or klass is object:
            continue
        for name, function in list(vars(klass).items()):
            if name in seen or name.startswith("__") or not inspect.isfunction(function):
                continue
            seen.add(name)

            def instrument(recorded, original):
                def wrapper(self, *args, **kwargs):
                    if threading.current_thread() is not main:
                        called.add(recorded)
                    return original(self, *args, **kwargs)
                wrapper.__wrapped__ = original
                return wrapper

            monkeypatch.setattr(app.App, name, instrument(name, function), raising=False)

    window = app.App()
    try:
        window.distro_var.set("Debian")
        window.update_idletasks()
        window.arch_var.set("amd64")
        window.selection_mode_var.set("Workload preset")
        window.update_idletasks()
        window.workload_var.set("Podman")
        window.update_idletasks()
        window.repo_rows = [RepoSpec("Local", repo.as_uri() + "/", "dependency",
                                     repo_format="apt", suite="stable", components="main",
                                     allow_unverified_index=True)]
        window.out_var.set(str(tmp_path / "out"))
        # Inject the policy rather than stubbing the dialog: that is how a
        # non-interactive caller runs a build, and it is what makes the path
        # Tk-free.
        window.__dict__["_trust_policy"] = lambda findings: True

        ticks = {"n": 0}

        def poll():
            ticks["n"] += 1
            finished = (window.active_operation is None
                        and window.__dict__.get("_activity_state") in ("idle", "failed"))
            if finished or ticks["n"] > 1500:
                window.quit()
            else:
                window.after(20, poll)

        window.after(50, lambda: (window.start_build(True), poll()))
        window.mainloop()
        assert window.__dict__.get("_activity_state") == "idle", "the survey needs a real build"
        assert "_confirm_warnings" in called, (
            "the survey must actually reach the trust decision, or an empty "
            "Tk-bound set proves nothing")
    finally:
        try:
            window.destroy()
        except tk.TclError:
            pass

    touches_tk = re.compile(
        r"self\.(after|event_generate|winfo_|update_idletasks|withdraw|deiconify|"
        r"grab_|clipboard_|bell|focus_)|\.configure\(|\.pack\(|\.grid\(|messagebox\.|"
        r"\btk\.|\bttk\.|filedialog\.|simpledialog\.")
    bound = set()
    for name in called:
        function = getattr(app.App, name)
        try:
            source = inspect.getsource(getattr(function, "__wrapped__", function))
        except (OSError, TypeError):
            continue
        if touches_tk.search(source):
            bound.add(name)

    assert len(called) > 25, f"the survey should reach the whole build path, saw {len(called)}"
    assert bound == TK_BOUND_ON_THE_BUILD_PATH, (
        "the UI boundary of the build path moved. Newly Tk-bound: "
        f"{sorted(bound - TK_BOUND_ON_THE_BUILD_PATH)}; newly clean: "
        f"{sorted(TK_BOUND_ON_THE_BUILD_PATH - bound)}")


@requires_display
def test_the_interactive_policy_is_still_the_default(application):
    """Injection must not silently change what the GUI does.

    An operator running a build with no policy supplied must still get the
    Activity-log review, not a silent accept or decline.
    """
    from feathered_app.application.results import ResultsMixin

    asked = {}
    application._gui_trust_review = lambda findings: asked.setdefault("findings", findings) or True
    assert ResultsMixin._confirm_warnings(application, ["unsigned index"]) is True
    assert asked["findings"] == ["unsigned index"]


@requires_display
def test_an_injected_policy_replaces_the_dialog_entirely(application):
    from feathered_app.application.results import ResultsMixin

    application._gui_trust_review = lambda findings: pytest.fail(
        "an injected policy must be used instead of the dialog")
    application.__dict__["_trust_policy"] = lambda findings: False

    assert ResultsMixin._confirm_warnings(application, ["unsigned index"]) is False
    # No findings means no decision to make, and no policy call either.
    assert ResultsMixin._confirm_warnings(application, []) is True


@requires_display
def test_every_mid_build_question_goes_through_a_policy(application):
    """Conflicts and waivers must be answerable without a UI, like trust review.

    Trust, conflict, and dependency-waiver prompts all need the same policy
    boundary so a headless build never depends on a message box.
    """
    from feathered_app.application.results import ResultsMixin

    asked = []
    application.__dict__["_decision_policy"] = lambda title, message: (
        asked.append(message) or True)
    application._gui_ask_on_ui_thread = lambda *a, **k: pytest.fail(
        "an injected policy must be used instead of a dialog")

    assert ResultsMixin._confirm_conflicts(application, ["a replaces b"]) is True
    assert asked and "conflict notice" in asked[0]

    application.__dict__["_decision_policy"] = lambda title, message: False
    assert ResultsMixin._confirm_conflicts(application, ["a replaces b"]) is False


@requires_display
def test_the_interactive_prompt_remains_the_default(application):
    """Injection must not change what an operator sees."""
    from feathered_app.application.results import ResultsMixin

    seen = {}

    def record(title, message, **kwargs):
        seen["message"] = message
        return True

    application._gui_ask_on_ui_thread = record

    assert ResultsMixin._ask_on_ui_thread(application, "T", "proceed?") is True
    assert seen["message"] == "proceed?"


@requires_display
def test_a_host_that_cannot_answer_declines(application):
    """The safe answer to an unreviewed question is no."""
    from types import SimpleNamespace

    from feathered_app.application.results import ResultsMixin

    assert ResultsMixin._ask_on_ui_thread(SimpleNamespace(), "T", "proceed?") is False


def test_the_download_plan_does_not_deadlock_without_a_consumer():
    """The last UI dependency: it blocked forever on an acknowledgement.

    `_publish_download_plan` published to the event queue and waited on an Event
    that only a running UI drain loop sets. With nothing draining -- a
    command-line run, a test, or a UI whose pump has stopped -- the build hung
    with nothing in the log to explain it.
    """
    import queue
    from types import SimpleNamespace

    from feathered_app.application.tools import ToolsMixin

    host = SimpleNamespace()
    host.events = queue.Queue()
    logged = []
    host._log = logged.append
    host.DOWNLOAD_PLAN_ACK_TIMEOUT_S = 0.05
    host._gui_publish_download_plan = lambda c, b: ToolsMixin._gui_publish_download_plan(
        host, c, b)

    finished = threading.Event()

    def worker():
        ToolsMixin._publish_download_plan(host, 7, 4096)
        finished.set()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout=5)

    assert finished.is_set(), "an unacknowledged plan must not hang the build"
    assert any("did not acknowledge" in line for line in logged), (
        "giving up silently would leave the operator no way to know why the "
        "planned total never appeared")
    assert host.events.get_nowait()[0] == "download_plan"


def test_an_injected_sink_replaces_the_queue_handshake():
    import queue
    from types import SimpleNamespace

    from feathered_app.application.tools import ToolsMixin

    host = SimpleNamespace()
    host.events = queue.Queue()
    recorded = []
    host.__dict__["_download_plan_sink"] = lambda c, b: recorded.append((c, b))
    host._gui_publish_download_plan = lambda *a: pytest.fail(
        "an injected sink must replace the UI handshake entirely")

    ToolsMixin._publish_download_plan(host, 3, 128)

    assert recorded == [(3, 128)]
    assert host.events.empty(), "nothing should reach the UI queue"


def test_a_host_with_no_sink_and_no_ui_continues():
    from types import SimpleNamespace

    from feathered_app.application.tools import ToolsMixin

    ToolsMixin._publish_download_plan(SimpleNamespace(), 1, 1)
