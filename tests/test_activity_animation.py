"""Headless animation and legacy-GUI adapter regression tests."""
from __future__ import annotations

from feathered_app.activity_animation import ActivityAnimation


class FakeScheduler:
    def __init__(self):
        self.next_id = 0
        self.callbacks = {}
        self.delays = []
        self.cancelled = []

    def after(self, delay, callback):
        self.next_id += 1
        self.delays.append(delay)
        self.callbacks[self.next_id] = callback
        return self.next_id

    def cancel(self, handle):
        self.cancelled.append(handle)
        self.callbacks.pop(handle, None)


def controller(*, available=True):
    scheduler = FakeScheduler()
    present = []
    snapshots = []
    flags = {"available": available, "active": True}
    animation = ActivityAnimation(
        schedule=scheduler.after,
        cancel=scheduler.cancel,
        available=lambda: flags["available"],
        operation_active=lambda: flags["active"],
        changed=lambda state: snapshots.append((state.phase, state.frame, state.job)),
        render=lambda: present.append("render"),
    )
    return animation, scheduler, flags, present, snapshots


def test_animation_has_one_timer_and_wraps_frames():
    animation, scheduler, _, present, _ = controller()
    assert animation.start()
    assert not animation.start(), "a second start must not restart or duplicate a live timer"
    assert animation.frame == 0
    assert scheduler.delays == [110]
    for _ in range(26):
        assert len(scheduler.callbacks) == 1
        _, callback = scheduler.callbacks.popitem()
        callback()
    assert animation.frame == 2  # 24-frame cycle
    assert len(present) == 26
    assert all(delay == 110 for delay in scheduler.delays)
    assert len(scheduler.callbacks) == 1


def test_pause_resume_invalidates_a_callback_already_queued():
    animation, scheduler, _, present, snapshots = controller()
    animation.start()
    first_id, queued_callback = next(iter(scheduler.callbacks.items()))
    animation.pause()
    assert scheduler.cancelled == [first_id]
    assert animation.phase == "waiting" and animation.job is None
    animation.resume()
    assert animation.phase == "active"
    next_job = animation.job
    queued_callback()  # Simulates a callback queued before after_cancel.
    assert animation.job == next_job
    assert animation.frame == 0
    assert present == []
    assert snapshots[-1] == ("active", 0, next_job)
    scheduler.callbacks.pop(next_job)()
    assert animation.frame == 1
    assert len(present) == 1


def test_finish_invalidates_old_timer_across_a_new_operation():
    animation, scheduler, _, present, _ = controller()
    animation.start()
    old = next(iter(scheduler.callbacks.values()))
    animation.stop(state="failed")
    assert animation.phase == "failed"
    assert animation.job is None
    animation.start()
    new_job = animation.job
    old()
    assert animation.frame == 0 and animation.job == new_job
    assert not present
    animation.stop()
    assert animation.phase == "idle"
    assert not scheduler.callbacks


def test_without_a_gui_active_operation_still_advances_on_manual_ticks():
    animation, scheduler, flags, present, _ = controller(available=False)
    assert animation.start()
    assert animation.phase == "active" and animation.job is None
    assert not scheduler.delays
    assert animation.tick()
    assert animation.frame == 1
    flags["active"] = False
    assert not animation.tick()
    assert animation.job is None
    assert animation.frame == 1
    animation.pause()
    assert animation.phase == "waiting"
    assert not animation.tick()
    animation.resume()
    assert animation.phase == "active"
    assert animation.job is None
    assert present == ["render"]


def test_destroyed_scheduler_can_still_disarm_generation():
    animation, scheduler, flags, _, _ = controller()
    animation.start()
    already_queued = next(iter(scheduler.callbacks.values()))
    flags["available"] = False  # Tk interpreter already closed.
    animation.stop()
    assert animation.job is None
    already_queued()
    assert animation.phase == "idle" and animation.frame == 0


def test_partial_app_adapts_headless_controller_and_preserves_legacy_fields():
    from app import App

    class Var:
        def __init__(self):
            self.value = None

        def set(self, value):
            self.value = value

    class Indicator:
        def __init__(self):
            self.frames = []

        def render_frame(self, frame, *, active=True, state=None):
            self.frames.append((frame, active, state))

    app = object.__new__(App)  # No Tk root required for state-machine tests.
    app.active_operation = "build"
    app.active_operation_label = "Building"
    app.status_var = Var()
    app.activity_indicator = Indicator()
    app._start_activity_animation()
    assert app._activity_state == "active"
    assert app._activity_frame == 0
    assert app._activity_job is None
    assert app.status_var.value == "Working  |  Building"
    app._activity_tick()
    assert app._activity_frame == 1
    app._set_operator_wait("Approve source")
    assert app._activity_state == "waiting"
    assert app.status_var.value == "Review required  |  Approve source"
    app._resume_after_operator_wait()
    assert app._activity_state == "active"
    app._stop_activity_animation(state="failed")
    assert app._activity_state == "failed"
    assert app.activity_indicator.frames[-1] == (0, False, "failed")


def test_app_schedules_only_one_timer_and_ignores_stale_gui_callback():
    from app import App

    scheduler = FakeScheduler()
    app = object.__new__(App)
    app.__dict__["tk"] = object()  # A fake live event-loop marker, not a Tcl interpreter.
    app.after = scheduler.after
    app.after_cancel = scheduler.cancel
    app.active_operation = "build"
    app.active_operation_label = "Building"
    app._start_activity_animation()
    first_id, old_callback = next(iter(scheduler.callbacks.items()))
    app._start_activity_animation()
    assert len(scheduler.callbacks) == 1
    assert app._activity_job == first_id
    app._set_operator_wait("Approve source")
    assert app._activity_job is None
    app._resume_after_operator_wait()
    second_id = app._activity_job
    assert second_id != first_id
    old_callback()
    assert app._activity_job == second_id and app._activity_frame == 0
    scheduler.callbacks.pop(second_id)()
    assert app._activity_frame == 1
    app._stop_activity_animation()
    assert app._activity_job is None
    assert not scheduler.callbacks


def test_timer_scheduling_handles_a_destroyed_tk_interpreter():
    import tkinter as tk
    from app import App

    app = object.__new__(App)
    app.__dict__["tk"] = object()
    app.active_operation = "build"
    app.active_operation_label = "Building"

    def expired_after(_delay, _callback):
        raise tk.TclError("application has been destroyed")

    app.after = expired_after
    app._start_activity_animation()
    assert app._activity_state == "active"
    assert app._activity_job is None
    app._stop_activity_animation()
    assert app._activity_state == "idle"


def test_real_root_destruction_cancels_activity_timer(tmp_path, monkeypatch):
    import os
    import sys
    import pytest

    if (not sys.platform.startswith("win") and sys.platform != "darwin"
            and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))):
        pytest.skip("requires a display or xvfb-run")
    for key in ("HOME", "APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(key, str(tmp_path))
    from app import App

    app = App()
    try:
        assert app._claim_operation("test", "Testing timer", cancellable=True)
        assert app._activity_job is not None
    finally:
        app.destroy()
    assert app._activity_job is None
    assert app._activity_animation.job is None
