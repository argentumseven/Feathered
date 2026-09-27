"""Tk-independent activity-animation lifecycle for exclusive operations.

Only the UI adapter knows about ``after`` / ``after_cancel``. This controller
owns the animation phase, frame, timer handle and generation; it cannot create
a Tk interpreter or touch widgets. Generation tokens ignore callbacks that
were already queued when an operation paused, finished or was cancelled.
All methods are called on the UI event-loop thread.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class ActivityAnimation:
    """One operation indicator, driven by injected event-loop primitives."""

    schedule: Callable[[int, Callable[[], None]], object] = field(repr=False)
    cancel: Callable[[object], None] = field(repr=False)
    available: Callable[[], bool] = field(repr=False)
    operation_active: Callable[[], bool] = field(repr=False)
    changed: Callable[["ActivityAnimation"], None] = field(repr=False)
    render: Callable[[], None] = field(repr=False)
    phase: str = "idle"
    frame: int = 0
    job: object | None = None
    interval_ms: int = 110
    frame_count: int = 24
    _generation: int = field(default=0, init=False, repr=False)

    def _publish(self) -> None:
        self.changed(self)

    def _schedule_next(self) -> None:
        if self.phase != "active" or self.job is not None or not self.available():
            return
        generation = self._generation
        # Capture this generation, not a mutable reference to its latest value.
        self.job = self.schedule(
            self.interval_ms, lambda: self.tick(generation))
        self._publish()

    def cancel_timer(self) -> None:
        """Disarm even if the event loop has already queued the callback."""
        self._generation += 1
        old_job, self.job = self.job, None
        self._publish()
        if old_job is not None and self.available():
            self.cancel(old_job)

    def start(self) -> bool:
        """Begin an animation, avoiding duplicate timers for an active one."""
        if self.phase == "active" and self.job is not None:
            return False
        self._generation += 1
        self.phase = "active"
        self.frame = 0
        self._publish()
        self._schedule_next()
        return True

    def tick(self, generation: int | None = None) -> bool:
        """Advance only a live generation belonging to an active operation."""
        if generation is not None and generation != self._generation:
            return False
        self.job = None
        self._publish()
        if self.phase != "active" or not self.operation_active():
            return False
        self.frame = (self.frame + 1) % self.frame_count
        self._publish()
        self.render()
        self._schedule_next()
        return True

    def pause(self) -> None:
        self.cancel_timer()
        self.phase = "waiting"
        self._publish()

    def resume(self) -> None:
        if self.phase == "active" and self.job is not None:
            return
        self.phase = "active"
        self._publish()
        self._schedule_next()

    def stop(self, *, state: str = "idle") -> None:
        self.cancel_timer()
        self.phase = state
        self._publish()
