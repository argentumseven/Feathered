"""Headless accounting for one bundle's package-payload transfer.

The event-loop thread owns this state. Build workers publish progress and item
status through the existing queue, not by mutating the state directly. The GUI
renders the resulting figures; this module does not import Tk or App.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
import time


@dataclass(frozen=True)
class TransferSnapshot:
    """Derived transfer figures for the GUI and other observers."""

    completed: int
    total: int
    transferred: int
    expected: int
    bytes_per_second: float
    eta_seconds: int | None
    progress_percent: float | None
    reused: int
    failed: int


@dataclass
class TransferProgressState:
    """One transfer's mutable accounting, independent of review table pages."""

    total: int = 0
    done: int = 0
    failed: int = 0
    reused: int = 0
    transferred: int = 0
    expected_bytes: int = 0
    started: float = 0.0
    progress_span: float = 1.0
    item_bytes: dict[str, int] = field(default_factory=dict)
    item_sizes: dict[str, int] = field(default_factory=dict)
    terminal_items: set[str] = field(default_factory=set)

    def begin(self, total: int, expected_bytes: int, *, progress_span: float = 1.0,
              started: float | None = None) -> None:
        """Atomically discard the previous transfer's counters and row progress."""
        self.total = max(0, int(total))
        self.expected_bytes = max(0, int(expected_bytes))
        self.done = self.failed = self.reused = self.transferred = 0
        self.progress_span = float(progress_span)
        self.started = time.monotonic() if started is None else float(started)
        self.item_bytes.clear()
        self.item_sizes.clear()
        self.terminal_items.clear()

    def record_item(self, identity: str, status: str, size: int = 0) -> bool:
        """Account for a package's terminal event exactly once.

        Return False for stale events arriving after terminal completion so
        callers also avoid repainting a completed row as active or failed.
        """
        if identity in self.terminal_items:
            return False
        announced = max(0, int(size or 0))
        if announced:
            self.item_sizes[identity] = announced
        if status in ("done", "reused"):
            # Some loaders omit size in their terminal notification, despite
            # having supplied it earlier through byte progress.
            credited = announced or self.item_sizes.get(identity, 0) or self.item_bytes.get(identity, 0)
            self.item_bytes[identity] = credited
            self.done += 1
            if status == "reused":
                self.reused += 1
            self.terminal_items.add(identity)
        elif status == "failed":
            self.item_bytes[identity] = 0
            self.failed += 1
            self.terminal_items.add(identity)
        self._update_total_bytes()
        return True

    def record_bytes(self, identity: str, transferred: int, expected: int) -> tuple[int, int, bool]:
        """Advance bytes monotonically, ignoring progress after terminal status."""
        if identity in self.terminal_items:
            return (self.item_bytes.get(identity, 0), self.item_sizes.get(identity, 0), False)
        current = max(0, int(transferred or 0))
        size = max(0, int(expected or 0))
        if size:
            self.item_sizes[identity] = size
        current = max(current, self.item_bytes.get(identity, 0))
        self.item_bytes[identity] = current
        self._update_total_bytes()
        return current, self.item_sizes.get(identity, 0), True

    def _update_total_bytes(self) -> None:
        self.transferred = sum(max(0, int(value or 0)) for value in self.item_bytes.values())

    @property
    def completed(self) -> int:
        return self.done + self.failed

    @property
    def payload_active(self) -> bool:
        return self.total > 0 and self.completed < self.total

    def snapshot(self, *, now: float | None = None) -> TransferSnapshot:
        elapsed = max(0.001, (time.monotonic() if now is None else now) - self.started)
        rate = self.transferred / elapsed
        remaining = max(0, self.expected_bytes - self.transferred)
        eta = (int(remaining / rate)
               if self.expected_bytes and rate > 1024 and self.payload_active else None)
        progress = (min(1.0, self.transferred / self.expected_bytes) *
                    self.progress_span * 100 if self.expected_bytes else None)
        return TransferSnapshot(
            self.completed, self.total, self.transferred, self.expected_bytes,
            rate, eta, progress, self.reused, self.failed)

    def status_parts(self, human_size: Callable[[float], str], *, mirror: bool = False,
                     now: float | None = None) -> list[str]:
        """Produce status facts, leaving footer styling and widgets to the UI."""
        snapshot = self.snapshot(now=now)
        unit = "package records" if mirror else "packages"
        volume = (f"{human_size(snapshot.transferred)} / {human_size(snapshot.expected)}"
                  if snapshot.expected else human_size(snapshot.transferred))
        parts = [f"{snapshot.completed}/{snapshot.total} {unit}", volume]
        if snapshot.bytes_per_second > 1024:
            parts.append(f"{human_size(snapshot.bytes_per_second)}/s")
        if snapshot.eta_seconds is not None:
            eta = snapshot.eta_seconds
            parts.append(f"~{eta // 60}m {eta % 60:02d}s left" if eta >= 60 else f"~{eta}s left")
        if snapshot.reused:
            parts.append(f"{snapshot.reused} already present")
        if snapshot.failed:
            parts.append(f"{snapshot.failed} failed")
        return parts


# Existing App, plugin and test callers can use their historical field names.
# Only the desktop composition/mixin is descriptor-backed. Bare SimpleNamespace
# test hosts passed to unbound GUI methods receive mirrored plain attributes.
_LEGACY = {
    "transfer_total": "total",
    "transfer_done": "done",
    "transfer_failed": "failed",
    "transfer_reused": "reused",
    "transfer_bytes": "transferred",
    "transfer_expected_bytes": "expected_bytes",
    "transfer_started": "started",
    "_transfer_progress_span": "progress_span",
    "_transfer_item_bytes": "item_bytes",
    "_transfer_item_sizes": "item_sizes",
    "_transfer_terminal_items": "terminal_items",
}


def transfer_state_for(host: Any) -> TransferProgressState:
    values = vars(host)
    state = values.get("_transfer_progress_state")
    if state is None:
        state = TransferProgressState()
        for legacy, field_name in _LEGACY.items():
            if legacy in values:
                setattr(state, field_name, values[legacy])
                if isinstance(host, TransferStateMixin):
                    values.pop(legacy)
        values["_transfer_progress_state"] = state
    return state


def sync_legacy_transfer_host(host: Any, state: TransferProgressState) -> None:
    """Only for lightweight objects invoking an unbound ToolsMixin method."""
    if not isinstance(host, TransferStateMixin):
        for legacy, field_name in _LEGACY.items():
            setattr(host, legacy, getattr(state, field_name))


class _TransferField:
    def __init__(self, name: str, field_name: str):
        self.name = name
        self.field_name = field_name

    def __get__(self, instance: Any, owner: type | None = None) -> Any:
        if instance is None:
            return self
        state = transfer_state_for(instance)
        values = vars(instance)
        if self.name in values:  # absorb late direct __dict__ injection
            setattr(state, self.field_name, values.pop(self.name))
        return getattr(state, self.field_name)

    def __set__(self, instance: Any, value: Any) -> None:
        state = transfer_state_for(instance)
        vars(instance).pop(self.name, None)
        setattr(state, self.field_name, value)

    def __delete__(self, instance: Any) -> None:
        state = transfer_state_for(instance)
        vars(instance).pop(self.name, None)
        default = getattr(TransferProgressState(), self.field_name)
        setattr(state, self.field_name, default)


class TransferStateMixin:
    """Adapter between legacy desktop attributes and the owned transfer state."""

    transfer_total = _TransferField("transfer_total", "total")
    transfer_done = _TransferField("transfer_done", "done")
    transfer_failed = _TransferField("transfer_failed", "failed")
    transfer_reused = _TransferField("transfer_reused", "reused")
    transfer_bytes = _TransferField("transfer_bytes", "transferred")
    transfer_expected_bytes = _TransferField("transfer_expected_bytes", "expected_bytes")
    transfer_started = _TransferField("transfer_started", "started")
    _transfer_progress_span = _TransferField("_transfer_progress_span", "progress_span")
    _transfer_item_bytes = _TransferField("_transfer_item_bytes", "item_bytes")
    _transfer_item_sizes = _TransferField("_transfer_item_sizes", "item_sizes")
    _transfer_terminal_items = _TransferField("_transfer_terminal_items", "terminal_items")

    @property
    def transfer_progress(self) -> TransferProgressState:
        return transfer_state_for(self)
