"""Execution reporting, progress mapping, warning capture, and cancellation.

This boundary is UI-agnostic: callers provide callbacks and an optional
cancellation probe. Credential redaction is enforced at the reporting sink.
"""
from __future__ import annotations

from typing import Callable, List, Optional, Protocol

from credential_redaction import redact_text


class Cancelled(RuntimeError):
    pass
class CancellationProbe(Protocol):
    """Cancellation needs a query, not a particular threading implementation."""

    def is_set(self) -> bool: ...
class Reporter:
    def __init__(self, log: Optional[Callable[[str], None]] = None,
                 progress: Optional[Callable[[str, float], None]] = None,
                 cancel_event: Optional[CancellationProbe] = None,
                 item: Optional[Callable[[str, str, dict], None]] = None,
                 transfer: Optional[Callable[[str, int, int], None]] = None):
        self._log = log or (lambda msg: None)
        self._progress = progress or (lambda label, value: None)
        self._item = item or (lambda identity, state, info: None)
        self._transfer = transfer or (lambda identity, transferred, total: None)
        self.cancel_event = cancel_event
        # Phase window: progress values are scaled into [start, start+span).
        self._phase_start = 0.0
        self._phase_span = 1.0
        # Warnings are both logged and retained so the GUI can show a count and
        # the bundle manifest can record what was not verified.
        self.warnings: List[str] = []

    def log(self, msg: str) -> None:
        # Redacting at the sink means a future call site cannot reintroduce a
        # credential leak by forgetting to redact its own message.
        self._log(redact_text(msg))

    def warn(self, msg: str) -> None:
        """Record a condition the operator must see before trusting a bundle."""
        text = redact_text(str(msg))
        if text not in self.warnings:
            self.warnings.append(text)
        self._log("WARNING: " + text)

    def item(self, identity: str, state: str, **info) -> None:
        """Report the state of one artifact: pending, active, done, reused, failed."""
        self._item(identity, state, info)

    def transfer(self, identity: str, transferred: int, total: int = 0) -> None:
        """Report current byte transfer for one artifact."""
        self._transfer(identity, max(0, int(transferred)), max(0, int(total)))

    def phase(self, start: float, span: float) -> None:
        """Map subsequent progress reports onto a slice of the overall bar.

        A build has two byte-heavy phases -- transferring packages, then
        sealing. Reporting each as its own 0..1 made the bar complete and then
        restart, which on a multi-terabyte mirror looks like the build began
        again. Each phase now advances its own portion of one monotonic bar.
        """
        self._phase_start = max(0.0, min(1.0, start))
        self._phase_span = max(0.0, min(1.0 - self._phase_start, span))

    def progress(self, label: str, value: float) -> None:
        local = max(0.0, min(1.0, value))
        self._progress(label, self._phase_start + local * self._phase_span)

    def check_cancel(self) -> None:
        if self.cancel_event and self.cancel_event.is_set():
            raise Cancelled("Operation cancelled")

__all__ = ["Cancelled", "CancellationProbe", "Reporter"]
