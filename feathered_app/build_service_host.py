"""Type-checked implementation of the non-GUI build feedback contract."""
from __future__ import annotations

import queue
import threading
from typing import Callable, Sequence

from feathered_app.build_host_contracts import BuildEvent, BuildFeedbackHost, CancellationSignal, EventSink
from feathered_app.build_services import BuildServices


class _BuildCancelEvent(threading.Event):
    """Combine caller cancellation with an explicit request_cancel()."""

    def __init__(self, should_cancel: Callable[[], bool]) -> None:
        super().__init__()
        self._should_cancel = should_cancel

    def is_set(self) -> bool:
        return super().is_set() or bool(self._should_cancel())


class BuildServiceHost(BuildFeedbackHost):
    """Actual service implementation inherited by HeadlessHost.

    Inheriting the protocol checks implementation signatures. Instantiation in
    this module also makes an omitted protocol member a type-checking failure.
    """

    def __init__(self, services: BuildServices) -> None:
        self._services = services
        self.cancel_event: CancellationSignal = _BuildCancelEvent(services.should_cancel)
        self.events: EventSink = services.events if services.events is not None else queue.Queue[BuildEvent]()

    def _log(self, message: object) -> None:
        self._services.reporter.log(str(message))

    def _progress(self, label: str, value: float) -> None:
        self._services.reporter.progress(str(label), float(value))

    def _confirm_warnings(self, warnings: Sequence[str]) -> bool:
        findings = list(warnings)
        return True if not findings else bool(self._services.trust_policy(findings))

    def _ask_on_ui_thread(self, title: str, message: str, **kwargs: object) -> bool:
        return bool(self._services.decision_policy(title, message))

    def _confirm_conflicts(self, conflicts: Sequence[str]) -> bool:
        rows = list(conflicts)
        preview = "\n".join(f"  - {row}" for row in rows)
        return self._ask_on_ui_thread(
            "Feathered", f"This closure declares {len(rows)} conflict notice(s):\n"
            f"{preview}\nBuild the bundle anyway?")

    def _publish_download_plan(self, count: int, expected_bytes: int) -> None:
        self._services.download_plan_sink(int(count), int(expected_bytes))

    def _on_item_event(self, identity: str, state: str, info: dict[str, object]) -> None:
        self.events.put(("item", identity, state, info))

    def _on_transfer_event(self, identity: str, transferred: int, total: int) -> None:
        if self._services.events is not None:
            self.events.put(("transfer", identity, transferred, total))

    def request_cancel(self) -> None:
        self.cancel_event.set()


def bind_build_services(services: BuildServices) -> BuildServiceHost:
    """Construct the checked feedback implementation for non-GUI consumers."""
    return BuildServiceHost(services)
