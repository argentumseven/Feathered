"""Typed service boundaries shared by build preparation and execution.

These contracts cover decisions, event delivery and publication capabilities.
They do not claim that package catalogs or the full resolver host are typed.
"""
from __future__ import annotations

from typing import Protocol, Sequence, TypeAlias

BuildEvent: TypeAlias = tuple[object, ...]


class EventSink(Protocol):
    def put(self, event: BuildEvent, /) -> None: ...


class CancellationSignal(Protocol):
    def is_set(self) -> bool: ...
    def set(self) -> None: ...


class PublicationPolicy(Protocol):
    def __call__(self, title: str, message: str, *,
                 choices: Sequence[tuple[str, str]], default: str, kind: str) -> str: ...


class PublicationOptions(Protocol):
    additive_publish: bool
    emit_repository: bool


class BuildFeedbackHost(Protocol):
    events: EventSink
    cancel_event: CancellationSignal

    def _log(self, message: object) -> None: ...
    def _progress(self, label: str, value: float) -> None: ...
    def _confirm_warnings(self, warnings: Sequence[str]) -> bool: ...
    def _confirm_conflicts(self, conflicts: Sequence[str]) -> bool: ...
    def _ask_on_ui_thread(self, title: str, message: str, **kwargs: object) -> bool: ...
    def _publish_download_plan(self, count: int, expected_bytes: int) -> None: ...
    def _on_item_event(self, identity: str, state: str, info: dict[str, object]) -> None: ...
    def request_cancel(self) -> None: ...
