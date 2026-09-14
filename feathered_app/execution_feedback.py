"""Checked feedback capabilities consumed by the shared build runner."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal, Protocol, Sequence

from core import Reporter
from feathered_app.build_host_contracts import BuildFeedbackHost, EventSink
from feathered_app.build_outcome import BuildOutcome, BuildStatus


class Decision(Protocol):
    def __call__(self, title: str, message: str, **kwargs: object) -> bool: ...


@dataclass(frozen=True)
class ExecutionFeedback:
    """Bind callbacks once; mutable progress belongs to this run's reporter."""
    reporter: Reporter
    events: EventSink
    decide: Decision
    confirm_conflicts: Callable[[Sequence[str]], bool]
    confirm_warnings: Callable[[Sequence[str]], bool]
    publish_download_plan: Callable[[int, int], None]


def bind_execution_feedback(host: BuildFeedbackHost) -> ExecutionFeedback:
    return ExecutionFeedback(
        Reporter(host._log, host._progress, host.cancel_event, item=host._on_item_event,
                 transfer=host._on_transfer_event),
        host.events, host._ask_on_ui_thread, host._confirm_conflicts,
        host._confirm_warnings, host._publish_download_plan)


def mirror_reporter(host: BuildFeedbackHost, parent: Reporter, source_id: str,
                    base: float, span: float) -> Reporter:
    """Keep mirror progress and item identity ordered within the parent run."""
    def item(identity: str, state: str, info: dict[str, object]) -> None:
        host._on_item_event(f'{source_id}|{identity}', state, info)

    reporter = Reporter(
        host._log,
        lambda label, value: host._progress(label, base + max(0.0, min(1.0, value)) * span),
        host.cancel_event, item=item,
        transfer=lambda identity, transferred, total:
        parent.transfer(f'{source_id}|{identity}', transferred, total))
    reporter.warnings = parent.warnings
    return reporter


def complete(events: EventSink, ok: bool | Literal['cancelled'], message: str,
             output_path: str | None = None) -> BuildOutcome:
    """Preserve the legacy terminal tuple and return the corresponding outcome."""
    status = BuildStatus.SUCCESS if ok is True else (
        BuildStatus.CANCELLED if ok == 'cancelled' else BuildStatus.FAILED)
    event = ('done', ok, message) + ((output_path,) if output_path is not None else ())
    events.put(event)
    return BuildOutcome(status, message, output_path)
