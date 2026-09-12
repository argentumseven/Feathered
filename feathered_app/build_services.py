"""Explicit reporting, decision and cancellation services for spec-driven builds.

GUI preparation uses the same rules with dialog adapters. The frozen dataclass
prevents service reassignment; supplied callbacks can hold mutable caller state.
Conflict, package-only and publication decisions are separate capabilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol, Sequence

from feathered_app.build_host_contracts import EventSink, PublicationPolicy


class Reporter(Protocol):
    """The subset of the reporter a build run actually uses."""

    def log(self, message: str) -> None: ...

    def warn(self, message: str) -> None: ...

    def progress(self, label: str, value: float) -> None: ...


def _decline(_title: str, _message: str) -> bool:
    """Default answer to any question nobody is present to answer.

    Declining rather than accepting, for the same reason the CLI declines: a
    caller that supplied no policy has, by definition, not reviewed the
    question.
    """
    return False


def _decline_findings(_findings: Sequence[str]) -> bool:
    return False


def _ignore_plan(_count: int, _expected_bytes: int) -> None:
    """Record nothing. A run with no UI has nowhere to show the plan."""


def _decline_publication(title: str, message: str, *,
                         choices: Sequence[tuple[str, str]], default: str, kind: str) -> str:
    return "cancel"


@dataclass(frozen=True)
class BuildServices:
    """Everything a build run needs that is not the request itself.

    Frozen for the same reason ``BuildSpec`` is: a run must not acquire new
    capabilities, or lose them, while it is in progress.
    """

    #  Progress and diagnostics. Required: a build with nowhere to report is
    #  not a build anyone can support afterwards.
    reporter: Reporter

    #  Mid-build decisions. Each defaults to declining, so a caller that forgets
    #  one gets a refused build rather than an unreviewed acceptance.
    trust_policy: Callable[[Sequence[str]], bool] = _decline_findings
    decision_policy: Callable[[str, str], bool] = _decline

    #  Where the planned transfer total goes. The GUI hands it to the event
    #  queue and waits; a headless run records it and continues.
    download_plan_sink: Callable[[int, int], None] = _ignore_plan

    #  Cooperative cancellation. Returning True asks the run to stop at its next
    #  checkpoint. Polled rather than raised so a partially written bundle is
    #  never left behind by an exception from another thread.
    should_cancel: Callable[[], bool] = lambda: False

    #  Optional sink for structured progress events. The GUI supplies its queue;
    #  a headless run supplies nothing and the run must not block on it.
    events: Optional[EventSink] = None

    package_only_policy: Callable[[str, str], bool] = _decline

    publication_policy: PublicationPolicy = _decline_publication

    #  Names of services the caller explicitly declined to supply, recorded so a
    #  run can say what it will refuse before it starts rather than when it
    #  reaches the question.
    unsupplied: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_host(cls, host, reporter: Reporter) -> "BuildServices":
        """Gather the seams an ``App`` (or any host) has installed.

        Reads only ``__dict__``, so a partially constructed host or a plain
        object works. Anything absent falls back to the declining default and is
        listed in ``unsupplied``.
        """
        supplied = {}
        missing = []
        for field_name, key in (("trust_policy", "_trust_policy"),
                                ("decision_policy", "_decision_policy"),
                                ("download_plan_sink", "_download_plan_sink")):
            value = host.__dict__.get(key)
            if callable(value):
                supplied[field_name] = value
            else:
                missing.append(key)
        events = host.__dict__.get("events")
        cancel = host.__dict__.get("cancel_event")
        should_cancel = cancel.is_set if cancel is not None else lambda: False
        return cls(reporter=reporter, events=events, should_cancel=should_cancel,
                   unsupplied=tuple(missing), **supplied)

    def describe(self) -> str:
        """One line a run can log before it starts."""
        if not self.unsupplied:
            return "Build services: all decision points supplied by the caller."
        return ("Build services: no caller policy for "
                + ", ".join(self.unsupplied)
                + " - those decisions will be declined.")
