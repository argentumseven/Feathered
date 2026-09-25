"""Small Tk-free owner for bounded, replaceable background queries.

Build execution keeps its existing operation lease. This coordinator is only for
queries whose obsolete results can safely be ignored by the UI.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from threading import Event, RLock, Thread
from typing import Callable, Generic, Iterator, TypeVar

T = TypeVar('T')


@dataclass(frozen=True)
class JobCompletion(Generic[T]):
    operation: str
    generation: int
    value: T | None = None
    error: str = ''
    cancelled: bool = False

    def __iter__(self) -> Iterator[object]:
        """Keep legacy tuple consumers usable while the GUI checks the envelope."""
        if not isinstance(self.value, tuple):
            raise TypeError('This completion has no legacy tuple payload')
        return iter(self.value)


@dataclass(frozen=True)
class _Job(Generic[T]):
    operation: str
    generation: int
    work: Callable[[Event], T]
    cancel: Event


class BackgroundJobs(Generic[T]):
    """At most two live queries and one pending replacement per named lane.

    Deliver is a thread-safe queue sink, never a Tk callback. Every accepted job
    gets one completion, including jobs replaced before starting. The receiver
    must call accepts() immediately before applying a completion.

    Cancellation is cooperative, so a cancelled worker may keep running (for
    example inside a network timeout) after its result became obsolete. Those
    workers no longer count against ``max_workers``; otherwise two stale queries
    would block every lane until they returned. They are bounded separately by
    ``max_cancelled`` so a stuck worker cannot cause unbounded thread growth.
    """
    def __init__(self, deliver: Callable[[JobCompletion[T]], None], *,
                 max_workers: int = 2, max_operations: int = 8,
                 max_cancelled: int | None = None) -> None:
        if max_workers < 1 or max_operations < 1:
            raise ValueError('Background job limits must be positive')
        if max_cancelled is None:
            max_cancelled = max_workers
        if max_cancelled < 0:
            raise ValueError('Background job limits must not be negative')
        self._deliver = deliver
        self._limit = max_workers
        self._max_cancelled = max_cancelled
        self._max_operations = max_operations
        self._lock = RLock()
        self._generations: dict[str, int] = {}
        self._pending: OrderedDict[str, _Job[T]] = OrderedDict()
        self._active: dict[tuple[str, int], _Job[T]] = {}
        self._closed = False

    def submit(self, operation: str, work: Callable[[Event], T]) -> int:
        with self._lock:
            if self._closed:
                raise RuntimeError('Background queries are closed')
            if operation not in self._generations and len(self._generations) >= self._max_operations:
                raise ValueError('Too many background query operations')
            self.cancel(operation)
            generation = self._generations.get(operation, 0) + 1
            self._generations[operation] = generation
            self._pending[operation] = _Job(operation, generation, work, Event())
            self._start_pending()
            return generation

    def cancel(self, operation: str) -> None:
        with self._lock:
            if operation in self._generations:
                self._generations[operation] += 1
            pending = self._pending.pop(operation, None)
            if pending is not None:
                self._deliver(JobCompletion(operation, pending.generation, cancelled=True))
            for job in self._active.values():
                if job.operation == operation:
                    job.cancel.set()
            if not self._closed:
                self._start_pending()

    def accepts(self, result: JobCompletion[T]) -> bool:
        with self._lock:
            return (not self._closed and not result.cancelled
                    and self._generations.get(result.operation) == result.generation)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            for operation in tuple(self._generations):
                self.cancel(operation)

    def _has_capacity(self) -> bool:
        live = sum(1 for job in self._active.values() if not job.cancel.is_set())
        return (live < self._limit
                and len(self._active) < self._limit + self._max_cancelled)

    def _start_pending(self) -> None:
        while self._pending and self._has_capacity():
            _, job = self._pending.popitem(last=False)
            key = (job.operation, job.generation)
            self._active[key] = job
            try:
                Thread(target=self._run, args=(job,), daemon=True).start()
            except Exception as exc:
                del self._active[key]
                self._deliver(JobCompletion(job.operation, job.generation,
                                            error=f'{type(exc).__name__}: {exc}'))

    def _run(self, job: _Job[T]) -> None:
        value: T | None = None
        error = ''
        try:
            if not job.cancel.is_set():
                value = job.work(job.cancel)
        except BaseException as exc:
            # Worker exits must release capacity as well as normal failures.
            error = f'{type(exc).__name__}: {exc}'
        finally:
            with self._lock:
                del self._active[(job.operation, job.generation)]
                self._deliver(JobCompletion(job.operation, job.generation, value,
                                            error, job.cancel.is_set()))
                self._start_pending()
