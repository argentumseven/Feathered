"""Mode-scoped storage for the two repository universes.

Feathered keeps two genuinely separate repository collections: the transaction
universe used by workload and exact-package acquisition, and the mirror universe
used by ``Entire repository (mirror)``. The documented guarantee is that neither
can contaminate the other -- ticking repositories for a mirror run must not
rewrite the source plan a later workload build resolves against.

Before 1.2.6 that guarantee was maintained by hand. ``repo_rows``,
``transaction_repo_rows`` and ``mirror_repo_rows`` were three plain attributes
aliasing one list, and correctness depended on every site that *rebound*
``repo_rows`` also rebinding the matching mode slot::

    self.repo_rows = list(rows)
    self.mirror_repo_rows = self.repo_rows   # easy to forget, silent if missed

In-place mutation was safe because the lists were the same object, so a missed
re-synchronisation produced no error and no failing test -- it produced a mirror
selection that quietly reappeared in a workload build, or a source-plan edit
that vanished when the operator switched intent. Every one of those sites lives
in the wizard modules, which carry 3-9% automated coverage.

This module removes the invariant instead of documenting it. There is one
storage object holding one list per mode. ``repo_rows`` reads and writes
whichever list the active mode owns, so rebinding it cannot desynchronise
anything, and switching mode is a single assignment with no copying at all.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Dict, Iterable, List, Optional

TRANSACTION = "transaction"
MIRROR = "mirror"
MODES = (TRANSACTION, MIRROR)


class RepositoryUniverse:
    """Two isolated repository collections and which one is currently active."""

    __slots__ = ("_rows", "_mode")

    def __init__(self, mode: str = TRANSACTION):
        self._rows: Dict[str, List] = {TRANSACTION: [], MIRROR: []}
        self._mode = self._checked(mode)

    @staticmethod
    def _checked(mode: str) -> str:
        text = str(mode or "").strip().lower()
        if text not in MODES:
            raise ValueError(
                f"Unknown repository universe mode {mode!r}; expected one of {MODES}.")
        return text

    @property
    def mode(self) -> str:
        return self._mode

    def activate(self, mode: str) -> bool:
        """Make ``mode`` active. Returns True only if the mode actually changed.

        Callers that must invalidate analysis state on a universe switch use the
        return value; the switch itself moves no packages and copies no lists.
        """
        target = self._checked(mode)
        if target == self._mode:
            return False
        self._mode = target
        return True

    def rows(self, mode: Optional[str] = None) -> List:
        """The live list for ``mode`` (default: the active mode).

        This is the stored list, not a copy, so in-place mutation by existing
        callers keeps working exactly as it did.
        """
        return self._rows[self._mode if mode is None else self._checked(mode)]

    def set_rows(self, rows: Iterable, mode: Optional[str] = None) -> List:
        """Replace the list for ``mode``, always storing a real ``list``."""
        key = self._mode if mode is None else self._checked(mode)
        current = self._rows[key]
        if rows is current:
            return current
        self._rows[key] = list(rows)
        return self._rows[key]

    def clear(self, mode: Optional[str] = None) -> None:
        self.set_rows([], mode)

    def __repr__(self) -> str:  # pragma: no cover - diagnostic only
        return (f"RepositoryUniverse(mode={self._mode!r}, "
                f"transaction={len(self._rows[TRANSACTION])}, "
                f"mirror={len(self._rows[MIRROR])})")


class _UniverseRows:
    """Expose one universe list as an ordinary-looking instance attribute.

    A data descriptor rather than a plain attribute, because the whole point is
    that assignment must land in the mode-scoped slot. ``__delete__`` and the
    unset-attribute behaviour are implemented so that partially constructed
    instances -- ``object.__new__(App)`` in the headless contract tests -- still
    raise ``AttributeError`` rather than falling through to ``tkinter.Misc``.
    """

    __slots__ = ("_mode", "_name")

    def __init__(self, mode: Optional[str], name: str):
        self._mode = mode
        self._name = name

    def __set_name__(self, owner, name):
        self._name = name

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        universe = instance.__dict__.get("_repository_universe")
        if universe is None:
            raise AttributeError(self._name)
        return universe.rows(self._mode)

    def __set__(self, instance, value):
        universe = instance.__dict__.get("_repository_universe")
        if universe is None:
            universe = RepositoryUniverse()
            instance.__dict__["_repository_universe"] = universe
        universe.set_rows(value, self._mode)

    def __delete__(self, instance):
        universe = instance.__dict__.get("_repository_universe")
        if universe is None:
            raise AttributeError(self._name)
        universe.clear(self._mode)


class _UniverseMode:
    """``_repository_universe_mode`` as a view over the universe's active mode."""

    __slots__ = ()

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        universe = instance.__dict__.get("_repository_universe")
        return TRANSACTION if universe is None else universe.mode

    def __set__(self, instance, value):
        universe = instance.__dict__.get("_repository_universe")
        if universe is None:
            universe = RepositoryUniverse()
            instance.__dict__["_repository_universe"] = universe
        universe.activate(value)


class RepositoryUniverseMixin:
    """Gives ``App`` mode-scoped ``repo_rows`` with no synchronisation duty."""

    repo_rows = _UniverseRows(None, "repo_rows")
    transaction_repo_rows = _UniverseRows(TRANSACTION, "transaction_repo_rows")
    mirror_repo_rows = _UniverseRows(MIRROR, "mirror_repo_rows")
    _repository_universe_mode = _UniverseMode()

    @property
    def repository_universe(self) -> RepositoryUniverse:
        """The backing store, created on first use.

        Kept in ``__dict__`` so it remains ordinary, inspectable instance state
        that an embedder or a test can replace wholesale.
        """
        universe = self.__dict__.get("_repository_universe")
        if universe is None:
            universe = RepositoryUniverse()
            self.__dict__["_repository_universe"] = universe
        return universe

    def repository_rows(self, mode: Optional[str] = None, default=()):
        """Read a universe list without constructing one.

        Several callers run against partially constructed instances -- headless
        contract tests, and provenance helpers reached before Repositories has
        ever been rendered. They previously reached into ``__dict__`` directly
        to get a non-raising read; that would now bypass the descriptor and see
        the wrong universe, so the non-raising read is offered here instead.
        """
        universe = self.__dict__.get("_repository_universe")
        if universe is None:
            return default
        return universe.rows(mode)

    def activate_repository_universe(self, mode: str) -> bool:
        """Switch active universe; True when the mode actually changed."""
        return self.repository_universe.activate(mode)

    @contextmanager
    def transaction_universe(self):
        """Run a block against the transaction universe, then restore the mode.

        Several target/release helpers rebuild the transaction source plan even
        while mirror intent is active. They must not touch the mirror universe.
        Previously that meant saving and restoring three attributes by hand in a
        try/finally; now it is a mode flip with no list movement, so an early
        return or an exception cannot leave the universes crossed.
        """
        universe = self.repository_universe
        previous = universe.mode
        universe.activate(TRANSACTION)
        try:
            yield universe
        finally:
            universe.activate(previous)
