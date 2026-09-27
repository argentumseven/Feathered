"""Tk-independent owner of analysis results and the operator's review choices.

The desktop shell retains its historical field names through ReviewStateMixin,
so other mixins and the build worker can migrate without changing their public
contracts. Widgets, callbacks, and worker lifecycle do not live in this object.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Collection, Iterable


@dataclass
class ReviewState:
    """One review session's mutable data; every collection is instance-local."""

    last_result: Any = None
    last_warnings: list[str] = field(default_factory=list)
    analysis_signature: Any = None
    result_rows: dict[str, str] = field(default_factory=dict)
    result_page: int = 0
    result_page_size: int = 1000
    item_states: dict[str, dict] = field(default_factory=dict)
    picked: set[str] = field(default_factory=set)
    picked_closure: set[str] | None = None
    ignored_unresolved: set[str] = field(default_factory=set)
    unresolved_rows: dict[str, str] = field(default_factory=dict)
    resolution_pass_budget: int = 0

    def accept_result(self, result: Any, *, signature: Any,
                      pick_mode: bool, unresolved_keys: Collection[str]) -> bool:
        """Reconcile a new analysis with existing waivers and package choices.

        An empty selection is intentional and must survive a build that resolves
        the same closure. Waivers survive only for requirements still unresolved.
        Return whether this was the same result object (for pagination/state).
        """
        same_result = result is self.last_result
        self.last_result = result
        self.analysis_signature = signature
        self.ignored_unresolved.intersection_update(unresolved_keys)
        result.ignored_unresolved = sorted(self.ignored_unresolved)
        current = {p.nevra for p in result.selected}
        if pick_mode and self.picked_closure == current and self.picked is not None:
            self.picked.intersection_update(current)
        else:
            self.picked = set(current) if pick_mode else set()
        self.picked_closure = current if pick_mode else None
        if not same_result:
            self.result_page = 0
            self.item_states = {}
        return same_result

    def blocking(self, result: Any, *, requirement_key) -> list[Any]:
        if result is None:
            return []
        return [req for req in result.unresolved
                if requirement_key(req) not in self.ignored_unresolved]

    def waive_rows(self, row_ids: Iterable[str]) -> bool:
        """Waive only issue rows actually rendered in the active result table."""
        keys = {self.unresolved_rows[iid] for iid in row_ids
                if iid in self.unresolved_rows}
        if not keys:
            return False
        self.ignored_unresolved.update(keys)
        self._sync_result_waivers()
        return True

    def restore_waivers(self) -> None:
        self.ignored_unresolved.clear()
        self._sync_result_waivers()

    def _sync_result_waivers(self) -> None:
        if self.last_result is not None:
            self.last_result.ignored_unresolved = sorted(self.ignored_unresolved)

    def bulk_pick(self, action: str, *, available: Collection[str],
                  roots: Collection[str] = (), highlighted: Collection[str] = ()) -> bool:
        """Change the global selection, not merely the visible result page."""
        all_ids = set(available)
        if action == "highlighted" and not highlighted:
            return False
        if action == "all":
            self.picked = set(all_ids)
        elif action == "none":
            self.picked = set()
        elif action == "invert":
            self.picked = all_ids - self.picked
        elif action == "roots":
            self.picked = all_ids.intersection(roots)
        else:
            self.picked = set(highlighted)
        self.picked_closure = all_ids
        return True

    def toggle(self, identity: str) -> bool:
        """Toggle a previously rendered package identity; return new checked state."""
        if identity in self.picked:
            self.picked.remove(identity)
            return False
        self.picked.add(identity)
        return True

    def discard_stale_result(self) -> None:
        """Discard rendered analysis; keep choices until the next analysis reconciles.

        Mirrors the former GUI invalidation contract. In particular, waivers
        cannot accidentally transfer to different requirements because the next
        accept_result intersects them with the new unresolved keys.
        """
        self.last_result = None
        self.analysis_signature = None
        self.last_warnings = []
        self.result_rows = {}
        self.item_states = {}
        self.result_page = 0


_REVIEW_FIELDS = {
    "last_result": "last_result",
    "last_warnings": "last_warnings",
    "analysis_signature": "analysis_signature",
    "result_rows": "result_rows",
    "result_page": "result_page",
    "result_page_size": "result_page_size",
    "_result_item_states": "item_states",
    "picked": "picked",
    "picked_closure": "picked_closure",
    "ignored_unresolved": "ignored_unresolved",
    "unresolved_rows": "unresolved_rows",
    "resolution_pass_budget": "resolution_pass_budget",
}


def _review_state(instance: Any) -> ReviewState:
    values = vars(instance)
    state = values.get("_review_state")
    if state is None:
        state = ReviewState()
        for legacy, field_name in _REVIEW_FIELDS.items():
            if legacy in values:
                setattr(state, field_name, values.pop(legacy))
        values["_review_state"] = state
    return state


class _ReviewField:
    """Descriptor preserving legacy names and direct __dict__ injection."""

    def __init__(self, legacy_name: str, state_field: str):
        self.legacy_name = legacy_name
        self.state_field = state_field

    def __get__(self, instance: Any, owner: type | None = None) -> Any:
        if instance is None:
            return self
        values = vars(instance)
        if self.legacy_name in values:
            state = _review_state(instance)
            # Creating the state already migrates every legacy field. An
            # injected field may also arrive *after* creation; handle both.
            if self.legacy_name in values:
                setattr(state, self.state_field, values.pop(self.legacy_name))
        state = values.get("_review_state")
        if state is None:
            raise AttributeError(self.legacy_name)
        return getattr(state, self.state_field)

    def __set__(self, instance: Any, value: Any) -> None:
        state = _review_state(instance)
        vars(instance).pop(self.legacy_name, None)
        setattr(state, self.state_field, value)

    def __delete__(self, instance: Any) -> None:
        values = vars(instance)
        state = values.get("_review_state")
        if state is None and self.legacy_name not in values:
            raise AttributeError(self.legacy_name)
        state = _review_state(instance)
        values.pop(self.legacy_name, None)
        setattr(state, self.state_field,
                getattr(ReviewState(), self.state_field))


class ReviewStateMixin:
    """Compatibility adapter for the desktop shell's historical review fields."""

    last_result = _ReviewField("last_result", "last_result")
    last_warnings = _ReviewField("last_warnings", "last_warnings")
    analysis_signature = _ReviewField("analysis_signature", "analysis_signature")
    result_rows = _ReviewField("result_rows", "result_rows")
    result_page = _ReviewField("result_page", "result_page")
    result_page_size = _ReviewField("result_page_size", "result_page_size")
    _result_item_states = _ReviewField("_result_item_states", "item_states")
    picked = _ReviewField("picked", "picked")
    picked_closure = _ReviewField("picked_closure", "picked_closure")
    ignored_unresolved = _ReviewField("ignored_unresolved", "ignored_unresolved")
    unresolved_rows = _ReviewField("unresolved_rows", "unresolved_rows")
    resolution_pass_budget = _ReviewField("resolution_pass_budget", "resolution_pass_budget")

    @property
    def review_state(self) -> ReviewState:
        return _review_state(self)
