"""GUI-independent state for exact-package and mirror source selection.

The repository *collections* are owned by RepositoryUniverse. This object owns
only the operator's choices and the visible mirror row-to-source mapping; it
never changes a repository's normal transaction-mode enabled flag. Legacy App
attributes remain as descriptors while callers transition to this explicit API.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Collection, Iterable

from feathered_app.repository_selection import MirrorSelectionService, MirrorSelectionSnapshot


@dataclass
class SourceSelectionState:
    """Mutable workflow state with no App, Tk or repository-list reference."""

    selected_packages: list[Any] = field(default_factory=list)
    mirror_repos: set[str] = field(default_factory=set)
    mirror_seen: set[str] = field(default_factory=set)
    mirror_iid_to_source_identity: dict[str, str] = field(default_factory=dict)
    mirror_iid_to_repo_index: dict[str, int] = field(default_factory=dict)

    def replace_packages(self, packages: Iterable[Any]) -> None:
        self.selected_packages = list(packages)

    def reset_mirror_for_target(self) -> None:
        """A target switch must not carry mirror choices from the old target."""
        self.mirror_repos.clear()
        self.mirror_seen.clear()
        self.mirror_iid_to_source_identity.clear()
        self.mirror_iid_to_repo_index.clear()

    def seed_mirror(self, repositories: Iterable[Any]) -> None:
        """Apply a new mirror preset without modifying repository enabled flags."""
        self.mirror_repos = {
            repo.source_identity for repo in repositories
            if repo.enabled and str(repo.url or "").strip()
        }
        self.mirror_seen.clear()
        self.mirror_iid_to_source_identity.clear()
        self.mirror_iid_to_repo_index.clear()

    def commit_mirror_refresh(self, snapshot: MirrorSelectionSnapshot,
                              row_ids: Collection[str]) -> None:
        """Atomically publish identities and choices after the UI renders rows.

        A malformed renderer must not leave selection mapped to the wrong row.
        Construct new dictionaries and validate them before changing live state.
        """
        rows = tuple(row_ids)
        if len(rows) != len(snapshot.candidates) or len(set(rows)) != len(rows):
            raise ValueError("Mirror row IDs must uniquely match visible candidates")
        by_identity = {iid: item.source_id
                       for iid, item in zip(rows, snapshot.candidates)}
        by_index = {iid: item.index
                    for iid, item in zip(rows, snapshot.candidates)}
        self.mirror_iid_to_source_identity = by_identity
        self.mirror_iid_to_repo_index = by_index
        self.mirror_repos = set(snapshot.selected)
        self.mirror_seen = set(snapshot.seen)

    def source_for_row(self, row_id: str) -> str:
        return self.mirror_iid_to_source_identity.get(row_id, row_id)

    def index_for_row(self, row_id: str) -> int | None:
        return self.mirror_iid_to_repo_index.get(row_id)

    def toggle_mirror_row(self, row_id: str) -> None:
        MirrorSelectionService.toggle(self.mirror_repos, self.source_for_row(row_id))

    def bulk_mirror_rows(self, row_ids: Iterable[str], action: str) -> None:
        visible = {self.source_for_row(row_id) for row_id in row_ids}
        self.mirror_repos = MirrorSelectionService.bulk(self.mirror_repos, visible, action)

    def remove_mirror_source(self, source_identity: str, *, still_configured: bool) -> None:
        if not still_configured:
            self.mirror_repos.discard(source_identity)
            self.mirror_seen.discard(source_identity)


# These are the only legacy attributes redirected to SourceSelectionState.
# Reading a raw __dict__ on a partially constructed/test host still works via
# selection_value(). App's descriptor also migrates a raw legacy write lazily.
_SELECTION_FIELDS = {
    "selected_packages": "selected_packages",
    "mirror_repos": "mirror_repos",
    "_mirror_seen": "mirror_seen",
    "_mirror_iid_to_source_identity": "mirror_iid_to_source_identity",
    "_mirror_iid_to_repo_index": "mirror_iid_to_repo_index",
}


def selection_value(host: Any, legacy_name: str, default: Any = None) -> Any:
    """Read state on a real App or an uninitialized/legacy headless host."""
    values = vars(host)
    if legacy_name in values:
        state = values.get("_source_selection_state")
        if state is not None:
            # Direct legacy writes are migrated rather than creating a second
            # source of truth for readers that bypass the App descriptors.
            value = values.pop(legacy_name)
            setattr(state, _SELECTION_FIELDS[legacy_name], value)
            return value
        return values[legacy_name]
    state = values.get("_source_selection_state")
    if state is None:
        return default
    return getattr(state, _SELECTION_FIELDS[legacy_name], default)


class _SelectionField:
    """Retain App's public field names while redirecting their actual storage."""

    def __init__(self, state_field: str, legacy_name: str):
        self.state_field = state_field
        self.legacy_name = legacy_name

    def __get__(self, instance: Any, owner: type | None = None) -> Any:
        if instance is None:
            return self
        values = vars(instance)
        if self.legacy_name in values:
            # Preserve the old direct-__dict__ injection contract for test and
            # embedding hosts; after the first read the new state owns it.
            state = _source_selection(instance)
            if self.legacy_name in values:
                setattr(state, self.state_field, values.pop(self.legacy_name))
        state = values.get("_source_selection_state")
        if state is None:
            raise AttributeError(self.legacy_name)
        return getattr(state, self.state_field)

    def __set__(self, instance: Any, value: Any) -> None:
        state = _source_selection(instance)
        vars(instance).pop(self.legacy_name, None)
        setattr(state, self.state_field, value)

    def __delete__(self, instance: Any) -> None:
        values = vars(instance)
        state = values.get("_source_selection_state")
        if state is None and self.legacy_name not in values:
            raise AttributeError(self.legacy_name)
        state = _source_selection(instance)
        values.pop(self.legacy_name, None)
        # Preserve deletion semantics without deleting required state fields:
        # callers receive the type-appropriate empty value after deletion.
        setattr(state, self.state_field,
                getattr(SourceSelectionState(), self.state_field))


def _source_selection(instance: Any) -> SourceSelectionState:
    values = vars(instance)
    state = values.get("_source_selection_state")
    if state is None:
        state = SourceSelectionState()
        for legacy, field_name in _SELECTION_FIELDS.items():
            if legacy in values:
                setattr(state, field_name, values.pop(legacy))
        values["_source_selection_state"] = state
    return state


class SourceSelectionMixin:
    """Compatibility adapter for existing GUI and headless App integrations."""

    selected_packages = _SelectionField("selected_packages", "selected_packages")
    mirror_repos = _SelectionField("mirror_repos", "mirror_repos")
    _mirror_seen = _SelectionField("mirror_seen", "_mirror_seen")
    _mirror_iid_to_source_identity = _SelectionField(
        "mirror_iid_to_source_identity", "_mirror_iid_to_source_identity")
    _mirror_iid_to_repo_index = _SelectionField(
        "mirror_iid_to_repo_index", "_mirror_iid_to_repo_index")

    @property
    def source_selection(self) -> SourceSelectionState:
        return _source_selection(self)
