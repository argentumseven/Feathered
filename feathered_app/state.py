"""Grouped views over Feathered's established ``App`` instance state.

The desktop shell historically stores mutable workflow state directly on the
``App`` instance.  These views provide explicit ownership groups without
changing that storage contract: reads and writes are forwarded to the same
legacy attributes.  This preserves Tk APIs, ``__dict__`` behaviour, monkeypatch
behaviour, and partially-constructed test instances while giving new code a
structured state surface through ``app.app_state``.
"""
from __future__ import annotations

from typing import Any


class _StateGroupView:
    __slots__ = ("_owner", "_mapping")

    def __init__(self, owner: Any, mapping: dict[str, str]):
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_mapping", mapping)

    def __getattr__(self, name: str) -> Any:
        mapping = object.__getattribute__(self, "_mapping")
        try:
            legacy_name = mapping[name]
        except KeyError as exc:
            raise AttributeError(name) from exc
        owner = object.__getattribute__(self, "_owner")
        try:
            # Bypass tkinter.Misc.__getattr__ for missing fields while still
            # preserving normal Python descriptor/instance lookup semantics.
            return object.__getattribute__(owner, legacy_name)
        except AttributeError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name: str, value: Any) -> None:
        mapping = object.__getattribute__(self, "_mapping")
        try:
            legacy_name = mapping[name]
        except KeyError as exc:
            raise AttributeError(name) from exc
        setattr(object.__getattribute__(self, "_owner"), legacy_name, value)

    def __delattr__(self, name: str) -> None:
        mapping = object.__getattribute__(self, "_mapping")
        try:
            legacy_name = mapping[name]
        except KeyError as exc:
            raise AttributeError(name) from exc
        try:
            delattr(object.__getattribute__(self, "_owner"), legacy_name)
        except AttributeError as exc:
            raise AttributeError(name) from exc

    def __dir__(self) -> list[str]:
        return sorted(object.__getattribute__(self, "_mapping"))


_OPERATION_FIELDS = {
    "events": "events",
    "cancel_event": "cancel_event",
    "worker": "worker",
    "active_operation": "active_operation",
    "active_operation_label": "active_operation_label",
    "operation_controls": "_operation_controls",
    "operation_saved_states": "_operation_saved_states",
    "operation_cancellable": "_operation_cancellable",
    "activity_job": "_activity_job",
    "activity_frame": "_activity_frame",
    "activity_state": "_activity_state",
    "operation_detail": "_operation_detail",
}

_REPOSITORY_FIELDS = {
    "repo_rows": "repo_rows",
    "transaction_repo_rows": "transaction_repo_rows",
    "mirror_repo_rows": "mirror_repo_rows",
    "repository_universe_mode": "_repository_universe_mode",
    "mirror_repos": "mirror_repos",
    "mirror_iid_to_source_identity": "_mirror_iid_to_source_identity",
    "mirror_iid_to_repo_index": "_mirror_iid_to_repo_index",
    "mirror_seen": "_mirror_seen",
    "repository_workflow_key": "_repository_workflow_key",
}

_ANALYSIS_FIELDS = {
    "loaded_signature": "loaded_signature",
    "loaded_packages": "loaded_packages",
    "last_result": "last_result",
    "last_warnings": "last_warnings",
    "analysis_signature": "analysis_signature",
    "result_rows": "result_rows",
    "picked": "picked",
    "picked_closure": "picked_closure",
    "ignored_unresolved": "ignored_unresolved",
    "unresolved_rows": "unresolved_rows",
    "resolution_pass_budget": "resolution_pass_budget",
    "selected_packages": "selected_packages",
}

_TRANSFER_FIELDS = {
    "last_output_path": "last_output_path",
    "transfer_total": "transfer_total",
    "transfer_done": "transfer_done",
    "transfer_failed": "transfer_failed",
    "transfer_reused": "transfer_reused",
    "transfer_bytes": "transfer_bytes",
    "transfer_expected_bytes": "transfer_expected_bytes",
    "transfer_started": "transfer_started",
}

_CATALOG_FIELDS = {
    "packages": "single_catalog_packages",
    "signature": "single_catalog_signature",
    "browser_window": "single_browser_window",
    "browser_tree": "single_browser_tree",
    "browser_rows": "single_browser_rows",
    "browser_status_var": "single_browser_status_var",
    "browser_query_var": "single_browser_query_var",
}


class ApplicationStateView:
    """Live grouped view over an application's existing mutable attributes."""

    __slots__ = ("operation", "repositories", "analysis", "transfer", "catalog")

    def __init__(self, owner: Any):
        self.operation = _StateGroupView(owner, _OPERATION_FIELDS)
        self.repositories = _StateGroupView(owner, _REPOSITORY_FIELDS)
        self.analysis = _StateGroupView(owner, _ANALYSIS_FIELDS)
        self.transfer = _StateGroupView(owner, _TRANSFER_FIELDS)
        self.catalog = _StateGroupView(owner, _CATALOG_FIELDS)


class _ApplicationStateDescriptor:
    """Non-data descriptor exposing a live state view without reserving writes.

    Because the descriptor intentionally defines no ``__set__`` or ``__delete__``,
    an embedder that historically used ``app.app_state`` as its own instance
    attribute can still assign that name and shadow this additive API.
    """

    __slots__ = ()

    def __get__(self, owner: Any, owner_type: type | None = None):
        if owner is None:
            return self
        return ApplicationStateView(owner)
