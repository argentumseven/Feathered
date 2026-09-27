"""Exercise the actual trust editor and shared-policy event handlers under Tk."""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

import pytest
from tests import test_application_startup as startup

application = startup.application
isolated_state = startup.isolated_state


def _descendants(widget):
    for child in widget.winfo_children():
        yield child
        yield from _descendants(child)


@startup.requires_display
def test_repository_trust_dialog_updates_the_injected_service(application):
    window = application
    assert window.repo_rows
    repo = window.repo_rows[0]
    service = window._get_repository_policy_service()
    window.edit_repo_trust(0)
    dialog = next(c for c in window.winfo_children()
                  if isinstance(c, tk.Toplevel) and c.title().startswith("Provenance:"))
    try:
        combos = [widget for widget in _descendants(dialog)
                  if isinstance(widget, ttk.Combobox)]
        digest = next(c for c in combos if "SHA-512" in c["values"])
        strategy = next(c for c in combos
                        if "Corroborate every package (maximum)" in c["values"])
        digest.set("SHA-512")
        digest.event_generate("<<ComboboxSelected>>")
        assert repo.digest_preference == "sha512"
        strategy.set("Corroborate every package (maximum)")
        strategy.event_generate("<<ComboboxSelected>>")
        assert repo.verification_strategy == "full-corroboration"
        assert (repo.digest_requirement, repo.evidence_policy) == ("required", "required")
        assert window._get_repository_policy_service() is service
    finally:
        dialog.destroy()


@startup.requires_display
def test_common_provenance_policy_is_applied_only_to_participating_sources(application,
                                                                              monkeypatch):
    window = application
    window.show_pane("keyrings")
    enabled = list(window.repo_rows[:2])
    assert len(enabled) == 2
    excluded = window.repo_rows[2]
    previous = excluded.verification_strategy
    monkeypatch.setattr(window, "_enabled_provenance_repos", lambda: enabled)
    window.prov_strategy_var.set("Require checksum coverage (strict)")
    window.prov_digest_var.set("SHA-384 or stronger")
    window._provenance_policy_changed()
    assert all(r.verification_strategy == "checksum-required" and
               r.digest_preference == "sha384" for r in enabled)
    assert excluded.verification_strategy == previous
