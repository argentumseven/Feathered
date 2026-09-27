"""Live Tk regressions for the introductory spacing on wizard pages 3 and 4."""
from __future__ import annotations

from tests import test_application_startup as startup

application = startup.application
isolated_state = startup.isolated_state


def _gap(after, before):
    """Vertical pixels between the bottom of `before` and top of `after`."""
    return after.winfo_rooty() - (before.winfo_rooty() + before.winfo_height())


def _intro(pane):
    # The first two direct children are the page title and its explanation.
    return pane.winfo_children()[1]


@startup.requires_display
def test_mirror_repositories_begin_just_after_the_explanation(application):
    window = application
    window.selection_mode_var.set("Entire repository (mirror)")
    window._selection_mode_changed()
    window.show_pane("repositories")
    window.update_idletasks()

    intro = _intro(window.panes["repositories"])
    card = window.mirror_selection_card._feather_card_holder
    assert 0 <= _gap(card, intro) <= 8
    # A hidden transport warning must not reserve a separate frame/blank area.
    assert not window.repository_transport_warning.winfo_manager()


@startup.requires_display
def test_package_verification_begins_just_after_the_explanation(application):
    window = application
    window.show_pane("keyrings")
    window.update_idletasks()

    intro = _intro(window.panes["keyrings"])
    card = window.prov_checksum_card._feather_card_holder
    assert 0 <= _gap(card, intro) <= 8
    assert not window.provenance_transport_warning.winfo_manager()


@startup.requires_display
def test_transport_warnings_insert_before_the_first_section_without_a_stale_gap(
        application, monkeypatch):
    import feathered_app.application.repositories as repository_ui

    window = application
    window.selection_mode_var.set("Entire repository (mirror)")
    window._selection_mode_changed()
    monkeypatch.setattr(repository_ui, "http_repository_advice",
                        lambda _sources: "HTTP repository: verify transport policy.")

    # A hidden pane's winfo_rooty() is not a valid screen coordinate. Measure
    # each one while it is visible, including after the warning is removed.
    def sections():
        return (
            ("repositories", window.repository_transport_warning,
             window.repository_workflow_host),
            ("keyrings", window.provenance_transport_warning,
             window.prov_checksum_card._feather_card_holder),
        )

    for key, warning, first_card in sections():
        window.show_pane(key)
        window._refresh_repository_transport_warning()
        window.update_idletasks()
        pane = window.panes[key]
        assert warning.winfo_manager() == "pack"
        assert pane.pack_slaves().index(warning) < pane.pack_slaves().index(first_card)
        assert 0 <= _gap(warning, _intro(pane)) <= 8
        assert 0 <= _gap(first_card, warning) <= 8

    monkeypatch.setattr(repository_ui, "http_repository_advice", lambda _sources: "")
    for key, warning, first_card in sections():
        window.show_pane(key)
        window._refresh_repository_transport_warning()
        window.update_idletasks()
        pane = window.panes[key]
        assert not warning.winfo_manager()
        assert 0 <= _gap(first_card, _intro(pane)) <= 8
