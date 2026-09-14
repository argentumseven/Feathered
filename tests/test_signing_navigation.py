"""Signing validation must reveal its corrective control in the real GUI."""
import pytest
from tests import test_application_startup as startup

application = startup.application
isolated_state = startup.isolated_state


def prepare(window, monkeypatch):
    import app
    monkeypatch.setattr(app.messagebox, 'showerror', lambda *args, **kwargs: None)
    window._has_review_contract = lambda: True
    window.signing_key_var.set('')
    window.signing_key_entry.configure(state='normal')
    window.show_pane('transfer')


def test_next_routes_missing_signing_key_to_provenance(application, monkeypatch):
    prepare(application, monkeypatch)
    application.sign_index_var.set(True)
    assert application.go_next() is False
    application.update_idletasks()
    assert application.active_pane == 'keyrings'
    assert application._attention_widget is application.signing_key_entry
    assert application._attention_card is application._card_for_widget(application.signing_key_entry)


def test_folder_naming_failure_still_targets_its_own_control(application, monkeypatch):
    from feathered_app.context import FOLDER_SCHEMES
    prepare(application, monkeypatch)
    application.sign_index_var.set(False)
    application.folder_scheme_var.set(FOLDER_SCHEMES[3])
    application.folder_stamp_var.set('none')
    application.folder_label_var.set('')
    assert application.go_next() is False
    assert application.active_pane == 'transfer'
    assert application._attention_widget is application.folder_label_entry


def test_missing_openpgp_routes_to_setup_card(application, monkeypatch):
    prepare(application, monkeypatch)
    application.signing_key_entry.configure(state='disabled')
    application.sign_index_var.set(True)
    assert application.go_next() is False
    assert application.active_pane == 'keyrings'
    assert application._attention_card is application._card_for_widget(application.openpgp_status_card)


@pytest.mark.parametrize('key, initially_enabled, expected_pane', [
    ('', False, 'keyrings'), ('example-key', False, 'transfer'), ('', True, 'transfer'),
])
def test_signing_checkbox_routes_only_when_setup_needed(
        application, monkeypatch, key, initially_enabled, expected_pane):
    prepare(application, monkeypatch)
    application.signing_key_var.set(key)
    application.sign_index_var.set(initially_enabled)
    application.update_idletasks()
    application.sign_index_row.event_generate('<Button-1>')
    application.update_idletasks()
    assert application.sign_index_var.get() is not initially_enabled
    assert application.active_pane == expected_pane
    if expected_pane == 'keyrings':
        assert application._attention_widget is application.signing_key_entry
        application.signing_key_var.set('chosen-key')
        assert application._attention_card is None
