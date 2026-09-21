"""HTTP advice follows actual GUI selections and policy changes."""
import pytest

from tests import test_application_startup as startup

application = startup.application
isolated_state = startup.isolated_state


@startup.requires_display
@pytest.mark.parametrize('mode', ['Workload preset', 'Choose packages', 'Entire repository (mirror)'])
def test_devuan_warning_follows_source_and_policy_changes(application, mode):
    window = application
    window.distro_var.set('Devuan')
    window._profile_changed()
    window.release_var.set('6.0')
    window._release_changed()
    window.selection_mode_var.set(mode)
    window._selection_mode_changed()
    window.show_pane('repositories')
    window._refresh_repository_transport_warning()
    window.update_idletasks()
    assert 'Devuan' in window.repository_transport_warning.cget('text')
    assert window.repository_transport_warning.winfo_ismapped()
    participating = window._build_repository_scope()
    assert participating
    for repo in participating:
        repo.keyring = 'example.gpg'
        repo.verification_strategy = 'skip-provenance'
    window._refresh_repo_tree_if_open()
    assert 'bypasses configured keyrings' in window.repository_transport_warning.cget('text')
    window.show_pane('keyrings')
    window.update_idletasks()
    assert window.provenance_transport_warning.winfo_ismapped()
    states = [window.keyring_tree.item(i, 'values')[1]
              for i in window.keyring_tree.get_children()]
    assert states and all(state == 'Keyring bypassed' for state in states)
    for repo in participating:
        repo.url = repo.url.replace('http://', 'https://', 1)
    window._refresh_repo_tree_if_open()
    window.update_idletasks()
    assert not window.provenance_transport_warning.winfo_ismapped()


@startup.requires_display
def test_mirror_deselection_clears_http_warning(application):
    window = application
    window.distro_var.set('Devuan')
    window._profile_changed()
    window.release_var.set('6.0')
    window._release_changed()
    window.selection_mode_var.set('Entire repository (mirror)')
    window._selection_mode_changed()
    window.show_pane('repositories')
    window._bulk_mirror('all')
    assert 'HTTP' in window.repository_transport_warning.cget('text')
    window._bulk_mirror('none')
    assert window.repository_transport_warning.cget('text') == ''
