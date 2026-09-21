"""Transport advice must follow build scope without changing acquisition policy."""
from dataclasses import asdict
from types import SimpleNamespace

import pytest

from feathered_app.application.discovery import DiscoveryMixin
from feathered_app.application.repositories import RepositoriesMixin
from feathered_app.repository_advisory import archive_keyring_state, http_repository_advice
from profiles import PROFILES
from repository_config import RepoSpec


class Widget:
    def __init__(self):
        self.options = {}
        self.visible = False

    def configure(self, **kwargs):
        self.options.update(kwargs)

    def pack(self, **kwargs):
        self.visible = True

    def pack_forget(self):
        self.visible = False


def test_devuan_defaults_stay_http_with_optional_keyrings():
    templates = PROFILES['devuan'].repos_factory('6.0', 'amd64')
    repos = [RepoSpec(t.name, t.url, repo_format='apt') for t in templates]
    assert repos and all(r.url.startswith('http://') for r in repos)
    before = [asdict(r) for r in repos]
    advice = http_repository_advice(repos)
    assert "Devuan's default repositories use HTTP" in advice
    assert 'trusted archive keyring' in advice
    assert 'does not encrypt HTTP' in advice
    assert 'continue without a keyring' in advice
    assert [asdict(r) for r in repos] == before


@pytest.mark.parametrize('url', ['https://deb.devuan.org/merged', 'file:///media/devuan', ''])
def test_non_http_sources_need_no_http_warning(url):
    assert http_repository_advice([RepoSpec('Devuan', url)]) == ''


def test_selected_mirror_warns_even_if_transaction_default_is_disabled():
    repo = RepoSpec('Devuan', 'http://deb.devuan.org/merged', enabled=False)
    assert 'HTTP' in http_repository_advice([repo])


def test_skip_policy_explicitly_explains_keyring_bypass():
    repo = RepoSpec('Devuan', 'http://deb.devuan.org/merged', keyring='archive.gpg',
                    verification_strategy='skip-provenance')
    assert 'bypasses configured keyrings' in http_repository_advice([repo])
    assert archive_keyring_state(repo) == ('Keyring bypassed', 'open')
    repo.verification_strategy = 'checksum-available'
    assert 'bypasses configured keyrings' not in http_repository_advice([repo])
    assert archive_keyring_state(repo) == ('Keyring configured', 'digest')


def test_advice_never_displays_repository_credentials():
    repo = RepoSpec('Private', 'http://user:secret@example.org/?token=hidden')
    text = http_repository_advice([repo])
    assert 'secret' not in text and 'hidden' not in text and 'user:' not in text


def test_both_warning_views_follow_actual_build_scope():
    selected = [RepoSpec('Devuan', 'http://deb.devuan.org/merged')]
    host = SimpleNamespace(repository_transport_warning=Widget(),
                           provenance_transport_warning=Widget(),
                           _build_repository_scope=lambda: selected)
    RepositoriesMixin._refresh_repository_transport_warning(host)
    for widget in (host.repository_transport_warning, host.provenance_transport_warning):
        assert widget.visible and 'Devuan' in widget.options['text']
    selected.clear()
    RepositoriesMixin._refresh_repository_transport_warning(host)
    for widget in (host.repository_transport_warning, host.provenance_transport_warning):
        assert not widget.visible and widget.options['text'] == ''


@pytest.mark.parametrize('verifier,signer', [(True, True), (True, False), (False, True), (False, False)])
def test_verification_and_signing_require_their_own_tools(monkeypatch, verifier, signer):
    import feathered_app.application.discovery as discovery
    monkeypatch.setattr(discovery, 'gpg_backend', lambda: 'gpgv' if verifier else None)
    monkeypatch.setattr(discovery, 'gpg_backend_version', lambda tool: 'gpgv test')
    monkeypatch.setattr(discovery.shutil, 'which', lambda tool: '/tools/gpg' if signer else None)
    verification_control = Widget()
    host = SimpleNamespace(openpgp_status_hint=Widget(), openpgp_install_row=Widget(),
                           signing_key_entry=Widget(),
                           _openpgp_dependent_widgets=[verification_control])
    DiscoveryMixin._sync_openpgp_availability(host)
    assert verification_control.options['state'] == ('normal' if verifier else 'disabled')
    assert host.signing_key_entry.options['state'] == ('normal' if signer else 'disabled')
    if verifier and not signer:
        assert 'gpgv verifier cannot sign' in host.openpgp_status_hint.options['text']
        assert host.openpgp_install_row.visible


def test_invalid_bundled_verifier_keeps_its_own_error(monkeypatch):
    import feathered_app.application.discovery as discovery
    def invalid():
        raise RuntimeError('hash mismatch')
    monkeypatch.setattr(discovery, 'gpg_backend', invalid)
    monkeypatch.setattr(discovery.shutil, 'which', lambda tool: '/tools/gpg')
    host = SimpleNamespace(openpgp_status_hint=Widget(), openpgp_install_row=Widget(),
                           signing_key_entry=Widget(), _openpgp_dependent_widgets=[Widget()])
    DiscoveryMixin._sync_openpgp_availability(host)
    assert 'failed authentication' in host.openpgp_status_hint.options['text']
    assert host.signing_key_entry.options['state'] == 'disabled'
    assert not host.openpgp_install_row.visible
