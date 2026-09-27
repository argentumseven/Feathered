"""Regression coverage for defects reproduced during the 1.4.0 review."""
from types import SimpleNamespace
from urllib.request import Request

import pytest

import credential_redaction as redaction
import repository_transport as transport
from core import RepoSpec, Reporter


@pytest.mark.parametrize('field', ['%74oken', 'to%6ben', '%20token%20', 'TOKEN'])
def test_encoded_query_credentials_never_reach_log_sink(field):
    lines = []
    reporter = Reporter(log=lines.append)
    reporter.log(f'Failed https://repo.invalid/?{field}=abc&channel=stable')
    reporter.warn(f'Retry https://repo.invalid/?{field}=abc')
    assert all('abc' not in line for line in lines + reporter.warnings)
    assert 'channel=stable' in lines[0]
    assert 'abc' not in redaction.redact_url(f'https://repo.invalid/?{field}=abc')


def test_overlapping_registered_secrets_are_fully_redacted(monkeypatch):
    monkeypatch.setattr(redaction, '_KNOWN_SECRETS', {'secret-prefix', 'secret-prefix-private-tail'})
    assert redaction.redact_text('failure: secret-prefix-private-tail') == 'failure: REDACTED'


@pytest.mark.parametrize('repo', [None, RepoSpec('Public', 'https://repo.invalid/')])
@pytest.mark.parametrize('credential', ['url', 'Authorization', 'Cookie'])
def test_child_request_credentials_confine_redirects(repo, credential):
    url = 'https://repo.invalid/child'
    headers = {}
    if credential == 'url':
        url += '?%74oken=abc'
    else:
        headers[credential] = 'secret'
    request = Request(url, headers=headers)
    with pytest.raises(RuntimeError, match='not allowed'):
        transport.RepositoryRedirectHandler(repo).redirect_request(
            request, None, 302, 'Found', {}, 'https://other.invalid/child')


def test_credentialed_child_redirect_still_supports_same_origin_and_explicit_cdn():
    repo = RepoSpec('Public', 'https://repo.invalid/',
                    redirect_allow_origins=['https://cdn.invalid'])
    handler = transport.RepositoryRedirectHandler(repo)
    request = Request('https://repo.invalid/child?token=abc')
    result = handler.redirect_request(request, None, 302, 'Found', {}, '/next')
    assert result.full_url == 'https://repo.invalid/next?token=abc'
    result = handler.redirect_request(request, None, 302, 'Found', {}, 'https://cdn.invalid/next')
    assert result.full_url == 'https://cdn.invalid/next'


@pytest.mark.parametrize('method,native_answer,expected', [
    ('askyesno', True, True), ('askyesno', False, False),
    ('askquestion', True, 'yes'), ('askquestion', False, 'no'),
    ('askokcancel', True, True), ('askokcancel', False, False),
    ('askretrycancel', True, True), ('askretrycancel', False, False),
])
def test_dialog_fallback_preserves_operator_answer(method, native_answer, expected):
    from feathered_app.ui.theme import _ThemedMessageBox
    native_method = 'askyesno' if method == 'askquestion' else method
    native = SimpleNamespace(**{native_method: lambda *args, **kwargs: native_answer})
    # No root forces the native fallback without needing a GUI/display.
    assert getattr(_ThemedMessageBox(native), method)('Title', 'Body') == expected


def test_custom_dialog_failure_does_not_choose_policy_default():
    from feathered_app.ui.theme import _ThemedMessageBox
    box = _ThemedMessageBox(SimpleNamespace())
    assert box.askchoice('Title', 'Body', [('proceed', 'Proceed'), ('cancel', 'Cancel')],
                         default='proceed') is None


def test_dialog_failure_destroys_partial_window(monkeypatch):
    from feathered_app.ui import theme
    destroyed = []
    def fail():
        raise theme.tk.TclError('display lost')
    window = SimpleNamespace(withdraw=fail, destroy=lambda: destroyed.append(True))
    monkeypatch.setattr(theme.tk, 'Toplevel', lambda root: window)
    box = theme._ThemedMessageBox(SimpleNamespace(askokcancel=lambda *a, **k: False))
    box.bind_root(SimpleNamespace(winfo_exists=lambda: True))
    assert box.askokcancel('Title', 'Body') is False
    assert destroyed == [True]
