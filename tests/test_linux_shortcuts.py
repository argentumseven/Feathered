"""Desktop escaping and headless dispatch are testable on every platform."""
import builtins
import sys
from types import SimpleNamespace
import pytest
from linux_setup import desktop_argument
import linux_launch


def test_desktop_exec_uses_both_required_escaping_layers():
    assert desktop_argument('/tmp/a b%/"`$\\') == '"/tmp/a b%%/\\\\"\\\\`\\\\$\\\\\\\\"'


@pytest.mark.parametrize('value', ['/tmp/a\nb', '/tmp/a\rb', '/tmp/a\x00b'])
def test_desktop_paths_cannot_inject_new_keys(value):
    with pytest.raises(ValueError):
        desktop_argument(value)


def test_cli_launch_does_not_import_tk_and_retains_exit_status(monkeypatch):
    original = builtins.__import__
    def guarded(name, *args, **kwargs):
        if name.split('.')[0] in {'tkinter', 'app'}:
            pytest.fail('CLI imported the GUI')
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', guarded)
    monkeypatch.setitem(sys.modules, 'zstandard', SimpleNamespace())
    monkeypatch.setitem(sys.modules, 'yaml', SimpleNamespace())
    received = []
    monkeypatch.setitem(sys.modules, 'feathered_cli', SimpleNamespace(main=lambda args: received.append(args) or 2))
    assert linux_launch.main('cli', ['build', '--spec', 'local spec.json']) == 2
    assert received == [['build', '--spec', 'local spec.json']]
