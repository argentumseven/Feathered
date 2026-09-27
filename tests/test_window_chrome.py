"""Exercise native ABI and unsupported-platform paths without Windows DLLs."""
import ctypes
from types import SimpleNamespace

import pytest

from feathered_app.ui import window_chrome as chrome


class Function:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


@pytest.mark.parametrize('legacy', [False, True])
def test_windows_titlebar_uses_wrapper_handle_and_theme_colours(monkeypatch, legacy):
    hwnd = 0x123456789
    calls = []
    parent = Function(lambda child: hwnd)
    def set_attribute(handle, attribute, value, size):
        calls.append((handle, attribute, value._obj.value, size))
        return -1 if legacy and attribute == 20 else 0
    setter = Function(set_attribute)
    libraries = {'user32': SimpleNamespace(GetParent=parent),
                 'dwmapi': SimpleNamespace(DwmSetWindowAttribute=setter)}
    monkeypatch.setattr(chrome.sys, 'platform', 'win32')
    monkeypatch.setattr(ctypes, 'WinDLL', lambda name, **kw: libraries[name], raising=False)
    window = SimpleNamespace(winfo_id=lambda: 42, overrideredirect=lambda: False)
    assert chrome.apply_dark_titlebar(window, '#0D1117', '#E6EAF0')
    assert all(call[0] == hwnd for call in calls)
    assert [c[1] for c in calls] == ([20, 19, 35, 36] if legacy else [20, 35, 36])
    assert calls[-2][2] == 0x17110D
    assert calls[-1][2] == 0xF0EAE6
    assert parent.restype == chrome.wintypes.HWND
    assert setter.argtypes[0] == chrome.wintypes.HWND


def test_linux_titlebar_path_does_not_touch_native_handles(monkeypatch):
    monkeypatch.setattr(chrome.sys, 'platform', 'linux')
    assert chrome.apply_dark_titlebar(object(), '#0D1117', '#E6EAF0') is False
    chrome.install_dark_titlebars(object(), '#0D1117', '#E6EAF0')


def test_unavailable_dwm_does_not_break_windows_startup(monkeypatch):
    monkeypatch.setattr(chrome.sys, 'platform', 'win32')
    def missing(*args, **kwargs):
        raise OSError('DWM unavailable')
    monkeypatch.setattr(ctypes, 'WinDLL', missing, raising=False)
    assert chrome.apply_dark_titlebar(SimpleNamespace(overrideredirect=lambda: False),
                                      '#0D1117', '#E6EAF0') is False
