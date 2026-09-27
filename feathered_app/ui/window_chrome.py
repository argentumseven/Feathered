"""Best-effort native dark title bars without replacing window controls."""
from __future__ import annotations

import ctypes
import sys
import tkinter as tk
from ctypes import wintypes


def _colorref(colour: str) -> int:
    red, green, blue = (int(colour[i:i + 2], 16) for i in (1, 3, 5))
    return red | (green << 8) | (blue << 16)


def apply_dark_titlebar(window, background: str, foreground: str) -> bool:
    """Style Tk's native Windows wrapper; unsupported hosts retain their frame.

    Called on Map, after Tk has created its wrapper HWND, including after a
    withdrawn window is shown again. Explicit pointer-sized signatures avoid
    truncating handles on 64-bit Windows. No DLL is loaded on other platforms.
    """
    if sys.platform != "win32":
        return False
    try:
        if window.overrideredirect():
            return False
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        dwm = ctypes.WinDLL("dwmapi", use_last_error=True)
        get_parent = user32.GetParent
        get_parent.argtypes = [wintypes.HWND]
        get_parent.restype = wintypes.HWND
        set_attribute = dwm.DwmSetWindowAttribute
        set_attribute.argtypes = [wintypes.HWND, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD]
        set_attribute.restype = ctypes.c_long
        child = window.winfo_id()
        hwnd = get_parent(child) or child
        enabled = wintypes.BOOL(1)
        result = set_attribute(hwnd, 20, ctypes.byref(enabled), ctypes.sizeof(enabled))
        if result != 0:
            # Earlier Windows 10 releases used attribute 19.
            result = set_attribute(hwnd, 19, ctypes.byref(enabled), ctypes.sizeof(enabled))
        # Windows 11 can match Feathered's exact header/text palette even
        # when Windows itself uses a light theme. Older systems ignore these.
        caption = wintypes.DWORD(_colorref(background))
        text = wintypes.DWORD(_colorref(foreground))
        caption_result = set_attribute(hwnd, 35, ctypes.byref(caption), ctypes.sizeof(caption))
        set_attribute(hwnd, 36, ctypes.byref(text), ctypes.sizeof(text))
        return result == 0 or caption_result == 0
    except (AttributeError, OSError, tk.TclError):
        # A cosmetic OS capability must never prevent startup or a dialog.
        return False


def install_dark_titlebars(root, background: str, foreground: str) -> None:
    """Cover the root and every Tk Toplevel, including standard Tk dialogs."""
    if sys.platform != "win32":
        return

    def on_map(event):
        if isinstance(event.widget, (tk.Tk, tk.Toplevel)):
            apply_dark_titlebar(event.widget, background, foreground)

    root.bind("<Map>", on_map, add="+")
    root.bind_class("Toplevel", "<Map>", on_map, add="+")
