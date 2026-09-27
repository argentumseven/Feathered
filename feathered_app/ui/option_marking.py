"""Render option advisories inside ttk.Combobox dropdowns.

ttk's popdown list is a plain Tk listbox that is refilled from ``-values``
every time it opens. Selection maps the clicked *index* back into ``-values``,
so the visible row text can carry a "· beta" tag and a colour while the stored
value stays exactly what the rest of Feathered expects. Rows are decorated on
idle immediately after the popdown is configured.

Classification comes from ``feathered_app.option_advisory``; this module only
paints. Any Tk failure leaves the stock dropdown unchanged.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

from feathered_app.option_advisory import STABLE, OptionAdvice, OptionStatus, display_label

# Yellow is deliberately loud: a beta at the top of a newest-first list should
# stand out at a glance. Dark text keeps it readable in either theme.
PRERELEASE_BG = "#FFD54F"
PRERELEASE_FG = "#1F1A00"
PRERELEASE_SELECT_BG = "#E0A800"
END_OF_LIFE_FG = "#8C8C8C"
INCOMPATIBLE_FG = "#E06C6C"

FIELD_STYLES = {
    OptionStatus.PRERELEASE: "Prerelease.TCombobox",
    OptionStatus.INCOMPATIBLE: "Incompatible.TCombobox",
}
# Styles this module may replace. Validation's Attention style is never touched.
_OWNED_STYLES = {"", "TCombobox", *FIELD_STYLES.values()}


def configure_option_styles(style: ttk.Style, *, field_bg: str, field_fg: str,
                            disabled_bg: str, disabled_fg: str) -> None:
    style.configure("Prerelease.TCombobox", fieldbackground=PRERELEASE_BG,
                    background=PRERELEASE_BG, foreground=PRERELEASE_FG,
                    arrowcolor=PRERELEASE_FG, bordercolor=PRERELEASE_SELECT_BG, padding=5)
    style.map("Prerelease.TCombobox",
              fieldbackground=[("disabled", disabled_bg), ("readonly", PRERELEASE_BG)],
              foreground=[("disabled", disabled_fg), ("readonly", PRERELEASE_FG)],
              selectbackground=[("readonly", PRERELEASE_BG)],
              selectforeground=[("readonly", PRERELEASE_FG)])
    style.configure("Incompatible.TCombobox", fieldbackground=field_bg, background=field_bg,
                    foreground=field_fg, arrowcolor=INCOMPATIBLE_FG,
                    bordercolor=INCOMPATIBLE_FG, padding=5)
    style.map("Incompatible.TCombobox",
              fieldbackground=[("disabled", disabled_bg), ("readonly", field_bg)],
              foreground=[("disabled", disabled_fg), ("readonly", field_fg)])


class _TclListbox:
    """Minimal listbox proxy for a Tk-created widget tkinter does not own.

    ttk creates the popdown listbox in Tcl, so ``nametowidget`` cannot find it.
    """

    def __init__(self, interp, path: str):
        self.tk, self.path = interp, path

    def _call(self, *args):
        return self.tk.call(self.path, *args)

    def size(self) -> int:
        return int(self._call("size"))

    def get(self, index) -> str:
        return str(self._call("get", index))

    def delete(self, index) -> None:
        self._call("delete", index)

    def insert(self, index, text) -> None:
        self._call("insert", index, text)

    def cget(self, option: str) -> str:
        return str(self._call("cget", "-" + option))

    def itemcget(self, index, option: str) -> str:
        return str(self._call("itemcget", index, "-" + option))

    def itemconfigure(self, index, **options) -> None:
        args = []
        for key, value in options.items():
            args += ["-" + key, value]
        self._call("itemconfigure", index, *args)

    def curselection(self) -> tuple:
        return tuple(int(i) for i in self.tk.splitlist(self._call("curselection")))

    def selection_clear(self, first, last) -> None:
        self._call("selection", "clear", first, last)

    def selection_set(self, index) -> None:
        self._call("selection", "set", index)

    def activate(self, index) -> None:
        self._call("activate", index)

    def see(self, index) -> None:
        self._call("see", index)


class OptionMarker:
    """Decorate one combobox according to a classify(value) callback."""

    def __init__(self, combo: ttk.Combobox, classify: Callable[[str], OptionAdvice], *,
                 variable: Optional[tk.Variable] = None,
                 on_change: Optional[Callable[[OptionAdvice], None]] = None):
        self.combo = combo
        self.classify = classify
        self.variable = variable
        self.on_change = on_change
        previous = str(combo.cget("postcommand") or "")
        self._previous_post = previous
        combo.configure(postcommand=self._posted)
        combo.bind("<<ComboboxSelected>>", lambda _e: self.refresh(), add="+")
        if variable is not None:
            variable.trace_add("write", lambda *_a: self.refresh())

    def advice(self, value: str) -> OptionAdvice:
        try:
            return self.classify(str(value)) or STABLE
        except Exception:
            # A classifier depending on half-initialized wizard state must not
            # break the dropdown; unknown means unmarked.
            return STABLE

    # -- popdown rows ------------------------------------------------------
    def _posted(self) -> None:
        if self._previous_post:
            try:
                self.combo.tk.eval(self._previous_post)
            except tk.TclError:
                pass
        try:
            self.combo.after_idle(self.decorate)
        except tk.TclError:
            pass

    def _listbox(self):
        try:
            popdown = self.combo.tk.call("ttk::combobox::PopdownWindow", self.combo)
        except tk.TclError:
            return None
        return _TclListbox(self.combo.tk, f"{popdown}.f.l")

    def decorate(self) -> int:
        """Paint the open list; returns the number of marked rows."""
        listbox = self._listbox()
        if listbox is None:
            return 0
        try:
            values = [str(v) for v in self.combo.tk.splitlist(self.combo.cget("values"))]
            if listbox.size() != len(values):
                return 0
            selected = listbox.curselection()
            base = {k: listbox.cget(k) for k in
                    ("background", "foreground", "selectbackground", "selectforeground")}
            advices = [self.advice(value) for value in values]
            for index, (value, advice) in enumerate(zip(values, advices)):
                text = display_label(value, advice)
                if listbox.get(index) != text:
                    listbox.delete(index)
                    listbox.insert(index, text)
            marked = 0
            for index, advice in enumerate(advices):
                colours = dict(base)
                if advice.status is OptionStatus.PRERELEASE:
                    colours.update(background=PRERELEASE_BG, foreground=PRERELEASE_FG,
                                   selectbackground=PRERELEASE_SELECT_BG,
                                   selectforeground=PRERELEASE_FG)
                elif advice.status is OptionStatus.END_OF_LIFE:
                    colours.update(foreground=END_OF_LIFE_FG)
                elif advice.status is OptionStatus.INCOMPATIBLE:
                    colours.update(foreground=INCOMPATIBLE_FG)
                marked += not advice.stable
                # Explicit per-row reset: Tk keeps item attributes by index
                # when the popdown's list variable is refilled.
                listbox.itemconfigure(index, **colours)
            listbox.selection_clear(0, "end")
            for index in selected:
                listbox.selection_set(index)
            if selected:
                listbox.activate(selected[0])
                listbox.see(selected[0])
            return marked
        except tk.TclError:
            return 0

    # -- closed field ------------------------------------------------------
    def refresh(self) -> OptionAdvice:
        value = self.variable.get() if self.variable is not None else self.combo.get()
        advice = self.advice(value)
        try:
            current = str(self.combo.cget("style") or "")
            if current in _OWNED_STYLES:
                wanted = FIELD_STYLES.get(advice.status, "TCombobox")
                if wanted != (current or "TCombobox"):
                    self.combo.configure(style=wanted)
        except tk.TclError:
            pass
        if self.on_change is not None:
            try:
                self.on_change(advice)
            except Exception:
                pass
        return advice


def attach_option_marker(combo, classify, *, variable=None, on_change=None) -> Optional[OptionMarker]:
    if combo is None:
        return None
    marker = OptionMarker(combo, classify, variable=variable, on_change=on_change)
    marker.refresh()
    return marker
