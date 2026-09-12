"""Regression tests for the 1.2.12 UI-fix pass.

Each test here pins a defect that shipped and was visible on screen, so the
suite fails if the underlying cause returns. Several of these could not have
been caught by asserting on application state alone: they are about which
widget carries the appearance, which ttk option name the theme actually reads,
and which colour lands on a specific pixel. They assert on those directly.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

tk = pytest.importorskip("tkinter")
from tkinter import ttk  # noqa: E402


def _display_available() -> bool:
    if sys.platform.startswith("win") or sys.platform == "darwin":
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


requires_display = pytest.mark.skipif(
    not _display_available(),
    reason="no display; run the suite under xvfb-run as the release gate does")


@pytest.fixture
def isolated_state(tmp_path, monkeypatch):
    for variable in ("APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(variable, str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(parents=True, exist_ok=True)
    return tmp_path


@pytest.fixture
def application(isolated_state):
    import app

    try:
        window = app.App()
    except tk.TclError as exc:  # pragma: no cover - environment, not code
        pytest.skip(f"Tk could not open a display: {exc}")
    try:
        yield window
    finally:
        try:
            window.destroy()
        except tk.TclError:
            pass


# --------------------------------------------------------------------------
# Readonly entry corners
# --------------------------------------------------------------------------

@requires_display
def test_readonly_entry_background_is_not_the_clam_frame_colour(application):
    """clam paints an entry's four border corner pixels with -background.

    Its own TEntry map sets -background to the light #dcdad5 frame colour in
    the readonly state. The application map overrode -fieldbackground but not
    -background, so every readonly entry -- the differential baseline path
    among them -- wore four pale dots on its corners.
    """
    from feathered_app.context import BG_PANEL

    style = ttk.Style(application)
    for state in ("readonly", "disabled"):
        resolved = style.lookup("TEntry", "background", [state])
        assert resolved.lower() == BG_PANEL.lower(), (
            f"TEntry -background in the {state} state is {resolved!r}; "
            "clam's light frame colour will show on the border corners")


@requires_display
def test_entry_focus_ring_uses_the_application_accent(application):
    """clam maps -lightcolor/-darkcolor to a blue #6f9dc6 on focus."""
    from feathered_app.context import ACCENT

    style = ttk.Style(application)
    for option in ("lightcolor", "darkcolor", "bordercolor"):
        resolved = style.lookup("TEntry", option, ["focus"])
        assert resolved.lower() == ACCENT.lower(), (
            f"focused TEntry -{option} is {resolved!r}, not the accent")


def _walk(widget):
    """Every widget in the live tree, depth first."""
    yield widget
    for child in widget.winfo_children():
        yield from _walk(child)


@requires_display
def test_every_live_readonly_entry_resolves_a_panel_background(application):
    """Check the actual widgets, not just the default style.

    A per-widget style (Attention.TEntry, say) inherits TEntry's map only if
    it does not define its own, so asserting on TEntry alone would miss a
    variant that reintroduced the light corners. Walk the built tree and
    resolve the background for the style each entry really uses.
    """
    from feathered_app.context import BG_PANEL

    style = ttk.Style(application)
    application.update_idletasks()

    checked = []
    for widget in _walk(application):
        if not isinstance(widget, ttk.Entry) or isinstance(widget, ttk.Combobox):
            continue
        if str(widget.cget("state")) != "readonly":
            continue
        name = str(widget.cget("style")) or widget.winfo_class()
        resolved = style.lookup(name, "background", ["readonly"])
        checked.append((name, resolved))
        assert resolved.lower() == BG_PANEL.lower(), (
            f"readonly entry using style {name!r} resolves -background {resolved!r}; "
            "clam will paint that on the four border corner pixels")

    assert checked, "expected at least the differential baseline entry to be readonly"
    assert application.baseline_entry in list(_walk(application))


@requires_display
def test_the_attention_entry_variant_did_not_reintroduce_the_corners(application):
    """Attention.TEntry is applied to invalid fields and must inherit the fix."""
    from feathered_app.context import BG_PANEL

    style = ttk.Style(application)
    for state in ("readonly", "disabled"):
        resolved = style.lookup("Attention.TEntry", "background", [state])
        assert resolved.lower() == BG_PANEL.lower(), (
            f"Attention.TEntry -background in the {state} state is {resolved!r}")


# --------------------------------------------------------------------------
# Checkbox consistency
# --------------------------------------------------------------------------

@requires_display
def test_clam_has_no_indicatorcolor_option(application):
    """The option the theme used to set does not exist under clam.

    This is the reason the Kubernetes checkboxes rendered as a white box with
    a black tick: `style.map(..., indicatorcolor=...)` was a silent no-op and
    -indicatorbackground stayed at clam's #ffffff default.
    """
    style = ttk.Style(application)
    options = style.element_options("Checkbutton.indicator")
    assert "indicatorcolor" not in options
    assert "indicatorbackground" in options and "indicatorforeground" in options


@requires_display
def test_stray_ttk_checkbuttons_are_still_legible(application):
    """Any ttk.Checkbutton that survives must not be white-on-dark."""
    from feathered_app.context import ACCENT, BG_INPUT

    style = ttk.Style(application)
    assert style.lookup("TCheckbutton", "indicatorbackground", ["selected"]).lower() == ACCENT.lower()
    assert style.lookup("TCheckbutton", "indicatorbackground", ["!selected"]).lower() == BG_INPUT.lower()


@requires_display
def test_no_themed_checkbutton_is_built_into_the_live_tree(application):
    """Walk the built application and find any surviving ttk indicator.

    The source check below covers dialogs that are not instantiated at
    startup; this covers everything that is.
    """
    application.update_idletasks()
    strays = [str(w) for w in _walk(application) if isinstance(w, ttk.Checkbutton)]
    assert not strays, (
        f"themed ttk.Checkbutton widgets are live in the tree: {strays}. "
        "Use _image_checkbutton so one checkbox style is used application-wide")


@requires_display
def test_kubernetes_checkboxes_use_the_drawn_house_widget(application):
    """Both Kubernetes checkboxes must be the same widget as the others.

    `_image_checkbutton` returns a tk.Frame carrying `_feather_set_enabled`;
    a ttk.Checkbutton does not. Assert on the marker in the live tree and on
    the source, so neither a rebuild nor a refactor reintroduces the mismatch.
    """
    import inspect

    from feathered_app.ui import kubernetes

    for module in (kubernetes,):
        source = inspect.getsource(module)
        assert "ttk.Checkbutton" not in source, (
            f"{module.__name__} is drawing a themed indicator again; use "
            "_image_checkbutton so one checkbox style is used application-wide")

    drawn = [w for w in _walk(application.vks_options)
             if getattr(w, "_feather_set_enabled", None) is not None]
    assert drawn, "Pin to inventory baseline is not a drawn checkbutton"


# --------------------------------------------------------------------------
# The drawn checkbox must honour the operation lock
# --------------------------------------------------------------------------

@requires_display
def test_a_drawn_checkbutton_survives_the_operation_lock(application):
    """A tk.Frame has no -state, and the lock unregisters what raises.

    Before `_feather_state`, registering a drawn checkbox meant it was dropped
    from `_operation_controls` on the first lock and stayed clickable during a
    build, which is precisely what registration was meant to prevent.
    """
    variable = tk.BooleanVar(value=False)
    row = application._image_checkbutton(application, variable, "lockable")
    application._register_operation_control(row)
    assert row in application._operation_controls

    application._lock_operation_controls()
    assert row in application._operation_controls, "the lock dropped the control"
    assert application._operation_control_state(row) == "disabled"

    row.event_generate("<Button-1>")
    application.update_idletasks()
    assert variable.get() is False, "a locked checkbox still toggled"

    application._unlock_operation_controls()
    assert application._operation_control_state(row) == "normal"
    row.destroy()


@requires_display
def test_a_drawn_checkbutton_runs_its_command_on_click_only(application):
    """`command` must mirror ttk.Checkbutton: clicks fire it, `set` does not."""
    calls = []
    variable = tk.BooleanVar(value=False)
    row = application._image_checkbutton(
        application, variable, "commanded", command=lambda: calls.append(variable.get()))

    variable.set(True)
    application.update_idletasks()
    assert calls == [], "a programmatic set must not invoke the command"

    row.event_generate("<Button-1>")
    application.update_idletasks()
    assert calls == [False], "a click must invoke the command after the flip"
    row.destroy()


# --------------------------------------------------------------------------
# Card visibility
# --------------------------------------------------------------------------

@requires_display
def test_hiding_a_card_hides_its_heading_too(application):
    """_card's title and border live on the holder, not the returned frame.

    Calling pack_forget() on the returned frame left an accent heading over a
    collapsed 1px box on screen, which is what the Kubernetes cards did for
    every non-Kubernetes workload.
    """
    card = application.k8s_api_card
    holder = card._feather_card_holder
    headings = [child for child in holder.winfo_children()
                if isinstance(child, ttk.Label)]
    assert headings, "the card heading should live on the holder"

    application._set_card_visible(card, True)
    application.update_idletasks()
    assert holder.winfo_manager() == "pack"

    application._set_card_visible(card, False)
    application.update_idletasks()
    assert holder.winfo_manager() == "", (
        "the holder is still mapped, so the heading is still on screen")


@requires_display
def test_a_hidden_card_returns_to_its_original_position(application):
    """Re-packing appends, so a card would migrate to the bottom of its pane."""
    card = application.k8s_api_card
    holder = card._feather_card_holder
    application._set_card_visible(card, True)
    application.update_idletasks()
    before = list(holder.master.pack_slaves())

    application._set_card_visible(card, False)
    application.update_idletasks()
    application._set_card_visible(card, True)
    application.update_idletasks()

    assert list(holder.master.pack_slaves()) == before, (
        "the card moved within its pane after being hidden and shown")


@requires_display
def test_repeated_visibility_toggles_are_idempotent(application):
    card = application.k8s_api_card
    holder = card._feather_card_holder
    for _ in range(3):
        application._set_card_visible(card, False)
        application._set_card_visible(card, False)
        application.update_idletasks()
        assert holder.winfo_manager() == ""
        application._set_card_visible(card, True)
        application._set_card_visible(card, True)
        application.update_idletasks()
        assert holder.winfo_manager() == "pack"


# --------------------------------------------------------------------------
# The style that was referenced but never defined
# --------------------------------------------------------------------------

@requires_display
def test_every_referenced_label_style_is_explicitly_configured(application):
    """An undefined dotted style silently inherits its base, with its colours.

    `FieldLabel.TLabel` was referenced once and never configured, so it
    inherited TLabel's BG_APP and painted a dark rectangle inside a BG_PANEL
    card. ttk gives no warning for this. Compare every referenced style name
    against the set actually configured in `_style`, rather than only checking
    that a background resolves -- inheritance means one always does.
    """
    import re

    layout_source = (ROOT / "feathered_app/ui/layout.py").read_text(encoding="utf-8")
    configured = set(re.findall(r'style\.configure\(\s*"([A-Za-z]+\.TLabel)"', layout_source))
    assert "FieldLabel.TLabel" in configured, (
        "FieldLabel.TLabel is referenced by panes.py but never configured; "
        "it will silently inherit TLabel's application background")

    referenced = set()
    for relative in ("feathered_app/ui/panes.py", "feathered_app/ui/layout.py",
                     "feathered_app/ui/kubernetes.py"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        referenced.update(re.findall(r'style=[\'"]([A-Za-z]+\.TLabel)[\'"]', text))

    missing = sorted(referenced - configured)
    assert not missing, (
        f"these label styles are used but never configured: {missing}. "
        "Each one inherits TLabel, including its background.")


@requires_display
def test_the_field_label_matches_the_card_it_sits_on(application):
    from feathered_app.context import BG_PANEL

    style = ttk.Style(application)
    assert style.lookup("FieldLabel.TLabel", "background").lower() == BG_PANEL.lower()
    row = application.mirror_conflict_row
    assert str(row.cget("background")).lower() == BG_PANEL.lower(), (
        "the mirror conflict row is painted with the application background "
        "again, which renders as a dark rectangle inside the card")


# --------------------------------------------------------------------------
# Differential baseline
# --------------------------------------------------------------------------

@requires_display
def test_clearing_the_baseline_refreshes_what_depended_on_it(application):
    """Clearing used to be a bare set(""), which traced to nothing."""
    calls = []
    application.baseline_var.set("/fixture/manifest.json")
    application._sync_output_capability_controls = lambda: calls.append("capability")

    application._clear_baseline()

    assert application.baseline_var.get() == ""
    assert "capability" in calls, "clearing did not refresh the derived controls"


@requires_display
def test_clearing_an_empty_baseline_does_nothing(application):
    calls = []
    application.baseline_var.set("")
    application._sync_output_capability_controls = lambda: calls.append("capability")
    application._clear_baseline()
    assert calls == []
