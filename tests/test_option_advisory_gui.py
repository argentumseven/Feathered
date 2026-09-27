"""Dropdown beta/incompatible marking on a real Tk root (runs under Xvfb in CI)."""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

import pytest

from feathered_app.option_advisory import OptionStatus, classify_release
from feathered_app.ui.option_marking import PRERELEASE_BG, attach_option_marker


@pytest.fixture
def gui(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path))
    import app
    try:
        root = app.App()
    except tk.TclError as exc:  # pragma: no cover - headless host without a display
        pytest.skip(f"Tk display unavailable: {exc}")
    root.withdraw()
    root.update_idletasks()
    yield root
    root.destroy()


def _pump(root, rounds=5):
    for _ in range(rounds):
        root.update()


def test_popdown_rows_are_tagged_and_selection_keeps_raw_value(gui):
    var = tk.StringVar(master=gui, value="26.04")
    combo = ttk.Combobox(gui, textvariable=var, values=["26.10", "26.04", "24.04"], state="readonly")
    combo.pack()
    marker = attach_option_marker(
        combo, lambda v: classify_release("ubuntu", v, prerelease={"26.10"}), variable=var)
    gui.deiconify(); _pump(gui)
    gui.tk.call("ttk::combobox::Post", combo)
    _pump(gui)
    listbox = marker._listbox()
    try:
        assert listbox.get(0).startswith("26.10") and "beta" in listbox.get(0)
        assert listbox.get(1) == "26.04"
        assert listbox.itemcget(0, "background").lower() == PRERELEASE_BG.lower()
        assert listbox.itemcget(1, "background").lower() != PRERELEASE_BG.lower()
        listbox.selection_clear(0, "end"); listbox.selection_set(0)
        gui.tk.call("ttk::combobox::LBSelected", listbox.path)
        _pump(gui)
    finally:
        gui.tk.call("ttk::combobox::Unpost", combo)
    # The display tag never leaks into the stored value.
    assert var.get() == "26.10"
    assert str(combo.cget("style")) == "Prerelease.TCombobox"
    var.set("26.04")
    assert str(combo.cget("style")) == "TCombobox"
    # Validation highlighting owns its style; the marker must not replace it.
    combo.configure(style="Attention.TCombobox")
    var.set("26.10")
    assert str(combo.cget("style")) == "Attention.TCombobox"


def test_ubuntu_defaults_to_stable_release_and_explains_beta(gui):
    from profiles import PROFILES
    ubuntu = PROFILES["ubuntu"]
    ubuntu.discovered_versions = ["26.10", "26.04", "24.04"]
    ubuntu.prerelease_versions = ["26.10"]
    gui.distro_var.set(PROFILES["rhel"].label); gui._profile_changed()
    gui.distro_var.set(ubuntu.label); gui._profile_changed()
    assert gui.release_var.get() == "26.04"
    assert gui.release_advisory.cget("text") == ""
    gui.release_var.set("26.10")
    text = gui.release_advisory.cget("text")
    assert "Beta" in text and "26.04" in text
    gui._set_release_choices(["26.10", "26.04"], keep_current=False)
    assert gui.release_var.get() == "26.04"


def test_init_precluded_workload_is_marked_until_a_compatible_source_exists(gui, monkeypatch):
    import profiles
    from profiles import PROFILES
    from repository_config import RepoSpec
    monkeypatch.setitem(profiles.DEVUAN_TO_DEBIAN, "excalibur", "trixie")
    devuan = PROFILES["devuan"]
    devuan.discovered_versions = ["excalibur"]
    gui.distro_var.set(devuan.label); gui._profile_changed()
    gui.init_system_var.set("sysvinit"); gui._release_changed()
    advice = gui._workload_option_advice("Docker Engine")
    assert advice.status is OptionStatus.INCOMPATIBLE and "sysvinit" in advice.reason
    assert gui._workload_option_advice("Web server - nginx").stable
    assert gui._default_workload_label() != "Docker Engine"
    custom = RepoSpec("Local docker", "https://docker-mirror.invalid/devuan", role="docker",
                      repo_format="apt")
    gui.repo_rows.append(custom)
    assert gui._workload_option_advice("Docker Engine").stable
    gui.distro_var.set(PROFILES["rhel"].label); gui._profile_changed()
    assert gui._workload_option_advice("Docker Engine").stable
