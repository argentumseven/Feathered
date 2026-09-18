"""Actually start the application.

Feathered shipped 1.2.7 with a NameError on line 293 of ui/layout.py: a constant
used in `_build_ui` without being imported. It crashed for every user on launch,
before the window appeared. 715 tests passed.

None of them constructed `App`. `ui/layout.py` carries 11% coverage, and the
uncovered 89% is the part that runs first. Every other test either drives a
`SimpleNamespace` stub or calls a mixin method unbound, so the composed class was
never built and `_build_ui` was never executed by anything except a user.

This module closes that. It is deliberately shallow -- construct, assert the
window exists, tear down -- because depth is not what was missing. Execution was.

Also asserted here: that the wizard's panes can each be shown. A pane builder
with the same class of error would otherwise fail only on the step that reaches
it, which for the later steps means after the operator has done real work.
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


def _display_available() -> bool:
    if sys.platform.startswith("win") or sys.platform == "darwin":
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


requires_display = pytest.mark.skipif(
    not _display_available(),
    reason="no display; run the suite under xvfb-run as the release gate does")


@pytest.fixture
def isolated_state(tmp_path, monkeypatch):
    """Keep the test out of the real per-user state directory."""
    for variable in ("APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(variable, str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(parents=True, exist_ok=True)
    return tmp_path


@pytest.fixture
def application(isolated_state):
    import app

    window = app.App()
    try:
        yield window
    finally:
        try:
            window.destroy()
        except tk.TclError:
            pass


@requires_display
def test_the_application_starts(application):
    """The test that would have caught the 1.2.7 startup NameError."""
    assert application.winfo_exists()


@requires_display
def test_the_footer_status_label_is_built_and_height_capped(application):
    """The specific widget whose construction crashed, and its guard."""
    from feathered_app.status_text import FOOTER_STATUS_LINES

    label = application.status_label
    assert label.winfo_exists()
    assert int(label.cget("height")) == FOOTER_STATUS_LINES


@requires_display
def test_a_long_status_cannot_grow_the_footer(application):
    """The behaviour the height cap exists for, measured rather than assumed."""
    application.update_idletasks()
    before = application.status_label.winfo_reqheight()

    application._set_footer_status("Unified mirror refused. " + "detail " * 400)
    application.update_idletasks()

    assert application.status_label.winfo_reqheight() == before


@requires_display
def test_every_wizard_pane_can_be_shown(application):
    """A pane that fails to build should fail here, not mid-workflow."""
    panes = list(getattr(application, "_pane_order", []) or application.panes.keys())
    assert panes, "the wizard must declare its panes"
    for name in panes:
        application.show_pane(name)
        application.update_idletasks()




@requires_display
def test_tooltip_is_destroyed_when_navigating_to_another_pane(application):
    application.show_pane("keyrings")
    label = tk.Label(application.panes["keyrings"], text="tooltip source")
    label.pack()
    application._attach_tooltip(label, "Testing...")
    application.update_idletasks()

    label.event_generate("<Enter>")
    application.update()
    windows = list(application.__dict__.get("_tooltip_windows", ()))
    assert len(windows) == 1
    tooltip = windows[0]
    assert tooltip.winfo_exists()

    application.show_pane("target")
    application.update()
    assert not application.__dict__.get("_tooltip_windows")
    assert not tooltip.winfo_exists()


@requires_display
def test_every_ui_refresh_method_survives_being_called(application):
    """The bug class, not the one instance of it.

    A NameError in a refresh handler surfaces only when a user reaches the
    control that calls it, which for later wizard steps means after real work.
    Calling them all is blunt, but the 1.2.7 startup crash showed that the
    suite's weakness was code no test executed at all, not code tested shallowly.
    """
    import inspect

    prefixes = ("_sync_", "_refresh_", "_update_", "_render_")
    probed, failures = [], []
    for name in sorted(dir(application)):
        if not name.startswith(prefixes):
            continue
        method = getattr(application, name, None)
        if not callable(method):
            continue
        try:
            signature = inspect.signature(method)
        except (TypeError, ValueError):
            continue
        if any(parameter.default is inspect.Parameter.empty
               and parameter.kind not in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD)
               for parameter in signature.parameters.values()):
            continue  # needs arguments; out of scope for a blind sweep
        probed.append(name)
        try:
            method()
            application.update_idletasks()
        except Exception as exc:  # noqa: BLE001 - the point is to catch anything
            failures.append(f"{name}: {type(exc).__name__}: {exc}")

    assert len(probed) > 30, "the sweep should reach most refresh handlers"
    assert not failures, "UI refresh handlers raised: " + "; ".join(failures)


@requires_display
def test_the_mirror_layout_controls_build_and_respond(application):
    """Controls added in 1.2.6/1.2.7 that no test had ever constructed."""
    from acquisition_model import MIRROR_LAYOUT_LABELS, MirrorLayout
    from mirror_unification import MERGE_POLICY_LABELS, MergePolicy

    application.mirror_layout_var.set(MIRROR_LAYOUT_LABELS[MirrorLayout.UNIFIED])
    application.mirror_conflict_policy_var.set(
        MERGE_POLICY_LABELS[MergePolicy.PREFER_PRIORITY])
    application._update_folder_preview()
    application.update_idletasks()

    assert application._mirror_layout() is MirrorLayout.UNIFIED
    assert application._merge_policy() is MergePolicy.PREFER_PRIORITY

    application.mirror_layout_var.set(MIRROR_LAYOUT_LABELS[MirrorLayout.SEPARATE])
    application._update_folder_preview()
    assert application._mirror_layout() is MirrorLayout.SEPARATE


@requires_display
def test_distribution_switch_clears_uncached_release_and_rebuilds_sources(application, monkeypatch):
    """Exercise the reported transition with the composed window and real callbacks."""
    from profiles import PROFILES

    window = application
    # No online discovery or cached release should determine this fixture.
    monkeypatch.setattr(window, "_auto_refresh_releases", lambda: None)
    monkeypatch.setattr(PROFILES["ubuntu"], "discovered_versions", [])
    window.distro_var.set(PROFILES["arch"].label)
    window._profile_changed()
    assert window.release_var.get() == "rolling"
    assert any(window._repo_tier(repo) == "base" for repo in window.transaction_repo_rows)

    window.distro_var.set(PROFILES["ubuntu"].label)
    window._profile_changed()
    assert window.release_var.get() == ""
    assert not any(window._repo_tier(repo) == "base" for repo in window.transaction_repo_rows)
    assert window.selected_packages == []
    assert window.loaded_packages == []
    assert window.last_result is None

    window.release_var.set("24.04")
    window._release_changed()
    base = [repo for repo in window.transaction_repo_rows if window._repo_tier(repo) == "base"]
    assert base
    assert all(repo.repo_format == "apt" and repo.target_release == "24.04" for repo in base)


@requires_display
def test_kubernetes_uses_content_version_axis_and_shows_repository_context(application, monkeypatch):
    from k8s_discovery import Observation
    from kubernetes_workflow import LABELS
    monkeypatch.setattr(application, '_discover_kubernetes_minors', lambda: None)
    monkeypatch.setattr(application, '_scan_k8s_patch_versions', lambda: None)
    application._k8s_observations = {'rpm': Observation(('1.33','1.32'),'test observation','fixture')}
    application.workload_var.set(LABELS['kubernetes-node'])
    application._workload_changed()
    assert application.package_version_label.cget('text') == 'Package patch / build'
    assert str(application.package_version_combo.cget('state')) == 'readonly'
    assert application.k8s_minor_var.get() == '1.33'
    assert application.k8s_api_card._feather_card_holder.winfo_manager() == 'pack'
    assert any('/v1.33/rpm/' in r.url for r in application.repo_rows)
    application.k8s_minor_var.set('1.32')
    rows = [r for r in application.repo_rows if r.role == 'kubernetes']
    assert len(rows) == 1 and '/v1.32/rpm/' in rows[0].url
    assert not hasattr(application, 'environment_var')


@requires_display
def test_discovery_failure_makes_version_editable_without_fallback_list(application, monkeypatch):
    from k8s_discovery import Observation
    from kubernetes_workflow import LABELS
    monkeypatch.setattr(application, '_discover_kubernetes_minors', lambda: None)
    monkeypatch.setattr(application, '_scan_k8s_patch_versions', lambda: None)
    application._k8s_observations = {'rpm': Observation((),'now','fixture','discovery failed')}
    application.workload_var.set(LABELS['kubernetes-client'])
    application._workload_changed()
    assert str(application.k8s_minor_combo.cget('state')) == 'normal'
    assert not application.k8s_minor_combo.cget('values')
    assert 'discovery failed' in application.k8s_observation_var.get()


@requires_display
def test_repeated_workload_changes_keep_controls_and_sources_in_sync(application, monkeypatch):
    from kubernetes_workflow import LABELS
    from k8s_discovery import Observation
    monkeypatch.setattr(application, '_discover_kubernetes_minors', lambda: None)
    monkeypatch.setattr(application, '_scan_k8s_patch_versions', lambda: None)
    application._k8s_observations = {'rpm': Observation(('1.33', '1.32'), 'fixture', 'fixture')}
    labels = list(application.workload_combo['values'])
    assert LABELS['kubernetes-node'] in labels
    for _ in range(3):
        for label in labels:
            application.workload_var.set(label)
            application._workload_changed()
            application._selection_mode_changed()
            application.update_idletasks()
            workload = application._workload()
            assert application.workload_panel.winfo_manager() == 'pack'
            assert application.workload_note.cget('text') == workload.description
            assert str(application.package_version_combo.cget('textvariable')) == str(application.package_version_var)
            assert application._repository_workflow_key == application._repository_workflow_key_for_target()
            active = workload.key in {'kubernetes-node', 'kubernetes-client'}
            assert bool(application.k8s_minor_controls.winfo_manager()) == active
            # Assert on the holder, not the inner frame. _card's accent heading
            # and bordered box live on the holder; the inner frame is always
            # packed inside that box. Checking the inner frame passed while the
            # heading stayed on screen for every non-Kubernetes workload.
            assert bool(application.k8s_api_card._feather_card_holder.winfo_manager()) == active
            if not workload.has_version_axis:
                assert application.package_version_var.get() == 'Follows repositories'
                assert str(application.package_version_combo.cget('state')) == 'disabled'


@requires_display
def test_patch_pin_survives_workload_switch_and_stale_results(application, monkeypatch):
    from kubernetes_workflow import LABELS
    from k8s_discovery import Observation
    monkeypatch.setattr(application, '_discover_kubernetes_minors', lambda: None)
    monkeypatch.setattr(application, '_scan_k8s_patch_versions', lambda: None)
    application._k8s_observations = {'rpm': Observation(('1.33', '1.32'), 'fixture', 'fixture')}
    application.workload_var.set(LABELS['kubernetes-client'])
    application._workload_changed()
    context = application._k8s_patch_context()
    application._receive_k8s_patch_versions(context, ['1.33.4-150500.1.1'], '')
    application.package_version_var.set('1.33.4-150500.1.1')
    application.workload_var.set('Docker Engine')
    application._workload_changed()
    application._receive_k8s_patch_versions(context, ['1.33.5-150500.1.1'], '')
    assert '1.33.5-150500.1.1' not in application.package_version_combo['values']
    application.workload_var.set(LABELS['kubernetes-client'])
    application._workload_changed()
    assert application.package_version_var.get() == '1.33.4-150500.1.1'
    application.k8s_minor_var.set('1.32')
    application._receive_k8s_patch_versions(context, ['1.33.6-150500.1.1'], '')
    assert application.package_version_var.get() == 'Latest'
    assert '1.33.6-150500.1.1' not in application.package_version_combo['values']


@requires_display
def test_progress_populates_minor_choices_without_overwriting_selection(application, monkeypatch):
    from kubernetes_workflow import LABELS
    from k8s_discovery import Observation
    monkeypatch.setattr(application, '_discover_kubernetes_minors', lambda: None)
    monkeypatch.setattr(application, '_scan_k8s_patch_versions', lambda: None)
    application.workload_var.set(LABELS['kubernetes-client'])
    application._workload_changed()
    application.k8s_minor_var.set('1.32')
    application._receive_k8s_observation('rpm', Observation(('1.34', '1.33'), 'fixture', 'fixture'), complete=False)
    assert '1.34' in application.k8s_minor_combo['values']
    assert 'checking for more' in application.k8s_observation_var.get()
    assert application.k8s_minor_var.get() == '1.32'
    application._receive_k8s_observation('rpm', Observation(('1.34', '1.33'), 'fixture', 'fixture'))
    assert application.k8s_minor_var.get() == '1.32'


@requires_display
def test_inventory_entry_uses_flat_readonly_colors(application):
    from feathered_app.context import BG_INPUT, LINE
    entry = application.inventory_entry
    assert entry.cget('readonlybackground') == BG_INPUT
    assert entry.cget('highlightbackground') == LINE
    assert str(entry.cget('relief')) == 'flat'
    assert int(entry.cget('borderwidth')) == 0
    application.inventory_var.set('C:/inventory/node-packages.txt')
    assert entry.get() == 'C:/inventory/node-packages.txt'


@requires_display
def test_incomplete_minor_does_not_break_workload_switching(application, monkeypatch):
    from kubernetes_workflow import LABELS
    monkeypatch.setattr(application, '_discover_kubernetes_minors', lambda: None)
    monkeypatch.setattr(application, '_scan_k8s_patch_versions', lambda: None)
    application.workload_var.set(LABELS['kubernetes-client'])
    application._workload_changed()
    application.k8s_minor_var.set('1.')
    for label in ['Docker Engine', LABELS['kubernetes-client'], 'Docker Engine']:
        application.workload_var.set(label)
        application._workload_changed()
        assert application.workload_note.cget('text') == application._workload().description
