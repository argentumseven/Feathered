"""Headless wizard policy and real GUI adapter contract regression tests."""
from __future__ import annotations

import pytest

from acquisition_model import AcquisitionIntent
from feathered_app.wizard_navigation import WizardNavigationService as Wizard


STAGES = ("target", "packages", "repositories", "keyrings", "transfer", "review")


@pytest.mark.parametrize("intent,label", [
    (AcquisitionIntent.PACKAGES, "Next: configure repositories  ›"),
    (AcquisitionIntent.REPOSITORY_MIRROR, "Next: choose repositories  ›"),
    (AcquisitionIntent.WORKLOAD, "Next: repositories  ›"),
])
def test_packages_next_label_depends_only_on_intent(intent, label):
    nav = Wizard.navigation(STAGES, "packages", intent=intent)
    assert nav.next_visible
    assert nav.next_label == label
    assert nav.back_enabled
    assert nav.header == "Step 2 of 6"


def test_navigation_boundaries_and_sidecar():
    first = Wizard.navigation(STAGES, "target")
    assert not first.back_enabled and first.next_visible
    final = Wizard.navigation(STAGES, "review")
    assert final.back_enabled and not final.next_visible
    assert Wizard.next_stage(STAGES, "transfer") == "review"
    assert Wizard.next_stage(STAGES, "review") is None
    tool = Wizard.navigation(STAGES, "tools")
    assert not tool.in_wizard and tool.back_enabled and not tool.next_visible
    assert tool.header == "Repository utilities"
    assert Wizard.next_stage(STAGES, "tools") is None
    assert Wizard.navigation((), "tools").next_visible is False


@pytest.mark.parametrize("release,architecture,expected", [
    ("", "x86_64", "release"), ("  ", "x86_64", "release"),
    ("2026.09", " ", "architecture"),
])
def test_target_requires_release_and_architecture(release, architecture, expected):
    with pytest.raises(RuntimeError, match=expected):
        Wizard.validate_target(release=release, architecture=architecture)


def test_target_accepts_whitespace_padded_valid_values():
    Wizard.validate_target(release=" 2026.09 ", architecture=" x86_64 ")


def test_repository_gate_preserves_reason_and_fallback():
    with pytest.raises(RuntimeError, match="Missing distribution sources"):
        Wizard.validate_repositories(blocked=True, reason="Missing distribution sources")
    with pytest.raises(RuntimeError, match="cannot proceed"):
        Wizard.validate_repositories(blocked=True, reason="")
    Wizard.validate_repositories(blocked=False, reason="stale error from earlier build")


def test_review_gate_rejects_empty_contract():
    with pytest.raises(RuntimeError, match="Nothing is selected"):
        Wizard.validate_review_contract(has_contract=False)
    Wizard.validate_review_contract(has_contract=True)


@pytest.mark.parametrize("pane,intent,missing,message,expected", [
    ("repositories", AcquisitionIntent.PACKAGES, ("distribution",), "", "exact_package_selection_card"),
    ("repositories", AcquisitionIntent.REPOSITORY_MIRROR, (), "", "mirror_selection_card"),
    ("repositories", AcquisitionIntent.WORKLOAD, ("distribution",), "", "base_sources_card"),
    ("repositories", AcquisitionIntent.WORKLOAD, ("enabled",), "", "base_sources_card"),
    ("repositories", AcquisitionIntent.WORKLOAD, ("workload",), "", "workload_repositories_card"),
    ("keyrings", None, (), "Missing entitlement", "entitlement_tree"),
    ("keyrings", None, (), "Missing private key", "entitlement_tree"),
    ("keyrings", None, (), "Repository CA missing", "entitlement_tree"),
    ("keyrings", None, (), "Missing checksum evidence", "prov_digest_combo"),
    ("keyrings", None, (), "Signature evidence missing", "prov_evidence_card"),
    ("packages", None, (), "invalid package", "package_selection_card"),
    ("transfer", None, (), "invalid folder", "folder_label_entry"),
    ("target", None, (), "missing arch", None),
])
def test_failure_focus_is_semantic_not_a_widget(pane, intent, missing, message, expected):
    assert Wizard.focus_key(pane, intent=intent, missing_scopes=missing, message=message) == expected


@pytest.mark.parametrize("pane,profile,source,message,has_base,expected", [
    ("keyrings", "rhel", "Red Hat CDN entitlement (official)", "Missing entitlement", False, "rhel-entitlement"),
    ("repositories", "rhel", "Red Hat CDN entitlement (official)", "Missing repository CA", True, "rhel-entitlement"),
    ("keyrings", "rhel", "Red Hat CDN entitlement (official)", "Checksum not available", False, None),
    ("keyrings", "fedora", "Red Hat CDN entitlement (official)", "Missing entitlement", False, None),
    ("repositories", "arch", "Installation media / local mirror (ISO, DVD, folder, SMB)", "not loaded", False, "local-media"),
    ("keyrings", "deb", "Installation media / local mirror (ISO, DVD, folder, SMB)", "not loaded", False, "local-media"),
    ("repositories", "arch", "Installation media / local mirror (ISO, DVD, folder, SMB)", "not loaded", True, None),
    ("transfer", "arch", "Installation media / local mirror (ISO, DVD, folder, SMB)", "not loaded", False, None),
    ("keyrings", "deb", "Custom repositories", "missing base", False, "custom-base"),
    ("repositories", "deb", "Custom repositories", "missing base", True, None),
    ("target", "deb", "Custom repositories", "missing base", False, None),
])
def test_recovery_is_explicit_and_only_offered_when_applicable(
        pane, profile, source, message, has_base, expected):
    assert Wizard.recovery_policy(
        pane=pane, profile_key=profile, source_method=source,
        message=message, has_enabled_base=has_base) == expected


@pytest.mark.parametrize("profile,family,expected", [
    ("rhel", "rpm", "Red Hat CDN entitlement (official)"),
    ("debian", "deb", "Distribution APT repositories"),
    ("arch", "arch", "Distribution pacman repositories"),
    ("fedora", "rpm", "Distribution repositories"),
])
def test_default_network_sources(profile, family, expected):
    assert Wizard.default_network_source_method(profile_key=profile, package_family=family) == expected


def test_service_import_does_not_import_tkinter_in_clean_interpreter():
    import subprocess
    import sys
    script = ("import sys; import feathered_app.wizard_navigation; "
              "assert 'tkinter' not in sys.modules")
    subprocess.run([sys.executable, "-c", script], check=True)


def test_real_gui_navigation_and_target_guard(application, monkeypatch):
    from app import messagebox
    failures = []
    monkeypatch.setattr(messagebox, "showerror", lambda *_args: failures.append(_args))
    application.show_pane("target")
    application.release_var.set(" ")
    assert application.go_next() is False
    assert application.active_pane == "target"
    assert failures and "release" in failures[-1][-1]
    application.release_var.set("2026.09")
    application.arch_var.set(" ")
    assert application.go_next() is False
    assert "architecture" in failures[-1][-1]
    application.arch_var.set("x86_64")
    assert application.go_next() is True
    assert application.active_pane == "packages"


def test_real_gui_legacy_navigation_buttons_and_sidecar(application):
    application.show_pane("target")
    assert str(application.back_btn.cget("state")) == "disabled"
    application.show_pane("packages")
    assert str(application.back_btn.cget("state")) == "normal"
    application.show_pane("review")
    assert str(application.next_btn.winfo_manager()) == ""
    assert application.go_next() is False
    application.show_pane("tools")
    assert "Return to build" in application.back_btn.cget("text")


def test_real_gui_custom_repository_recovery_changes_only_on_choice(application, monkeypatch):
    from app import messagebox
    choices = iter(("custom", "defaults"))
    monkeypatch.setattr(messagebox, "askchoice", lambda *args, **kwargs: next(choices))
    changes = []
    monkeypatch.setattr(application, "_source_method_changed", lambda: changes.append(True))
    monkeypatch.setattr(application, "_repo_tier", lambda repo: "base")
    application.repo_rows = []
    application.source_method_var.set("Custom repositories")
    assert application._recover_wizard_transition("repositories", "No base source") is True
    assert application.source_method_var.get() == "Custom repositories"
    assert not changes
    # Showing Repositories can repopulate its defaults; isolate the second
    # decision by restoring the deliberately empty source set.
    application.repo_rows = []
    assert application._recover_wizard_transition("repositories", "No base source") is True
    assert application.source_method_var.get() == application._default_network_source_method()
    assert changes == [True]

@pytest.fixture
def application(tmp_path, monkeypatch):
    import os
    if os.name != "nt" and not os.environ.get("DISPLAY"):
        pytest.skip("GUI adapter tests need xvfb-run on Linux")
    monkeypatch.setenv("APPDATA", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(parents=True, exist_ok=True)
    from app import App
    window = App()
    try:
        yield window
    finally:
        window.destroy()
