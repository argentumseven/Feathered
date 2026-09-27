"""Headless Review projection rules and the real Tk application adapter."""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from acquisition_model import AcquisitionCapability as Cap, AcquisitionIntent as Intent
from feathered_app.review_projection import (
    ReviewMirrorSource, ReviewProjectionService as Review, ReviewRepository,
    ReviewRequestedPackage, ReviewSummaryInput, ReviewWorkload,
)


def _repo(*, tier="base", url=True, key=False, strategy="checksum-available",
          label="Verify what is available (basic)", evidence=False, vendor="", selected=False):
    return ReviewRepository(tier, url, key, strategy, label, evidence, vendor, selected)


def _summary(**overrides):
    defaults = dict(
        intent=Intent.WORKLOAD, capability=Cap.FULL_TRANSACTION, reason="",
        distribution="Arch", release="rolling", architecture="x86_64",
        repositories=(_repo(),), selected_package_count=0,
        workload_label="nginx", package_version="Follows repositories",
        vendor_signature_profiles={}, signing_key_configured=False,
        baseline_configured=False, mode="Include dependencies",
        requires_distribution_sources=True, output_path="C:/airgap/bundle",
    )
    defaults.update(overrides)
    return Review.summary(ReviewSummaryInput(**defaults))


def test_exact_package_roots_are_independent_of_workload():
    roots = Review.requested_roots(intent=Intent.PACKAGES,
        exact_packages=(ReviewRequestedPackage("nginx-1", "Arch extra"),
                        ReviewRequestedPackage("lz4-1:1.10-2", "Arch core")))
    assert roots == [("nginx-1", "requested", "Arch extra", "explicit package selection"),
                     ("lz4-1:1.10-2", "requested", "Arch core", "explicit package selection")]


def test_mirror_roots_keep_identity_and_only_receive_redacted_urls():
    roots = Review.requested_roots(intent=Intent.REPOSITORY_MIRROR,
        mirrors=(ReviewMirrorSource("same label", "https://mirror.test/a"),
                 ReviewMirrorSource("same label", "https://mirror.test/b")))
    assert roots == [
        ("same label", "selected", "https://mirror.test/a", "repository selected for mirroring"),
        ("same label", "selected", "https://mirror.test/b", "repository selected for mirroring"),
    ]


@pytest.mark.parametrize("workload,reason", [
    (ReviewWorkload("plain"), "requested by plain"),
    (ReviewWorkload("custom", custom=True), "custom package request"),
    (ReviewWorkload("Kubernetes", custom=True, contextual_packages=True), "VKS node OS package addition"),
])
def test_workload_contract_preserves_reason_and_version(workload, reason):
    rows = Review.requested_roots(intent=Intent.WORKLOAD, workload=workload,
                                  requests=(("nginx", "1.4"), ("brotli", None)))
    assert rows == [("nginx 1.4", "requested", "enabled repositories", reason),
                    ("brotli", "requested", "enabled repositories", reason)]


def test_workload_without_materialized_plan_has_no_contract():
    assert Review.requested_roots(intent=Intent.WORKLOAD) == []


def test_full_transaction_summary_and_missing_base_policy():
    normal = _summary()
    assert normal.labels["Selection"] == "nginx · Follows repositories · Include dependencies"
    assert normal.labels["Output"] == "Full transaction bundle"
    assert normal.labels["Sources"] == "1 enabled, 1 distribution/base source(s)"
    assert normal.labels["Bundle path"] == "C:/airgap/bundle"
    assert normal.labels["Verification"] == "0/1 sources with archive keys | Verify what is available (basic)"
    assert not normal.source_warning and not normal.output_warning
    absent = _summary(repositories=(_repo(tier="additional"),))
    assert absent.labels["Sources"].endswith("add a base source")
    assert absent.source_warning
    allowed = _summary(repositories=(_repo(tier="additional"),), requires_distribution_sources=False)
    assert not allowed.source_warning
    assert "add a base source" not in allowed.labels["Sources"]


def test_package_only_does_not_claim_dependency_completeness():
    package_only = _summary(intent=Intent.PACKAGES, capability=Cap.PACKAGE_ONLY,
                            reason="no base index", repositories=(_repo(tier="additional"),),
                            selected_package_count=2)
    assert package_only.labels["Selection"] == "2 exact package(s) · package-only acquisition"
    assert package_only.labels["Output"] == "Package-only artifacts; dependency completeness not derived"
    assert package_only.labels["Sources"].endswith("no base index")
    assert package_only.source_warning and package_only.output_warning


def test_mirror_selection_and_explicit_output_paths():
    mirror = _summary(intent=Intent.REPOSITORY_MIRROR, capability=Cap.REPOSITORY_MIRROR,
        repositories=(_repo(selected=True), _repo(tier="additional", selected=False)),
        mirror_output_paths=("C:/airgap/core", "C:/airgap/extra"))
    assert mirror.labels["Selection"] == "Mirror 1 repository/repositories"
    assert mirror.labels["Bundle path"] == "C:/airgap/core\nC:/airgap/extra"
    assert mirror.labels["Output"] == "Repository mirror; package-root dependency closure does not apply"
    assert _summary(intent=Intent.REPOSITORY_MIRROR, capability=Cap.REPOSITORY_MIRROR,
                    mirror_output_paths=()).labels["Bundle path"] == "-"


def test_blocked_state_preserves_failure_reason():
    blocked = _summary(capability=Cap.BLOCKED, reason="No permitted source")
    assert blocked.labels["Sources"] == "No permitted source"
    assert blocked.labels["Output"].startswith("Blocked until")


def test_multiple_verification_strategies_and_duplicate_vendor_profiles():
    result = _summary(repositories=(
        _repo(key=True, strategy="full-corroboration", label="Maximum", evidence=True, vendor="acme"),
        _repo(tier="workload", strategy="checksum-required", label="Strict", vendor="acme"),
        _repo(tier="additional", strategy="checksum-required", label="Strict", vendor="other")),
        vendor_signature_profiles={"acme": {"keyring": "  vendor.asc ", "policy": "require"},
                                   "other": {"policy": "require"}},
        signing_key_configured=True)
    text = result.labels["Verification"]
    assert "1/3 sources with archive keys" in text
    assert "mixed verification strategies" in text
    assert "1 evidence source(s) configured" in text
    assert "1 vendor keyring profile(s)" in text
    assert "signatures required for 2 vendor(s)" in text
    assert text.endswith("bundle signed")


def test_baseline_warning_and_target_platform_note():
    result = _summary(baseline_configured=True, platform_note="Use matching kernel")
    assert result.labels["Output"] == "Differential against a baseline"
    assert result.output_warning
    assert result.labels["Linux Distribution"] == "Arch rolling (x86_64)\nPlatform note: Use matching kernel"


def test_empty_repositories_use_existing_mixed_strategy_fallback():
    result = _summary(repositories=(), output_path="")
    assert result.labels["Verification"] == "0/0 sources with archive keys | mixed verification strategies"
    assert result.labels["Bundle path"] == "-"


def test_summary_does_not_mutate_or_share_output_across_calls():
    original = _summary()
    updated = _summary(selected_package_count=3, intent=Intent.PACKAGES)
    assert original.labels["Selection"] != updated.labels["Selection"]
    assert original.labels["Selection"] == "nginx · Follows repositories · Include dependencies"


def test_mirror_contract_adapter_redacts_credentials_and_filters_unselected():
    from types import SimpleNamespace
    from feathered_app.application.selection import SelectionMixin
    host = SimpleNamespace(
        _ui_acquisition_state=lambda: SimpleNamespace(intent=Intent.REPOSITORY_MIRROR),
        repo_rows=[SimpleNamespace(name="duplicate", url="https://user:secret@mirror.test/first"),
                   SimpleNamespace(name="duplicate", url="https://mirror.test/second"),
                   SimpleNamespace(name="disabled", url="")],
        _mirror_repo_selected=lambda repo: repo.url.endswith("first"),
    )
    rows = SelectionMixin._review_contract_rows(host)
    assert len(rows) == 1
    assert rows[0][0] == "duplicate"
    assert "secret" not in rows[0][2]
    assert "mirror.test/first" in rows[0][2]


def test_headless_module_import_does_not_initialize_tk():
    snippet = ("import sys; import feathered_app.review_projection; "
               "assert 'tkinter' not in sys.modules")
    subprocess.run([sys.executable, "-c", snippet], check=True)


@pytest.mark.skipif(sys.platform.startswith("linux") and
                    not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
                    reason="requires a virtual or desktop display")
def test_real_gui_review_summary_uses_projection_and_preserves_widget_contract(tmp_path, monkeypatch):
    for key in ("APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(key, str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    from app import App
    app = App()
    try:
        captured = []
        original = Review.summary
        def capture(data):
            captured.append(data)
            return original(data)
        monkeypatch.setattr(Review, "summary", staticmethod(capture))
        app.show_pane("review")
        app._refresh_review_summary()
        assert captured and all(isinstance(data.repositories, tuple) for data in captured)
        for label in ("Linux Distribution", "Sources", "Selection", "Verification", "Bundle path", "Output"):
            assert app.review_labels[label].cget("text")
        assert "sources with archive keys" in app.review_labels["Verification"].cget("text")
    finally:
        app.destroy()
