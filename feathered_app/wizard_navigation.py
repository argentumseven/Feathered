"""Headless decisions for wizard navigation, prerequisites, and error recovery.

LayoutMixin owns widgets, focus and dialog presentation. This module accepts
plain snapshots, never an App, Tk variable or repository object; navigation
policy can consequently be exercised without initializing a desktop window.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Collection, Sequence

from acquisition_model import AcquisitionIntent


@dataclass(frozen=True)
class NavigationView:
    """Presentation-independent state for the Next/Back navigation controls."""

    in_wizard: bool
    back_label: str
    back_enabled: bool
    next_visible: bool
    next_label: str
    header: str


class WizardNavigationService:
    """Deterministic wizard rules; external validators remain with their owners."""

    @staticmethod
    def navigation(stage_order: Sequence[str], active: str,
                   *, intent: AcquisitionIntent | None = None) -> NavigationView:
        if active not in stage_order:
            return NavigationView(False, "‹  Return to build", True, False,
                                  "Next  ›", "Repository utilities")
        index = stage_order.index(active)
        is_last = index == len(stage_order) - 1
        next_label = "Next  ›"
        if active == "packages":
            if intent is AcquisitionIntent.PACKAGES:
                next_label = "Next: configure repositories  ›"
            elif intent is AcquisitionIntent.REPOSITORY_MIRROR:
                next_label = "Next: choose repositories  ›"
            else:
                next_label = "Next: repositories  ›"
        return NavigationView(True, "‹  Back", index > 0, not is_last,
                              "Next  ›" if is_last else next_label,
                              f"Step {index + 1} of {len(stage_order)}")

    @staticmethod
    def next_stage(stage_order: Sequence[str], active: str) -> str | None:
        if active not in stage_order:
            return None
        index = stage_order.index(active)
        return stage_order[index + 1] if index + 1 < len(stage_order) else None

    @staticmethod
    def validate_target(*, release: str, architecture: str) -> None:
        if not release.strip():
            raise RuntimeError("Choose or enter a Linux release before continuing.")
        if not architecture.strip():
            raise RuntimeError("Choose a target architecture before continuing.")

    @staticmethod
    def validate_repositories(*, blocked: bool, reason: str) -> None:
        if blocked:
            raise RuntimeError(
                reason or "The selected acquisition cannot proceed with the current repositories.")

    @staticmethod
    def validate_review_contract(*, has_contract: bool) -> None:
        if not has_contract:
            raise RuntimeError(
                "Nothing is selected for this build. Return to Content/Repositories "
                "and complete the acquisition request before Review.")

    @staticmethod
    def focus_key(pane: str, *, intent: AcquisitionIntent | None = None,
                  missing_scopes: Collection[str] = (), message: str = "") -> str | None:
        """Return a logical focus target; callers resolve it to a widget."""
        if pane == "repositories":
            if intent is AcquisitionIntent.PACKAGES:
                return "exact_package_selection_card"
            if intent is AcquisitionIntent.REPOSITORY_MIRROR:
                return "mirror_selection_card"
            if "distribution" in missing_scopes or "enabled" in missing_scopes:
                return "base_sources_card"
            return "workload_repositories_card"
        if pane == "keyrings":
            lower = message.lower()
            if any(token in lower for token in ("entitlement", "private key", "repository ca")):
                return "entitlement_tree"
            return "prov_digest_combo" if "checksum" in lower else "prov_evidence_card"
        return {
            "packages": "package_selection_card",
            "transfer": "folder_label_entry",
        }.get(pane)

    @staticmethod
    def recovery_policy(*, pane: str, profile_key: str, source_method: str,
                        message: str, has_enabled_base: bool) -> str | None:
        """Identify an available alternate source policy, without showing UI."""
        lower = message.lower()
        if (profile_key == "rhel" and source_method == "Red Hat CDN entitlement (official)"
                and any(token in lower for token in ("entitlement", "private key", "repository ca"))):
            return "rhel-entitlement"
        if pane not in {"repositories", "keyrings"} or has_enabled_base:
            return None
        if source_method == "Installation media / local mirror (ISO, DVD, folder, SMB)":
            return "local-media"
        if source_method == "Custom repositories":
            return "custom-base"
        return None

    @staticmethod
    def default_network_source_method(*, profile_key: str, package_family: str) -> str:
        if profile_key == "rhel":
            return "Red Hat CDN entitlement (official)"
        if package_family == "deb":
            return "Distribution APT repositories"
        if package_family == "arch":
            return "Distribution pacman repositories"
        return "Distribution repositories"
