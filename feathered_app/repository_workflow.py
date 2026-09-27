"""Headless routing and cache identity for the Repositories wizard page.

The GUI collects current target and content selections once; route selection and
view identity are deterministic functions of that snapshot. Tk controls and pane
construction remain in PaneMixin.
"""
from __future__ import annotations

from acquisition_model import AcquisitionIntent


class RepositoryWorkflowService:
    @staticmethod
    def mode(intent: AcquisitionIntent, *, contextual_packages: bool = False) -> str:
        if intent is AcquisitionIntent.REPOSITORY_MIRROR:
            return "mirror"
        if intent is AcquisitionIntent.PACKAGES:
            return "packages"
        return "contextual-packages" if contextual_packages else "workload"

    @staticmethod
    def cache_key(*, mode: str, workload: str = "", profile: str = "",
                  release: str = "", architecture: str = "", init_system: str = "") -> str:
        """Include the full visible target so stale repository panes are rebuilt."""
        return "|".join((mode, "" if mode == "mirror" else workload,
                         profile, release.strip(), architecture.strip(), init_system))
