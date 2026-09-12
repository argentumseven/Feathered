"""Derive target, package-family, and acquisition intent from a build request.

This module determines the selected distribution profile, package family,
workload/package/mirror mode, and mirror layout/disagreement policy.

Like feathered_app/build_request.py this imports no Tk, enforced by
tests/test_build_request_module.py. Every accessor here prefers the frozen
request while a build is running and falls back to the live control otherwise,
which is what lets the same code serve the wizard and the worker.

The domain enums and label mappings come from acquisition_model,
mirror_unification and profiles -- all already Tk-free -- rather than from
feathered_app.context, which pulls in the widget toolkit.
"""
from __future__ import annotations

from acquisition_model import (AcquisitionCapability, AcquisitionIntent, AcquisitionState,
                               AnalysisType, MirrorLayout, PublicationType, VerificationScope,
                               derive_acquisition_state, intent_from_selection_mode,
                               mirror_layout_from_label)
from mirror_unification import MergePolicy, merge_policy_from_label
from feathered_app.build_request import BuildRequestMixin
from profiles import profile_by_label
from source_readiness import evaluate_source_readiness
from workloads import workload_by_label


class BuildIntentMixin:
    """Derivations of the operator's selection. No widget access."""

    def _profile(self):
        """The selected distribution profile.

        Reached from the worker thread on nearly every build step -- family
        predicates, backend dispatch, metadata construction -- so it takes the
        frozen request while a build is running. Previously this read distro_var
        directly, and the resulting "main thread is not in main loop" was caught
        by the per-repository handler in _load_enabled_repos and reported as
        "source could not be read", which looks exactly like an unreachable
        repository rather than a defect.
        """
        frozen = getattr(self, "_build_snapshot_value", None)
        label = frozen("target", "distribution") if callable(frozen) else None
        if label is None:
            label = self.distro_var.get()
        return profile_by_label(label)

    def _is_deb(self):
        return self._profile().package_family == "deb"

    def _is_arch(self):
        return self._profile().package_family == "arch"

    def _acquisition_intent(self) -> AcquisitionIntent:
        # Keep state derivation usable with BuildIntentMixin.__new__(App) in headless tests.
        # tkinter.Tk.__getattr__ recurses when no interpreter exists, so domain
        # state reads use __dict__ directly.
        # While a build is running this comes from the frozen request rather
        # than the widget: the worker thread reaches here, and Tk variables are
        # not safe to read off the main thread.
        frozen = getattr(self, "_build_snapshot_value", None)
        mode = frozen("content", "selection_mode") if callable(frozen) else None
        var = self.__dict__.get("selection_mode_var")
        if mode is not None:
            intent = intent_from_selection_mode(mode)
        elif var is not None:
            intent = intent_from_selection_mode(var.get())
        if mode is not None or var is not None:
            if intent is AcquisitionIntent.WORKLOAD:
                # The "Custom packages" preset is exact-package acquisition by
                # another name: the operator picks arbitrary package identities.
                # Deriving PACKAGES here routes it through the one shared
                # workflow (repositories first, then the exact-package chooser
                # on Repositories) rather than a diverging custom layout.
                try:
                    if self._workload().custom:
                        return AcquisitionIntent.PACKAGES
                except Exception:
                    pass
            return intent
        mirror_override = self.__dict__.get("_mirror_mode")
        if callable(mirror_override) and mirror_override():
            return AcquisitionIntent.REPOSITORY_MIRROR
        single_override = self.__dict__.get("_single_mode")
        if callable(single_override) and single_override():
            return AcquisitionIntent.PACKAGES
        return AcquisitionIntent.WORKLOAD

    def _mirror_mode(self) -> bool:
        """Mirror every package in the chosen repositories, not a closure."""
        return self._acquisition_intent() is AcquisitionIntent.REPOSITORY_MIRROR

    def _unified_mirror_mode(self) -> bool:
        return self._mirror_mode() and self._mirror_layout() is MirrorLayout.UNIFIED

    def _single_mode(self):
        """True when the operator is picking exact packages rather than a preset."""
        return self._acquisition_intent() is AcquisitionIntent.PACKAGES

    def _mirror_layout(self) -> MirrorLayout:
        """Which mirror publication layout the operator selected.

        Frozen request first: the worker thread reaches this through the mirror
        publication path, and mirror_layout_var is a Tk variable.
        """
        frozen = getattr(self, "_build_snapshot_value", None)
        pinned = frozen("mirror", "layout") if callable(frozen) else None
        if pinned is not None:
            return (MirrorLayout.UNIFIED if pinned == MirrorLayout.UNIFIED.value
                    else MirrorLayout.SEPARATE)
        var = self.__dict__.get("mirror_layout_var")
        if var is None:
            return MirrorLayout.SEPARATE
        try:
            return mirror_layout_from_label(var.get())
        except Exception:
            return MirrorLayout.SEPARATE

    def _merge_policy(self) -> MergePolicy:
        """How to treat repositories that cannot be proven to agree.

        Absent or unreadable control means STRICT: an unset preference must
        never be read as permission to merge unchecked artifacts. The frozen
        request is preferred while a build runs, for thread safety.
        """
        frozen = getattr(self, "_build_snapshot_value", None)
        pinned = frozen("mirror", "disagreement_policy") if callable(frozen) else None
        if pinned is not None:
            return (MergePolicy.PREFER_PRIORITY
                    if pinned == MergePolicy.PREFER_PRIORITY.value else MergePolicy.STRICT)
        var = self.__dict__.get("mirror_conflict_policy_var")
        if var is None:
            return MergePolicy.STRICT
        try:
            return merge_policy_from_label(var.get())
        except Exception:
            return MergePolicy.STRICT

    def _workload(self):
        """The selected workload preset.

        Prefers the frozen request while a build is running: this is reached
        from the worker thread via _acquisition_intent, and workload_var is a Tk
        variable. Outside a build it reads the live control, so the wizard keeps
        reflecting what the operator has selected.
        """
        frozen = getattr(self, "_build_snapshot_value", None)
        label = frozen("content", "workload") if callable(frozen) else None
        if label is None:
            # __dict__ read, not attribute access: tkinter.Misc.__getattr__
            # recurses on a partially constructed instance, which is how this
            # surfaced as a RecursionError rather than an AttributeError.
            label = BuildRequestMixin._live_value(self, "workload_var")
        # Reach the catalogue without attribute access: tkinter.Misc.__getattr__
        # recurses on a partially constructed instance. A host that has not
        # loaded workloads yet has no preset to return, which is not the same as
        # having none configured, so fall back to the class attribute first.
        catalogue = self.__dict__.get("workloads")
        if catalogue is None:
            catalogue = getattr(type(self), "workloads", None) or {}
        return workload_by_label(catalogue, label)

    def _selected_mirror_repositories(self):
        """Return selected mirror repositories in their visible/configured order."""
        return [r for r in self.repo_rows
                if str(getattr(r, "url", "") or "").strip() and self._mirror_repo_selected(r)]

    def _mirror_repo_selected(self, repo) -> bool:
        source_id = getattr(repo, "source_identity", getattr(repo, "name", ""))
        pinned = BuildRequestMixin._build_snapshot_value(self, "mirror", "selected_repositories")
        selected = pinned if pinned is not None else self.__dict__.get("mirror_repos", set())
        return source_id in selected

    def _active_source_method(self) -> str:
        mirror = self._mirror_mode()
        field = "mirror_method" if mirror else "method"
        variable = "mirror_source_method_var" if mirror else "source_method_var"
        pinned = BuildRequestMixin._build_snapshot_value(self, "sources", field)
        if pinned is not None:
            return str(pinned)
        if mirror and self.__dict__.get(variable) is None:
            variable = "source_method_var"
        return BuildRequestMixin._live_value(self, variable)

    def _pick_mode(self) -> bool:
        """Package selection is always reviewable after an analysis.

        This was first an entry in the dependency-policy dropdown and then a
        checkbox; both meant an analysis run without it could not be reviewed
        without recomputing the closure. Mirror mode is excluded because its
        whole point is copying repositories wholesale.
        """
        return not self._mirror_mode()

