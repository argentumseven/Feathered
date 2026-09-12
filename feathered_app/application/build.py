"""Repository scoping, request construction, build options, and build orchestration.

"""

from feathered_app.build_preparation import BuildPreparationMixin, prepare_job, DecisionDeclined

from feathered_app import build_runner
from feathered_app.build_request import BuildRequestMixin, _SnapshotMode
from feathered_app.build_sources import BuildSourcesMixin
from feathered_app.context import (
    APP_TITLE,
    AcquisitionCapability,
    AcquisitionIntent,
    BuildOptions,
    copy,
    Cancelled,
    MaterializedWorkload,
    Optional,
    Path,
    Reporter,
    evaluate_source_readiness,
    intent_from_selection_mode,
    missing_reachable_scopes,
    re,
    redact_text,
    mirror_sources_record,
    redact_url,
    repository_verification_strategy,
    unified_mirror_note,
    threading,
    tk,
    traceback,
    workload_resolution,
)
from feathered_app.ui.theme import messagebox


def _indexed_evidence_records(repo, resolver, value_field: str) -> dict:
    """Preserve one provenance record per evidence URL without secret-key collisions."""
    return {
        str(index): {
            "url": redact_url(url),
            value_field: resolver(repo, url),
        }
        for index, url in enumerate(repo.evidence_urls)
    }


class BuildMixin(BuildRequestMixin, BuildSourcesMixin, BuildPreparationMixin):
    """Repository scoping, request construction, build options, and build orchestration.

    Frozen-request accessors live in feathered_app.build_request and are kept
    independent of Tk so worker execution does not depend on live widgets.
    """


    def _scope_operator_repository_to_current_target(self, repo):
        """Attach non-persistent UI scope metadata to an operator-added repo."""
        try:
            repo.target_profile_key = self._profile().key
            repo.target_release = BuildMixin._selected_release(self)
            repo.target_arch = self.arch_var.get()
            family = self._profile().package_family
            repo.repo_format = "apt" if family == "deb" else "pacman" if family == "arch" else "rpm"
        except Exception:
            pass
        return repo


    def _ensure_transaction_base_sources(self) -> None:
        """Populate the target-derived base plan when it should be automatic.

        Custom and local-media plans are intentionally allowed to be empty.
        Distribution/CDN plans are not: if their rows disappeared during a
        workflow rebuild, reconstruct them from the Linux Distribution state.
        """
        if self._mirror_mode():
            return
        if getattr(self, "source_method_var", None) is None:
            self.source_method_var = tk.StringVar(value=self._default_transaction_source_method())
        method = self.source_method_var.get()
        if method in {"Custom repositories", "Installation media / local mirror (ISO, DVD, folder, SMB)"}:
            return
        if any(self._repo_tier(r) == "base" for r in self.repo_rows):
            return
        self._apply_source_method()


    def start_build(self, do_download: bool):
        if self._busy():
            return
        # 1.0.41 never starts an
        # analysis/download with an empty Review contract. The buttons mirror
        # this rule, and this guard keeps programmatic/direct calls honest too.
        if not self._has_review_contract():
            intent = self._acquisition_intent()
            if intent is AcquisitionIntent.PACKAGES:
                message = "No exact packages are selected. Configure repositories and choose at least one package on Repositories first."
                self._focus_validation("repositories", getattr(self, "exact_package_selection_card", None), message)
            elif intent is AcquisitionIntent.REPOSITORY_MIRROR:
                message = "No repositories are selected for mirroring. Choose at least one repository on Repositories first."
                self._focus_validation("repositories", getattr(self, "mirror_selection_card", None), message)
            else:
                message = "Nothing is selected for this build. Choose a workload on Content first."
                self._focus_validation("packages", getattr(self, "package_selection_card", None), message)
            messagebox.showerror(APP_TITLE, message)
            return
        state = self._acquisition_state()
        if state.blocked:
            message = state.reason or "The current acquisition request is blocked by its repository configuration."
            target = (getattr(self, "mirror_selection_card", None) if state.intent is AcquisitionIntent.REPOSITORY_MIRROR
                      else getattr(self, "exact_package_selection_card", None) if state.intent is AcquisitionIntent.PACKAGES
                      else getattr(self, "workload_repositories_card", None))
            self._focus_validation("repositories", target, message)
            messagebox.showerror(APP_TITLE, redact_text(message))
            return
        if not self._single_mode() and not self._mirror_mode():
            self._activate_workload_repository_selection()
        if do_download and self.last_result is not None and \
                self._parameter_signature() != getattr(self, "analysis_signature", None):
            if not messagebox.askyesno(
                    APP_TITLE,
                    "Parameters have changed since the last analysis, so the results shown no "
                    "longer describe what would be built.\n\nRe-analyze and then build?",
                    default="yes"):
                return
            self._invalidate_analysis_if_changed()
        if do_download and self._pick_mode() and self.last_result is not None \
                and not self.picked:
            messagebox.showerror(
                APP_TITLE,
                "No packages are selected, so there is nothing to build. Use the Selection "
                "buttons above the result list - 'All' to include everything, or 'Requested "
                "only' for just the packages you asked for.")
            return
        picked_at_start = (set(self.picked)
                           if do_download and self._pick_mode() and self.last_result is not None
                           else None)
        try:
            job = prepare_job(
                self, do_download=do_download, state=state,
                picked_at_start=picked_at_start,
                confirm_package_only=lambda title, message: messagebox.askyesno(
                    title, message, default="no"))
        except DecisionDeclined:
            self.__dict__.pop("_build_naming_time", None)
            return
        except Exception as exc:
            self.__dict__.pop("_build_naming_time", None)
            self._route_validation_error(str(exc))
            messagebox.showerror(APP_TITLE, redact_text(str(exc)))
            return
        if state.capability is AcquisitionCapability.PACKAGE_ONLY:
            worker_label = "Downloading workload package artifacts…"
        elif state.capability is AcquisitionCapability.REPOSITORY_MIRROR:
            worker_label = "Inventorying selected repository mirror…"
        else:
            worker_label = "Analyzing dependency closure…"
        self._begin_worker(worker_label)
        if do_download:
            # Build no longer blanks the
            # visible selection while it re-analyzes.  Keep the contract on
            # screen and use a pulsing border until payload transfer begins.
            self._start_review_work_glow()
        self.last_warnings = []
        self._refresh_trust_review_bar()
        # Freeze Tk-owned inputs before the worker exists. Nothing below this
        # line may read a widget.
        self._snapshot_build_inputs()
        # The orchestration is a named function with declared inputs, not a
        # closure over this scope. See feathered_app/build_runner.py.
        self.worker = threading.Thread(
            target=build_runner.run, args=(self, job), daemon=True)
        self.worker.start()


