"""Shared source, inventory, trust and publication preparation rules.

The GUI supplies live accessors and dialogs; a spec host supplies frozen values
and explicit policies. This module imports neither App nor the UI context.
"""
from __future__ import annotations

import copy
from datetime import datetime
from pathlib import Path

from acquisition_model import AcquisitionCapability, AcquisitionIntent, derive_acquisition_state
from core import BuildOptions, Cancelled, infer_vendor_id
from feathered_app.build_output import FOLDER_SCHEMES
from feathered_app.build_request import BuildRequestMixin
from feathered_app.build_runner import BuildPlan
from feathered_app.prepared_plan import PreparedPlan
from source_readiness import evaluate_source_readiness
from feathered_app.source_scope import (
    BuildScopeContext, ParticipationContext,
    RepositoryTarget, TargetScope, participates, select_build_scope, target_compatible,
)
import workload_resolution


class PreparationRejected(RuntimeError):
    """The request cannot be prepared with its supplied inputs."""


class DecisionDeclined(Cancelled):
    """A required operator decision was declined."""


class BuildPreparationMixin:
    """Rules shared by GUI preparation and a spec-driven host."""

    def _repository_target_compatible(self, repo) -> bool:
        """Whether a repository belongs to the currently selected Linux target.

        Profile-derived repositories are rebuilt/retargeted by the profile
        machinery. Operator-added repositories are instead remembered with the
        target tuple under which they were created so they can survive a
        temporary target switch without silently participating in the wrong
        distribution/release/architecture.
        """
        try:
            profile = self._profile()
            target = TargetScope(profile.package_family, profile.key,
                                 BuildRequestMixin._selected_release(self), self._selected_arch())
        except Exception:
            # Preserve partial-host compatibility; build preparation separately
            # validates that a complete target has been selected.
            return True
        return target_compatible(target, RepositoryTarget(
            getattr(repo, "repo_format", ""), getattr(repo, "target_profile_key", ""),
            getattr(repo, "target_release", ""), getattr(repo, "target_arch", "")))


    def _repository_participates_in_current_intent(self, repo) -> bool:
        """Whether *repo* belongs to the current transaction workflow.

        ``enabled`` is operator/configuration state.  It is not, by itself, a
        statement that an auto-materialized workload side-channel belongs to a
        different Content intent.  Keeping this distinction here prevents a
        Docker source from leaking into Specific packages provenance merely
        because Docker was selected earlier in the session.
        """
        context = ParticipationContext(
            enabled=lambda row: bool(getattr(row, "enabled", False)),
            url=lambda row: str(getattr(row, "url", "") or ""),
            profile_managed=lambda row: bool(getattr(row, "workload_profile_managed", False)),
            identity=lambda row: getattr(row, "source_identity", None),
            role=lambda row: row.role,
            compatible=lambda row: self._repository_target_compatible(row),
            mirror_mode=lambda: self._mirror_mode(),
            mirror_selected=lambda row: self._mirror_repo_selected(row),
            tier=lambda row: self._repo_tier(row),
            exact_mode=lambda: self._single_mode(),
            exact_source_ids=lambda: {
                getattr(getattr(pkg, "repo", None), "source_identity", None)
                for pkg in getattr(self, "selected_packages", [])},
            required_roles=lambda: set(self._workload_required_repository_roles()),
        )
        return participates(repo, context)


    def _participating_transaction_repositories(self):
        if self._mirror_mode():
            return [r for r in self.repo_rows if self._repository_participates_in_current_intent(r)]
        return [r for r in self.repo_rows if self._repository_participates_in_current_intent(r)]


    def _package_coverage_repositories(self):
        """Enabled repositories relevant to the selected *root* packages only.

        Coverage is not dependency analysis. A dedicated workload root should
        therefore be checked against its workload role without first requiring
        or probing the target distribution's base repository plan. Distribution
        roots still require the enabled base set, and free-form selections may
        use the whole enabled repository set.
        """
        enabled = self._participating_transaction_repositories()
        if self._mirror_mode():
            return [r for r in self.repo_rows if r.url.strip() and self._mirror_repo_selected(r)]
        if self._single_mode():
            source_ids = {p.repo.source_identity for p in getattr(self, "selected_packages", [])}
            return [r for r in enabled if r.source_identity in source_ids]
        readiness = evaluate_source_readiness(
            self._source_plan(), enabled, tier_getter=self._repo_tier)
        return list(readiness.root_repositories)


    def _validate_source_plan(self):
        if self._mirror_mode():
            # Mirroring copies repositories; there is no workload, so workload
            # requirements (Docker's repository, for instance) do not apply.
            # Consulting the workload dropdown here produced "this workload
            # requires Docker's package repository" for a mirror run.
            selected = [r for r in self.repo_rows if r.url.strip()
                        and self._mirror_repo_selected(r)]
            if not selected:
                raise RuntimeError(
                    "No repositories are ticked, so there is nothing to mirror. Tick the "
                    "repositories you want on the Repositories step - 'All' selects "
                    "every enabled repository.")
            return
        workload = self._workload()
        if self._single_mode():
            if not self.selected_packages:
                raise RuntimeError("Choose at least one exact package + version first")
            enabled_ids = {r.source_identity for r in self.repo_rows if r.enabled and r.url}
            missing_sources = sorted({p.repo.name for p in self.selected_packages
                                      if p.repo.source_identity not in enabled_ids})
            if missing_sources:
                raise RuntimeError(
                    "Repository/repositories containing selected exact packages are no longer enabled: "
                    + ", ".join(missing_sources) + ". Choose the affected package(s) again or re-enable the exact source.")
        else:
            if self._workload_uses_distribution_sources() and not any(
                    r.enabled and r.url.strip() and self._repo_tier(r) == "base" for r in self.repo_rows):
                raise RuntimeError(
                    f"{workload.label} includes distribution-native root packages, but no distribution "
                    "repository is enabled. Enable the required distribution sources on Repositories.")
            for role in self._workload_required_repository_roles():
                if not any(r.enabled and r.role == role and r.url for r in self.repo_rows):
                    raise RuntimeError(
                        f"{workload.label} requires a workload repository for role '{role}'. "
                        "Add or enable its recommended source on Repositories.")
        # Do not require a repository whose *label* is role="dependency" here.
        # The resolver can satisfy transitive dependencies from any enabled
        # repository; only requested workload roots are role-constrained.  A
        # curated/internal workload repository may therefore be self-contained.
        # Requiring a separate dependency-tagged source would reject a source
        # set the resolver can actually solve.
        if self._needs_dependency_repos() and not self._package_only_acquisition_mode() and \
                self._profile().key == "rhel" and \
                self._active_source_method() == "Red Hat CDN entitlement (official)" and \
                not self._entitlement_ready():
            raise RuntimeError("Red Hat CDN access requires the Red Hat vendor entitlement certificate, private key, and repository CA. Configure the Red Hat row under Provenance and Keying first.")


    def _build_repository_scope(self, package_only: bool = False):
        """Repositories that may actually participate in the current operation.

        Normal dependency analysis intentionally keeps the complete enabled set
        because any enabled repository may satisfy a transitive dependency.
        Package-only acquisition is different: it promises only the selected
        roots, so unrelated base/additional repositories must not become hidden
        prerequisites. Mirror mode similarly uses only repositories selected for
        mirroring.
        """
        context = BuildScopeContext(
            participating=lambda: self._participating_transaction_repositories(),
            root_coverage=lambda: self._package_coverage_repositories(),
            capability=lambda: self._acquisition_state().capability,
            repositories=lambda: self.repo_rows,
            mirror_selected=lambda repo: self._mirror_repo_selected(repo),
            url=lambda repo: repo.url,
            name=lambda repo: getattr(repo, "name", "?"),
            init_conflict=lambda repo: self._init_repository_conflict(repo),
            log=lambda message: self._log(message),
        )
        return select_build_scope(context, package_only=package_only)


    def _build_options(self, package_only: bool = False):
        if not package_only:
            state = self._acquisition_state()
            package_only = state.capability is AcquisitionCapability.PACKAGE_ONLY
        try:
            trust_scope = self._build_repository_scope(package_only=package_only)
        except Exception:
            trust_scope = None
        try:
            trust = self._trust_options(trust_scope)
        except TypeError:  # Lightweight compatibility/test doubles may expose the older no-arg helper.
            trust = self._trust_options()
        if package_only:
            # A workload-only upstream cannot prove a complete transaction, so
            # dependencies are never followed. Repository metadata over the
            # collected roots is the operator's explicit choice (default off on
            # entering package-only): a local repository of a few artifacts is
            # a legitimate object, and the PACKAGE-ONLY warning still records
            # that it is not install-complete.
            trust["emit_repository"] = bool(trust.get("emit_repository"))
            return BuildOptions(
                include_dependencies=False, include_recommends=False,
                include_rootless=False, target_inventory=None,
                max_resolution_passes=self.resolution_pass_budget or 8,
                **trust,
            )
        if state.capability is AcquisitionCapability.REPOSITORY_MIRROR:
            # A repository mirror is a complete repository object, not a flat
            # package collection or a differential addendum. Every publication
            # fork therefore emits its own repository metadata and ignores any
            # stale differential baseline retained from another workflow.
            trust["emit_repository"] = True
            trust["baseline_manifest"] = ""
            return BuildOptions(
                include_dependencies=False, include_recommends=False,
                include_rootless=False, target_inventory=None,
                max_resolution_passes=self.resolution_pass_budget or 8,
                **trust,
            )
        if self._single_mode():
            # Exact-package mode is intentionally strict: only strong RPM
            # Requires or APT Depends/Pre-Depends are followed. Weak recommendations are excluded.
            return BuildOptions(include_dependencies=True, include_recommends=False,
                                include_rootless=False,
                                max_resolution_passes=self.resolution_pass_budget or 8,
                                **trust)
        mode = BuildRequestMixin._selected_content(self, "dependency_mode", "mode_var")
        inv = None
        if mode == "Target-aware complete":
            inventory_path = BuildRequestMixin._selected_inventory(self)
            if inventory_path:
                inv = self._parse_target_inventory_backend(Path(inventory_path))
        return BuildOptions(
            include_dependencies=True,
            include_recommends=mode == "Complete + weak dependencies",
            include_rootless=False,
            target_inventory=inv,
            max_resolution_passes=self.resolution_pass_budget or 8,
            **trust,
        )


    def _local_media_pending(self) -> bool:
        """True when a local-media source is selected but nothing was loaded."""
        method = self._active_source_method()
        if method != "Installation media / local mirror (ISO, DVD, folder, SMB)":
            return False
        return not any(r.enabled and r.url.startswith("file:") for r in self.repo_rows)


    def _validate_signing(self) -> None:
        """An explicit security request must not degrade to a warning."""
        if (self._selected_output_option("sign_bundle_index", "sign_index_var", flag=True)
                and not self._selected_output_option("signing_key", "signing_key_var").strip()):
            raise RuntimeError(
                "Bundle sealing is enabled but no signing key is set. Add a GPG key id on the "
                "Provenance & Keying step, or turn off sealing under Output Directories.")


    def _validate_output_naming(self) -> None:
        """Custom naming needs either literal text or a date/time prefix."""
        if BuildRequestMixin._selected_output_option(self, "folder_scheme", "folder_scheme_var") != FOLDER_SCHEMES[3]:
            return
        if not BuildRequestMixin._selected_output_option(self, "folder_label", "folder_label_var").strip() and BuildRequestMixin._selected_output_option(self, "folder_stamp", "folder_stamp_var") not in {"date", "time"}:
            raise RuntimeError(
                "The output folder scheme is set to 'Custom label', but both the label and Prefix are empty. "
                "Enter a label, choose Date or Date + time, or choose a different naming scheme.")


    def _validate_sources(self, want_dependencies: bool) -> None:
        """Validate that there is a usable source set before metadata loading.

        Repository roles constrain requested roots, not dependency providers.
        Transitive dependencies are intentionally resolved across all enabled
        repositories, so a self-contained internal/workload repository must be
        allowed to prove that it satisfies the closure.  Missing dependencies
        are reported by the resolver instead of being guessed from a UI role.
        """
        # A pending base-media plan matters only when the selected workload has
        # distribution-native roots. Dedicated workload/internal repositories
        # are allowed to prove their own roots (and, during normal analysis,
        # potentially a self-contained closure) without an irrelevant base-plan
        # configuration becoming a global gate.
        if self._local_media_pending() and self._workload_uses_distribution_sources():
            raise RuntimeError(
                "Local media is selected as the base source, but no media folder has been loaded. "
                "Use 'Choose folder…' on Repositories and select the mounted ISO or mirror "
                "root - the folder containing repodata/ (RPM), dists/ (APT), or a pacman repository .db (Arch).")
        enabled = self._participating_transaction_repositories()
        if not enabled:
            raise RuntimeError("No usable package sources are enabled. Configure and enable at least one "
                               "repository before checking coverage or analyzing the build.")


    def _trust_options(self, repositories=None) -> dict:
        """Collect trust settings for repositories that can participate in this build."""
        source_rows = list(repositories) if repositories is not None else [
            r for r in self.repo_rows if r.enabled and r.url.strip()]
        enabled_vendor_ids = {
            getattr(r, "vendor_id", "") or infer_vendor_id(r.name, r.url)
            for r in source_rows if r.repo_format == "rpm"
        }
        vendor_keyrings = {
            vendor_id: str(self.vendor_signature_profiles.get(vendor_id, {}).get("keyring", "")).strip()
            for vendor_id in enabled_vendor_ids
            if str(self.vendor_signature_profiles.get(vendor_id, {}).get("keyring", "")).strip()
        }
        required_vendors = {
            vendor_id for vendor_id in enabled_vendor_ids
            if self.vendor_signature_profiles.get(vendor_id, {}).get("policy") == "require"
        }
        return {
            # Legacy global fields are intentionally blank/false. Vendor package
            # signature trust is scoped explicitly below.
            "vendor_keyring": "",
            "require_vendor_signatures": False,
            "vendor_keyrings": vendor_keyrings,
            "require_vendor_signatures_by_vendor": required_vendors,
            "signing_key": self._selected_output_option("signing_key", "signing_key_var").strip(),
            "baseline_manifest": self._selected_output_option(
                "baseline_path", "baseline_var").strip(),
            "optional_roots": self._optional_roots(),
            "sign_bundle_index": self._selected_output_option(
                "sign_bundle_index", "sign_index_var", flag=True),
            "emit_repository": self._selected_output_option(
                "emit_repository", "emit_repo_var", flag=True),
            # verification strategy is per
            # repository. Keep the legacy BuildOptions digest flag false; the
            # explicit 1.0.36 strategy enforces strict/fallback behavior itself.
            "require_package_digests": False,
        }


    def _optional_roots(self) -> set:
        """Names whose absence should be reported, not fatal.

        Exact-package mode has no optional members: the operator asked for those
        specific packages by name, so a missing one is an error.
        """
        if self._single_mode() or self._mirror_mode():
            return set()
        workload = self._workload()
        if workload.custom:
            return set()
        family = self._profile().package_family
        optional = set(workload.optional_for(family))
        optional.update(root.package for root in workload.source_plan(family).roots if root.optional)
        return optional


    def _entitlement_ready(self):
        # GUI credentials are also accepted while its repository UI is staged.
        if all(self.__dict__.get(k) for k in ('rhsm_cert', 'rhsm_key', 'rhsm_ca')):
            return True
        base = [r for r in self.repo_rows if r.enabled and self._repo_tier(r) == 'base']
        return bool(base) and all(r.client_cert and r.client_key and r.ca_cert for r in base)

    def _needs_dependency_repos(self):
        return not self._mirror_mode()

    def _workload_uses_distribution_sources(self):
        return self._source_plan().distribution_required

    def _init_repository_conflict(self, repo):
        return workload_resolution.repository_init_conflict(
            repo.name, repo.url, self._profile().key, self._selected_init_system())

    def _acquisition_state(self):
        intent = self._acquisition_intent()
        if intent is AcquisitionIntent.REPOSITORY_MIRROR:
            return derive_acquisition_state(intent, mirror_repository_count=len(self._selected_mirror_repositories()))
        rows = self._participating_transaction_repositories()
        if intent is AcquisitionIntent.PACKAGES:
            enabled = {r.source_identity for r in rows}
            return derive_acquisition_state(intent, exact_root_count=len(self.selected_packages),
                exact_root_sources_ready=bool(self.selected_packages) and
                all(p.repo.source_identity in enabled for p in self.selected_packages))
        plan = self._source_plan()
        if (self._profile().key == 'rhel' and plan.roots and not plan.distribution_required
                and self._active_source_method() == 'Red Hat CDN entitlement (official)'
                and not self._entitlement_ready()):
            rows = [r for r in rows if self._repo_tier(r) != 'base']
        return derive_acquisition_state(intent, workload_readiness=evaluate_source_readiness(
            plan, rows, tier_getter=self._repo_tier))

    def _package_only_acquisition_mode(self):
        return self._acquisition_state().capability is AcquisitionCapability.PACKAGE_ONLY


def prepare_job(host, *, do_download=True, state=None, picked_at_start=None,
                confirm_package_only=None) -> PreparedPlan:
    """Validate one operation and lock its publication choices before execution.

    Callers own source configuration and selected-package resolution. A GUI
    adapter can supply its already derived state and current reviewed selection.
    Publication interaction is a host callback; no GUI is imported here.
    """
    if state is None:
        state = host._acquisition_state()
    if state.blocked:
        raise PreparationRejected(state.reason or 'The acquisition request is blocked.')
    package_only = state.capability is AcquisitionCapability.PACKAGE_ONLY
    if package_only:
        message = host._package_only_warning_text()
        if not do_download:
            raise PreparationRejected(message)
        confirm = confirm_package_only or host._ask_on_ui_thread
        if not confirm('Feathered', message + '\n\nDownload only the requested workload package artifacts?'):
            raise DecisionDeclined('Package-only acquisition was declined.')
    host._validate_source_plan()
    requests = host._package_requests()
    requested_source_plan = host._request_source_plan_metadata(requests)
    repositories = copy.deepcopy(host._build_repository_scope(package_only=package_only))
    opts = host._build_options(package_only=package_only)
    from dataclasses import replace
    from kubernetes_workflow import VKS_KEY, rolling_source
    context = BuildRequestMixin._selected_workload_context(host)
    context.validate()
    if context.workload == VKS_KEY and not host._mirror_mode():
        path = BuildRequestMixin._selected_inventory(host)
        if path:
            opts.target_inventory = host._parse_target_inventory_backend(Path(path))
        baseline_available = bool(
            opts.target_inventory is not None
            and getattr(opts.target_inventory, "retained_packages", None))
        if context.pin_baseline and not baseline_available:
            context = replace(context, pin_baseline=False)
            log = getattr(host, "_log", None)
            if callable(log):
                log("Pin to inventory baseline was ignored because no usable installed inventory is loaded.")
        if context.pin_baseline:
            repositories = [r for r in repositories if not rolling_source(r)]
        opts.include_dependencies = True
        opts.emit_repository = True
    opts.workload_context = context
    host._validate_signing()
    host._validate_output_naming()
    host._validate_sources(opts.include_dependencies)
    # Freeze the clock before any confirmation; GUI snapshot capture preserves it.
    host.__dict__['_build_naming_time'] = datetime.now()
    locked_name = None
    forks = []
    if do_download:
        if host._mirror_mode() and not host._unified_mirror_mode():
            proposed = host._mirror_output_folder_names()
            names = [name for _, name in proposed]
            if len(names) != len(set(names)):
                raise PreparationRejected('Selected repositories resolve to the same output folder name.')
            for repo, name in proposed:
                repo_opts = copy.deepcopy(opts)
                confirmed = host._confirm_output_folder_name(name, repo_opts)
                if confirmed is None:
                    raise DecisionDeclined('Output publication was declined.')
                forks.append((repo.source_identity, confirmed, repo_opts))
        else:
            folder_name = host._folder_name()
            if folder_name in {"", ".", ".."}:
                raise PreparationRejected('The output folder label must identify a child directory.')
            locked_name = host._confirm_output_folder_name(folder_name, opts)
            if locked_name is None:
                raise DecisionDeclined('Output publication was declined.')
    return BuildPlan(state, opts, requests, requested_source_plan, repositories,
                     package_only, picked_at_start, do_download, locked_name, forks)
